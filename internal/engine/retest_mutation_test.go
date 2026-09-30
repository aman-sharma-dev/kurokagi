package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kurokagi/kurokagi/internal/config"
)

func controlledMutationRetest(t *testing.T, method, mode, access string) (*Scanner, RetestInput, *atomic.Int32, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var item map[string]any
	var mu sync.Mutex
	var posts, writes, cleanupDeletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/items":
			mu.Lock()
			items := []any{}
			if item != nil {
				items = append(items, item)
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "items": items})
		case r.Method == http.MethodPost && r.URL.Path == "/api/items":
			posts.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			meta, _ := body["meta"].(map[string]any)
			initialStatus := "draft"
			if mode == "no-op" {
				initialStatus = "published"
			}
			mu.Lock()
			item = map[string]any{"id": "fresh-item", "meta": map[string]any{"marker": meta["marker"]}, "status": initialStatus, "workspace_id": "team-a"}
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/items/fresh-item":
			if mode == "delete-timeout-unknown" && writes.Load() > 0 {
				http.Error(w, "unknown", http.StatusServiceUnavailable)
				return
			}
			mu.Lock()
			snapshot := item
			mu.Unlock()
			if snapshot == nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"complete": true})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "item": snapshot, "status": snapshot["status"]})
		case (r.Method == http.MethodPut || r.Method == http.MethodPatch) && r.URL.Path == "/api/items/fresh-item":
			writes.Add(1)
			if mode == "deny" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			if mode != "timeout-unknown" {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				mu.Lock()
				item["status"] = body["status"]
				mu.Unlock()
			}
			if strings.HasPrefix(mode, "timeout") {
				time.Sleep(80 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/items/fresh-item":
			if r.Header.Get("Authorization") == "alice" {
				cleanupDeletes.Add(1)
				mu.Lock()
				item = nil
				mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writes.Add(1)
			if mode == "deny" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			if mode != "delete-remains" {
				mu.Lock()
				item = nil
				mu.Unlock()
			}
			if strings.HasPrefix(mode, "delete-timeout") {
				time.Sleep(80 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	c := fixture(t, false)
	c.Target.BaseURL, c.Target.AllowedOrigins = server.URL, []string{server.URL}
	c.Target.AllowedPaths = []string{"/api"}
	c.Limits.MaxRequests, c.Limits.Timeout = 40, "20ms"
	setup := config.Operation{ID: "controlled-setup", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs", Access: "ALLOWED", Classification: "BFLA", ContentType: "application/json", Disposable: method == http.MethodDelete,
		RequestBody:  map[string]any{"meta": map[string]any{"marker": "${KURO_TEST_MARKER}"}},
		Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "meta.marker", ResourceIDField: "id", RequestMarkerField: "meta.marker", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}
	mutation := config.Operation{ID: "controlled-mutation", Path: "/api/items/{id}", Method: method, Actor: "bob", Owner: "alice", Resource: "docs", Access: access, Classification: "BOLA", ControlledResourceOperationID: setup.ID, ContentType: "application/json",
		RequestBody:  map[string]any{"status": "published"},
		Verification: config.VerificationStrategy{Type: "RESOURCE_STATE", Path: "/api/items/{id}", Field: "status", ResourceIDField: "id", MarkerField: "meta.marker", BaselineCompleteField: "complete"}}
	if method == http.MethodDelete {
		mutation.Verification = config.VerificationStrategy{Type: "RESOURCE_ABSENT", Path: "/api/items/{id}", ResourceIDField: "id", MarkerField: "meta.marker", BaselineCompleteField: "complete"}
	}
	c.Operations = []config.Operation{setup, mutation}
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	spec := `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/items":{"get":{},"post":{}},"/api/items/{id}":{"get":{},"put":{},"patch":{},"delete":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c.OpenAPI.Path = specPath
	c.Mutations = config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST", "PUT", "PATCH", "DELETE"}, AllowedPaths: []string{"/api/items", "/api/items/{id}"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 4, CleanupRequestBudget: 4, CleanupTimeout: "1s"}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := functionFinding("BOLA", mutation.ID, mutation.Actor, mutation.Owner, mutation.Resource, "", method, mutation.Path, "").Fingerprint
	input := RetestInput{SchemaVersion: "1", Fingerprint: fingerprint, Classification: mutation.Classification, Resource: mutation.Resource, Actor: mutation.Actor, Victim: mutation.Owner, Method: method, Path: mutation.Path}
	return s, input, &posts, &writes, &cleanupDeletes
}

func TestTargetedRelationshipPATCHRetestRequiresFreshBoundaryProof(t *testing.T) {
	for _, tc := range []struct {
		name, actorContext string
		want               string
		writes             int32
	}{{"different boundary", "team-b", "STILL_PRESENT", 1}, {"same boundary", "team-a", "NOT_TESTABLE", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, input, _, writes, _ := controlledMutationRetest(t, http.MethodPatch, "transition", "DENIED")
			s.cfg.Operations[1].Classification = "RELATIONSHIP"
			s.cfg.Operations[1].Relationship = "workspace"
			s.cfg.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
			s.cfg.Identities[0].Contexts = map[string]string{"workspace": "team-a"}
			s.cfg.Identities[1].Contexts = map[string]string{"workspace": tc.actorContext}
			input.Classification, input.Relationship = "RELATIONSHIP", "workspace"
			input.Fingerprint = functionFinding("RELATIONSHIP", "controlled-mutation", "bob", "alice", "docs", "workspace", http.MethodPatch, "/api/items/{id}", "").Fingerprint
			got := s.Retest(context.Background(), input)
			if got.Outcome != tc.want || writes.Load() != tc.writes {
				t.Fatalf("result=%+v writes=%d", got, writes.Load())
			}
		})
	}
}

func TestTargetedPUTPATCHRetestOutcomes(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		for _, tc := range []struct {
			mode, access, want                             string
			expectedWrites, expectedPosts, expectedCleanup int32
		}{{"transition", "DENIED", "STILL_PRESENT", 1, 1, 1}, {"deny", "DENIED", "FIXED", 1, 1, 1}, {"timeout-transition", "DENIED", "STILL_PRESENT", 1, 1, 1}, {"timeout-unknown", "DENIED", "INCONCLUSIVE", 1, 1, 1}, {"transition", "ALLOWED", "NOT_TESTABLE", 0, 0, 0}, {"no-op", "DENIED", "NOT_TESTABLE", 0, 1, 1}} {
			t.Run(method+"/"+tc.mode+"/"+tc.access, func(t *testing.T) {
				s, input, posts, writes, cleanup := controlledMutationRetest(t, method, tc.mode, tc.access)
				if strings.HasPrefix(tc.mode, "timeout") {
					s.client.Timeout = 20 * time.Millisecond
				}
				got := s.Retest(context.Background(), input)
				if got.Outcome != tc.want {
					t.Fatalf("got=%+v want=%s", got, tc.want)
				}
				if writes.Load() != tc.expectedWrites {
					t.Fatalf("attack update count=%d want=%d", writes.Load(), tc.expectedWrites)
				}
				if posts.Load() != tc.expectedPosts || cleanup.Load() != tc.expectedCleanup {
					t.Fatalf("setup POST/cleanup DELETE counts=%d/%d want=%d/%d", posts.Load(), cleanup.Load(), tc.expectedPosts, tc.expectedCleanup)
				}
			})
		}
	}
}

func TestTargetedDELETERetestOutcomes(t *testing.T) {
	for _, tc := range []struct {
		mode, access, want             string
		posts, expectedWrites, cleanup int32
	}{{"delete", "DENIED", "STILL_PRESENT", 1, 1, 0}, {"deny", "DENIED", "FIXED", 1, 1, 1}, {"delete-remains", "DENIED", "INCONCLUSIVE", 1, 1, 1}, {"delete-timeout-absent", "DENIED", "STILL_PRESENT", 1, 1, 0}, {"delete-timeout-unknown", "DENIED", "INCONCLUSIVE", 1, 1, 0}, {"delete", "ALLOWED", "NOT_TESTABLE", 0, 0, 0}} {
		t.Run(tc.mode+"/"+tc.access, func(t *testing.T) {
			s, input, posts, writes, cleanup := controlledMutationRetest(t, http.MethodDelete, tc.mode, tc.access)
			if strings.HasPrefix(tc.mode, "delete-timeout") {
				s.client.Timeout = 20 * time.Millisecond
			}
			got := s.Retest(context.Background(), input)
			if got.Outcome != tc.want {
				t.Fatalf("got=%+v want=%s", got, tc.want)
			}
			if writes.Load() != tc.expectedWrites {
				t.Fatalf("attack DELETE count=%d want=%d", writes.Load(), tc.expectedWrites)
			}
			if posts.Load() != tc.posts || cleanup.Load() != tc.cleanup {
				t.Fatalf("setup POST/cleanup DELETE counts=%d/%d want=%d/%d", posts.Load(), cleanup.Load(), tc.posts, tc.cleanup)
			}
		})
	}
}

func TestTargetedRelationshipDELETERetestRequiresFreshBoundaryProof(t *testing.T) {
	for _, tc := range []struct {
		name, actorContext string
		want               string
		writes             int32
	}{{"different boundary", "team-b", "STILL_PRESENT", 1}, {"same boundary", "team-a", "NOT_TESTABLE", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, input, _, writes, _ := controlledMutationRetest(t, http.MethodDelete, "delete", "DENIED")
			s.cfg.Operations[1].Classification = "RELATIONSHIP"
			s.cfg.Operations[1].Relationship = "workspace"
			s.cfg.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
			s.cfg.Identities[0].Contexts = map[string]string{"workspace": "team-a"}
			s.cfg.Identities[1].Contexts = map[string]string{"workspace": tc.actorContext}
			input.Classification, input.Relationship = "RELATIONSHIP", "workspace"
			input.Fingerprint = functionFinding("RELATIONSHIP", "controlled-mutation", "bob", "alice", "docs", "workspace", http.MethodDelete, "/api/items/{id}", "").Fingerprint
			got := s.Retest(context.Background(), input)
			if got.Outcome != tc.want || writes.Load() != tc.writes {
				t.Fatalf("result=%+v writes=%d", got, writes.Load())
			}
		})
	}
}
