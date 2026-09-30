package main

import (
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
	"github.com/kurokagi/kurokagi/internal/engine"
)

type updateFixture struct {
	mode                                         string
	mu                                           sync.Mutex
	item                                         map[string]any
	marker                                       string
	complete                                     bool
	posts, puts, patches, deletes, attackDeletes atomic.Int32
}

func newUpdateFixture(mode string) (*httptest.Server, *updateFixture) {
	f := &updateFixture{mode: mode, complete: mode != "incomplete-post"}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/docs" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "doc-a", "name": "doc"}})
		case strings.HasPrefix(r.URL.Path, "/api/docs/") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"id": filepath.Base(r.URL.Path), "name": "doc"})
		case r.URL.Path == "/api/items" && r.Method == http.MethodGet:
			f.mu.Lock()
			items := []map[string]any{}
			if f.item != nil {
				item := map[string]any{}
				for k, v := range f.item {
					item[k] = v
				}
				items = append(items, item)
			}
			complete := f.complete
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": complete, "items": items})
		case r.URL.Path == "/api/items" && r.Method == http.MethodPost:
			f.posts.Add(1)
			if mode == "setup-no-create" {
				w.WriteHeader(http.StatusCreated)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			meta, _ := body["metadata"].(map[string]any)
			marker, _ := meta["kuro_test_id"].(string)
			workspaceID, _ := body["workspace_id"].(string)
			status := "draft"
			if mode == "no-op" {
				status = "published"
			}
			f.mu.Lock()
			f.marker = marker
			f.item = map[string]any{"id": "created-1", "status": status, "workspace_id": workspaceID, "metadata": map[string]any{"kuro_test_id": marker}}
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/api/items/created-1" && r.Method == http.MethodGet:
			f.mu.Lock()
			item := map[string]any{}
			if f.item != nil {
				for k, v := range f.item {
					item[k] = v
				}
			}
			complete := f.complete
			if mode == "pre-incomplete" && f.patches.Load()+f.puts.Load() == 0 {
				complete = false
			}
			if mode == "delete-incomplete-pre" && f.attackDeletes.Load() == 0 {
				complete = false
			}
			if mode == "delete-marker-mismatch" && f.attackDeletes.Load() == 0 {
				meta, _ := item["metadata"].(map[string]any)
				item["metadata"] = map[string]any{"kuro_test_id": "not-the-test-marker"}
				_ = meta
			}
			f.mu.Unlock()
			if item == nil {
				http.NotFound(w, r)
				return
			}
			id := item["id"]
			if mode == "delete-id-mismatch" && f.attackDeletes.Load() == 0 {
				id = "other-resource"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": complete, "id": id, "status": item["status"], "workspace_id": item["workspace_id"], "metadata": item["metadata"]})
		case r.URL.Path == "/api/items/created-1" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
			if r.Method == http.MethodPatch {
				f.patches.Add(1)
			} else {
				f.puts.Add(1)
			}
			if mode == "redirect" && f.patches.Load()+f.puts.Load() == 1 {
				http.Redirect(w, r, "/api/items/created-1", http.StatusTemporaryRedirect)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			state, _ := body["status"].(string)
			f.mu.Lock()
			if f.item != nil && mode != "no-change" {
				if mode != "restore-fail" || state != "draft" {
					f.item["status"] = state
				}
			}
			if mode == "timeout-unknown" && state == "published" {
				f.complete = false
			}
			if state == "draft" {
				f.complete = true
			}
			f.mu.Unlock()
			if (mode == "timeout-store" || mode == "timeout-unknown") && state == "published" {
				time.Sleep(100 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/api/items/created-1" && r.Method == http.MethodDelete:
			f.deletes.Add(1)
			if r.Header.Get("Authorization") == "BOB_UPDATE_SECRET" {
				f.attackDeletes.Add(1)
				if mode == "delete-remains" || mode == "delete-204-remains" || mode == "delete-404-remains" || mode == "delete-unknown" || mode == "delete-redirect" || mode == "delete-cleanup-fail" || mode == "delete-cleanup-unknown" {
					if mode == "delete-unknown" {
						f.mu.Lock()
						f.complete = false
						f.mu.Unlock()
					}
					if mode == "delete-redirect" {
						http.Redirect(w, r, "/api/items/created-1", http.StatusTemporaryRedirect)
						return
					}
					if mode == "delete-204-remains" {
						w.WriteHeader(http.StatusNoContent)
					} else if mode == "delete-404-remains" {
						w.WriteHeader(http.StatusNotFound)
					} else {
						w.WriteHeader(http.StatusForbidden)
					}
					return
				}
				f.mu.Lock()
				f.item = nil
				f.complete = true
				f.mu.Unlock()
				if mode == "delete-timeout-absent" || mode == "delete-timeout-unknown" {
					if mode == "delete-timeout-unknown" {
						f.mu.Lock()
						f.complete = false
						f.mu.Unlock()
					}
					time.Sleep(100 * time.Millisecond)
					return
				}
				if mode == "delete-403-absent" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if mode == "delete-cleanup-fail" || mode == "delete-cleanup-unknown" {
				if mode == "delete-cleanup-unknown" {
					f.mu.Lock()
					f.complete = false
					f.mu.Unlock()
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.mu.Lock()
			f.item = nil
			f.complete = true
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return s, f
}

func controlledDeleteConfig(serverURL, specPath, access, classification string) config.Config {
	c := controlledUpdateConfig(serverURL, specPath, "PATCH", "DENIED", "BOLA")
	setup := c.Operations[0]
	setup.Disposable = true
	setup.RequestBody = map[string]any{"workspace_id": "workspace-a", "metadata": map[string]any{"kuro_test_id": "${KURO_TEST_MARKER}"}}
	delete := config.Operation{ID: "delete-item", ControlledResourceOperationID: setup.ID, Path: "/api/items/{id}", Method: "DELETE", Actor: "bob", Owner: "alice", Resource: "docs", Access: access, Classification: classification,
		Verification: config.VerificationStrategy{Type: "RESOURCE_ABSENT", Path: "/api/items/{id}", MarkerField: "metadata.kuro_test_id", ResourceIDField: "id", BaselineCompleteField: "complete"}}
	c.Operations = []config.Operation{setup, delete}
	c.Mutations.AllowedMethods = []string{"POST", "DELETE"}
	c.Mutations.AllowedPaths = []string{"/api/items", "/api/items/{id}"}
	c.Mutations.RequestBudget = 4
	c.Mutations.CleanupRequestBudget = 4
	return c
}

func runControlledDeleteCLI(t *testing.T, mode, access, classification string, mutate func(*config.Config)) (engine.Result, *updateFixture, int) {
	t.Helper()
	server, fixture := newUpdateFixture(mode)
	defer server.Close()
	dir := t.TempDir()
	specPath, configPath, outPath := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "config.json"), filepath.Join(dir, "result.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Local controlled DELETE","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}},"/api/items/{id}":{"get":{},"delete":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := controlledDeleteConfig(server.URL, specPath, access, classification)
	if strings.Contains(mode, "timeout") {
		c.Limits.Timeout = "20ms"
	}
	if mutate != nil {
		mutate(&c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	exit := run([]string{"scan", "-config", configPath, "-out", outPath})
	resultBytes, err := os.ReadFile(outPath)
	if err == nil {
		for _, canary := range []string{"ALICE_UPDATE_SECRET", "BOB_UPDATE_SECRET", "${KURO_TEST_MARKER}", "kuro_test_id", fixture.marker} {
			if canary == "" {
				continue
			}
			if strings.Contains(string(resultBytes), canary) {
				t.Fatalf("DELETE evidence leaked canary %q: %s", canary, resultBytes)
			}
		}
		var result engine.Result
		if err = json.Unmarshal(resultBytes, &result); err != nil {
			t.Fatal(err)
		}
		return result, fixture, exit
	}
	return engine.Result{}, fixture, exit
}

func controlledUpdateConfig(serverURL, specPath, method, access, classification string) config.Config {
	c := config.Config{SchemaVersion: "3", Target: config.Target{BaseURL: serverURL, AllowedOrigins: []string{serverURL}, AllowedPaths: []string{"/api"}},
		Identities:   []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "ALICE_UPDATE_SECRET"}}, {ID: "bob", Headers: map[string]string{"Authorization": "BOB_UPDATE_SECRET"}}},
		Resources:    []config.Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility", Relationships: []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}}},
		Expectations: []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}},
		Operations: []config.Operation{
			{ID: "seed-item", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs", Access: "ALLOWED", Classification: "BFLA", ContentType: "application/json", RequestBody: map[string]any{"metadata": map[string]any{"kuro_test_id": "${KURO_TEST_MARKER}"}}, Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "metadata.kuro_test_id", ResourceIDField: "id", RequestMarkerField: "metadata.kuro_test_id", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}},
			{ID: "update-item", ControlledResourceOperationID: "seed-item", Path: "/api/items/{id}", Method: method, Actor: "bob", Owner: "alice", Resource: "docs", Access: access, Classification: classification, ContentType: "application/json", RequestBody: map[string]any{"status": "published"}, RestoreBody: map[string]any{"status": "${KURO_PREVIOUS_STATE}"}, Verification: config.VerificationStrategy{Type: "RESOURCE_STATE", Path: "/api/items/{id}", Field: "status", ResourceIDField: "id", MarkerField: "metadata.kuro_test_id", BaselineCompleteField: "complete"}},
		}, Mutations: config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST", "PUT", "PATCH"}, AllowedPaths: []string{"/api/items", "/api/items/{id}"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 4, CleanupRequestBudget: 6, CleanupTimeout: "1s"},
		Limits: config.Limits{Timeout: "500ms", MaxRequests: 100, Concurrency: 1, MaxResponseBytes: 4096, MaxObjects: 20, RedirectPolicy: "same_origin"}}
	c.OpenAPI.Path = specPath
	return c
}

func runControlledUpdateCLI(t *testing.T, mode, method, access, classification string, mutate func(*config.Config)) (engine.Result, int, *updateFixture) {
	t.Helper()
	server, fixture := newUpdateFixture(mode)
	defer server.Close()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	configPath := filepath.Join(dir, "config.json")
	outPath := filepath.Join(dir, "result.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Local controlled update","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}},"/api/items/{id}":{"get":{},"put":{},"patch":{},"delete":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := controlledUpdateConfig(server.URL, specPath, method, access, classification)
	if mode == "timeout-store" || mode == "timeout-unknown" {
		c.Limits.Timeout = "20ms"
	}
	if mutate != nil {
		mutate(&c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	exit := run([]string{"scan", "-config", configPath, "-out", outPath})
	resultBytes, err := os.ReadFile(outPath)
	if err != nil {
		return engine.Result{}, exit, fixture
	}
	for _, canary := range []string{"ALICE_UPDATE_SECRET", "BOB_UPDATE_SECRET", "${KURO_TEST_MARKER}", "${KURO_PREVIOUS_STATE}", "published", "draft"} {
		if strings.Contains(string(resultBytes), canary) {
			t.Fatalf("sensitive mutation canary %q leaked: %s", canary, resultBytes)
		}
	}
	var result engine.Result
	if err = json.Unmarshal(resultBytes, &result); err != nil {
		t.Fatal(err)
	}
	return result, exit, fixture
}

func TestCLIControlledPUTPATCHLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, mode, method, access, class string
		mutate                            func(*config.Config)
		wantFindings, wantWrites          int
		wantState                         string
	}{
		{"denied patch transition", "normal", "PATCH", "DENIED", "BOLA", nil, 1, 2, "RESTORATION_SUCCEEDED"},
		{"denied put transition", "normal", "PUT", "DENIED", "BFLA", nil, 1, 2, "RESTORATION_SUCCEEDED"},
		{"unchanged patch", "no-change", "PATCH", "DENIED", "BOLA", nil, 0, 1, "RESTORATION_NOT_REQUIRED"},
		{"unchanged put", "no-change", "PUT", "DENIED", "BOLA", nil, 0, 1, "RESTORATION_NOT_REQUIRED"},
		{"preexisting desired state", "no-op", "PATCH", "DENIED", "BOLA", nil, 0, 0, "RESTORATION_NOT_REQUIRED"},
		{"incomplete prestate", "pre-incomplete", "PATCH", "DENIED", "BOLA", nil, 0, 0, ""},
		{"timeout after store", "timeout-store", "PATCH", "DENIED", "BOLA", nil, 1, 2, "RESTORATION_SUCCEEDED"},
		{"timeout unknown", "timeout-unknown", "PATCH", "DENIED", "BOLA", nil, 0, 2, "RESTORATION_SUCCEEDED"},
		{"allowed transition", "normal", "PATCH", "ALLOWED", "BOLA", nil, 0, 2, "RESTORATION_SUCCEEDED"},
		{"unknown transition", "normal", "PATCH", "UNKNOWN", "BOLA", nil, 0, 2, "RESTORATION_SUCCEEDED"},
		{"relationship patch", "normal", "PATCH", "DENIED", "BOLA", func(c *config.Config) { c.Operations[1].Relationship = "workspace" }, 1, 2, "RESTORATION_SUCCEEDED"},
		{"write BFLA", "normal", "PATCH", "DENIED", "BFLA", nil, 1, 2, "RESTORATION_SUCCEEDED"},
		{"restore fails", "restore-fail", "PATCH", "DENIED", "BOLA", nil, 1, 2, "RESTORATION_FAILED"},
		{"fallback cleanup", "normal", "PATCH", "DENIED", "BOLA", func(c *config.Config) { c.Operations[1].RestoreBody = nil }, 1, 1, "RESTORATION_NOT_REQUIRED"},
		{"redirect", "redirect", "PATCH", "DENIED", "BOLA", nil, 0, 1, "RESTORATION_NOT_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, fixture := runControlledUpdateCLI(t, tc.mode, tc.method, tc.access, tc.class, tc.mutate)
			if len(result.Findings) != tc.wantFindings {
				t.Fatalf("findings=%d want=%d coverage=%+v", len(result.Findings), tc.wantFindings, result.Coverage)
			}
			writes := int(fixture.patches.Load() + fixture.puts.Load())
			if writes != tc.wantWrites {
				t.Fatalf("write count=%d want=%d", writes, tc.wantWrites)
			}
			if fixture.deletes.Load() != 1 {
				t.Fatalf("expected one fallback cleanup DELETE, got %d", fixture.deletes.Load())
			}
			fixture.mu.Lock()
			remaining := fixture.item != nil
			fixture.mu.Unlock()
			if remaining {
				t.Fatal("scanner-created update fixture remained after cleanup")
			}
			found := false
			for _, coverage := range result.Coverage {
				if coverage.Operation == tc.method+" /api/items/{id}" {
					found = true
					if coverage.Cleanup != "CLEANUP_SUCCEEDED" || !coverage.CleanupAttempted {
						t.Fatalf("fallback cleanup was not positively verified: %+v", coverage)
					}
					if tc.wantState != "" && coverage.Restoration != tc.wantState {
						t.Fatalf("restoration=%s want=%s coverage=%+v", coverage.Restoration, tc.wantState, coverage)
					}
					if tc.name == "restore fails" && result.Completion != "partial" {
						t.Fatalf("restoration failure did not make completion partial: %+v", result)
					}
				}
			}
			if !found {
				t.Fatalf("missing update coverage: %+v", result.Coverage)
			}
		})
	}
}

func TestCLIControlledUpdatePreconditionsAndMethodGates(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		mutate       func(*config.Config)
		mode         string
	}{
		{"mutations disabled PATCH", "PATCH", func(c *config.Config) { c.Mutations.Enabled = false }, "normal"},
		{"mutations disabled PUT", "PUT", func(c *config.Config) { c.Mutations.Enabled = false }, "normal"},
		{"patch method disabled", "PATCH", func(c *config.Config) { c.Mutations.AllowedMethods = []string{"POST", "PUT"} }, "normal"},
		{"put method disabled", "PUT", func(c *config.Config) { c.Mutations.AllowedMethods = []string{"POST", "PATCH"} }, "normal"},
		{"path not allowlisted", "PATCH", func(c *config.Config) { c.Mutations.AllowedPaths = []string{"/api/items"} }, "normal"},
		{"setup does not create controlled resource", "PATCH", nil, "setup-no-create"},
		{"insufficient lifecycle budgets", "PATCH", func(c *config.Config) {
			c.Limits.MaxRequests = 5
			c.Mutations.RequestBudget = 2
			c.Mutations.CleanupRequestBudget = 4
		}, "normal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, fixture := runControlledUpdateCLI(t, tc.mode, tc.method, "DENIED", "BOLA", tc.mutate)
			if fixture.patches.Load()+fixture.puts.Load() != 0 {
				t.Fatalf("precondition failure sent update method: puts=%d patches=%d", fixture.puts.Load(), fixture.patches.Load())
			}
			if tc.name == "insufficient lifecycle budgets" && fixture.posts.Load() != 0 {
				t.Fatalf("insufficient lifecycle budget sent setup POST: %d", fixture.posts.Load())
			}
			if len(result.Findings) != 0 {
				t.Fatalf("precondition failure produced finding: %+v", result.Findings)
			}
		})
	}
}

func TestCLIDeterministicControlledUpdateFingerprint(t *testing.T) {
	first, _, _ := runControlledUpdateCLI(t, "normal", "PATCH", "DENIED", "BOLA", nil)
	second, _, _ := runControlledUpdateCLI(t, "normal", "PATCH", "DENIED", "BOLA", nil)
	if len(first.Findings) != 1 || len(second.Findings) != 1 || first.Findings[0].Fingerprint != second.Findings[0].Fingerprint {
		t.Fatalf("controlled update fingerprint was not semantically stable: %+v %+v", first.Findings, second.Findings)
	}
}

func TestCLIOrdinaryDELETEAuthorizationRemainsBlocked(t *testing.T) {
	result, _, fixture := runControlledUpdateCLI(t, "normal", "PATCH", "DENIED", "BOLA", func(c *config.Config) {
		c.Operations = append(c.Operations, config.Operation{ID: "ordinary-delete", Path: "/api/items/{id}", Method: "DELETE", Actor: "bob", Owner: "alice", Resource: "docs", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "ok"}})
	})
	if len(result.Findings) != 1 || fixture.deletes.Load() != 1 {
		t.Fatalf("ordinary DELETE authorization escaped cleanup-only path: findings=%d DELETEs=%d", len(result.Findings), fixture.deletes.Load())
	}
	for _, coverage := range result.Coverage {
		if coverage.Operation == "DELETE /api/items/{id}" && coverage.State != "SKIPPED_BY_POLICY" && coverage.State != "UNSUPPORTED" {
			t.Fatalf("configured DELETE was not reported unsupported: %+v", coverage)
		}
	}
}

func TestCLIControlledDELETELifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, mode, access, classification, wantState string
		mutate                                        func(*config.Config)
		findings, attacks, totalDeletes               int32
		cleanup                                       string
	}{
		{"disabled", "normal", "DENIED", "BOLA", "SKIPPED_BY_POLICY", func(c *config.Config) { c.Mutations.Enabled = false }, 0, 0, 0, ""},
		{"method not allowed", "normal", "DENIED", "BOLA", "SKIPPED_BY_POLICY", func(c *config.Config) { c.Mutations.AllowedMethods = []string{"POST"} }, 0, 0, 0, ""},
		{"setup did not create resource", "setup-no-create", "DENIED", "BOLA", "NO_DISPOSABLE_RESOURCE", nil, 0, 0, 0, ""},
		{"incomplete pre-delete proof", "delete-incomplete-pre", "DENIED", "BOLA", "INCOMPLETE_PRE_DELETE_PROOF", nil, 0, 0, 1, "CLEANUP_SUCCEEDED"},
		{"marker mismatch", "delete-marker-mismatch", "DENIED", "BOLA", "INCOMPLETE_PRE_DELETE_PROOF", nil, 0, 0, 1, "CLEANUP_SUCCEEDED"},
		{"resource ID mismatch", "delete-id-mismatch", "DENIED", "BOLA", "INCOMPLETE_PRE_DELETE_PROOF", nil, 0, 0, 1, "CLEANUP_SUCCEEDED"},
		{"denied deletion verified", "normal", "DENIED", "BOLA", "VERIFIED_DENIED_DELETION", nil, 1, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"forbidden remains and cleanup", "delete-remains", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_SUCCEEDED"},
		{"cleanup failed", "delete-cleanup-fail", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_FAILED"},
		{"cleanup inconclusive", "delete-cleanup-unknown", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_INCONCLUSIVE"},
		{"204 is not proof", "delete-204-remains", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_SUCCEEDED"},
		{"404 is not proof", "delete-404-remains", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_SUCCEEDED"},
		{"403 but state absent", "delete-403-absent", "DENIED", "BOLA", "VERIFIED_DENIED_DELETION", nil, 1, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"timeout but state absent", "delete-timeout-absent", "DENIED", "BOLA", "VERIFIED_DENIED_DELETION", nil, 1, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"timeout unknown", "delete-timeout-unknown", "DENIED", "BOLA", "ATTACK_INCONCLUSIVE", nil, 0, 1, 1, ""},
		{"allowed never finding", "normal", "ALLOWED", "BOLA", "VERIFIED_ABSENT", nil, 0, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"unknown never finding", "normal", "UNKNOWN", "BOLA", "VERIFIED_ABSENT", nil, 0, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"relationship delete", "normal", "DENIED", "RELATIONSHIP", "VERIFIED_DENIED_DELETION", func(c *config.Config) {
			c.Operations[1].Relationship = "workspace"
			c.Identities[0].Contexts = map[string]string{"workspace": "workspace-a"}
			c.Identities[1].Contexts = map[string]string{"workspace": "workspace-b"}
		}, 1, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"BFLA delete", "normal", "DENIED", "BFLA", "VERIFIED_DENIED_DELETION", nil, 1, 1, 1, "CLEANUP_NOT_REQUIRED"},
		{"redirect does not repeat", "delete-redirect", "DENIED", "BOLA", "TESTED", nil, 0, 1, 2, "CLEANUP_SUCCEEDED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, fixture, exit := runControlledDeleteCLI(t, tc.mode, tc.access, tc.classification, tc.mutate)
			_ = exit // Findings and partial-result exit codes are expected for some cases.
			if int32(len(result.Findings)) != tc.findings || fixture.attackDeletes.Load() != tc.attacks || fixture.deletes.Load() != tc.totalDeletes {
				t.Fatalf("findings=%d attack DELETEs=%d total DELETEs=%d; want %d/%d/%d; coverage=%+v", len(result.Findings), fixture.attackDeletes.Load(), fixture.deletes.Load(), tc.findings, tc.attacks, tc.totalDeletes, result.Coverage)
			}
			found := false
			for _, coverage := range result.Coverage {
				if coverage.Operation != "DELETE /api/items/{id}" {
					continue
				}
				found = true
				if coverage.State != tc.wantState {
					t.Fatalf("state=%s want=%s coverage=%+v", coverage.State, tc.wantState, coverage)
				}
				if tc.cleanup != "" && coverage.Cleanup != tc.cleanup {
					t.Fatalf("cleanup=%s want=%s coverage=%+v", coverage.Cleanup, tc.cleanup, coverage)
				}
			}
			if tc.classification == "RELATIONSHIP" && (len(result.Findings) != 1 || len(result.Findings[0].RelationshipProof) != 1 || result.Findings[0].RelationshipProof[0].Boundary != "different") {
				t.Fatalf("relationship finding lacks proven boundary evidence: %+v", result.Findings)
			}
			if !found {
				t.Fatalf("missing DELETE coverage: %+v", result.Coverage)
			}
		})
	}
}

func TestCLITargetedPUTPATCHAndDELETERetestLifecycles(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			server, fixture := newUpdateFixture("normal")
			defer server.Close()
			dir := t.TempDir()
			specPath := filepath.Join(dir, "openapi.json")
			configPath := filepath.Join(dir, "config.json")
			scanPath, findingPath, retestPath := filepath.Join(dir, "scan.json"), filepath.Join(dir, "finding.json"), filepath.Join(dir, "retest.json")
			spec := `{"openapi":"3.0.3","info":{"title":"Local retest","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}},"/api/items/{id}":{"get":{},"put":{},"patch":{},"delete":{}}}}`
			if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
				t.Fatal(err)
			}
			var c config.Config
			if method == http.MethodDelete {
				c = controlledDeleteConfig(server.URL, specPath, "DENIED", "BOLA")
			} else {
				c = controlledUpdateConfig(server.URL, specPath, method, "DENIED", "BOLA")
			}
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if code := run([]string{"scan", "-config", configPath, "-out", scanPath}); code != 1 {
				t.Fatalf("source scan exit=%d", code)
			}
			scanBytes, err := os.ReadFile(scanPath)
			if err != nil {
				t.Fatal(err)
			}
			var scanResult engine.Result
			if err := json.Unmarshal(scanBytes, &scanResult); err != nil || len(scanResult.Findings) != 1 {
				t.Fatalf("source finding count=%d err=%v", len(scanResult.Findings), err)
			}
			findingBytes, err := json.Marshal(scanResult.Findings[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(findingPath, findingBytes, 0600); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			fixture.item, fixture.marker, fixture.complete = nil, "", true
			fixture.mu.Unlock()
			fixture.posts.Store(0)
			fixture.puts.Store(0)
			fixture.patches.Store(0)
			fixture.deletes.Store(0)
			fixture.attackDeletes.Store(0)
			if code := run([]string{"retest", "-config", configPath, "-finding", findingPath, "-out", retestPath}); code != 1 {
				t.Fatalf("retest exit=%d", code)
			}
			resultBytes, err := os.ReadFile(retestPath)
			if err != nil {
				t.Fatal(err)
			}
			var retest struct {
				SchemaVersion string                `json:"schema_version"`
				Results       []engine.RetestResult `json:"results"`
			}
			if err := json.Unmarshal(resultBytes, &retest); err != nil {
				t.Fatal(err)
			}
			if retest.SchemaVersion != "1" || len(retest.Results) != 1 || retest.Results[0].Outcome != "STILL_PRESENT" {
				t.Fatalf("retest result=%+v", retest)
			}
			if method == http.MethodDelete {
				if fixture.posts.Load() != 1 || fixture.attackDeletes.Load() != 1 || fixture.deletes.Load() != 1 || retest.Results[0].Cleanup != "CLEANUP_NOT_REQUIRED" {
					t.Fatalf("DELETE retest did not use only its disposable lifecycle: result=%+v fixture=%+v", retest.Results[0], fixture)
				}
			} else if fixture.posts.Load() != 1 || fixture.deletes.Load() != 1 || fixture.patches.Load()+fixture.puts.Load() < 1 || retest.Results[0].Cleanup != "CLEANUP_SUCCEEDED" {
				t.Fatalf("update retest lifecycle incomplete: result=%+v fixture=%+v", retest.Results[0], fixture)
			}
			for _, canary := range []string{"ALICE_UPDATE_SECRET", "BOB_UPDATE_SECRET", "${KURO_TEST_MARKER}", "created-1"} {
				if strings.Contains(string(resultBytes), canary) {
					t.Fatalf("retest output leaked %q", canary)
				}
			}
		})
	}
}

func TestCLIControlledDELETEPolicyAndResourceGates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"mutation path not allowlisted", func(c *config.Config) { c.Mutations.AllowedPaths = []string{"/api/items"} }},
		{"no handle link", func(c *config.Config) { c.Operations[1].ControlledResourceOperationID = "" }},
		{"not declared disposable", func(c *config.Config) { c.Operations[0].Disposable = false }},
		{"inadequate global budget", func(c *config.Config) { c.Limits.MaxRequests = 6 }},
		{"inadequate mutation budget", func(c *config.Config) { c.Mutations.RequestBudget = 1 }},
		{"inadequate cleanup budget", func(c *config.Config) { c.Mutations.CleanupRequestBudget = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, fixture, _ := runControlledDeleteCLI(t, "normal", "DENIED", "BOLA", tc.mutate)
			if fixture.attackDeletes.Load() != 0 {
				t.Fatalf("gate allowed attack DELETE: %d", fixture.attackDeletes.Load())
			}
			if len(result.Findings) != 0 {
				t.Fatalf("gate produced finding: %+v", result.Findings)
			}
		})
	}
}

func TestCLIDeterministicControlledDELETEFingerprint(t *testing.T) {
	first, _, _ := runControlledDeleteCLI(t, "normal", "DENIED", "BOLA", nil)
	second, _, _ := runControlledDeleteCLI(t, "normal", "DENIED", "BOLA", nil)
	if len(first.Findings) != 1 || len(second.Findings) != 1 || first.Findings[0].Fingerprint != second.Findings[0].Fingerprint {
		t.Fatalf("semantic controlled DELETE fingerprint was not stable: first=%+v second=%+v", first.Findings, second.Findings)
	}
}

func TestCLIControlledDELETERequiresRelationshipBoundaryProof(t *testing.T) {
	result, fixture, _ := runControlledDeleteCLI(t, "normal", "DENIED", "RELATIONSHIP", func(c *config.Config) {
		c.Operations[1].Relationship = "workspace"
		c.Identities[0].Contexts = map[string]string{"workspace": "workspace-b"}
		c.Identities[1].Contexts = map[string]string{"workspace": "workspace-c"}
	})
	if fixture.attackDeletes.Load() != 0 || fixture.deletes.Load() != 1 || len(result.Findings) != 0 {
		t.Fatalf("unproven owner relationship reached DELETE: attacks=%d deletes=%d findings=%+v coverage=%+v", fixture.attackDeletes.Load(), fixture.deletes.Load(), result.Findings, result.Coverage)
	}
	for _, coverage := range result.Coverage {
		if coverage.Operation == "DELETE /api/items/{id}" && coverage.State != "INCOMPLETE_PRE_DELETE_PROOF" {
			t.Fatalf("relationship mismatch not reported as incomplete: %+v", coverage)
		}
	}
}
