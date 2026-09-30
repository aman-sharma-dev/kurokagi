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

type retestMarkerLog struct {
	mu     sync.Mutex
	values []string
}

func controlledPOSTRetest(t *testing.T, mode, access string) (*Scanner, RetestInput, *atomic.Int32, *atomic.Int32, *retestMarkerLog) {
	t.Helper()
	var items []map[string]any
	var mu sync.Mutex
	var deletes atomic.Int32
	markers := &retestMarkerLog{}
	s, _, posts := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/items":
			w.Header().Set("Content-Type", "application/json")
			if mode == "incomplete-baseline" {
				_ = json.NewEncoder(w).Encode(map[string]any{"complete": false, "items": []any{}})
				return
			}
			mu.Lock()
			snapshot := append([]map[string]any(nil), items...)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "items": snapshot})
		case r.Method == http.MethodPost && r.URL.Path == "/api/items":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			meta, _ := body["meta"].(map[string]any)
			marker, _ := meta["marker"].(string)
			markers.mu.Lock()
			markers.values = append(markers.values, marker)
			markers.mu.Unlock()
			if mode == "denied" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			if mode != "no-create" && mode != "timeout-no-create" {
				mu.Lock()
				items = append(items, map[string]any{"id": "created-1", "meta": map[string]any{"marker": marker}})
				mu.Unlock()
			}
			if mode == "timeout-store" || mode == "timeout-no-create" {
				time.Sleep(100 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/items/created-1":
			deletes.Add(1)
			if mode != "cleanup-fail" {
				mu.Lock()
				items = nil
				mu.Unlock()
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	if mode == "timeout-store" || mode == "timeout-no-create" {
		s.client.Timeout = 20 * time.Millisecond
	}
	s.cfg.Operations[0].Access = access
	fingerprint := functionFinding("BFLA", "controlled-create", "alice", "", "docs", "", http.MethodPost, "/api/items", "").Fingerprint
	input := RetestInput{SchemaVersion: "1", Fingerprint: fingerprint, Classification: "BFLA", Resource: "docs", Actor: "alice", Method: "POST", Path: "/api/items"}
	return s, input, posts, &deletes, markers
}

func TestTargetedPOSTRetestProofAndCleanup(t *testing.T) {
	tests := []struct {
		name, mode, access, want, cleanup string
		wantCompletion                    string
	}{
		{"reproduced", "create", "DENIED", "STILL_PRESENT", "CLEANUP_SUCCEEDED", "complete"},
		{"denied", "denied", "DENIED", "FIXED", "", "complete"},
		{"timeout with creation", "timeout-store", "DENIED", "STILL_PRESENT", "CLEANUP_SUCCEEDED", "complete"},
		{"timeout unknown", "timeout-no-create", "DENIED", "INCONCLUSIVE", "", "partial"},
		{"2xx without creation", "no-create", "DENIED", "INCONCLUSIVE", "", "partial"},
		{"allowed expectation", "create", "ALLOWED", "NOT_TESTABLE", "CLEANUP_SUCCEEDED", "complete"},
		{"unknown expectation", "create", "UNKNOWN", "NOT_TESTABLE", "CLEANUP_SUCCEEDED", "complete"},
		{"cleanup failure", "cleanup-fail", "DENIED", "STILL_PRESENT", "CLEANUP_FAILED", "partial"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, in, posts, deletes, markers := controlledPOSTRetest(t, tc.mode, tc.access)
			got := s.Retest(context.Background(), in)
			if got.Outcome != tc.want {
				t.Fatalf("result=%+v want outcome %s", got, tc.want)
			}
			if posts.Load() != 1 {
				t.Fatalf("attack POST count=%d want 1", posts.Load())
			}
			if tc.cleanup == "" {
				if deletes.Load() != 0 {
					t.Fatalf("unexpected cleanup DELETE count=%d", deletes.Load())
				}
			} else if deletes.Load() != 1 || got.Cleanup != tc.cleanup {
				t.Fatalf("cleanup count/state=%d/%s want 1/%s", deletes.Load(), got.Cleanup, tc.cleanup)
			}
			if got.Completion != tc.wantCompletion {
				t.Fatalf("completion=%s want %s", got.Completion, tc.wantCompletion)
			}
			markers.mu.Lock()
			markerValues := append([]string(nil), markers.values...)
			markers.mu.Unlock()
			if len(markerValues) != 1 || markerValues[0] == "" {
				t.Fatalf("fresh test marker missing: %#v", markerValues)
			}
			encoded, _ := json.Marshal(got)
			for _, secret := range []string{"BODY_POST_CANARY", "ALICE_POST_CANARY", "${KURO_TEST_MARKER}", markerValues[0], "created-1"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("POST secret/runtime data leaked in retest result: %q", secret)
				}
			}
		})
	}
}

func TestPOSTRetestPolicyAndScopePreflightSendNoPOST(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Scanner)
	}{
		{"disabled", func(s *Scanner) { s.cfg.Mutations.Enabled = false }},
		{"method removed", func(s *Scanner) { s.cfg.Mutations.AllowedMethods = nil }},
		{"path removed", func(s *Scanner) { s.cfg.Mutations.AllowedPaths = []string{"/api/other"} }},
		{"scope removed", func(s *Scanner) { s.cfg.Target.AllowedPaths = []string{"/elsewhere"} }},
		{"actor missing", func(s *Scanner) { s.cfg.Identities = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, in, posts, _, _ := controlledPOSTRetest(t, "create", "DENIED")
			tc.change(s)
			got := s.Retest(context.Background(), in)
			if got.Outcome != "NOT_TESTABLE" {
				t.Fatalf("result=%+v", got)
			}
			if posts.Load() != 0 {
				t.Fatalf("preflight failure sent %d POSTs", posts.Load())
			}
		})
	}
}

func TestPOSTRetestCancellationAndIncompleteBaselineSendNoPOST(t *testing.T) {
	t.Run("cancelled before execution", func(t *testing.T) {
		s, in, posts, _, _ := controlledPOSTRetest(t, "create", "DENIED")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got := s.Retest(ctx, in)
		if got.Outcome != "INCONCLUSIVE" || posts.Load() != 0 {
			t.Fatalf("result=%+v POSTs=%d", got, posts.Load())
		}
	})
	t.Run("incomplete baseline", func(t *testing.T) {
		s, in, posts, _, _ := controlledPOSTRetest(t, "incomplete-baseline", "DENIED")
		got := s.Retest(context.Background(), in)
		if got.Outcome != "NOT_TESTABLE" || posts.Load() != 0 {
			t.Fatalf("result=%+v POSTs=%d", got, posts.Load())
		}
	})
}

func TestPOSTRetestCancellationAfterDispatchVerifiesAndCleans(t *testing.T) {
	var cancel context.CancelFunc
	var items []map[string]any
	var mu sync.Mutex
	var deletes atomic.Int32
	s, _, posts := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/items":
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			snapshot := append([]map[string]any(nil), items...)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "items": snapshot})
		case r.Method == http.MethodPost && r.URL.Path == "/api/items":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			meta, _ := body["meta"].(map[string]any)
			marker, _ := meta["marker"].(string)
			mu.Lock()
			items = append(items, map[string]any{"id": "created-after-cancel", "meta": map[string]any{"marker": marker}})
			mu.Unlock()
			cancel()
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/items/created-after-cancel":
			deletes.Add(1)
			mu.Lock()
			items = nil
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	ctx, stop := context.WithCancel(context.Background())
	cancel = stop
	defer stop()
	fingerprint := functionFinding("BFLA", "controlled-create", "alice", "", "docs", "", http.MethodPost, "/api/items", "").Fingerprint
	in := RetestInput{SchemaVersion: "1", Fingerprint: fingerprint, Classification: "BFLA", Resource: "docs", Actor: "alice", Method: "POST", Path: "/api/items"}
	got := s.Retest(ctx, in)
	if got.Outcome != "STILL_PRESENT" || got.Cleanup != "CLEANUP_SUCCEEDED" || got.Completion != "complete" {
		t.Fatalf("result=%+v", got)
	}
	if posts.Load() != 1 || deletes.Load() != 1 {
		t.Fatalf("POST/DELETE counts=%d/%d", posts.Load(), deletes.Load())
	}
}

func TestPOSTRetestFingerprintIgnoresEphemeralState(t *testing.T) {
	first := functionFinding("BFLA", "controlled-create", "alice", "", "docs", "", http.MethodPost, "/api/items", "").Fingerprint
	second := functionFinding("BFLA", "controlled-create", "alice", "", "docs", "", http.MethodPost, "/api/items", "").Fingerprint
	if first != second {
		t.Fatalf("ephemeral test state changed semantic fingerprint: %s != %s", first, second)
	}
}

func TestTargetedOperationRetestOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vulnerable bool
		status     int
		want       string
	}{{"reproduced", true, http.StatusOK, "STILL_PRESENT"}, {"denied", false, http.StatusForbidden, "FIXED"}, {"not found is not denial proof", false, http.StatusNotFound, "INCONCLUSIVE"}} {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if tc.vulnerable {
					_, _ = w.Write([]byte(`{"data":{"count":1}}`))
					return
				}
				http.Error(w, "denied", tc.status)
			}))
			defer srv.Close()
			c := fixture(t, tc.vulnerable)
			c.Target.BaseURL, c.Target.AllowedOrigins = srv.URL, []string{srv.URL}
			c.Target.AllowedPaths = []string{"/api"}
			spec := filepath.Join(t.TempDir(), "openapi.json")
			if err := os.WriteFile(spec, []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/admin/users":{"get":{}}}}`), 0600); err != nil {
				t.Fatal(err)
			}
			c.OpenAPI.Path = spec
			c.Operations = []config.Operation{{ID: "admin-user-list", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := functionFinding("BFLA", "admin-user-list", "bob", "", "operation:admin-user-list", "", "GET", "/api/admin/users", "").Fingerprint
			in := RetestInput{SchemaVersion: "1", Fingerprint: fingerprint}
			got := s.Retest(context.Background(), in)
			if got.Outcome != tc.want {
				t.Fatalf("outcome=%s reason=%s want=%s", got.Outcome, got.ReasonCode, tc.want)
			}
			if requests != 1 {
				t.Fatalf("targeted retest made %d requests, want exactly 1", requests)
			}
		})
	}
}

func TestResourceRetestBOLAAndIDOR(t *testing.T) {
	for _, class := range []string{"BOLA", "IDOR"} {
		for _, vulnerable := range []bool{true, false} {
			t.Run(class+map[bool]string{true: "_still_present", false: "_fixed"}[vulnerable], func(t *testing.T) {
				c := fixture(t, vulnerable)
				c.Resources[0].Classification = class
				c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Access: "DENIED"}, {Identity: "alice", Owner: "bob", Resource: "docs", Access: "DENIED"}}
				c.Operations = []config.Operation{{ID: "unrelated-admin", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "UNKNOWN", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.id"}}}
				requests := 0
				requestPaths := []string{}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					requestPaths = append(requestPaths, r.URL.Path)
					if r.URL.Path == "/api/docs" {
						if r.Header.Get("Authorization") == "alice" {
							_, _ = w.Write([]byte(`[{"id":"current-A","name":"owner-proof"}]`))
						} else {
							_, _ = w.Write([]byte(`[{"id":"current-B","name":"actor-proof"}]`))
						}
						return
					}
					if r.URL.Path == "/api/docs/current-A" {
						if !vulnerable {
							http.Error(w, "denied", http.StatusForbidden)
							return
						}
						_, _ = w.Write([]byte(`{"id":"current-A","name":"owner-proof"}`))
						return
					}
					http.NotFound(w, r)
				}))
				defer srv.Close()
				c.Target.BaseURL = srv.URL
				c.Target.AllowedOrigins = []string{srv.URL}
				c.Target.AllowedPaths = []string{"/api"}
				s, err := New(c)
				if err != nil {
					t.Fatal(err)
				}
				fp := finding(class, "docs", "", "alice", "bob", "", "/api/docs/{id}", "").Fingerprint
				sourceFP, inertRef := fp, "historical-untrusted-id"
				if class == "BOLA" && vulnerable {
					inertRef = "legacy-id-hint"
					sourceFP = finding(class, "docs", inertRef, "alice", "bob", "", "/api/docs/{id}", "").Fingerprint
				}
				got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: sourceFP, Classification: class, Resource: "docs", Victim: "alice", Actor: "bob", Method: "GET", Path: "/api/docs/{id}", ResourceRef: inertRef})
				want := "STILL_PRESENT"
				if !vulnerable {
					want = "FIXED"
				}
				if got.Outcome != want {
					t.Fatalf("got %+v want %s", got, want)
				}
				if got.CurrentFingerprint != fp {
					t.Fatalf("current semantic fingerprint=%s want %s", got.CurrentFingerprint, fp)
				}
				if requests != 3 {
					t.Fatalf("targeted resource retest requests=%d want 2 discovery + 1 detail", requests)
				}
				for _, path := range requestPaths {
					if strings.Contains(path, "historical-untrusted-id") {
						t.Fatalf("replayed historical resource ID in %q", path)
					}
				}
			})
		}
	}
}

func TestSemanticResourceFingerprintIgnoresRuntimeID(t *testing.T) {
	a := finding("BOLA", "docs", "runtime-A", "alice", "bob", "", "/api/docs/{id}", "e1")
	b := finding("BOLA", "docs", "runtime-B", "alice", "bob", "", "/api/docs/{id}", "e2")
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("runtime IDs changed semantic fingerprint: %s != %s", a.Fingerprint, b.Fingerprint)
	}
}

func TestRelationshipRetestUsesCurrentRelationshipMapping(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "reproduced", true: "denied"}[denied], func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path == "/api/docs" {
					if r.Header.Get("Authorization") == "alice" {
						_, _ = w.Write([]byte(`[{"id":"A","name":"secret-A","workspace_id":"wa"}]`))
					} else {
						_, _ = w.Write([]byte(`[{"id":"B","name":"secret-B","workspace_id":"wb"}]`))
					}
					return
				}
				if r.URL.Path == "/api/docs/A" {
					if denied {
						http.Error(w, "denied", 403)
						return
					}
					_, _ = w.Write([]byte(`{"id":"A","name":"secret-A","workspace_id":"wa"}`))
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()
			c := fixture(t, false)
			c.Target.BaseURL = srv.URL
			c.Target.AllowedOrigins = []string{srv.URL}
			c.Target.AllowedPaths = []string{"/api"}
			c.Resources[0].Classification = "RELATIONSHIP"
			c.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
			c.Identities[0].Contexts = map[string]string{"workspace": "wa"}
			c.Identities[1].Contexts = map[string]string{"workspace": "wb"}
			c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Relationship: "workspace", Access: "DENIED"}}
			// Keep the OpenAPI contract from the fixture, whose collection/detail paths match.
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			fp := finding("RELATIONSHIP", "docs", "", "alice", "bob", "workspace", "/api/docs/{id}", "").Fingerprint
			got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: fp, Classification: "RELATIONSHIP", Resource: "docs", Victim: "alice", Actor: "bob", Relationship: "workspace", Method: "GET", Path: "/api/docs/{id}"})
			want := "STILL_PRESENT"
			if denied {
				want = "FIXED"
			}
			if got.Outcome != want {
				t.Fatalf("got %+v want %s", got, want)
			}
			if requests != 3 {
				t.Fatalf("requests=%d want 3 discovery+targeted detail", requests)
			}
		})
	}
}

func TestResourceRetestCurrentExpectationAndHistoricalID(t *testing.T) {
	for _, access := range []string{"ALLOWED", "UNKNOWN"} {
		t.Run(access, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; http.NotFound(w, r) }))
			defer srv.Close()
			c := fixture(t, true)
			c.Target.BaseURL = srv.URL
			c.Target.AllowedOrigins = []string{srv.URL}
			c.Target.AllowedPaths = []string{"/api"}
			c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Access: access}}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			fp := finding("BOLA", "docs", "", "alice", "bob", "", "/api/docs/{id}", "").Fingerprint
			got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: fp, Classification: "BOLA", Resource: "docs", Victim: "alice", Actor: "bob", Method: "GET", Path: "/api/docs/{id}", ResourceRef: "historical-untrusted-id"})
			if got.Outcome != "NOT_TESTABLE" || got.ReasonCode != "EXPECTATION_NOT_DENIED" {
				t.Fatalf("unexpected current %s result: %+v", access, got)
			}
			if requests != 0 {
				t.Fatalf("current %s expectation sent %d requests", access, requests)
			}
		})
	}
}

func TestResourceRetestMissingActorAndOutOfScopeDoNotSendRequests(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; http.NotFound(w, r) }))
	defer srv.Close()
	c := fixture(t, true)
	c.Target.BaseURL = srv.URL
	c.Target.AllowedOrigins = []string{srv.URL}
	c.Target.AllowedPaths = []string{"/api"}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	input := RetestInput{SchemaVersion: "1", Fingerprint: finding("BOLA", "docs", "", "alice", "deleted-actor", "", "/api/docs/{id}", "").Fingerprint, Classification: "BOLA", Resource: "docs", Victim: "alice", Actor: "deleted-actor", Method: "GET", Path: "/api/docs/{id}"}
	got := s.Retest(context.Background(), input)
	if got.Outcome != "NOT_TESTABLE" || got.ReasonCode != "ACTOR_MISSING" {
		t.Fatalf("unexpected missing actor result: %+v", got)
	}
	input.Actor = "bob"
	input.Fingerprint = finding("BOLA", "docs", "", "alice", "bob", "", "/api/docs/{id}", "").Fingerprint
	s.cfg.Target.AllowedPaths = []string{"/elsewhere"}
	got = s.Retest(context.Background(), input)
	if got.Outcome != "NOT_TESTABLE" || got.ReasonCode != "OUT_OF_SCOPE" {
		t.Fatalf("unexpected scope result: %+v", got)
	}
	if requests != 0 {
		t.Fatalf("preflight failures sent %d requests", requests)
	}
}

func TestRelationshipRemovedIsNotTestableWithoutRequests(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; http.NotFound(w, r) }))
	defer srv.Close()
	c := fixture(t, false)
	c.Target.BaseURL = srv.URL
	c.Target.AllowedOrigins = []string{srv.URL}
	c.Target.AllowedPaths = []string{"/api"}
	c.Resources[0].Classification = "RELATIONSHIP"
	c.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
	c.Identities[0].Contexts = map[string]string{"workspace": "w1"}
	c.Identities[1].Contexts = map[string]string{"workspace": "w2"}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	in := RetestInput{SchemaVersion: "1", Fingerprint: finding("RELATIONSHIP", "docs", "", "alice", "bob", "tenant", "/api/docs/{id}", "").Fingerprint, Classification: "RELATIONSHIP", Resource: "docs", Victim: "alice", Actor: "bob", Relationship: "tenant", Method: "GET", Path: "/api/docs/{id}"}
	got := s.Retest(context.Background(), in)
	if got.Outcome != "NOT_TESTABLE" || got.ReasonCode != "RELATIONSHIP_MISSING" {
		t.Fatalf("unexpected removed relationship result: %+v", got)
	}
	if requests != 0 {
		t.Fatalf("removed relationship issued %d requests", requests)
	}
}

func TestIncompleteOwnershipDiscoveryAndCancellationAreNeverFixed(t *testing.T) {
	t.Run("incomplete discovery", func(t *testing.T) {
		requests := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		c := fixture(t, false)
		c.Target.BaseURL = srv.URL
		c.Target.AllowedOrigins = []string{srv.URL}
		c.Target.AllowedPaths = []string{"/api"}
		c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Access: "DENIED"}}
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		fp := finding("BOLA", "docs", "", "alice", "bob", "", "/api/docs/{id}", "").Fingerprint
		got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: fp, Classification: "BOLA", Resource: "docs", Victim: "alice", Actor: "bob", Method: "GET", Path: "/api/docs/{id}"})
		if got.Outcome != "INCONCLUSIVE" || got.ReasonCode != "DISCOVERY_INCOMPLETE" {
			t.Fatalf("incomplete discovery result: %+v", got)
		}
		if requests != 2 {
			t.Fatalf("incomplete discovery requests=%d want 2", requests)
		}
	})
	t.Run("cancelled request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(30 * time.Millisecond)
			_, _ = w.Write([]byte(`{"data":{"count":1}}`))
		}))
		defer srv.Close()
		c := fixture(t, true)
		c.Target.BaseURL = srv.URL
		c.Target.AllowedOrigins = []string{srv.URL}
		c.Target.AllowedPaths = []string{"/api"}
		c.OpenAPI.Path = filepath.Join(t.TempDir(), "openapi.json")
		if err := os.WriteFile(c.OpenAPI.Path, []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/admin/users":{"get":{}}}}`), 0600); err != nil {
			t.Fatal(err)
		}
		c.Operations = []config.Operation{{ID: "admin-user-list", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}
		s, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		fp := functionFinding("BFLA", "admin-user-list", "bob", "", "operation:admin-user-list", "", "GET", "/api/admin/users", "").Fingerprint
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		got := s.Retest(ctx, RetestInput{SchemaVersion: "1", Fingerprint: fp})
		if got.Outcome != "INCONCLUSIVE" || (got.ReasonCode != "CANCELLED" && got.ReasonCode != "NETWORK_TIMEOUT") {
			t.Fatalf("cancellation result: %+v", got)
		}
	})
}

func TestRelationshipContextIncompleteIsInconclusive(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/api/docs" {
			if r.Header.Get("Authorization") == "alice" {
				_, _ = w.Write([]byte(`[{"id":"A","name":"owner","workspace_id":"wa"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":"B","name":"actor","workspace_id":"wb"}]`))
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := fixture(t, false)
	c.Target.BaseURL = srv.URL
	c.Target.AllowedOrigins = []string{srv.URL}
	c.Target.AllowedPaths = []string{"/api"}
	c.Resources[0].Classification = "RELATIONSHIP"
	c.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
	c.Identities[0].Contexts = map[string]string{"workspace": "wa"}
	c.Identities[1].Contexts = map[string]string{}
	c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Relationship: "workspace", Access: "DENIED"}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	fp := finding("RELATIONSHIP", "docs", "", "alice", "bob", "workspace", "/api/docs/{id}", "").Fingerprint
	got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: fp, Classification: "RELATIONSHIP", Resource: "docs", Victim: "alice", Actor: "bob", Relationship: "workspace", Method: "GET", Path: "/api/docs/{id}"})
	if got.Outcome != "INCONCLUSIVE" || got.ReasonCode != "RELATIONSHIP_INCOMPLETE" {
		t.Fatalf("relationship context result: %+v", got)
	}
	if requests != 2 {
		t.Fatalf("incomplete relationship test sent %d requests, want discovery only", requests)
	}
}

func TestTargetUnavailableIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	c := fixture(t, false)
	c.Target.BaseURL = base
	c.Target.AllowedOrigins = []string{base}
	c.Target.AllowedPaths = []string{"/api"}
	c.OpenAPI.Path = filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(c.OpenAPI.Path, []byte(`{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/api/admin/users":{"get":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.Operations = []config.Operation{{ID: "admin-user-list", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	fp := functionFinding("BFLA", "admin-user-list", "bob", "", "operation:admin-user-list", "", "GET", "/api/admin/users", "").Fingerprint
	got := s.Retest(context.Background(), RetestInput{SchemaVersion: "1", Fingerprint: fp})
	if got.Outcome != "INCONCLUSIVE" || got.ReasonCode != "TARGET_UNAVAILABLE" {
		t.Fatalf("network failure result: %+v", got)
	}
}
