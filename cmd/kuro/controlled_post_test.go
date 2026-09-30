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

type postFixture struct {
	mode     string
	complete bool
	posts    atomic.Int32
	deletes  atomic.Int32
	mu       sync.Mutex
	items    []map[string]any
}

func newPostFixture(mode string) (*httptest.Server, *postFixture) {
	fixture := &postFixture{mode: mode, complete: mode != "incomplete"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/docs" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "doc-a", "name": "document"}})
		case strings.HasPrefix(r.URL.Path, "/api/docs/") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"id": filepath.Base(r.URL.Path), "name": "document"})
		case r.URL.Path == "/api/items" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fixture.mu.Lock()
			items := append([]map[string]any(nil), fixture.items...)
			complete := fixture.complete
			fixture.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": complete, "items": items})
		case r.URL.Path == "/api/items" && r.Method == http.MethodPost:
			fixture.posts.Add(1)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			metadata, _ := body["metadata"].(map[string]any)
			marker, _ := metadata["kuro_test_id"].(string)
			switch fixture.mode {
			case "redirect":
				http.Redirect(w, r, "/api/items", http.StatusTemporaryRedirect)
				return
			case "no-create":
				w.WriteHeader(http.StatusCreated)
				return
			case "timeout-no-create":
				time.Sleep(100 * time.Millisecond)
				return
			case "wrong-marker":
				marker += "-wrong"
			}
			if fixture.mode != "no-create" && fixture.mode != "timeout-no-create" {
				fixture.mu.Lock()
				fixture.items = append(fixture.items, map[string]any{"id": "created-1", "metadata": map[string]any{"kuro_test_id": marker}})
				if fixture.mode == "duplicate" {
					fixture.items = append(fixture.items, map[string]any{"id": "created-2", "metadata": map[string]any{"kuro_test_id": marker}})
				}
				fixture.mu.Unlock()
			}
			if fixture.mode == "timeout-store" {
				time.Sleep(100 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("POST_RESPONSE_CANARY"))
		case strings.HasPrefix(r.URL.Path, "/api/items/") && r.Method == http.MethodDelete:
			fixture.deletes.Add(1)
			if fixture.mode == "delete-redirect" {
				http.Redirect(w, r, "/api/items/created-1", http.StatusTemporaryRedirect)
				return
			}
			if fixture.mode == "delete-404" {
				http.NotFound(w, r)
				return
			}
			if fixture.mode != "delete-remains" {
				fixture.mu.Lock()
				fixture.items = nil
				if fixture.mode == "delete-timeout-unknown" {
					fixture.complete = false
				}
				fixture.mu.Unlock()
			}
			if fixture.mode == "delete-timeout-store" || fixture.mode == "delete-timeout-unknown" {
				time.Sleep(100 * time.Millisecond)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	return server, fixture
}

func controlledCLIConfig(serverURL, specPath string, access string) config.Config {
	c := config.Config{
		SchemaVersion: "3",
		Target:        config.Target{BaseURL: serverURL, AllowedOrigins: []string{serverURL}, AllowedPaths: []string{"/api"}},
		Identities:    []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "ALICE_POST_CANARY"}}, {ID: "bob", Headers: map[string]string{"Authorization": "BOB_POST_CANARY"}}},
		Resources:     []config.Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}},
		Expectations:  []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}},
		Operations: []config.Operation{{ID: "create-item", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs", Access: access, Classification: "BFLA",
			ContentType: "application/json", RequestBody: map[string]any{"metadata": map[string]any{"kuro_test_id": "${KURO_TEST_MARKER}"}, "payload": "BODY_POST_CANARY"},
			Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "metadata.kuro_test_id", ResourceIDField: "id", RequestMarkerField: "metadata.kuro_test_id", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}},
		Mutations: config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/api/items"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 1, CleanupRequestBudget: 3, CleanupTimeout: "1s"},
		Limits:    config.Limits{Timeout: "300ms", MaxRequests: 100, Concurrency: 1, MaxResponseBytes: 4096, MaxObjects: 20, RedirectPolicy: "same_origin"},
	}
	c.OpenAPI.Path = specPath
	return c
}

func runControlledPostCLI(t *testing.T, mode, access string, mutateConfig func(*config.Config), timeout string) (engine.Result, int, *postFixture) {
	t.Helper()
	server, fixture := newPostFixture(mode)
	defer server.Close()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	configPath := filepath.Join(dir, "config.json")
	outPath := filepath.Join(dir, "result.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Local POST fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := controlledCLIConfig(server.URL, specPath, access)
	if timeout != "" {
		c.Limits.Timeout = timeout
	}
	if mutateConfig != nil {
		mutateConfig(&c)
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
		// Invalid configuration exits before a scan result file is created.
		return engine.Result{}, exit, fixture
	}
	if strings.Contains(string(resultBytes), "BODY_POST_CANARY") || strings.Contains(string(resultBytes), "ALICE_POST_CANARY") || strings.Contains(string(resultBytes), "${KURO_TEST_MARKER}") || strings.Contains(string(resultBytes), "POST_RESPONSE_CANARY") {
		t.Fatal("POST body, credential, or marker template leaked into output")
	}
	var result engine.Result
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		t.Fatal(err)
	}
	return result, exit, fixture
}

func TestCLIControlledPOSTLifecycle(t *testing.T) {
	t.Run("mutations disabled", func(t *testing.T) {
		result, _, fixture := runControlledPostCLI(t, "create", "DENIED", func(c *config.Config) { c.Mutations.Enabled = false }, "")
		if fixture.posts.Load() != 0 || len(result.Findings) != 0 {
			t.Fatalf("disabled policy sent POST or found issue: posts=%d findings=%d", fixture.posts.Load(), len(result.Findings))
		}
	})
	t.Run("method not allowlisted", func(t *testing.T) {
		_, exit, fixture := runControlledPostCLI(t, "create", "DENIED", func(c *config.Config) { c.Mutations.AllowedMethods = []string{"PUT"} }, "")
		if exit != 2 || fixture.posts.Load() != 0 {
			t.Fatalf("invalid method policy was not rejected before POST: exit=%d posts=%d", exit, fixture.posts.Load())
		}
	})
	t.Run("path not allowlisted", func(t *testing.T) {
		_, exit, fixture := runControlledPostCLI(t, "create", "DENIED", func(c *config.Config) { c.Mutations.AllowedPaths = []string{"/api/other"} }, "")
		if exit != 2 || fixture.posts.Load() != 0 {
			t.Fatalf("invalid path policy was not rejected before POST: exit=%d posts=%d", exit, fixture.posts.Load())
		}
	})
	t.Run("body marker template invalid", func(t *testing.T) {
		_, exit, fixture := runControlledPostCLI(t, "create", "DENIED", func(c *config.Config) {
			c.Operations[0].RequestBody = map[string]any{"metadata": map[string]any{"kuro_test_id": "not-the-generated-marker"}}
		}, "")
		if exit != 2 || fixture.posts.Load() != 0 {
			t.Fatalf("invalid body template was not rejected before POST: exit=%d posts=%d", exit, fixture.posts.Load())
		}
	})
	t.Run("incomplete baseline", func(t *testing.T) {
		result, _, fixture := runControlledPostCLI(t, "incomplete", "DENIED", nil, "")
		if fixture.posts.Load() != 0 || len(result.Findings) != 0 {
			t.Fatal("incomplete baseline allowed POST")
		}
	})
	for _, tc := range []struct {
		name        string
		mode        string
		access      string
		wantFinding int
		wantPost    int32
		timeout     string
	}{
		{"denied creates controlled resource", "create", "DENIED", 1, 1, ""},
		{"201 creates nothing", "no-create", "DENIED", 0, 1, ""},
		{"wrong marker", "wrong-marker", "DENIED", 0, 1, ""},
		{"duplicate marker", "duplicate", "DENIED", 0, 1, ""},
		{"allowed creates resource", "create", "ALLOWED", 0, 1, ""},
		{"unknown creates resource", "create", "UNKNOWN", 0, 1, ""},
		{"timeout after store verified", "timeout-store", "DENIED", 1, 1, "20ms"},
		{"timeout without store", "timeout-no-create", "DENIED", 0, 1, "20ms"},
		{"redirect not followed", "redirect", "DENIED", 0, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _, fixture := runControlledPostCLI(t, tc.mode, tc.access, nil, tc.timeout)
			if got := fixture.posts.Load(); got != tc.wantPost {
				t.Fatalf("POST count=%d want %d coverage=%+v errors=%+v warnings=%+v", got, tc.wantPost, result.Coverage, result.Errors, result.Warnings)
			}
			if got := len(result.Findings); got != tc.wantFinding {
				t.Fatalf("findings=%d want %d coverage=%+v errors=%+v", got, tc.wantFinding, result.Coverage, result.Errors)
			}
			for _, coverage := range result.Coverage {
				if coverage.Operation == "POST /api/items" && coverage.State == "TESTED" && coverage.Cleanup != "CLEANUP_SUCCEEDED" {
					t.Fatalf("cleanup not verified successful: %+v", coverage)
				}
			}
		})
	}
}

func TestCLIDeterministicControlledPOSTFingerprint(t *testing.T) {
	first, firstExit, firstFixture := runControlledPostCLI(t, "create", "DENIED", nil, "")
	second, secondExit, secondFixture := runControlledPostCLI(t, "create", "DENIED", nil, "")
	if firstExit != 1 || secondExit != 1 || firstFixture.posts.Load() != 1 || secondFixture.posts.Load() != 1 || len(first.Findings) != 1 || len(second.Findings) != 1 {
		t.Fatalf("unexpected repeated CLI outcomes: exits=(%d,%d), posts=(%d,%d)", firstExit, secondExit, firstFixture.posts.Load(), secondFixture.posts.Load())
	}
	if first.Findings[0].Fingerprint != second.Findings[0].Fingerprint {
		t.Fatalf("semantic POST fingerprint was not stable: %s != %s", first.Findings[0].Fingerprint, second.Findings[0].Fingerprint)
	}
}

func TestCLITargetedPOSTRetestLifecycle(t *testing.T) {
	server, fixture := newPostFixture("create")
	defer server.Close()
	dir := t.TempDir()
	specPath, configPath := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "config.json")
	scanOut, findingPath := filepath.Join(dir, "scan.json"), filepath.Join(dir, "finding.json")
	retestOut := filepath.Join(dir, "retest.json")
	spec := `{"openapi":"3.0.3","info":{"title":"local retest","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := controlledCLIConfig(server.URL, specPath, "DENIED")
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"scan", "-config", configPath, "-out", scanOut}); code != 1 {
		t.Fatalf("source scan exit=%d", code)
	}
	scanBytes, err := os.ReadFile(scanOut)
	if err != nil {
		t.Fatal(err)
	}
	var source engine.Result
	if err = json.Unmarshal(scanBytes, &source); err != nil || len(source.Findings) != 1 {
		t.Fatalf("source findings=%d err=%v", len(source.Findings), err)
	}
	findingBytes, err := json.Marshal(source.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(findingPath, findingBytes, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.posts.Store(0)
	fixture.deletes.Store(0)
	if code := run([]string{"retest", "-config", configPath, "-finding", findingPath, "-out", retestOut}); code != 1 {
		t.Fatalf("retest exit=%d", code)
	}
	encodedResult, err := os.ReadFile(retestOut)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		SchemaVersion string                `json:"schema_version"`
		Results       []engine.RetestResult `json:"results"`
	}
	if err = json.Unmarshal(encodedResult, &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "1" || len(result.Results) != 1 || result.Results[0].Outcome != "STILL_PRESENT" || result.Results[0].Cleanup != "CLEANUP_SUCCEEDED" || fixture.posts.Load() != 1 || fixture.deletes.Load() != 1 {
		t.Fatalf("retest=%+v POSTs=%d cleanup DELETEs=%d", result, fixture.posts.Load(), fixture.deletes.Load())
	}
	for _, canary := range []string{"BODY_POST_CANARY", "ALICE_POST_CANARY", "${KURO_TEST_MARKER}", "created-1"} {
		if strings.Contains(string(encodedResult), canary) {
			t.Fatalf("ret-test output leaked %q", canary)
		}
	}
}

func TestCLICleanupDeleteRequiresVerification(t *testing.T) {
	for _, tc := range []struct {
		mode, timeout, want string
	}{
		{"create", "", "CLEANUP_SUCCEEDED"},
		{"delete-remains", "", "CLEANUP_FAILED"},
		{"delete-timeout-store", "20ms", "CLEANUP_SUCCEEDED"},
		{"delete-timeout-unknown", "20ms", "CLEANUP_INCONCLUSIVE"},
		{"delete-404", "", "CLEANUP_FAILED"},
		{"delete-redirect", "", "CLEANUP_FAILED"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			result, _, fixture := runControlledPostCLI(t, tc.mode, "DENIED", nil, tc.timeout)
			if fixture.posts.Load() != 1 || fixture.deletes.Load() != 1 || len(result.Findings) != 1 {
				t.Fatalf("cleanup changed proof outcome or dispatched wrong number of requests: posts=%d deletes=%d findings=%d", fixture.posts.Load(), fixture.deletes.Load(), len(result.Findings))
			}
			var got string
			for _, coverage := range result.Coverage {
				if coverage.Operation == "POST /api/items" {
					got = coverage.Cleanup
				}
			}
			if got != tc.want {
				t.Fatalf("cleanup=%q want %q; coverage=%+v warnings=%+v", got, tc.want, result.Coverage, result.Warnings)
			}
		})
	}
}

func TestCLICleanupRunsForAllowedAndUnknownPOST(t *testing.T) {
	for _, access := range []string{"ALLOWED", "UNKNOWN"} {
		t.Run(access, func(t *testing.T) {
			result, _, fixture := runControlledPostCLI(t, "create", access, nil, "")
			if fixture.deletes.Load() != 1 || len(result.Findings) != 0 {
				t.Fatalf("expected one hygiene cleanup without a vulnerability finding: deletes=%d findings=%d", fixture.deletes.Load(), len(result.Findings))
			}
		})
	}
}

func TestCLICleanupScopeAndAllowlistFailuresNeverDelete(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"outside target scope", func(c *config.Config) { c.Operations[0].Verification.CleanupPath = "/outside/items/{id}" }},
		{"outside cleanup allowlist", func(c *config.Config) { c.Mutations.CleanupPaths = []string{"/api/other/{id}"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, fixture := runControlledPostCLI(t, "create", "DENIED", tc.mutate, "")
			if fixture.deletes.Load() != 0 {
				t.Fatalf("unsafe cleanup policy sent DELETE: %d", fixture.deletes.Load())
			}
		})
	}
}
