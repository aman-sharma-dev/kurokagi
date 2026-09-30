package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/engine"
)

func TestCLIEndToEndFixtures(t *testing.T) {
	for _, tc := range []struct {
		mode           string
		exit, findings int
		inconclusive   bool
	}{{"vulnerable", 1, 1, false}, {"secure", 0, 0, false}, {"ambiguous", 4, 0, true}} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/"+tc.mode+"/api/docs" {
					if r.Header.Get("Authorization") == "alice" {
						_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": "A", "name": "document-A"}})
					} else {
						_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": "B", "name": "document-B"}})
					}
					return
				}
				id := filepath.Base(r.URL.Path)
				if tc.mode == "secure" && ((r.Header.Get("Authorization") == "alice" && id == "B") || (r.Header.Get("Authorization") == "bob" && id == "A")) {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				if tc.mode == "ambiguous" {
					_ = json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "document-" + id})
			}))
			defer srv.Close()
			dir := t.TempDir()
			spec := filepath.Join(dir, "openapi.json")
			cfgPath := filepath.Join(dir, "config.json")
			out := filepath.Join(dir, "result.json")
			prefix := "/" + tc.mode + "/api"
			_ = os.WriteFile(spec, []byte(`{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"`+prefix+`/docs":{"get":{}},"`+prefix+`/docs/{id}":{"get":{}}}}`), 0600)
			c := config.Config{SchemaVersion: "3", Target: config.Target{BaseURL: srv.URL, AllowedOrigins: []string{srv.URL}, AllowedPaths: []string{prefix}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice", "X-Secret": "SECRETVALUE_CANARY"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob", "X-Secret": "SECRETVALUE_CANARY"}}}, Resources: []config.Resource{{Name: "docs", Classification: "BOLA", Collection: prefix + "/docs", Detail: prefix + "/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Expectations: []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Access: "DENIED"}, {Identity: "alice", Owner: "bob", Resource: "docs", Access: "ALLOWED"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
			c.OpenAPI.Path = spec
			b, _ := json.Marshal(c)
			if err := os.WriteFile(cfgPath, b, 0600); err != nil {
				t.Fatal(err)
			}
			got := run([]string{"scan", "-config", cfgPath, "-out", out})
			if got != tc.exit {
				t.Fatalf("exit=%d want %d", got, tc.exit)
			}
			resultBytes, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var result engine.Result
			if err = json.Unmarshal(resultBytes, &result); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(resultBytes), "SECRETVALUE_CANARY") {
				t.Fatal("secret header leaked to scan output")
			}
			if len(result.Findings) != tc.findings {
				t.Fatalf("findings=%d want %d", len(result.Findings), tc.findings)
			}
			if result.SchemaVersion != "2" || result.Tool["name"] != "Kurokagi" || result.Target.Origin != srv.URL || result.Completion == "" {
				t.Fatalf("incomplete machine result contract: %+v", result)
			}
			found := false
			for _, cov := range result.Coverage {
				if cov.State == "INCONCLUSIVE" {
					found = true
				}
			}
			if found != tc.inconclusive {
				t.Fatalf("inconclusive=%v want %v", found, tc.inconclusive)
			}
		})
	}
}

func TestLoadRetestInputsAcceptsNativeFindingsAndDeduplicatesSemantically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	first := engine.Finding{Fingerprint: strings.Repeat("a", 64), Type: "BOLA", Resource: "docs", ResourceRef: "runtime-one", VictimIdentity: "alice", AccessingIdentity: "bob", Method: "GET", Path: "/api/docs/{id}"}
	second := first
	second.ResourceRef = "runtime-two"
	body, err := json.Marshal([]engine.Finding{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := loadRetestInputs(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 {
		t.Fatalf("deduped inputs=%d want 1", len(inputs))
	}
	got := inputs[0]
	if got.SchemaVersion != "1" || got.Fingerprint != first.Fingerprint || got.Resource != "docs" || got.Actor != "bob" || got.ResourceRef != "" {
		t.Fatalf("native finding selector not preserved safely: %+v", got)
	}
}

func TestRetestInputRejectsHistoricalAuthorityFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	body := `{"schema_version":"1","finding_fingerprint":"` + strings.Repeat("a", 64) + `","credentials":"SECRET_CANARY","scope":"https://evil.invalid"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRetestInputs(path); err == nil {
		t.Fatal("historical credential/scope material was accepted")
	}
}

func FuzzLoadRetestInputsDoesNotPanic(f *testing.F) {
	f.Add([]byte(`{"schema_version":"1","finding_fingerprint":"` + strings.Repeat("a", 64) + `"}`))
	f.Add([]byte(`{"schema_version":"1","finding_fingerprint":"bad","request_body":{"secret":"CANARY"}}`))
	f.Add([]byte(`{"schema_version":"1","schema_version":"1","finding_fingerprint":"` + strings.Repeat("a", 64) + `"}`))
	f.Add([]byte(`[{}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "retest.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		inputs, err := loadRetestInputs(path)
		if err != nil {
			return
		}
		for _, input := range inputs {
			if input.SchemaVersion != "1" || len(input.Fingerprint) != 64 {
				t.Fatalf("malformed retest input accepted: %+v", input)
			}
		}
	})
}

func TestCLIVerticalAuthorizationFixture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/docs":
			if r.Header.Get("Authorization") == "alice" {
				_, _ = w.Write([]byte(`[{"id":"A","name":"doc-A"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":"B","name":"doc-B"}]`))
			}
		case "/api/docs/A":
			if r.Header.Get("Authorization") == "bob" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"id":"A","name":"doc-A"}`))
		case "/api/docs/B":
			if r.Header.Get("Authorization") == "alice" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"id":"B","name":"doc-B"}`))
		case "/api/admin/users":
			_, _ = w.Write([]byte(`{"data":{"count":2}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	configPath := filepath.Join(dir, "config.json")
	outPath := filepath.Join(dir, "result.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/admin/users":{"get":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{SchemaVersion: "3", Target: config.Target{BaseURL: srv.URL, AllowedOrigins: []string{srv.URL}, AllowedPaths: []string{"/api"}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob"}}}, Resources: []config.Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Expectations: []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}}, Operations: []config.Operation{{ID: "admin-users", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
	c.OpenAPI.Path = specPath
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if exit := run([]string{"scan", "-config", configPath, "-out", outPath}); exit != 1 {
		t.Fatalf("CLI exit=%d, want 1", exit)
	}
	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var result engine.Result
	if err = json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Type != "BFLA" || result.Findings[0].AccessingIdentity != "bob" {
		t.Fatalf("unexpected CLI result: %+v", result.Findings)
	}
}

func TestCLIInvalidInputAndTargetFailureExitCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if exit := run([]string{"scan", "-config", missing}); exit != 2 {
		t.Fatalf("invalid input exit=%d, want 2", exit)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	configPath := filepath.Join(dir, "config.json")
	outPath := filepath.Join(dir, "result.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{SchemaVersion: "3", Target: config.Target{BaseURL: base, AllowedOrigins: []string{base}, AllowedPaths: []string{"/api"}}, Identities: []config.Identity{{ID: "a"}, {ID: "b"}}, Resources: []config.Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 10, Concurrency: 2, MaxResponseBytes: 1024, MaxObjects: 4, RedirectPolicy: "none"}}
	c.OpenAPI.Path = specPath
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if exit := run([]string{"scan", "-config", configPath, "-out", outPath}); exit != 3 {
		t.Fatalf("target failure exit=%d, want 3", exit)
	}
	output, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var result engine.Result
	if err = json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) == 0 || result.Errors[0].Code != engine.CodeTargetUnreachable {
		t.Fatalf("target failure missing structured error: %+v", result.Errors)
	}
}
