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
	}{{"vulnerable", 1, 2, false}, {"secure", 0, 0, false}, {"ambiguous", 0, 0, true}} {
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
			c := config.Config{SchemaVersion: "1", Target: config.Target{BaseURL: srv.URL, AllowedOrigins: []string{srv.URL}, AllowedPaths: []string{prefix}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice", "X-Secret": "SECRETVALUE_CANARY"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob", "X-Secret": "SECRETVALUE_CANARY"}}}, Resources: []config.Resource{{Name: "docs", Collection: prefix + "/docs", Detail: prefix + "/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Expectations: []config.Expectation{{Identity: "alice", Resource: "docs", Access: "DENIED"}, {Identity: "bob", Resource: "docs", Access: "DENIED"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
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
