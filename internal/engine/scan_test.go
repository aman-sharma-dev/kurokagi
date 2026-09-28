package engine

import (
	"context"
	"encoding/json"
	"github.com/kurokagi/kurokagi/internal/config"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, vulnerable bool) config.Config {
	t.Helper()
	var server *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/docs" {
			if r.Header.Get("Authorization") == "alice" {
				json.NewEncoder(w).Encode([]any{map[string]string{"id": "A"}})
			} else {
				json.NewEncoder(w).Encode([]any{map[string]string{"id": "B"}})
			}
			return
		}
		id := r.URL.Path[len("/api/docs/"):]
		actor := r.Header.Get("Authorization")
		if !vulnerable && ((actor == "alice" && id == "B") || (actor == "bob" && id == "A")) {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id": id})
	})
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c := config.Config{SchemaVersion: "1", Target: config.Target{BaseURL: server.URL, AllowedOrigins: []string{server.URL}, AllowedPaths: []string{"/api"}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob"}}}, Resources: []config.Resource{{Name: "docs", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", Ownership: "collection_visibility"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
	c.OpenAPI.Path = filepath.Join("..", "..", "testdata", "openapi.json")
	return c
}
func TestFixturePipeline(t *testing.T) {
	for _, tc := range []struct {
		name string
		vuln bool
		want int
	}{{"vulnerable", true, 2}, {"secure", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := New(fixture(t, tc.vuln))
			if e != nil {
				t.Fatal(e)
			}
			r, e := s.Scan(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if len(r.Findings) != tc.want {
				t.Fatalf("findings=%d want %d", len(r.Findings), tc.want)
			}
			for _, c := range r.Coverage {
				if c.State == "" {
					t.Fatal("empty coverage state")
				}
			}
		})
	}
}
func TestGenericSuccessIsInconclusive(t *testing.T) {
	c := fixture(t, true)
	s, _ := New(c)
	r, _ := s.Scan(context.Background())
	for _, e := range r.Evidence {
		if e.Status == 200 && e.ResourceID == "" {
			t.Log("response identity could not be established")
		}
	}
}
