package engine

import (
	"context"
	"encoding/json"
	"github.com/kurokagi/kurokagi/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, vulnerable bool) config.Config {
	t.Helper()
	var server *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/docs" {
			if r.Header.Get("X-IDVerify") == "1" {
				id := "A"
				if r.Header.Get("Authorization") == "bob" {
					id = "B"
				}
				_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": id}})
				return
			}
			if r.Header.Get("X-Duplicate") == "1" && r.Header.Get("Authorization") == "alice" {
				_ = json.NewEncoder(w).Encode([]any{
					map[string]string{"id": "A", "name": "document-A"},
					map[string]string{"id": "A", "name": "conflicting-A"},
				})
				return
			}
			if r.Header.Get("X-Common") == "1" {
				id := "A"
				if r.Header.Get("Authorization") == "bob" {
					id = "B"
				}
				json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "type": "document"}})
				return
			}
			if r.Header.Get("Authorization") == "alice" {
				json.NewEncoder(w).Encode([]any{map[string]string{"id": "A", "name": "document-A"}})
			} else {
				json.NewEncoder(w).Encode([]any{map[string]string{"id": "B", "name": "document-B"}})
			}
			return
		}
		if r.URL.Path == "/api/admin/users" {
			if !vulnerable {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]int{"count": 3}})
			return
		}
		id := r.URL.Path[len("/api/docs/"):]
		actor := r.Header.Get("Authorization")
		if r.Header.Get("X-Ambiguous") == "1" {
			json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
			return
		}
		if r.Header.Get("X-Echo") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
			return
		}
		if r.Header.Get("X-IDVerify") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": id})
			return
		}
		if r.Header.Get("X-Common") == "1" {
			json.NewEncoder(w).Encode(map[string]string{"id": id, "type": "document"})
			return
		}
		if !vulnerable && ((actor == "alice" && id == "B") || (actor == "bob" && id == "A")) {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		if vulnerable {
			json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "document-" + id})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
	})
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c := config.Config{SchemaVersion: "3", Target: config.Target{BaseURL: server.URL, AllowedOrigins: []string{server.URL}, AllowedPaths: []string{"/api"}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob"}}}, Resources: []config.Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Expectations: []config.Expectation{{Identity: "alice", Resource: "docs", Access: "DENIED"}, {Identity: "bob", Resource: "docs", Access: "DENIED"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
	c.OpenAPI.Path = filepath.Join("..", "..", "testdata", "openapi.json")
	return c
}

func TestExplicitVerticalFunctionAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name         string
		vulnerable   bool
		wantFindings int
	}{{"vulnerable", true, 1}, {"secure", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture(t, tc.vulnerable)
			c.Expectations = []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}}
			c.Operations = []config.Operation{{ID: "admin-user-list", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}
			spec := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/admin/users":{"get":{}}}}`
			c.OpenAPI.Path = filepath.Join(t.TempDir(), "openapi.json")
			if err := os.WriteFile(c.OpenAPI.Path, []byte(spec), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.wantFindings {
				t.Fatalf("findings=%d, want %d", len(result.Findings), tc.wantFindings)
			}
			if tc.vulnerable && (result.Findings[0].Type != "BFLA" || result.Findings[0].AccessingIdentity != "bob") {
				t.Fatalf("unexpected vertical finding: %+v", result.Findings[0])
			}
			if !contains(result.Capabilities, "vertical_function_authorization") {
				t.Fatal("vertical capability not recorded")
			}
		})
	}
}

func TestConfiguredMutatingOperationsAreNeverSent(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/docs" {
			id, name := "A", "doc-A"
			if r.Header.Get("Authorization") == "bob" {
				id, name = "B", "doc-B"
			}
			_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": name}})
			return
		}
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()
	methods := []string{"POST", "PUT", "PATCH", "DELETE"}
	paths := map[string]any{"/api/docs": map[string]any{"get": map[string]any{}}, "/api/docs/{id}": map[string]any{"get": map[string]any{}}}
	ops := map[string]any{}
	for _, method := range methods {
		ops[strings.ToLower(method)] = map[string]any{"responses": map[string]any{"204": map[string]any{"description": "ok"}}}
	}
	paths["/api/write"] = ops
	specBytes, _ := json.Marshal(map[string]any{"openapi": "3.0.3", "info": map[string]string{"title": "writes", "version": "1"}, "paths": paths})
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(specPath, specBytes, 0600); err != nil {
		t.Fatal(err)
	}
	c := fixture(t, false)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.OpenAPI.Path = specPath
	for _, method := range methods {
		c.Operations = append(c.Operations, config.Operation{ID: strings.ToLower(method), Path: "/api/write", Method: method, Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "ok"}})
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range methods {
		if _, _, _, err := s.execute(context.Background(), c.Identities[1], requestSpec{Method: method, URL: server.URL + "/api/write", Body: []byte("REQUEST_BODY_SECRET_CANARY")}); err == nil {
			t.Errorf("executor accepted %s", method)
		}
		if _, _, _, _, err := s.requestOnce(context.Background(), c.Identities[1], requestSpec{Method: method, URL: server.URL + "/api/write", Body: []byte("REQUEST_BODY_SECRET_CANARY")}); err == nil {
			t.Errorf("transport boundary accepted %s", method)
		}
	}
	if writes.Load() != 0 {
		t.Fatalf("executor sent rejected methods: %d", writes.Load())
	}
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 0 {
		t.Fatalf("mutating requests reached fixture: %d", writes.Load())
	}
	for _, method := range methods {
		found := false
		for _, coverage := range result.Coverage {
			if coverage.Operation == method+" /api/write" {
				found = true
				if coverage.State != "UNSUPPORTED" && coverage.State != "SKIPPED_BY_POLICY" || !strings.Contains(coverage.Reason, "policy") && !strings.Contains(coverage.Reason, "mutations are disabled") {
					t.Fatalf("unexpected coverage for %s: %+v", method, coverage)
				}
			}
		}
		if !found {
			t.Errorf("no honest coverage for %s", method)
		}
	}
	// Even declared OpenAPI write operations without Kuro configuration are metadata only.
	c.Operations = nil
	metadataOnly, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := metadataOnly.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 0 {
		t.Fatalf("OpenAPI metadata triggered a write: %d", writes.Load())
	}
}

func TestAuthorizationExpectationsAreMethodSpecific(t *testing.T) {
	c := fixture(t, false)
	c.Expectations = []config.Expectation{
		{Identity: "bob", Owner: "alice", Resource: "docs", Method: "GET", Access: "DENIED"},
		{Identity: "bob", Owner: "alice", Resource: "docs", Method: "PATCH", Access: "ALLOWED"},
		{Identity: "bob", Owner: "alice", Resource: "docs", Relationship: "workspace", Method: "GET", Access: "DENIED"},
		{Identity: "bob", Owner: "alice", Resource: "docs", Relationship: "workspace", Method: "PATCH", Access: "ALLOWED"},
	}
	c.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("method-specific expectation config invalid: %v", err)
	}
	if got := expectation(c, "bob", "alice", "docs", "", "GET"); got != "DENIED" {
		t.Fatalf("GET expectation=%s", got)
	}
	if got := expectation(c, "bob", "alice", "docs", "", "PATCH"); got != "ALLOWED" {
		t.Fatalf("PATCH expectation=%s", got)
	}
	if got := expectation(c, "bob", "alice", "docs", "workspace", "GET"); got != "DENIED" {
		t.Fatalf("relationship GET expectation=%s", got)
	}
	if got := expectation(c, "bob", "alice", "docs", "workspace", "PATCH"); got != "ALLOWED" {
		t.Fatalf("relationship PATCH expectation=%s", got)
	}
}

func TestMethodAwareOperationsAcceptMutationTemplatesWithoutExecuting(t *testing.T) {
	c := fixture(t, false)
	c.Operations = []config.Operation{{ID: "delete-user", Path: "/api/users/{userId}", Method: "delete", Actor: "bob", Owner: "alice", Resource: "docs", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESOURCE_ABSENT"}}}
	if _, err := New(c); err != nil {
		t.Fatalf("mutation operation should be representable: %v", err)
	}
}

func TestUnsupportedOperationMethodAndVerificationFailClosed(t *testing.T) {
	for _, tc := range []config.Operation{
		{ID: "trace", Path: "/api/admin/users", Method: "TRACE", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "ok"}},
		{ID: "unknown-verifier", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "MAGIC", Field: "ok"}},
	} {
		c := fixture(t, false)
		c.Operations = []config.Operation{tc}
		if _, err := New(c); err == nil {
			t.Errorf("accepted unsupported operation: %+v", tc)
		}
	}
	if (config.Operation{Method: "DELETE"}).Safety() != config.SafetyDestructive {
		t.Fatal("DELETE not classified destructive")
	}
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		if (config.Operation{Method: method}).Safety() != config.SafetyMutating {
			t.Errorf("%s not classified mutating", method)
		}
	}
}

func TestOperationFindingFingerprintIsStableAndMethodSpecific(t *testing.T) {
	first := functionFinding("BFLA", "admin-edit", "bob", "alice", "users", "workspace", "get", "/api/admin/users", "e1")
	repeat := functionFinding("BFLA", "admin-edit", "bob", "alice", "users", "workspace", "GET", "/api/admin/users", "e2")
	patch := functionFinding("BFLA", "admin-edit", "bob", "alice", "users", "workspace", "PATCH", "/api/admin/users", "e3")
	if first.Fingerprint != repeat.Fingerprint {
		t.Fatal("method normalization/evidence changes made fingerprint unstable")
	}
	if first.Fingerprint == patch.Fingerprint {
		t.Fatal("GET and PATCH findings collided")
	}
}

func TestNonResponseVerificationIsSkippedForGET(t *testing.T) {
	c := fixture(t, false)
	c.Operations = []config.Operation{{ID: "future-exists", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "DENIED", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS"}}}
	spec := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/admin/users":{"get":{}}}}`
	c.OpenAPI.Path = filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(c.OpenAPI.Path, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, coverage := range result.Coverage {
		if coverage.Operation == "GET /api/admin/users" && coverage.State != "UNSUPPORTED" {
			t.Fatalf("unimplemented strategy executed: %+v", coverage)
		}
	}
}

func TestConfiguredOperationVerifierNeedsPositiveEvidence(t *testing.T) {
	for _, body := range []string{
		`{"data":{"ok":false}}`,
		`{"data":{"count":0}}`,
		`{"data":{"token":""}}`,
		`{"message":"ok"}`,
	} {
		if configuredSuccess([]byte(body), "data.ok") || configuredSuccess([]byte(body), "data.count") || configuredSuccess([]byte(body), "data.token") {
			t.Fatalf("non-positive response accepted as operation proof: %s", body)
		}
	}
	if !configuredSuccess([]byte(`{"data":{"ok":true}}`), "data.ok") || !configuredSuccess([]byte(`{"data":{"count":3}}`), "data.count") {
		t.Fatal("positive configured operation evidence rejected")
	}
}

func TestCredentialProvidersNeverAppearInResult(t *testing.T) {
	const aliceBearer = "ALICE_BEARER_CANARY_9f2a"
	const aliceCookie = "ALICE_COOKIE_CANARY_0b1d"
	const staticHeader = "STATIC_HEADER_CANARY_4c7e"
	const bobBearer = "BOB_BEARER_CANARY_6a31"
	const bobCookie = "BOB_COOKIE_CANARY_3d8c"
	const providerHeader = "PROVIDER_HEADER_CANARY_aa90"
	validIdentity := func(r *http.Request) bool {
		switch r.Header.Get("X-Identity") {
		case "alice":
			cookie, _ := r.Cookie("session")
			return r.Header.Get("Authorization") == "Bearer "+aliceBearer && r.Header.Get("X-Static") == staticHeader && cookie != nil && cookie.Value == aliceCookie
		case "bob":
			cookie, _ := r.Cookie("session")
			return r.Header.Get("Authorization") == "Bearer "+bobBearer && r.Header.Get("X-Provider") == providerHeader && cookie != nil && cookie.Value == bobCookie
		default:
			return false
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validIdentity(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		identity := r.Header.Get("X-Identity")
		if r.URL.Path == "/api/docs" {
			id, name := "A", "document-A"
			if identity == "bob" {
				id, name = "B", "document-B"
			}
			_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": name}})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/docs/")
		name := "document-" + id
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": name})
	}))
	defer server.Close()
	c := fixture(t, true)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.Expectations = []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}}
	c.Identities = []config.Identity{
		{ID: "alice", Headers: map[string]string{"X-Identity": "alice", "X-Static": staticHeader}, Credentials: []config.Credential{{Type: "bearer", Value: aliceBearer}, {Type: "cookie", Name: "session", Value: aliceCookie}}},
		{ID: "bob", Headers: map[string]string{"X-Identity": "bob"}, Credentials: []config.Credential{{Type: "bearer", Value: bobBearer}, {Type: "cookie", Name: "session", Value: bobCookie}, {Type: "header", Name: "X-Provider", Value: providerHeader}}},
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{aliceBearer, aliceCookie, staticHeader, bobBearer, bobCookie, providerHeader} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("credential provider leaked %q into result", secret)
		}
	}
}

func TestPaginatedDiscoveryIsBoundedAndConservative(t *testing.T) {
	var detailHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := r.Header.Get("Authorization")
		if r.URL.Path == "/api/docs" {
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page > 2 {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			prefix := "A"
			if actor == "bob" {
				prefix = "B"
			}
			id := prefix + strconv.Itoa(page)
			_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": "document-" + id}})
			return
		}
		detailHits.Add(1)
		id := strings.TrimPrefix(r.URL.Path, "/api/docs/")
		owner := "alice"
		if strings.HasPrefix(id, "B") {
			owner = "bob"
		}
		if actor != owner {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "document-" + id})
	}))
	defer server.Close()
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Pagination fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	makeConfig := func(maxPages int) config.Config {
		c := fixture(t, false)
		c.Target.BaseURL = server.URL
		c.Target.AllowedOrigins = []string{server.URL}
		c.OpenAPI.Path = specPath
		c.Expectations = []config.Expectation{{Identity: "alice", Owner: "bob", Resource: "docs", Access: "DENIED"}, {Identity: "bob", Owner: "alice", Resource: "docs", Access: "DENIED"}}
		c.Resources[0].Pagination = &config.Pagination{Type: "page", PageParam: "page", PageSizeParam: "size", StartPage: 1, PageSize: 1, MaxPages: maxPages}
		return c
	}
	complete, err := New(makeConfig(3))
	if err != nil {
		t.Fatal(err)
	}
	result, err := complete.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || result.Completion != "complete" {
		t.Fatalf("complete pagination result: findings=%d completion=%s", len(result.Findings), result.Completion)
	}
	if detailHits.Load() == 0 {
		t.Fatal("complete discovery did not proceed to detail checks")
	}
	for _, coverage := range result.Coverage {
		if coverage.Operation == "discover" && coverage.State != "TESTED" {
			t.Fatalf("complete pages reported incomplete: %+v", coverage)
		}
	}
	detailHits.Store(0)
	truncated, err := New(makeConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	partial, err := truncated.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(partial.Findings) != 0 || partial.Completion != "partial" || detailHits.Load() != 0 {
		t.Fatalf("truncated discovery was treated as complete: findings=%d completion=%s detailRequests=%d", len(partial.Findings), partial.Completion, detailHits.Load())
	}
}

func TestRelationshipAuthorizationNeedsExplicitDeniedBoundaryProof(t *testing.T) {
	for _, tc := range []struct {
		name       string
		vulnerable bool
		want       int
	}{{"cross_workspace_vulnerable", true, 1}, {"cross_workspace_secure", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actor := r.Header.Get("Authorization")
				if r.URL.Path == "/api/docs" {
					id, workspace := "doc-A", "ws-A"
					if actor == "bob" {
						id, workspace = "doc-B", "ws-B"
					}
					_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": "private-" + id, "workspace_id": workspace}})
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/api/docs/")
				workspace := "ws-A"
				if id == "doc-B" {
					workspace = "ws-B"
				}
				if !tc.vulnerable && actor == "bob" && id == "doc-A" {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "private-" + id, "workspace_id": workspace})
			}))
			defer server.Close()
			c := fixture(t, tc.vulnerable)
			c.Target.BaseURL = server.URL
			c.Target.AllowedOrigins = []string{server.URL}
			c.Identities[0].Contexts = map[string]string{"workspace": "ws-A"}
			c.Identities[1].Contexts = map[string]string{"workspace": "ws-B"}
			c.Resources[0].Classification = "RELATIONSHIP"
			c.Resources[0].Relationships = []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
			c.Expectations = []config.Expectation{{Identity: "bob", Owner: "alice", Resource: "docs", Relationship: "workspace", Access: "DENIED"}}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Scan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.want {
				t.Fatalf("findings=%d, want %d", len(result.Findings), tc.want)
			}
			if tc.vulnerable {
				finding := result.Findings[0]
				if finding.Type != "RELATIONSHIP" || finding.Relationship != "workspace" || len(finding.RelationshipProof) != 1 || finding.RelationshipProof[0].Boundary != "different" {
					t.Fatalf("missing explicit boundary proof: %+v", finding)
				}
				encoded, _ := json.Marshal(result)
				for _, secret := range []string{"ws-A", "ws-B", "doc-A", "doc-B"} {
					if strings.Contains(string(encoded), secret) {
						t.Fatalf("raw resource/context value leaked in result: %s", secret)
					}
				}
			}
		})
	}
}

func TestRelationshipDifferenceDoesNotCreateSeparateResourceIdentity(t *testing.T) {
	relations := []config.Relationship{{Name: "workspace", Kind: "workspace", Field: "workspace_id"}}
	body := []byte(`[{"id":"doc-1","name":"first","workspace_id":"ws-A"},{"id":"doc-1","name":"second","workspace_id":"ws-B"}]`)
	if _, err := extractResourceCandidates(body, []config.IdentifierField{{Path: "id", Parameter: "id"}}, []string{"name"}, relations); err == nil {
		t.Fatal("same composite resource with conflicting relationship context was treated as two owned resources")
	}
}

func TestStructuredDifferentialEvidenceIgnoresVolatileFieldsAndValues(t *testing.T) {
	baseline := map[string]any{"name": "secret-a", "updated": "t1", "nested": map[string]any{"enabled": true}, "items": []any{map[string]any{"value": "a"}}}
	got := compareJSONFields(baseline, []byte(`{"name":"secret-b","updated":"t2","nested":{"enabled":false},"items":[{"value":"b"}]}`), []string{"updated"})
	want := []string{"items.0.value", "name", "nested.enabled"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("differential paths=%v, want %v", got, want)
	}
	for _, path := range got {
		if strings.Contains(path, "secret") {
			t.Fatalf("differential evidence leaked a value: %q", path)
		}
	}
}

func TestExplicitUnknownVerticalExpectationNeverFindsBFLA(t *testing.T) {
	c := fixture(t, true)
	c.Expectations = []config.Expectation{{Identity: "alice", Resource: "docs", Access: "UNKNOWN"}, {Identity: "bob", Resource: "docs", Access: "UNKNOWN"}}
	c.Operations = []config.Operation{{ID: "admin-user-list", Path: "/api/admin/users", Method: "GET", Actor: "bob", Access: "UNKNOWN", Classification: "BFLA", Verification: config.VerificationStrategy{Type: "RESPONSE_FIELD", Field: "data.count"}}}
	spec := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/admin/users":{"get":{}}}}`
	c.OpenAPI.Path = filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(c.OpenAPI.Path, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.Type == "BFLA" {
			t.Fatal("UNKNOWN vertical expectation produced a finding")
		}
	}
}

func TestExplicitIDORClassificationReachesFinding(t *testing.T) {
	c := fixture(t, true)
	c.Resources[0].Classification = "IDOR"
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings=%d, want 2", len(result.Findings))
	}
	for _, finding := range result.Findings {
		if finding.Type != "IDOR" {
			t.Fatalf("classification changed: %+v", finding)
		}
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
			if !tc.vuln {
				denials := 0
				for _, cov := range r.Coverage {
					if cov.Operation == "cross_identity" && cov.State == "TESTED" && cov.Reason == "access denied" {
						denials++
					}
				}
				if denials != 2 {
					t.Fatalf("secure fixture should prove two denial results, got %d", denials)
				}
			}
		})
	}
}
func TestGenericSuccessIsInconclusive(t *testing.T) {
	c := fixture(t, false)
	for i := range c.Identities {
		c.Identities[i].Headers["X-Ambiguous"] = "1"
	}
	s, _ := New(c)
	r, _ := s.Scan(context.Background())
	if len(r.Findings) != 0 {
		t.Fatal("ambiguous response produced a finding")
	}
	found := false
	for _, c := range r.Coverage {
		if c.Operation == "cross_identity" && c.State == "INCONCLUSIVE" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected INCONCLUSIVE coverage")
	}
}

func TestUnknownExpectationNeverFindsBOLA(t *testing.T) {
	c := fixture(t, true)
	c.Expectations = nil
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatal("UNKNOWN expectation produced a finding")
	}
	for _, cov := range r.Coverage {
		if cov.Operation == "cross_identity" && cov.State != "INCONCLUSIVE" {
			t.Fatalf("unexpected coverage %+v", cov)
		}
	}
	for _, cov := range r.Coverage {
		if cov.Operation == "cross_identity" && !strings.Contains(cov.Reason, "expectation is UNKNOWN") {
			t.Fatalf("UNKNOWN expectation reason was not explicit: %+v", cov)
		}
	}
}

func TestCommonVerificationValueDoesNotProveBOLA(t *testing.T) {
	c := fixture(t, true)
	for i := range c.Identities {
		c.Identities[i].Headers["X-Common"] = "1"
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("shared type=document verification value produced %d findings", len(r.Findings))
	}
	for _, cov := range r.Coverage {
		if cov.Operation == "cross_identity" && cov.State != "INCONCLUSIVE" {
			t.Fatalf("expected common verification values to be inconclusive: %+v", cov)
		}
	}
}

func TestVerificationFieldEchoingIDDoesNotProveBOLA(t *testing.T) {
	c := fixture(t, true)
	for i := range c.Identities {
		c.Identities[i].Headers["X-IDVerify"] = "1"
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("ID-reflecting verification value produced a finding: findings=%d err=%v", len(r.Findings), err)
	}
	for _, cov := range r.Coverage {
		if cov.Operation == "cross_identity" && cov.State != "INCONCLUSIVE" {
			t.Fatalf("ID-reflecting verification should be inconclusive: %+v", cov)
		}
	}
}

func TestDuplicateCandidateIDsAreInconclusive(t *testing.T) {
	_, err := extractCandidates([]byte(`[{"id":"A","name":"one"},{"id":"A","name":"two"}]`), "id", "name")
	if err == nil {
		t.Fatal("duplicate conflicting candidate IDs must be rejected")
	}
	c := fixture(t, true)
	c.Identities[0].Headers["X-Duplicate"] = "1"
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("duplicate collection evidence was not fail-closed: findings=%d err=%v", len(r.Findings), err)
	}
	inconclusive := false
	for _, cov := range r.Coverage {
		if cov.Operation == "cross_identity" && cov.State == "INCONCLUSIVE" {
			inconclusive = true
		}
	}
	if !inconclusive {
		t.Fatal("duplicate candidate evidence should make cross-identity coverage inconclusive")
	}
}

func TestNestedExplicitResourceFieldPaths(t *testing.T) {
	body := []byte(`{"data":{"items":[{"resource":{"key":"one"},"proof":{"label":"first"}}]}}`)
	candidates, err := extractCandidates(body, "resource.key", "proof.label")
	if err != nil || len(candidates) != 1 || candidates[0].PathValues["id"] != "one" || candidates[0].Verify == "" || candidates[0].ID == "one" {
		t.Fatalf("nested extraction = %#v, %v", candidates, err)
	}
	value, ok := extractOne([]byte(`{"data":{"resource":{"key":"one"}}}`), "resource.key")
	if !ok || value != "one" {
		t.Fatalf("nested detail extraction = %q, %v", value, ok)
	}
	ambiguous, err := extractCandidates([]byte(`{"data":{"items":[{"id":"one"}]},"results":[{"id":"two"}]}`), "id", "name")
	if err != nil || len(ambiguous) != 0 {
		t.Fatalf("ambiguous collection envelope must not select an arbitrary list: %#v, %v", ambiguous, err)
	}
}

func TestCompositeIdentifiersAndVerificationFields(t *testing.T) {
	identifiers := []config.IdentifierField{{Path: "organization.id", Parameter: "org_id"}, {Path: "document.key", Parameter: "doc_id"}}
	verification := []string{"metadata.revision", "content.title"}
	body := []byte(`{"items":[{"organization":{"id":"org-α"},"document":{"key":"doc-1"},"metadata":{"revision":"rev-7"},"content":{"title":"Design"}}]}`)
	candidates, err := extractResourceCandidates(body, identifiers, verification, nil)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidate extraction: %#v %v", candidates, err)
	}
	item := candidates[0]
	if item.PathValues["org_id"] != "org-α" || item.PathValues["doc_id"] != "doc-1" || item.ID == "org-α" || strings.Contains(item.ID, "doc-1") {
		t.Fatalf("raw composite identity exposed: %#v", item)
	}
	ref, idValues, _, ok := extractResourceRef([]byte(`{"data":{"organization":{"id":"org-α"},"document":{"key":"doc-1"}}}`), identifiers, nil)
	verify, verifyValues, verifyOK := extractVerificationDigest([]byte(`{"data":{"metadata":{"revision":"rev-7"},"content":{"title":"Design"}}}`), verification)
	if !ok || !verifyOK || ref != item.ID || verify != item.Verify || valuesIntersect(idValues, verifyValues) {
		t.Fatal("composite identity/evidence tuple was not stable")
	}
	firstFinding := finding("BOLA", "documents", item.ID, "alice", "bob", "", "/api/orgs/{org_id}/docs/{doc_id}", "ev-1")
	secondFinding := finding("BOLA", "documents", item.ID, "alice", "bob", "", "/api/orgs/{org_id}/docs/{doc_id}", "ev-2")
	other := finding("BOLA", "documents", candidatesWithDifferentCompositeRef(identifiers), "alice", "bob", "", "/api/orgs/{org_id}/docs/{doc_id}", "ev-3")
	if firstFinding.Fingerprint != secondFinding.Fingerprint || firstFinding.Fingerprint != other.Fingerprint {
		t.Fatal("composite resource runtime IDs changed semantic finding identity")
	}
	serialized, _ := json.Marshal(firstFinding)
	for _, secretLike := range []string{"org-α", "doc-1", "rev-7", "Design"} {
		if strings.Contains(string(serialized), secretLike) {
			t.Fatalf("raw resource value leaked into finding: %s", serialized)
		}
	}
	path, err := detailPath("/api/orgs/{org_id}/docs/{doc_id}", item.PathValues)
	if err != nil || path != "/api/orgs/org-α/docs/doc-1" {
		t.Fatalf("detail path=%q err=%v", path, err)
	}
}

func candidatesWithDifferentCompositeRef(fields []config.IdentifierField) string {
	return tupleDigest([]string{fields[0].Path, fields[1].Path}, []string{"org-β", "doc-1"}, false)
}

func FuzzExtractOneAndCandidateFields(f *testing.F) {
	f.Add([]byte(`{"id":"alpha","profile":{"name":"Ada"}}`), "id")
	f.Add([]byte(`{"data":{"id":null}}`), "data.id")
	f.Add([]byte(`[]`), "profile.name")
	f.Fuzz(func(t *testing.T, body []byte, field string) {
		if len(body) > 1<<16 || len(field) > 1024 {
			t.Skip()
		}
		_, _ = extractOne(body, field)
		_, _ = extractCandidates(body, field, field)
	})
}

func TestReflectedAuthorizationIsAbsentFromResult(t *testing.T) {
	const canary = "CANARY_AUTH_73d2f"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/docs" {
			id, name := canary, "victim-unique"
			if r.Header.Get("Authorization") != canary {
				id, name = "B", "attacker-unique"
			}
			_ = json.NewEncoder(w).Encode([]any{map[string]string{"id": id, "name": name}})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/docs/")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "name": "detail-" + id})
	}))
	defer server.Close()
	c := fixture(t, true)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.Identities[0].Headers["Authorization"] = "${KURO_AUTH_CANARY}"
	_ = os.Setenv("KURO_AUTH_CANARY", canary)
	defer os.Unsetenv("KURO_AUTH_CANARY")
	c.Identities[1].Headers["Authorization"] = "other"
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(loaded)
	if err != nil {
		t.Fatal(err)
	}
	r, scanErr := s.Scan(context.Background())
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	serialized, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), canary) || strings.Contains(errString(scanErr), canary) {
		t.Fatalf("authorization canary leaked: %s", serialized)
	}
	for _, ev := range r.Evidence {
		if ev.ResourceRef != "" && len(ev.ResourceRef) != 64 {
			t.Fatalf("resource evidence reference is not a stable digest: %+v", ev)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestSafeContentTypeAllowlist(t *testing.T) {
	if got := safeContentType("Application/JSON; charset=utf-8"); got != "application/json" {
		t.Fatalf("unexpected normalized content type %q", got)
	}
	if got := safeContentType("application/CANARY_AUTH_73d2f"); got != "" {
		t.Fatalf("arbitrary response content type entered output: %q", got)
	}
}

func TestFindingFingerprintOmitsResponseControlledIDs(t *testing.T) {
	first := finding("BOLA", "documents", "ref-abc", "alice", "bob", "", "/api/docs/{id}", "ev-1")
	second := finding("BOLA", "documents", "ref-abc", "alice", "bob", "", "/api/docs/{id}", "ev-2")
	if first.Fingerprint != second.Fingerprint || strings.Contains(first.Fingerprint, "CANARY") {
		t.Fatal("finding fingerprint must not encode response-controlled resource IDs")
	}
}

func TestResourceMappingRejectsQuerySecrets(t *testing.T) {
	c := fixture(t, true)
	c.Resources[0].Collection = "/api/docs?api_key=CANARY_QUERY_SECRET"
	if err := c.Validate(); err == nil || strings.Contains(err.Error(), "CANARY_QUERY_SECRET") {
		t.Fatalf("query-bearing path accepted or error leaked secret: %v", err)
	}
}

func TestSharedVisibilityDoesNotEstablishVictim(t *testing.T) {
	c := fixture(t, true)
	c.Identities[1].Headers["Authorization"] = "alice"
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatal("shared visibility produced a BOLA finding")
	}
	found := false
	for _, cov := range r.Coverage {
		if cov.State == "INCONCLUSIVE" {
			found = true
		}
	}
	if !found {
		t.Fatal("shared visibility should produce INCONCLUSIVE coverage")
	}
}

func TestIDOnlyEchoIsInconclusive(t *testing.T) {
	c := fixture(t, true)
	for i := range c.Identities {
		c.Identities[i].Headers["X-Echo"] = "1"
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatal("ID-only echo produced a finding")
	}
	found := false
	for _, cov := range r.Coverage {
		if cov.State == "INCONCLUSIVE" {
			found = true
		}
	}
	if !found {
		t.Fatal("ID-only echo should produce INCONCLUSIVE coverage")
	}
}

func BenchmarkFindingFingerprint(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = finding("BOLA", "documents", "ref-abc", "alice", "bob", "", "/api/docs/{id}", "ev-123")
	}
}

func TestRedirectAndResponseLimits(t *testing.T) {
	var foreignHits int
	var localHits atomic.Int64
	var okHits atomic.Int64
	var outPrefixHits atomic.Int64
	var chainHits atomic.Int64
	paced := make(chan time.Time, 2)
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits++ }))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/localredirect" {
			localHits.Add(1)
			w.Header().Set("Location", "/api/ok")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/api/outprefix" {
			w.Header().Set("Location", "/private/secret")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/private/secret" {
			outPrefixHits.Add(1)
			return
		}
		if r.URL.Path == "/api/pacedredirect" {
			paced <- time.Now()
			w.Header().Set("Location", "/api/pacedend")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/api/pacedend" {
			paced <- time.Now()
			_, _ = w.Write([]byte("ok"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/chain/") {
			chainHits.Add(1)
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/chain/"))
			w.Header().Set("Location", "/api/chain/"+strconv.Itoa(n+1))
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/api/redirect" {
			w.Header().Set("Location", foreign.URL+"/api/leak")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path == "/api/ok" {
			okHits.Add(1)
			_, _ = w.Write([]byte("ok"))
			return
		}
		if r.URL.Path == "/api/slow" {
			time.Sleep(80 * time.Millisecond)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 128)))
	}))
	defer server.Close()
	c := fixture(t, true)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.Limits.MaxResponseBytes = 16
	c.Limits.RedirectPolicy = "same_origin"
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err := s.request(context.Background(), c.Identities[0], server.URL+"/api/redirect")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusFound || foreignHits != 0 {
		t.Fatalf("status=%d foreign hits=%d", status, foreignHits)
	}
	status, _, _, err = s.request(context.Background(), c.Identities[0], server.URL+"/api/outprefix")
	if err != nil || status != http.StatusFound || outPrefixHits.Load() != 0 {
		t.Fatalf("out-of-prefix redirect was followed: status=%d hits=%d err=%v", status, outPrefixHits.Load(), err)
	}
	status, _, _, err = s.request(context.Background(), c.Identities[0], server.URL+"/api/chain/0")
	if err != nil || status != http.StatusFound || chainHits.Load() != 6 {
		t.Fatalf("redirect chain cap failed: status=%d requests=%d err=%v", status, chainHits.Load(), err)
	}
	status, body, _, err := s.request(context.Background(), c.Identities[0], server.URL+"/api/localredirect")
	if err != nil || status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("in-scope redirect status=%d body=%q err=%v", status, body, err)
	}
	paceConfig := c
	paceConfig.Limits.RequestsPerSecond = 10
	paceScanner, err := New(paceConfig)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _, err = paceScanner.request(context.Background(), c.Identities[0], server.URL+"/api/pacedredirect")
	first, second := <-paced, <-paced
	if err != nil || status != http.StatusOK || second.Sub(first) < 80*time.Millisecond {
		t.Fatalf("redirect hop did not obey pacing: status=%d interval=%s err=%v", status, second.Sub(first), err)
	}
	_, _, _, err = s.request(context.Background(), c.Identities[0], server.URL+"/api/large")
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected bounded response error, got %v", err)
	}
	c.Limits.MaxRequests = 1
	limited, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _ = limited.request(context.Background(), c.Identities[0], server.URL+"/api/redirect")
	_, _, _, err = limited.request(context.Background(), c.Identities[0], server.URL+"/api/redirect")
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("expected global request budget error, got %v", err)
	}
	beforeOK := okHits.Load()
	limitedRedirect, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = limitedRedirect.request(context.Background(), c.Identities[0], server.URL+"/api/localredirect")
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") || okHits.Load() != beforeOK {
		t.Fatalf("budget did not block next redirect hop: ok hits before=%d after=%d err=%v", beforeOK, okHits.Load(), err)
	}
	c.Limits.MaxRequests = 10
	c.Limits.Timeout = "10ms"
	timed, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = timed.request(context.Background(), c.Identities[0], server.URL+"/api/slow")
	if err == nil {
		t.Fatal("expected request timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = canceled.request(ctx, c.Identities[0], server.URL+"/api/redirect")
	if err == nil {
		t.Fatal("expected canceled request")
	}
}

func TestConcurrentRequestsRespectGlobalBudget(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	c := fixture(t, true)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.Limits.MaxRequests = 3
	c.Limits.Concurrency = 4
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = s.request(context.Background(), c.Identities[0], server.URL+"/api/ok")
		}()
	}
	wg.Wait()
	s.mu.Lock()
	used := s.used
	s.mu.Unlock()
	if hits.Load() > int64(c.Limits.MaxRequests) || used > c.Limits.MaxRequests || hits.Load() != int64(used) {
		t.Fatalf("global accounting violated: wire hits=%d used=%d", hits.Load(), used)
	}
}
