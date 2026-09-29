package engine

import (
	"context"
	"encoding/json"
	"github.com/kurokagi/kurokagi/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	c := config.Config{SchemaVersion: "1", Target: config.Target{BaseURL: server.URL, AllowedOrigins: []string{server.URL}, AllowedPaths: []string{"/api"}}, Identities: []config.Identity{{ID: "alice", Headers: map[string]string{"Authorization": "alice"}}, {ID: "bob", Headers: map[string]string{"Authorization": "bob"}}}, Resources: []config.Resource{{Name: "docs", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}, Expectations: []config.Expectation{{Identity: "alice", Resource: "docs", Access: "DENIED"}, {Identity: "bob", Resource: "docs", Access: "DENIED"}}, Limits: config.Limits{Timeout: "1s", MaxRequests: 20, Concurrency: 2, MaxResponseBytes: 4096, MaxObjects: 10, RedirectPolicy: "none"}}
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
		if ev.ResourceID != "" {
			t.Fatalf("response-controlled resource ID entered evidence: %+v", ev)
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
	first := finding("documents", "alice", "bob", "/api/docs/{id}", "ev-1")
	second := finding("documents", "alice", "bob", "/api/docs/{id}", "ev-2")
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
		_ = finding("documents", "alice", "bob", "/api/docs/{id}", "ev-123")
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
