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

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/openapi"
)

func controlledPOSTScanner(t *testing.T, handler http.HandlerFunc) (*Scanner, config.Config, *atomic.Int32) {
	t.Helper()
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	c := fixture(t, false)
	c.Target.BaseURL = server.URL
	c.Target.AllowedOrigins = []string{server.URL}
	c.Target.AllowedPaths = []string{"/api"}
	c.Limits.MaxRequests = 30
	c.Limits.Concurrency = 1
	op := config.Operation{ID: "controlled-create", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs",
		Access: "DENIED", Classification: "BFLA", ContentType: "application/json",
		RequestBody:  map[string]any{"meta": map[string]any{"marker": "${KURO_TEST_MARKER}"}},
		Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "meta.marker", ResourceIDField: "id", RequestMarkerField: "meta.marker", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}
	c.Operations = []config.Operation{op}
	c.Mutations = config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST"}, AllowedPaths: []string{"/api/items"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 2, CleanupRequestBudget: 3, CleanupTimeout: "1s"}
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	spec := `{"openapi":"3.0.3","info":{"title":"Controlled POST","version":"1"},"paths":{"/api/docs":{"get":{}},"/api/docs/{id}":{"get":{}},"/api/items":{"get":{},"post":{}}}}`
	if err := os.WriteFile(specPath, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	c.OpenAPI.Path = specPath
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, &posts
}

func TestControlledPOSTCapabilityIsRequiredBoundAndSingleUse(t *testing.T) {
	s, c, posts := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/items" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.URL.Path == "/api/items" && r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"complete":true,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	})
	op := c.Operations[0]
	actor := c.Identities[0]
	policy := proofPolicy{origins: c.Target.AllowedOrigins, paths: c.Target.AllowedPaths, mutationPaths: c.Mutations.AllowedPaths, cleanupPaths: c.Mutations.CleanupPaths}
	preexistingIdentity, err := newMutationTestIdentity("scan-1", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	preexistingBody := `{"complete":true,"items":[{"id":"old","meta":{"marker":"` + preexistingIdentity.marker + `"}}]}`
	if _, err := establishMarkerBaseline(preexistingIdentity, s.endpoint(op.Verification.Path), 200, []byte(preexistingBody), op.Verification, policy); err == nil {
		t.Fatal("pre-existing generated marker passed baseline")
	}
	preexistingPostBody, err := controlledRequestBody(preexistingIdentity, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeControlledPOST(s, "scan-1", actor, op, preexistingIdentity, nil, s.endpoint(op.Path), preexistingPostBody); err == nil || posts.Load() != 0 {
		t.Fatal("pre-existing marker did not prevent capability issuance")
	}
	testIdentity, err := newMutationTestIdentity("scan-1", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	body, err := controlledRequestBody(testIdentity, op)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := establishMarkerBaseline(testIdentity, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), op.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	url := s.endpoint(op.Path)
	ordinary := requestSpec{Method: http.MethodPost, URL: url, Body: body, ContentType: "application/json", operationID: op.ID}
	if _, _, _, err := s.execute(context.Background(), actor, ordinary); err == nil || posts.Load() != 0 {
		t.Fatal("ordinary RequestSpec POST bypassed capability boundary")
	}
	auth, err := authorizeControlledPOST(s, "scan-1", actor, op, testIdentity, baseline, url, body)
	if err != nil {
		t.Fatal(err)
	}
	allowed := ordinary
	allowed.postAuth = auth
	allowed.runID = "scan-1"
	if status, _, _, err := s.execute(context.Background(), actor, allowed); err != nil || status != http.StatusCreated || posts.Load() != 1 {
		t.Fatalf("valid capability did not dispatch exactly once: status=%d posts=%d err=%v", status, posts.Load(), err)
	}
	if _, _, _, err := s.execute(context.Background(), actor, allowed); err == nil || posts.Load() != 1 {
		t.Fatal("reused POST capability was accepted")
	}
	otherRun := allowed
	otherRun.runID = "scan-2"
	if _, _, _, err := s.execute(context.Background(), actor, otherRun); err == nil || posts.Load() != 1 {
		t.Fatal("capability from another scan was accepted")
	}

	secondIdentity, err := newMutationTestIdentity("scan-1", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := controlledRequestBody(secondIdentity, op)
	if err != nil {
		t.Fatal(err)
	}
	secondBaseline, err := establishMarkerBaseline(secondIdentity, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), op.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	secondAuth, err := authorizeControlledPOST(s, "scan-1", actor, op, secondIdentity, secondBaseline, url, secondBody)
	if err != nil {
		t.Fatal(err)
	}
	changedBody := append([]byte(nil), secondBody...)
	changedBody = append(changedBody, ' ')
	if _, _, _, err := s.execute(context.Background(), actor, requestSpec{Method: http.MethodPost, URL: url, Body: changedBody, ContentType: "application/json", postAuth: secondAuth, operationID: op.ID, runID: "scan-1"}); err == nil || posts.Load() != 1 {
		t.Fatal("body-substituted capability was accepted")
	}
	if _, _, _, err := s.execute(context.Background(), actor, requestSpec{Method: http.MethodPost, URL: url + "?x=1", Body: secondBody, ContentType: "application/json", postAuth: secondAuth, operationID: op.ID, runID: "scan-1"}); err == nil || posts.Load() != 1 {
		t.Fatal("path-substituted capability was accepted")
	}
	if _, _, _, err := s.execute(context.Background(), actor, requestSpec{Method: http.MethodPost, URL: url, Body: secondBody, ContentType: "application/json", postAuth: secondAuth, operationID: op.ID, runID: "scan-1"}); err != nil || posts.Load() != 2 {
		t.Fatalf("unmodified second capability failed: posts=%d err=%v", posts.Load(), err)
	}
	thirdIdentity, err := newMutationTestIdentity("scan-1", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	thirdBody, _ := controlledRequestBody(thirdIdentity, op)
	thirdBaseline, _ := establishMarkerBaseline(thirdIdentity, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), op.Verification, policy)
	if _, err := authorizeControlledPOST(s, "scan-1", actor, op, thirdIdentity, thirdBaseline, url, thirdBody); err == nil || posts.Load() != 2 {
		t.Fatal("mutation request budget did not block capability issuance")
	}
	fourthIdentity, err := newMutationTestIdentity("scan-1", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	fourthBody, _ := controlledRequestBody(fourthIdentity, op)
	fourthBaseline, _ := establishMarkerBaseline(fourthIdentity, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), op.Verification, policy)
	s.cfg.Mutations.RequestBudget = 3
	s.cfg.Limits.MaxRequests = s.used
	if _, err := authorizeControlledPOST(s, "scan-1", actor, op, fourthIdentity, fourthBaseline, url, fourthBody); err == nil || posts.Load() != 2 {
		t.Fatal("global request budget did not block capability issuance")
	}
}

func TestCleanupStillRunsAfterParentCancellationOnceProofExists(t *testing.T) {
	var deletes atomic.Int32
	s, c, _ := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/items/controlled-1" {
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/items" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"complete":true,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	})
	op, actor := c.Operations[0], c.Identities[0]
	policy := proofPolicy{origins: c.Target.AllowedOrigins, paths: c.Target.AllowedPaths, mutationPaths: c.Mutations.AllowedPaths, cleanupPaths: c.Mutations.CleanupPaths}
	test, err := newMutationTestIdentity("cancelled-run", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := establishMarkerBaseline(test, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), op.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	postBody := `{"id":"controlled-1","meta":{"marker":"` + test.marker + `"}}`
	proof, err := proveObservedResource(test, baseline, s.endpoint(op.Verification.Path), 200, []byte(`{"complete":true,"items":[`+postBody+`]}`), op.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	resourceAuth, err := cleanupAuthorizationFromHandle(test, handle)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := constructCleanupCandidate(resourceAuth, handle, s.base.Scheme+"://"+s.base.Host)
	if err != nil {
		t.Fatal(err)
	}
	executionAuth, err := authorizeCleanupExecution(s, test.runID, actor, op, candidate)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	if parent.Err() == nil {
		t.Fatal("parent context was not cancelled")
	}
	out := controlledPostOutcome{}
	state := s.executeControlledCleanup(test.runID, actor, op, candidate, executionAuth, proof, s.endpoint(op.Verification.Path), &out)
	if state != "CLEANUP_SUCCEEDED" || deletes.Load() != 1 || !out.coverage.CleanupAttempted {
		t.Fatalf("proven resource was not cleaned with the dedicated bounded context: outcome=%s deletes=%d", state, deletes.Load())
	}
}

func controlledUpdateExecutionFixture(t *testing.T, cancelMutation context.CancelFunc) (*Scanner, config.Config, config.Operation, config.Operation, controlledPostOutcome, openapi.Document, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var writes, deletes atomic.Int32
	state := "draft"
	testMarker := ""
	var mu sync.Mutex
	s, c, _ := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/items":
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "items": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/items/controlled-1":
			mu.Lock()
			v := state
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"complete": true, "item": map[string]any{"id": "controlled-1", "meta": map[string]any{"marker": testMarker}}, "status": v})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/items/controlled-1":
			writes.Add(1)
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			value, _ := payload["status"].(string)
			mu.Lock()
			state = value
			mu.Unlock()
			if cancelMutation != nil && writes.Load() == 1 {
				cancelMutation()
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/items/controlled-1":
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	c.Mutations.AllowedMethods = []string{"POST", "PATCH"}
	c.Mutations.AllowedPaths = []string{"/api/items", "/api/items/{id}"}
	c.Mutations.CleanupPaths = []string{"/api/items/{id}"}
	c.Mutations.CleanupRequestBudget = 6
	s.cfg = c
	setup := c.Operations[0]
	update := config.Operation{ID: "update", ControlledResourceOperationID: setup.ID, Path: "/api/items/{id}", Method: "PATCH", Actor: "bob", Owner: "alice", Resource: "docs", Access: "DENIED", Classification: "BOLA", ContentType: "application/json", RequestBody: map[string]any{"status": "published"}, RestoreBody: map[string]any{"status": "${KURO_PREVIOUS_STATE}"}, Verification: config.VerificationStrategy{Type: "RESOURCE_STATE", Path: "/api/items/{id}", Field: "status", ResourceIDField: setup.Verification.ResourceIDField, MarkerField: setup.Verification.MarkerField, BaselineCompleteField: "complete"}}
	policy := proofPolicy{origins: c.Target.AllowedOrigins, paths: c.Target.AllowedPaths, mutationPaths: c.Mutations.AllowedPaths, cleanupPaths: c.Mutations.CleanupPaths}
	testID, err := newMutationTestIdentity("cancel-run", setup, policy)
	if err != nil {
		t.Fatal(err)
	}
	testMarker = testID.marker
	baseline, err := establishMarkerBaseline(testID, s.endpoint(setup.Verification.Path), 200, []byte(`{"complete":true,"items":[]}`), setup.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	observed := `{"complete":true,"items":[{"id":"controlled-1","meta":{"marker":"` + testID.marker + `"}}]}`
	proof, err := proveObservedResource(testID, baseline, s.endpoint(setup.Verification.Path), 200, []byte(observed), setup.Verification, policy)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	// The pre-state proof is acquired by executeControlledUpdate from the fixture GET.
	outcome := controlledPostOutcome{test: testID, proof: proof, handle: handle}
	doc := openapi.Document{Paths: map[string]map[string]json.RawMessage{"/api/items/{id}": {"get": json.RawMessage(`{}`), "patch": json.RawMessage(`{}`)}}}
	return s, c, setup, update, outcome, doc, &writes, &deletes
}

func TestControlledUpdateCancellationBoundaries(t *testing.T) {
	t.Run("before update", func(t *testing.T) {
		s, c, setup, op, outcome, doc, writes, deletes := controlledUpdateExecutionFixture(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := s.executeControlledUpdate(ctx, "cancel-run", doc, c.Identities[1], op, setup, outcome, "docs", "PATCH /api/items/{id}")
		if writes.Load() != 0 || deletes.Load() != 1 || result.executed {
			t.Fatalf("cancel before update did not block attack and clean setup: writes=%d deletes=%d", writes.Load(), deletes.Load())
		}
	})
	t.Run("after update", func(t *testing.T) {
		var cancel context.CancelFunc
		s, c, setup, op, outcome, doc, writes, deletes := controlledUpdateExecutionFixture(t, func() {
			if cancel != nil {
				cancel()
			}
		})
		ctx, stop := context.WithCancel(context.Background())
		cancel = stop
		result := s.executeControlledUpdate(ctx, "cancel-run", doc, c.Identities[1], op, setup, outcome, "docs", "PATCH /api/items/{id}")
		if !result.executed || result.finding == nil || result.coverage.Restoration != "RESTORATION_SUCCEEDED" || deletes.Load() != 1 || writes.Load() != 2 {
			t.Fatalf("cancellation after write did not verify/restore/clean: writes=%d deletes=%d coverage=%+v findings=%v", writes.Load(), deletes.Load(), result.coverage, result.finding)
		}
	})
}

func TestCancelledControlledPOSTNeverDispatches(t *testing.T) {
	s, _, posts := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/items" {
			_, _ = w.Write([]byte(`{"complete":true,"items":[]}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/docs") {
			http.Error(w, "cancelled", http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := s.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 {
		t.Fatalf("cancelled scan sent %d POST requests", posts.Load())
	}
	for _, coverage := range result.Coverage {
		if coverage.Operation == "POST /api/items" && coverage.State != "SKIPPED" {
			t.Fatalf("unexpected cancelled operation coverage: %+v", coverage)
		}
	}
}

func TestCancellationAfterPOSTSurfacesUnverifiedStateWithoutRetry(t *testing.T) {
	var cancel context.CancelFunc
	var deletes atomic.Int32
	s, _, posts := controlledPOSTScanner(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/docs" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"doc-a","name":"document"}]`))
		case strings.HasPrefix(r.URL.Path, "/api/docs/") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":"doc-a","name":"document"}`))
		case r.URL.Path == "/api/items" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"complete":true,"items":[]}`))
		case r.URL.Path == "/api/items" && r.Method == http.MethodPost:
			cancel()
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	ctx, stop := context.WithCancel(context.Background())
	cancel = stop
	result, err := s.Scan(ctx)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 || deletes.Load() != 0 || result.Status != "cancelled" {
		t.Fatalf("unexpected post-cancellation behavior: posts=%d deletes=%d status=%s", posts.Load(), deletes.Load(), result.Status)
	}
	found := false
	for _, coverage := range result.Coverage {
		if coverage.Operation == "POST /api/items" {
			found = true
			if coverage.Cleanup != "NOT_POSSIBLE" || coverage.State != "INCONCLUSIVE" {
				t.Fatalf("possible created state was not surfaced: %+v", coverage)
			}
		}
	}
	if !found {
		t.Fatal("cancelled POST lifecycle coverage missing")
	}
}
