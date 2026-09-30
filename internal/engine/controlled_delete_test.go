package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/openapi"
)

func TestControlledDeleteCapabilityIsDistinctBoundAndSingleUse(t *testing.T) {
	var deletes atomic.Int32
	var closeNextDelete atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			if closeNextDelete.CompareAndSwap(true, false) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	c := fixture(t, false)
	c.Target.BaseURL, c.Target.AllowedOrigins, c.Target.AllowedPaths = server.URL, []string{server.URL}, []string{"/api"}
	c.Mutations = config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST", "DELETE"}, AllowedPaths: []string{"/api/items", "/api/items/{id}"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 3, CleanupRequestBudget: 3, CleanupTimeout: "1s"}
	setup := config.Operation{ID: "seed", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs", Access: "ALLOWED", Classification: "BFLA",
		Disposable:  true,
		ContentType: "application/json", RequestBody: map[string]any{"meta": map[string]any{"marker": "${KURO_TEST_MARKER}"}},
		Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "meta.marker", RequestMarkerField: "meta.marker", ResourceIDField: "id", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}
	attack := config.Operation{ID: "attack", ControlledResourceOperationID: setup.ID, Path: "/api/items/{id}", Method: "DELETE", Actor: "bob", Owner: "alice", Resource: "docs", Access: "DENIED", Classification: "BOLA",
		Verification: config.VerificationStrategy{Type: "RESOURCE_ABSENT", Path: "/api/items/{id}", MarkerField: "meta.marker", ResourceIDField: "id", BaselineCompleteField: "complete"}}
	c.Operations = []config.Operation{setup, attack}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	policy := proofPolicy{origins: c.Target.AllowedOrigins, paths: c.Target.AllowedPaths, mutationPaths: c.Mutations.AllowedPaths, cleanupPaths: c.Mutations.CleanupPaths}
	test, err := newMutationTestIdentity("run", setup, policy)
	if err != nil {
		t.Fatal(err)
	}
	proof := &controlledResourceProof{test: test, resourceID: "item-1"}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	actor := config.Identity{ID: "bob"}
	target := s.endpoint("/api/items/item-1")
	_, preState := proveControlledDeleteState(test, handle, attack.Verification, target, http.StatusOK, []byte(`{"complete":true,"id":"item-1","meta":{"marker":"`+test.marker+`"}}`))
	stale := *preState
	stale.observedAt = time.Now().Add(-time.Minute)
	if _, err := authorizeControlledDelete(s, "run", actor, attack, setup, handle, &stale, nil, target); err == nil || deletes.Load() != 0 {
		t.Fatal("stale pre-delete proof authorized an attack")
	}
	changedSetup := setup
	changedSetup.Disposable = false
	if _, err := authorizeControlledDelete(s, "run", actor, attack, changedSetup, handle, preState, nil, target); err == nil || deletes.Load() != 0 {
		t.Fatal("configuration-only disposable claim substituted for the proof-bound POST setup")
	}
	auth, err := authorizeControlledDelete(s, "run", actor, attack, setup, handle, preState, nil, target)
	if err != nil {
		t.Fatal(err)
	}
	base := requestSpec{Method: http.MethodDelete, URL: target, operationID: attack.ID, operationPath: attack.Path, runID: "run", attackDeleteAuth: auth}
	if _, _, _, err := s.execute(context.Background(), c.Identities[0], base); err == nil || deletes.Load() != 0 {
		t.Fatal("actor substitution passed")
	}
	wrongTarget := base
	wrongTarget.URL = s.endpoint("/api/items/item-2")
	if _, _, _, err := s.execute(context.Background(), actor, wrongTarget); err == nil || deletes.Load() != 0 {
		t.Fatal("resource substitution passed")
	}
	wrongPath := base
	wrongPath.operationPath = "/api/other/{id}"
	if _, _, _, err := s.execute(context.Background(), actor, wrongPath); err == nil || deletes.Load() != 0 {
		t.Fatal("path substitution passed")
	}
	cleanupGrant, err := cleanupAuthorizationFromHandle(test, handle)
	if err != nil {
		t.Fatal(err)
	}
	cleanupTarget, err := constructCleanupCandidate(cleanupGrant, handle, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cleanupExec, err := authorizeCleanupExecution(s, "run", c.Identities[0], setup, cleanupTarget)
	if err != nil {
		t.Fatal(err)
	}
	interchanged := base
	interchanged.cleanupAuth = cleanupExec
	if _, _, _, err := s.execute(context.Background(), actor, interchanged); err == nil || deletes.Load() != 0 {
		t.Fatal("cleanup authorization was interchangeable with attack authorization")
	}
	cleanupOnly := base
	cleanupOnly.attackDeleteAuth = nil
	cleanupOnly.cleanupAuth = cleanupExec
	if _, _, _, err := s.execute(context.Background(), actor, cleanupOnly); err == nil || deletes.Load() != 0 {
		t.Fatal("cleanup capability alone authorized the attack operation")
	}
	ordinary := requestSpec{Method: http.MethodDelete, URL: target, operationID: attack.ID, operationPath: attack.Path, runID: "run"}
	if _, _, _, err := s.execute(context.Background(), actor, ordinary); err == nil || deletes.Load() != 0 {
		t.Fatal("ordinary RequestSpec DELETE bypassed capability boundary")
	}
	escape := base
	escape.URL = "https://outside.example/api/items/item-1"
	if _, _, _, err := s.execute(context.Background(), actor, escape); err == nil || deletes.Load() != 0 {
		t.Fatal("out-of-scope origin substitution passed")
	}
	if status, _, _, err := s.execute(context.Background(), actor, base); err != nil || status != http.StatusNoContent || deletes.Load() != 1 {
		t.Fatalf("valid one-use attack failed: status=%d writes=%d err=%v", status, deletes.Load(), err)
	}
	if _, _, _, err := s.execute(context.Background(), actor, base); err == nil || deletes.Load() != 1 {
		t.Fatal("replayed attack capability dispatched a second DELETE")
	}
	secondProof := &controlledResourceProof{test: test, resourceID: "item-2"}
	secondHandle, err := controlledHandleFromProof(secondProof)
	if err != nil {
		t.Fatal(err)
	}
	secondTarget := s.endpoint("/api/items/item-2")
	_, secondPreState := proveControlledDeleteState(test, secondHandle, attack.Verification, secondTarget, http.StatusOK, []byte(`{"complete":true,"id":"item-2","meta":{"marker":"`+test.marker+`"}}`))
	secondAuth, err := authorizeControlledDelete(s, "run", actor, attack, setup, secondHandle, secondPreState, nil, secondTarget)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.request(context.Background(), c.Identities[0], secondTarget); err != nil {
		t.Fatal(err)
	} // keep-alive connection for the retry probe
	closeNextDelete.Store(true)
	secondSpec := requestSpec{Method: http.MethodDelete, URL: secondTarget, operationID: attack.ID, operationPath: attack.Path, runID: "run", attackDeleteAuth: secondAuth}
	if _, _, _, err := s.execute(context.Background(), actor, secondSpec); err == nil {
		t.Fatal("closed-connection DELETE unexpectedly succeeded")
	}
	if deletes.Load() != 2 {
		t.Fatalf("transport replayed a DELETE: wire attempts=%d", deletes.Load()-1)
	}
}

func TestControlledDeleteCancellationAvoidsDuplicateDelete(t *testing.T) {
	for _, cancelAfterDispatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "before attack", true: "after dispatch"}[cancelAfterDispatch], func(t *testing.T) {
			var mu sync.Mutex
			present, marker := true, ""
			var attacks, cleanups atomic.Int32
			var cancel context.CancelFunc
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/items/item-1":
					mu.Lock()
					alive, mark := present, marker
					mu.Unlock()
					if alive {
						_, _ = w.Write([]byte(`{"complete":true,"id":"item-1","meta":{"marker":"` + mark + `"}}`))
					} else {
						_, _ = w.Write([]byte(`{"complete":true,"items":[]}`))
					}
				case r.Method == http.MethodGet && r.URL.Path == "/api/items":
					mu.Lock()
					alive, mark := present, marker
					mu.Unlock()
					items := `[]`
					if alive {
						items = `[{"id":"item-1","meta":{"marker":"` + mark + `"}}]`
					}
					_, _ = w.Write([]byte(`{"complete":true,"items":` + items + `}`))
				case r.Method == http.MethodDelete && r.Header.Get("Authorization") == "bob":
					attacks.Add(1)
					mu.Lock()
					present = false
					mu.Unlock()
					if cancelAfterDispatch {
						cancel()
					}
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodDelete:
					cleanups.Add(1)
					mu.Lock()
					present = false
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			c := fixture(t, false)
			c.Target.BaseURL, c.Target.AllowedOrigins, c.Target.AllowedPaths = server.URL, []string{server.URL}, []string{"/api"}
			c.Mutations = config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST", "DELETE"}, AllowedPaths: []string{"/api/items", "/api/items/{id}"}, CleanupPaths: []string{"/api/items/{id}"}, RequestBudget: 3, CleanupRequestBudget: 3, CleanupTimeout: "1s"}
			setup := config.Operation{ID: "seed", Path: "/api/items", Method: "POST", Actor: "alice", Resource: "docs", Access: "ALLOWED", Classification: "BFLA", Disposable: true,
				ContentType: "application/json", RequestBody: map[string]any{"meta": map[string]any{"marker": "${KURO_TEST_MARKER}"}},
				Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "meta.marker", RequestMarkerField: "meta.marker", ResourceIDField: "id", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}
			operation := config.Operation{ID: "attack", ControlledResourceOperationID: setup.ID, Path: "/api/items/{id}", Method: "DELETE", Actor: "bob", Owner: "alice", Resource: "docs", Access: "DENIED", Classification: "BOLA",
				Verification: config.VerificationStrategy{Type: "RESOURCE_ABSENT", Path: "/api/items/{id}", MarkerField: "meta.marker", ResourceIDField: "id", BaselineCompleteField: "complete"}}
			c.Operations = []config.Operation{setup, operation}
			s, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			policy := proofPolicy{origins: c.Target.AllowedOrigins, paths: c.Target.AllowedPaths, mutationPaths: c.Mutations.AllowedPaths, cleanupPaths: c.Mutations.CleanupPaths}
			test, err := newMutationTestIdentity("run", setup, policy)
			if err != nil {
				t.Fatal(err)
			}
			marker = test.marker
			proof := &controlledResourceProof{test: test, resourceID: "item-1"}
			handle, err := controlledHandleFromProof(proof)
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithCancel(context.Background())
			cancel = stop
			if !cancelAfterDispatch {
				cancel()
			}
			doc := openapi.Document{Paths: map[string]map[string]json.RawMessage{
				"/api/items": {"get": json.RawMessage(`{}`)}, "/api/items/{id}": {"get": json.RawMessage(`{}`), "delete": json.RawMessage(`{}`)},
			}}
			out := s.executeControlledDelete(ctx, "run", doc, c.Identities[1], operation, setup, controlledPostOutcome{test: test, proof: proof, handle: handle}, "docs", "DELETE /api/items/{id}")
			if cancelAfterDispatch {
				if attacks.Load() != 1 || cleanups.Load() != 0 || out.coverage.DeleteState != string(deleteResourceAbsent) || out.coverage.Cleanup != "CLEANUP_NOT_REQUIRED" {
					t.Fatalf("post-dispatch cancel duplicated or skipped verification: attacks=%d cleanup=%d coverage=%+v", attacks.Load(), cleanups.Load(), out.coverage)
				}
			} else if attacks.Load() != 0 || cleanups.Load() != 1 || out.coverage.State != "SKIPPED" || out.coverage.Cleanup != "CLEANUP_SUCCEEDED" {
				t.Fatalf("pre-attack cancellation did not perform bounded cleanup: attacks=%d cleanup=%d coverage=%+v", attacks.Load(), cleanups.Load(), out.coverage)
			}
			stop()
		})
	}
}
