package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kurokagi/kurokagi/internal/config"
)

func controlledOperation() config.Operation {
	return config.Operation{ID: "create-item", Path: "/api/items", Method: "POST", Actor: "writer", Resource: "item", Access: "DENIED", Classification: "BFLA",
		ContentType: "application/json", RequestBody: map[string]any{"metadata": map[string]any{"kuro_test_id": "${KURO_TEST_MARKER}"}, "label": "safe-test"},
		Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/api/items", MarkerField: "metadata.kuro_test_id", ResourceIDField: "id", RequestMarkerField: "metadata.kuro_test_id", BaselineCompleteField: "complete", CleanupPath: "/api/items/{id}"}}
}

func controlledFixture(t *testing.T) (*mutationTestIdentity, config.VerificationStrategy, proofPolicy) {
	t.Helper()
	op := controlledOperation()
	policy := proofPolicy{origins: []string{"https://api.example"}, paths: []string{"/api/items"}, mutationPaths: []string{"/api/items"}, cleanupPaths: []string{"/api/items/{id}"}}
	identity, err := newMutationTestIdentity("run-current", op, policy)
	if err != nil {
		t.Fatal(err)
	}
	return identity, op.Verification, policy
}

func baselineFor(t *testing.T, identity *mutationTestIdentity, strategy config.VerificationStrategy, policy proofPolicy, body string) *baselineProof {
	t.Helper()
	proof, err := establishMarkerBaseline(identity, "https://api.example/api/items", 200, []byte(body), strategy, policy)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func observeFor(t *testing.T, identity *mutationTestIdentity, baseline *baselineProof, strategy config.VerificationStrategy, policy proofPolicy, body string) (*controlledResourceProof, error) {
	t.Helper()
	var observed any
	if err := json.Unmarshal([]byte(body), &observed); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(map[string]any{"complete": true, "items": []any{observed}})
	if err != nil {
		t.Fatal(err)
	}
	return proveObservedResource(identity, baseline, "https://api.example/api/items", 200, response, strategy, policy)
}

func TestControlledMarkerIsUniqueAndBounded(t *testing.T) {
	id, _, _ := controlledFixture(t)
	other, _, _ := controlledFixture(t)
	if id.marker == "" || len(id.marker) > 64 || id.marker == other.marker || !strings.HasPrefix(id.marker, "kuro-") {
		t.Fatalf("invalid or repeated generated marker")
	}
}

func TestControlledIdentityRequiresExplicitMarkerField(t *testing.T) {
	op := config.Operation{ID: "op", Path: "/items", Method: "POST", Actor: "actor", Resource: "item",
		Verification: config.VerificationStrategy{Path: "/items", CleanupPath: "/items/{id}"}}
	policy := proofPolicy{origins: []string{"https://api.example"}, paths: []string{"/items"}, mutationPaths: []string{"/items"}, cleanupPaths: []string{"/items/{id}"}}
	if _, err := newMutationTestIdentity("run", op, policy); err == nil {
		t.Fatal("identity accepted without configured marker field")
	}
}

func TestStateJSONRejectsDuplicateKeysAsAmbiguous(t *testing.T) {
	for _, body := range []string{`{"status":"draft","status":"published"}`, `{"outer":{"id":"one","id":"two"}}`, `{"complete":true} {"complete":true}`} {
		if _, err := decodeJSON([]byte(body)); err == nil {
			t.Fatalf("ambiguous JSON accepted: %s", body)
		}
	}
}

func TestControlledIdentityRequiresCleanupAllowlist(t *testing.T) {
	op := config.Operation{ID: "op", Path: "/items", Method: "POST", Actor: "actor", Resource: "item",
		ContentType: "application/json", RequestBody: map[string]any{"meta": map[string]any{"marker": "${KURO_TEST_MARKER}"}},
		Verification: config.VerificationStrategy{Type: "RESOURCE_EXISTS", Path: "/items", MarkerField: "meta.marker", ResourceIDField: "id", RequestMarkerField: "meta.marker", BaselineCompleteField: "complete", CleanupPath: "/items/{id}"}}
	policy := proofPolicy{origins: []string{"https://api.example"}, paths: []string{"/items"}, mutationPaths: []string{"/items"}}
	if _, err := newMutationTestIdentity("run", op, policy); err == nil {
		t.Fatal("identity accepted cleanup path absent from dedicated allowlist")
	}
}

func TestControlledRequestTemplateInjectsOnlyGeneratedMarker(t *testing.T) {
	id, _, _ := controlledFixture(t)
	op := controlledOperation()
	body, err := controlledRequestBody(id, op)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	metadata := decoded["metadata"].(map[string]any)
	if metadata["kuro_test_id"] != id.marker || strings.Contains(string(body), "${KURO_TEST_MARKER}") {
		t.Fatalf("marker was not injected: %s", body)
	}
	if op.RequestBody.(map[string]any)["metadata"].(map[string]any)["kuro_test_id"] != "${KURO_TEST_MARKER}" {
		t.Fatal("template was mutated")
	}
	op.ID = "other-operation"
	if _, err := controlledRequestBody(id, op); err == nil {
		t.Fatal("request template from another operation was accepted")
	}
	op.ID = id.operationID
	op.RequestBody.(map[string]any)["label"] = "changed-after-identity"
	if _, err := controlledRequestBody(id, op); err == nil {
		t.Fatal("changed request body was accepted for an existing test identity")
	}
}

func TestPreexistingMarkerCannotProveCurrentCreation(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	if _, err := establishMarkerBaseline(id, "https://api.example/api/items", 200, []byte(`{"complete":true,"items":[{"id":"preexisting","metadata":{"kuro_test_id":"`+id.marker+`"}}]}`), strategy, policy); err == nil {
		t.Fatal("pre-existing marker passed baseline")
	}
	if _, err := establishMarkerBaseline(id, "https://api.example/api/items", 200, []byte(`{"items":[]}`), strategy, policy); err == nil {
		t.Fatal("incomplete baseline passed without explicit completeness evidence")
	}
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	if _, err := observeFor(t, id, baseline, strategy, policy, `{"id":"preexisting","metadata":{"kuro_test_id":"`+id.marker+`"}}`); err != nil {
		t.Fatalf("isolated positive observation should be representable: %v", err)
	}
}

func TestControlledProofRequiresObservedUniqueMarkerAndIdentifier(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	tests := []struct {
		name string
		body string
	}{
		{"resource id alone", `{"id":"abc"}`},
		{"wrong marker", `{"id":"abc","metadata":{"kuro_test_id":"someone-else"}}`},
		{"missing marker", `{"id":"abc","metadata":{}}`},
		{"ambiguous marker", `[{"id":"a","metadata":{"kuro_test_id":"` + id.marker + `"}},{"id":"b","metadata":{"kuro_test_id":"` + id.marker + `"}}]`},
		{"invalid identifier", `{"id":"../elsewhere","metadata":{"kuro_test_id":"` + id.marker + `"}}`},
		{"missing identifier", `{"metadata":{"kuro_test_id":"` + id.marker + `"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if proof, err := observeFor(t, id, baseline, strategy, policy, tt.body); err == nil || proof != nil {
				t.Fatalf("unexpected proof: %#v, %v", proof, err)
			}
		})
	}
	if proof, err := proveObservedResource(id, baseline, "https://api.example/api/items", 201, []byte(`{"complete":true,"items":[{"id":"abc","metadata":{"kuro_test_id":"`+id.marker+`"}}]}`), strategy, policy); err != nil || proof == nil {
		t.Fatalf("201 with independent marker observation should be provable: %v", err)
	}
	if proof, err := proveObservedResource(id, baseline, "https://api.example/api/items", 201, []byte(`{"complete":true,"items":[{"id":"abc"}]}`), strategy, policy); err == nil || proof != nil {
		t.Fatal("HTTP status alone established proof")
	}
	if proof, err := proveObservedResource(id, baseline, "https://api.example/api/items", 200, []byte(`{"complete":false,"items":[{"id":"abc","metadata":{"kuro_test_id":"`+id.marker+`"}}]}`), strategy, policy); err == nil || proof != nil {
		t.Fatal("incomplete verification response established proof")
	}
}

func TestProofRequiresCurrentTestAndInScopeVerification(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	other, _, _ := controlledFixture(t)
	body := `{"id":"item-1","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	if _, err := observeFor(t, other, baseline, strategy, policy, body); err == nil {
		t.Fatal("baseline from a different test was accepted")
	}
	if _, err := proveObservedResource(id, baseline, "https://outside.example/api/items", 200, []byte(body), strategy, policy); err == nil {
		t.Fatal("out-of-scope verification was accepted")
	}
	if _, err := proveObservedResource(id, baseline, "https://api.example/api/items?next=https://evil.example", 200, []byte(body), strategy, policy); err == nil {
		t.Fatal("query-bearing verification was accepted")
	}
}

func TestHandleAndCleanupCapabilityRequireProofAndAreBound(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	if _, err := controlledHandleFromProof(nil); err == nil {
		t.Fatal("handle constructed without proof")
	}
	if _, err := cleanupAuthorizationFromHandle(id, nil); err == nil {
		t.Fatal("cleanup authorization constructed without handle")
	}
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	proof, err := observeFor(t, id, baseline, strategy, policy, body)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := cleanupAuthorizationFromHandle(id, handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanupAuthorizationFromHandle(id, handle); err == nil {
		t.Fatal("multiple cleanup capabilities were issued for one controlled resource")
	}
	forgedHandle := &controlledResourceHandle{proof: proof, resourceID: "other-item", resource: handle.resource,
		operationID: handle.operationID, actor: handle.actor, cleanupPath: handle.cleanupPath}
	if _, err := cleanupAuthorizationFromHandle(id, forgedHandle); err == nil {
		t.Fatal("forged resource handle passed proof binding")
	}
	candidate, err := constructCleanupCandidate(auth, handle, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.method != "DELETE" || candidate.url != "https://api.example/api/items/item-42" {
		t.Fatalf("unexpected candidate: %#v", candidate)
	}

	other, _, _ := controlledFixture(t)
	if _, err := constructCleanupCandidate(auth, handle, "https://outside.example"); err == nil {
		t.Fatal("out-of-scope target was accepted")
	}
	if _, err := constructCleanupCandidate(auth, handle, "https://api.example"); err == nil {
		t.Fatal("cleanup capability was reusable")
	}
	if _, err := cleanupAuthorizationFromHandle(other, handle); err == nil {
		t.Fatal("handle was reused in another test")
	}
}

func TestCleanupCandidateRejectsUnsafeTemplatesAndIdentifiers(t *testing.T) {
	for _, template := range []string{"/api/items/{id}/../users", "/api/items/{id}?next=x", "/api/items/{id}#fragment", "/api/items/%2e%2e/{id}", "/api/items/{id}/{id}"} {
		t.Run(template, func(t *testing.T) {
			id, strategy, policy := controlledFixture(t)
			id.cleanupPath = template
			id.policy.cleanupPaths = []string{template}
			strategy.CleanupPath = template
			policy.cleanupPaths = []string{template}
			baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
			body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
			proof, err := observeFor(t, id, baseline, strategy, policy, body)
			if err != nil {
				t.Fatal(err)
			}
			handle, _ := controlledHandleFromProof(proof)
			auth, _ := cleanupAuthorizationFromHandle(id, handle)
			if _, err := constructCleanupCandidate(auth, handle, "https://api.example"); err == nil {
				t.Fatalf("unsafe template accepted: %s", template)
			}
		})
	}
}

func TestCleanupAuthorizationRejectsResourceAndPathTampering(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	proof, err := observeFor(t, id, baseline, strategy, policy, body)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ := controlledHandleFromProof(proof)
	auth, _ := cleanupAuthorizationFromHandle(id, handle)
	if _, err := constructCleanupCandidate(auth, &controlledResourceHandle{proof: proof, resourceID: "different-item", resource: handle.resource,
		operationID: handle.operationID, actor: handle.actor, cleanupPath: handle.cleanupPath}, "https://api.example"); err == nil {
		t.Fatal("cleanup authorization targeted a different resource")
	}
	otherID, otherStrategy, otherPolicy := controlledFixture(t)
	otherBaseline := baselineFor(t, otherID, otherStrategy, otherPolicy, `{"complete":true,"items":[]}`)
	otherBody := `{"id":"item-99","metadata":{"kuro_test_id":"` + otherID.marker + `"}}`
	otherProof, err := observeFor(t, otherID, otherBaseline, otherStrategy, otherPolicy, otherBody)
	if err != nil {
		t.Fatal(err)
	}
	otherHandle, _ := controlledHandleFromProof(otherProof)
	otherAuth, _ := cleanupAuthorizationFromHandle(otherID, otherHandle)
	otherAuth.path = "/api/other/{id}"
	if _, err := constructCleanupCandidate(otherAuth, otherHandle, "https://api.example"); err == nil {
		t.Fatal("changed cleanup path was accepted")
	}
}

func TestCleanupTransportCapabilityIsExactAndSingleUse(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	proof, err := observeFor(t, id, baseline, strategy, policy, body)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	resourceAuth, err := cleanupAuthorizationFromHandle(id, handle)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := constructCleanupCandidate(resourceAuth, handle, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	op := controlledOperation()
	actor := config.Identity{ID: "writer"}
	scanner := &Scanner{cfg: config.Config{Target: config.Target{AllowedOrigins: policy.origins, AllowedPaths: policy.paths}, Mutations: config.MutationPolicy{Enabled: true, CleanupPaths: policy.cleanupPaths}}}
	auth, err := authorizeCleanupExecution(scanner, id.runID, actor, op, candidate)
	if err != nil {
		t.Fatal(err)
	}
	spec := requestSpec{Method: "DELETE", URL: candidate.url, cleanupAuth: auth, operationID: op.ID, runID: id.runID}
	if !auth.matches(scanner, actor, spec) {
		t.Fatal("valid exact cleanup request rejected")
	}
	changed := spec
	changed.URL = "https://api.example/api/items/other-item"
	if auth.matches(scanner, actor, changed) {
		t.Fatal("capability accepted substituted URL")
	}
	changed = spec
	changed.operationID = "another-operation"
	if auth.matches(scanner, actor, changed) {
		t.Fatal("capability accepted substituted operation")
	}
	changed = spec
	changed.Headers = http.Header{"X-Override": []string{"1"}}
	if auth.matches(scanner, actor, changed) {
		t.Fatal("capability accepted caller-supplied headers")
	}
	handle.resourceID = "other-item"
	if auth.matches(scanner, actor, spec) {
		t.Fatal("capability accepted substituted resource ID")
	}
	handle.resourceID = proof.resourceID
	if !auth.consume() || auth.consume() {
		t.Fatal("cleanup capability was not one-use")
	}
}

func TestControlledUpdateCapabilityBindsMethodResourcePathBodyAndReplay(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	proof, err := observeFor(t, id, baseline, strategy, policy, body)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := controlledHandleFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	op := config.Operation{ID: "publish", ControlledResourceOperationID: id.operationID, Path: "/api/items/{id}", Method: "PATCH", Actor: id.actor, Resource: id.resource, Access: "DENIED", Classification: "BOLA", Owner: "victim", ContentType: "application/json", RequestBody: map[string]any{"status": "published"}, Verification: config.VerificationStrategy{Type: "RESOURCE_STATE", Path: "/api/items/{id}", Field: "status", ResourceIDField: strategy.ResourceIDField, MarkerField: strategy.MarkerField, BaselineCompleteField: "complete"}}
	stateBody := []byte(`{"complete":true,"item":{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}},"status":"draft"}`)
	state, err := proveControlledState(id, handle, op, "https://api.example/api/items/item-42", 200, stateBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proveControlledState(id, handle, op, "https://api.example/api/items/item-42", 200, []byte(`{"complete":true,"item":{"id":"item-42","metadata":{"kuro_test_id":"forged"}},"status":"draft"}`)); err == nil {
		t.Fatal("state proof accepted a resource without the fresh test marker")
	}
	policy.cleanupPaths = []string{"/api/items/{id}"}
	base, _ := url.Parse("https://api.example")
	scanner := &Scanner{base: base, cfg: config.Config{Target: config.Target{AllowedOrigins: policy.origins, AllowedPaths: policy.paths}, Mutations: config.MutationPolicy{Enabled: true, AllowedMethods: []string{"POST", "PATCH"}, AllowedPaths: []string{"/api/items/{id}"}, RequestBudget: 2}}}
	actor := config.Identity{ID: id.actor}
	target := "https://api.example/api/items/item-42"
	mutationBody := []byte(`{"status":"published"}`)
	auth, err := authorizeControlledMutation(scanner, id.runID, actor, op, handle, state, nil, target, mutationBody, false)
	if err != nil {
		t.Fatal(err)
	}
	spec := requestSpec{Method: "PATCH", URL: target, Body: mutationBody, ContentType: "application/json", mutationAuth: auth, operationID: op.ID, operationPath: op.Path, runID: id.runID}
	if !auth.matches(scanner, actor, spec) {
		t.Fatal("valid controlled PATCH capability rejected")
	}
	variants := []requestSpec{spec, spec, spec, spec}
	variants[0].Method = "PUT"
	variants[1].URL = "https://api.example/api/items/other"
	variants[2].Body = []byte(`{"status":"deleted"}`)
	variants[3].operationPath = "/api/other/{id}"
	for i, v := range variants {
		if auth.matches(scanner, actor, v) {
			t.Fatalf("capability accepted tampered request variant %d", i)
		}
	}
	handle.resourceID = "other"
	if auth.matches(scanner, actor, spec) {
		t.Fatal("capability accepted resource substitution")
	}
	handle.resourceID = proof.resourceID
	if !auth.consume() || auth.consume() {
		t.Fatal("controlled update capability was not single-use")
	}
	for _, method := range []string{"PUT", "PATCH"} {
		if _, _, _, err := scanner.execute(context.Background(), actor, requestSpec{Method: method, URL: target}); err == nil {
			t.Fatalf("ordinary RequestSpec %s was accepted", method)
		}
		if _, _, _, _, err := scanner.requestOnce(context.Background(), actor, requestSpec{Method: method, URL: target}); err == nil {
			t.Fatalf("transport accepted ordinary %s", method)
		}
	}
}

func TestProofArtifactsNeverSerializeIntoResults(t *testing.T) {
	id, strategy, policy := controlledFixture(t)
	baseline := baselineFor(t, id, strategy, policy, `{"complete":true,"items":[]}`)
	body := `{"id":"item-42","metadata":{"kuro_test_id":"` + id.marker + `"}}`
	proof, err := observeFor(t, id, baseline, strategy, policy, body)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ := controlledHandleFromProof(proof)
	auth, _ := cleanupAuthorizationFromHandle(id, handle)
	const credentialCanary = "CREDENTIAL_CANARY_DO_NOT_SERIALIZE"
	const requestBodyCanary = "REQUEST_BODY_CANARY_DO_NOT_SERIALIZE"
	op := controlledOperation()
	op.RequestBody.(map[string]any)["payload"] = requestBodyCanary
	policyWithMutation := proofPolicy{origins: []string{"https://api.example"}, paths: []string{"/api/items"}, mutationPaths: []string{"/api/items"}, cleanupPaths: []string{"/api/items/{id}"}}
	identity, err := newMutationTestIdentity("redaction-run", op, policyWithMutation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlledRequestBody(identity, op); err != nil {
		t.Fatal(err)
	}
	result := Result{SchemaVersion: "2", Coverage: []Coverage{{State: "TESTED"}}, Errors: []ScanError{{Code: CodeInternalError, Message: "safe generic error"}}}
	serialized, err := json.Marshal(struct {
		Result Result `json:"result"`
		Proof  any    `json:"proof,omitempty"`
		Handle any    `json:"handle,omitempty"`
		Auth   any    `json:"auth,omitempty"`
	}{Result: result, Proof: proof, Handle: handle, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{id.marker, "item-42", "DELETE", "cleanupPath", "resourceID"} {
		if strings.Contains(string(serialized), forbidden) {
			t.Fatalf("internal proof material %q serialized: %s", forbidden, serialized)
		}
	}
	if strings.Contains(string(serialized), credentialCanary) || strings.Contains(string(serialized), requestBodyCanary) {
		t.Fatal("credential or request body canary leaked into serialized result")
	}
}
