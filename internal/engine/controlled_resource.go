package engine

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/scope"
)

// These types intentionally have no exported fields or constructors. They are
// ephemeral proof artifacts, not serialized credentials or transport tokens.
type mutationTestIdentity struct {
	runID, operationID, marker, actor, resource string
	creationPath, verificationPath, cleanupPath string
	markerField, requestMarkerField, idField    string
	baselineCompleteField                       string
	bodyTemplateDigest                          string
	operationDigest                             string
	policy                                      proofPolicy
}

type baselineProof struct {
	test *mutationTestIdentity
}

type controlledResourceProof struct {
	test               *mutationTestIdentity
	resourceID         string
	verificationURL    string
	markerDigest       string
	responseDigest     string
	verificationStatus int
}

type controlledResourceHandle struct {
	proof               *controlledResourceProof
	resourceID          string
	resource            string
	operationID         string
	actor               string
	cleanupPath         string
	mu                  sync.Mutex
	authorizationIssued bool
}

type controlledCleanupAuthorization struct {
	test   *mutationTestIdentity
	handle *controlledResourceHandle
	method string
	path   string
	mu     sync.Mutex
	used   bool
}

type cleanupCandidate struct {
	method string
	url    string
	test   *mutationTestIdentity
	handle *controlledResourceHandle
}

type cleanupExecutionAuthorization struct {
	scanner                                   *Scanner
	test                                      *mutationTestIdentity
	handle                                    *controlledResourceHandle
	runID, operationID, identity, method, url string
	origin                                    string
	mu                                        sync.Mutex
	used                                      bool
}

type controlledStateProof struct {
	test   *mutationTestIdentity
	handle *controlledResourceHandle
	field  string
	value  any
	digest string
}

type controlledMutationAuthorization struct {
	scanner                                                                           *Scanner
	test                                                                              *mutationTestIdentity
	handle                                                                            *controlledResourceHandle
	state                                                                             *controlledStateProof
	relationshipProof                                                                 []RelationshipProof
	runID, operationID, identity, method, url, operationPath, bodyDigest, stateDigest string
	classification                                                                    string
	restoration                                                                       bool
	mu                                                                                sync.Mutex
	used                                                                              bool
}

// controlledDeleteAuthorization is attack authority, deliberately unrelated to
// the lifecycle-only cleanup authorization above.
type controlledDeleteAuthorization struct {
	scanner                                                                                *Scanner
	test                                                                                   *mutationTestIdentity
	handle                                                                                 *controlledResourceHandle
	preState                                                                               *controlledDeletePreProof
	relationshipProof                                                                      []RelationshipProof
	runID, operationID, identity, resource, method, path, url, expectation, classification string
	mu                                                                                     sync.Mutex
	used                                                                                   bool
}

type controlledDeletePreProof struct {
	test                                                          *mutationTestIdentity
	handle                                                        *controlledResourceHandle
	verificationURL, verificationPath, resourceID, responseDigest string
	observedAt                                                    time.Time
	state                                                         controlledDeleteResourceState
}

func authorizeControlledDelete(scanner *Scanner, runID string, actor config.Identity, operation, setup config.Operation,
	handle *controlledResourceHandle, preState *controlledDeletePreProof, relationshipProof []RelationshipProof, target string) (*controlledDeleteAuthorization, error) {
	if scanner == nil || handle == nil || handle.proof == nil || handle.proof.test == nil || handle.proof.test.runID != runID ||
		operation.ID == "" || preState == nil || preState.test != handle.proof.test || preState.handle != handle || preState.state != deleteResourcePresent ||
		preState.resourceID != handle.resourceID || preState.responseDigest == "" || time.Since(preState.observedAt) < 0 || time.Since(preState.observedAt) > 5*time.Second ||
		handle.proof.resourceID != handle.resourceID || handle.operationID != setup.ID || handle.resource != setup.Resource ||
		config.NormalizeMethod(setup.Method) != http.MethodPost || setup.Access != "ALLOWED" || !setup.Disposable ||
		operation.ControlledResourceOperationID != setup.ID || operation.Resource != setup.Resource ||
		config.NormalizeMethod(operation.Method) != http.MethodDelete || actor.ID != operation.Actor ||
		!scanner.cfg.Mutations.Enabled || !containsAllowedMethod(scanner.cfg.Mutations.AllowedMethods, http.MethodDelete) ||
		!allowedConfiguredPath(operation.Path, scanner.cfg.Mutations.AllowedPaths) ||
		(operation.Access != "DENIED" && operation.Access != "ALLOWED" && operation.Access != "UNKNOWN") ||
		!validDeleteClassification(operation.Classification) || !scope.Match(target, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(target, handle.proof.test.policy.origins, handle.proof.test.policy.paths) || !safeResourceID.MatchString(handle.resourceID) {
		return nil, errors.New("controlled DELETE attack authorization gates were not satisfied")
	}
	if _, err := controlledRequestBody(handle.proof.test, setup); err != nil {
		return nil, errors.New("DELETE setup does not match the proof-bound disposable POST operation")
	}
	if operation.Classification != "BFLA" && operation.Owner == "" && operation.Classification != "RELATIONSHIP" ||
		operation.Classification == "RELATIONSHIP" && (operation.Relationship == "" || operation.Owner == "") ||
		operation.Classification != "BFLA" && operation.Actor == operation.Owner {
		return nil, errors.New("controlled DELETE classification is incomplete")
	}
	if operation.Classification == "RELATIONSHIP" {
		if len(relationshipProof) != 1 || relationshipProof[0].Name != operation.Relationship || relationshipProof[0].Boundary != "different" || relationshipProof[0].ActorContextRef == "" || relationshipProof[0].ResourceContextRef == "" {
			return nil, errors.New("controlled DELETE relationship boundary proof is required")
		}
	} else if len(relationshipProof) != 0 {
		return nil, errors.New("unexpected relationship proof for non-relationship DELETE")
	}
	expected := scanner.endpoint(strings.Replace(operation.Path, "{id}", url.PathEscape(handle.resourceID), 1))
	if strings.Count(operation.Path, "{id}") != 1 || target != expected {
		return nil, errors.New("controlled DELETE target is not bound to the proven resource")
	}
	preURL := scanner.endpoint(strings.Replace(operation.Verification.Path, "{id}", url.PathEscape(handle.resourceID), 1))
	if preState.verificationPath != operation.Verification.Path || preState.verificationURL != preURL ||
		!allowedConfiguredPath(operation.Path, handle.proof.test.policy.mutationPaths) || !scope.Match(preURL, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) {
		return nil, errors.New("fresh controlled-resource existence proof does not match DELETE verification policy")
	}
	return &controlledDeleteAuthorization{scanner: scanner, test: handle.proof.test, handle: handle, runID: runID,
		preState: preState, relationshipProof: append([]RelationshipProof(nil), relationshipProof...),
		operationID: operation.ID, identity: actor.ID, resource: operation.Resource, method: http.MethodDelete,
		path: operation.Path, url: target, expectation: operation.Access, classification: operation.Classification}, nil
}

func (auth *controlledDeleteAuthorization) matches(scanner *Scanner, identity config.Identity, spec requestSpec) bool {
	if auth == nil || scanner == nil || auth.scanner != scanner || auth.test == nil || auth.handle == nil || auth.handle.proof == nil || auth.preState == nil ||
		auth.handle.proof.test != auth.test || auth.handle.resourceID != auth.handle.proof.resourceID || auth.test.runID != auth.runID ||
		auth.preState.test != auth.test || auth.preState.handle != auth.handle || auth.preState.resourceID != auth.handle.resourceID ||
		auth.preState.state != deleteResourcePresent || auth.preState.responseDigest == "" || time.Since(auth.preState.observedAt) < 0 || time.Since(auth.preState.observedAt) > 5*time.Second ||
		(auth.classification == "RELATIONSHIP" && (len(auth.relationshipProof) != 1 || auth.relationshipProof[0].Name == "" || auth.relationshipProof[0].Boundary != "different")) ||
		(auth.classification != "RELATIONSHIP" && len(auth.relationshipProof) != 0) ||
		spec.runID != auth.runID || spec.operationID != auth.operationID || identity.ID != auth.identity || spec.Method != http.MethodDelete ||
		spec.URL != auth.url || spec.operationPath != auth.path || spec.attackDeleteAuth != auth || len(spec.Body) != 0 || len(spec.Headers) != 0 ||
		len(spec.queryKeys) != 0 || spec.ContentType != "" || !scanner.cfg.Mutations.Enabled ||
		spec.cleanupAuth != nil || spec.mutationAuth != nil || spec.postAuth != nil ||
		!containsAllowedMethod(scanner.cfg.Mutations.AllowedMethods, http.MethodDelete) || !allowedConfiguredPath(auth.path, scanner.cfg.Mutations.AllowedPaths) || !allowedConfiguredPath(auth.path, auth.test.policy.mutationPaths) ||
		!scope.Match(spec.URL, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) || !scope.Match(spec.URL, auth.test.policy.origins, auth.test.policy.paths) {
		return false
	}
	want := scanner.endpoint(strings.Replace(auth.path, "{id}", url.PathEscape(auth.handle.resourceID), 1))
	return auth.method == http.MethodDelete && strings.Count(auth.path, "{id}") == 1 && want == auth.url && auth.resource == auth.handle.resource &&
		auth.operationID != auth.test.operationID && (auth.expectation == "DENIED" || auth.expectation == "ALLOWED" || auth.expectation == "UNKNOWN") &&
		validDeleteClassification(auth.classification)
}

func (auth *controlledDeleteAuthorization) consume() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.used {
		return false
	}
	auth.used = true
	return true
}

func (auth *controlledDeleteAuthorization) wasConsumed() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.used
}

type postExecutionAuthorization struct {
	scanner     *Scanner
	test        *mutationTestIdentity
	baseline    *baselineProof
	operationID string
	identity    string
	method      string
	url         string
	bodyDigest  string
	mu          sync.Mutex
	used        bool
}

type proofPolicy struct {
	origins       []string
	paths         []string
	mutationPaths []string
	cleanupPaths  []string
}

var safeResourceID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func newMutationTestIdentity(runID string, operation config.Operation, policy proofPolicy) (*mutationTestIdentity, error) {
	if runID == "" || operation.ID == "" || operation.Actor == "" || operation.Resource == "" ||
		operation.Method == "" || config.NormalizeMethod(operation.Method) != "POST" ||
		!validControlledAccess(operation.Access) || !validControlledClassification(operation.Classification) ||
		(operation.Classification != "BFLA" && operation.Owner == "") ||
		!validControlledField(operation.Verification.MarkerField) || operation.Verification.Path == "" ||
		!validControlledField(operation.Verification.RequestMarkerField) || !validControlledField(operation.Verification.ResourceIDField) ||
		!validControlledField(operation.Verification.BaselineCompleteField) ||
		operation.Verification.CleanupPath == "" || len(policy.origins) == 0 || len(policy.paths) == 0 || len(policy.mutationPaths) == 0 ||
		!configuredPathInScope(operation.Path, policy) || !allowedConfiguredPath(operation.Path, policy.mutationPaths) ||
		!allowedCleanupTemplate(operation.Verification.CleanupPath, policy.cleanupPaths) ||
		!configuredPathInScope(operation.Verification.Path, policy) ||
		!configuredTemplateInScope(operation.Verification.CleanupPath, policy) || !validControlledBodyTemplate(operation) {
		return nil, errors.New("controlled test identity configuration is incomplete")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("could not generate controlled test marker")
	}
	marker := "kuro-" + hex.EncodeToString(nonce[:])
	bodyTemplate, _ := json.Marshal(operation.RequestBody)
	bodyDigest := sha256.Sum256(bodyTemplate)
	encodedOperation, _ := json.Marshal(operation)
	operationHash := sha256.Sum256(encodedOperation)
	policy = cloneProofPolicy(policy)
	return &mutationTestIdentity{
		runID: runID, operationID: operation.ID, marker: marker, actor: operation.Actor,
		resource: operation.Resource, creationPath: operation.Path, verificationPath: operation.Verification.Path,
		cleanupPath: operation.Verification.CleanupPath, markerField: operation.Verification.MarkerField,
		requestMarkerField: operation.Verification.RequestMarkerField, idField: operation.Verification.ResourceIDField,
		baselineCompleteField: operation.Verification.BaselineCompleteField,
		bodyTemplateDigest:    hex.EncodeToString(bodyDigest[:]),
		operationDigest:       hex.EncodeToString(operationHash[:]),
		policy:                policy,
	}, nil
}

func validControlledBodyTemplate(operation config.Operation) bool {
	mediaType, _, err := mime.ParseMediaType(operation.ContentType)
	if err != nil || mediaType != "application/json" || strings.TrimSpace(operation.ContentType) != "application/json" {
		return false
	}
	body, err := json.Marshal(operation.RequestBody)
	if err != nil || len(body) == 0 || len(body) > 16*1024 {
		return false
	}
	root, err := decodeJSON(body)
	if err != nil {
		return false
	}
	object, ok := root.(map[string]any)
	if !ok {
		return false
	}
	value, present := jsonPath(object, operation.Verification.RequestMarkerField)
	return present && value == "${KURO_TEST_MARKER}"
}

// controlledRequestBody renders a copy of the explicit JSON template. It is
// intentionally not connected to requestSpec or any transport path.
func controlledRequestBody(test *mutationTestIdentity, operation config.Operation) ([]byte, error) {
	if test == nil || !validControlledBodyTemplate(operation) {
		return nil, errors.New("controlled request template does not match current test")
	}
	encodedOperation, err := json.Marshal(operation)
	if err != nil {
		return nil, errors.New("controlled request template is invalid")
	}
	operationHash := sha256.Sum256(encodedOperation)
	if hex.EncodeToString(operationHash[:]) != test.operationDigest {
		return nil, errors.New("controlled operation changed after test identity creation")
	}
	encoded, err := json.Marshal(operation.RequestBody)
	if err != nil || len(encoded) > 16*1024 {
		return nil, errors.New("controlled request template is invalid")
	}
	bodyDigest := sha256.Sum256(encoded)
	if hex.EncodeToString(bodyDigest[:]) != test.bodyTemplateDigest {
		return nil, errors.New("controlled request template changed after test identity creation")
	}
	root, err := decodeJSON(encoded)
	if err != nil {
		return nil, errors.New("controlled request template is invalid")
	}
	object, ok := root.(map[string]any)
	if !ok || !replaceJSONPath(object, test.requestMarkerField, test.marker) {
		return nil, errors.New("controlled request marker location is invalid")
	}
	encoded, err = json.Marshal(object)
	if err != nil || len(encoded) > 16*1024 {
		return nil, errors.New("rendered controlled request is invalid")
	}
	return encoded, nil
}

func authorizeControlledPOST(scanner *Scanner, runID string, actor config.Identity, operation config.Operation, test *mutationTestIdentity, baseline *baselineProof, target string, body []byte) (*postExecutionAuthorization, error) {
	if scanner == nil || !scanner.cfg.Mutations.Enabled || !postAllowed(scanner.cfg.Mutations.AllowedMethods) ||
		config.NormalizeMethod(operation.Method) != "POST" || test == nil || baseline == nil || baseline.test != test ||
		test.runID != runID || test.operationID != operation.ID || test.actor != actor.ID ||
		test.creationPath != operation.Path || !validControlledAccess(operation.Access) || !validControlledClassification(operation.Classification) ||
		operation.Resource == "" || (operation.Classification != "BFLA" && operation.Owner == "") ||
		!allowedConfiguredPath(operation.Path, scanner.cfg.Mutations.AllowedPaths) ||
		!scope.Match(target, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(target, test.policy.origins, test.policy.paths) || len(body) == 0 || len(body) > 16*1024 {
		return nil, errors.New("controlled POST authorization gates were not satisfied")
	}
	scanner.mu.Lock()
	globalBudgetAvailable := scanner.used < scanner.cfg.Limits.MaxRequests
	mutationBudgetAvailable := scanner.mutationUsed < scanner.cfg.Mutations.RequestBudget
	scanner.mu.Unlock()
	if !globalBudgetAvailable || !mutationBudgetAvailable {
		return nil, errors.New("controlled POST request budget is exhausted")
	}
	expected, err := controlledRequestBody(test, operation)
	if err != nil || !bytes.Equal(expected, body) {
		return nil, errors.New("controlled POST body does not match the current test")
	}
	bodyDigest := sha256.Sum256(body)
	return &postExecutionAuthorization{scanner: scanner, test: test, baseline: baseline, operationID: operation.ID,
		identity: actor.ID, method: "POST", url: target, bodyDigest: hex.EncodeToString(bodyDigest[:])}, nil
}

func validControlledAccess(access string) bool {
	return access == "ALLOWED" || access == "DENIED" || access == "UNKNOWN"
}

func validControlledClassification(classification string) bool {
	return classification == "BFLA" || classification == "BOLA" || classification == "IDOR" || classification == "RELATIONSHIP"
}

func validDeleteClassification(classification string) bool {
	return validControlledClassification(classification) || classification == "RELATIONSHIP"
}

func (auth *postExecutionAuthorization) matches(scanner *Scanner, identity config.Identity, spec requestSpec) bool {
	if auth == nil || scanner == nil || auth.scanner != scanner || auth.test == nil || auth.baseline == nil ||
		auth.baseline.test != auth.test || auth.test.operationID != auth.operationID || spec.operationID != auth.operationID ||
		spec.runID != auth.test.runID || identity.ID != auth.identity ||
		config.NormalizeMethod(spec.Method) != auth.method || spec.URL != auth.url || !scanner.cfg.Mutations.Enabled ||
		!postAllowed(scanner.cfg.Mutations.AllowedMethods) ||
		!allowedConfiguredPath(auth.test.creationPath, scanner.cfg.Mutations.AllowedPaths) ||
		!scope.Match(spec.URL, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(spec.URL, auth.test.policy.origins, auth.test.policy.paths) || spec.ContentType != "application/json" {
		return false
	}
	digest := sha256.Sum256(spec.Body)
	return hex.EncodeToString(digest[:]) == auth.bodyDigest
}

func postAllowed(methods []string) bool {
	return containsAllowedMethod(methods, "POST")
}

func (auth *postExecutionAuthorization) consume() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.used {
		return false
	}
	auth.used = true
	return true
}

func (auth *postExecutionAuthorization) wasDispatched() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.used
}

func replaceJSONPath(root map[string]any, field string, value any) bool {
	parts := strings.Split(field, ".")
	current := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			return false
		}
		current = next
	}
	last := parts[len(parts)-1]
	if current[last] != "${KURO_TEST_MARKER}" {
		return false
	}
	current[last] = value
	return true
}

func cloneProofPolicy(policy proofPolicy) proofPolicy {
	return proofPolicy{origins: append([]string(nil), policy.origins...), paths: append([]string(nil), policy.paths...),
		mutationPaths: append([]string(nil), policy.mutationPaths...), cleanupPaths: append([]string(nil), policy.cleanupPaths...)}
}

func allowedConfiguredPath(candidate string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if candidate == allowed || strings.HasSuffix(allowed, "/*") && strings.HasPrefix(candidate, strings.TrimSuffix(allowed, "*")) {
			return true
		}
	}
	return false
}

func configuredPathInScope(path string, policy proofPolicy) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#%\\{}") {
		return false
	}
	for _, origin := range policy.origins {
		if scope.Match(strings.TrimSuffix(origin, "/")+path, policy.origins, policy.paths) {
			return true
		}
	}
	return false
}

func configuredTemplateInScope(path string, policy proofPolicy) bool {
	if strings.Count(path, "{id}") != 1 || strings.ContainsAny(strings.Replace(path, "{id}", "", 1), "{}?#%\\") {
		return false
	}
	return configuredPathInScope(strings.Replace(path, "{id}", "kuroid", 1), policy)
}

func sameProofPolicy(a, b proofPolicy) bool {
	return equalStrings(a.origins, b.origins) && equalStrings(a.paths, b.paths) &&
		equalStrings(a.mutationPaths, b.mutationPaths) && equalStrings(a.cleanupPaths, b.cleanupPaths)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validVerificationURL(test *mutationTestIdentity, raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == test.verificationPath &&
		scope.Match(raw, test.policy.origins, test.policy.paths)
}

func validControlledField(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// establishMarkerBaseline proves the generated marker was absent from a
// successful, in-scope safe GET before the future creation request.
func establishMarkerBaseline(test *mutationTestIdentity, verificationURL string, status int, body []byte, strategy config.VerificationStrategy, policy proofPolicy) (*baselineProof, error) {
	if test == nil || status < 200 || status >= 300 || !sameProofPolicy(test.policy, policy) ||
		!validVerificationURL(test, verificationURL) || strategy.Type != "RESOURCE_EXISTS" ||
		strategy.Path != test.verificationPath || strategy.MarkerField != test.markerField ||
		strategy.BaselineCompleteField != test.baselineCompleteField {
		return nil, errors.New("controlled marker baseline was not established")
	}
	root, err := decodeJSON(body)
	if err != nil {
		return nil, errors.New("controlled marker baseline was not established")
	}
	rootObject, isObject := root.(map[string]any)
	if !isObject {
		return nil, errors.New("controlled marker baseline completeness was not established")
	}
	complete, present := jsonPath(rootObject, test.baselineCompleteField)
	if !present || complete != true {
		return nil, errors.New("controlled marker baseline completeness was not established")
	}
	if countMarkerMatches(root, test.markerField, test.marker) != 0 {
		return nil, errors.New("generated marker already exists in baseline")
	}
	return &baselineProof{test: test}, nil
}

// proveObservedResource binds control to a post-baseline GET observation with
// exactly one matching marker and an unambiguous safe identifier.
func proveObservedResource(test *mutationTestIdentity, baseline *baselineProof, verificationURL string, status int, body []byte, strategy config.VerificationStrategy, policy proofPolicy) (*controlledResourceProof, error) {
	if test == nil || baseline == nil || baseline.test != test || strategy.Type != "RESOURCE_EXISTS" ||
		strategy.Path != test.verificationPath || strategy.MarkerField != test.markerField ||
		strategy.ResourceIDField != test.idField || strategy.CleanupPath != test.cleanupPath ||
		strategy.BaselineCompleteField != test.baselineCompleteField ||
		!validControlledField(strategy.ResourceIDField) || !sameProofPolicy(test.policy, policy) ||
		!validVerificationURL(test, verificationURL) {
		return nil, errors.New("controlled resource proof prerequisites failed")
	}
	u, err := url.Parse(verificationURL)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != strategy.Path || status < 200 || status >= 300 {
		return nil, errors.New("controlled resource verification was not conclusive")
	}
	root, err := decodeJSON(body)
	if err != nil {
		return nil, errors.New("controlled resource verification was not conclusive")
	}
	rootObject, isObject := root.(map[string]any)
	if !isObject {
		return nil, errors.New("controlled resource verification completeness was not established")
	}
	complete, present := jsonPath(rootObject, test.baselineCompleteField)
	if !present || complete != true {
		return nil, errors.New("controlled resource verification completeness was not established")
	}
	var matches []string
	walkObjects(root, func(object map[string]any) {
		marker, markerOK := jsonPath(object, test.markerField)
		if !markerOK || marker != test.marker {
			return
		}
		id, idOK := jsonPath(object, strategy.ResourceIDField)
		idText, ok := safeIDValue(id)
		if !idOK || !ok {
			matches = append(matches, "")
			return
		}
		matches = append(matches, idText)
	})
	if len(matches) != 1 || matches[0] == "" {
		return nil, errors.New("controlled resource marker was missing, ambiguous, or lacked an identifier")
	}
	markerHash := sha256.Sum256([]byte(test.marker))
	responseHash := sha256.Sum256(body)
	return &controlledResourceProof{
		test: test, resourceID: matches[0], verificationURL: verificationURL,
		markerDigest: hex.EncodeToString(markerHash[:]), responseDigest: hex.EncodeToString(responseHash[:]),
		verificationStatus: status,
	}, nil
}

func controlledHandleFromProof(proof *controlledResourceProof) (*controlledResourceHandle, error) {
	if proof == nil || proof.test == nil || proof.resourceID == "" || !safeResourceID.MatchString(proof.resourceID) {
		return nil, errors.New("controlled resource proof is required")
	}
	return &controlledResourceHandle{proof: proof, resourceID: proof.resourceID, resource: proof.test.resource,
		operationID: proof.test.operationID, actor: proof.test.actor, cleanupPath: proof.test.cleanupPath}, nil
}

func cleanupAuthorizationFromHandle(test *mutationTestIdentity, handle *controlledResourceHandle) (*controlledCleanupAuthorization, error) {
	if test == nil || handle == nil || handle.proof == nil || handle.proof.test != test ||
		handle.operationID != test.operationID || handle.resource != test.resource ||
		handle.actor != test.actor || handle.cleanupPath != test.cleanupPath ||
		!safeResourceID.MatchString(handle.resourceID) || handle.proof.resourceID != handle.resourceID {
		return nil, errors.New("valid current-test controlled resource handle is required")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.authorizationIssued {
		return nil, errors.New("cleanup authorization was already issued for this resource")
	}
	handle.authorizationIssued = true
	return &controlledCleanupAuthorization{test: test, handle: handle, method: "DELETE", path: test.cleanupPath}, nil
}

func constructCleanupCandidate(auth *controlledCleanupAuthorization, handle *controlledResourceHandle, baseURL string) (cleanupCandidate, error) {
	if auth == nil || handle == nil || auth.test == nil || auth.test != handle.proof.test ||
		auth.handle != handle || auth.method != "DELETE" || auth.path != auth.test.cleanupPath ||
		handle.cleanupPath != auth.path || !safeResourceID.MatchString(handle.resourceID) {
		return cleanupCandidate{}, errors.New("cleanup capability does not match controlled resource")
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.used {
		return cleanupCandidate{}, errors.New("cleanup capability has already been consumed")
	}
	if !allowedCleanupTemplate(auth.path, auth.test.policy.cleanupPaths) {
		return cleanupCandidate{}, errors.New("cleanup path is not explicitly allowlisted")
	}
	if strings.ContainsAny(auth.path, "?#%\\") || strings.Contains(auth.path, "..") || strings.Count(auth.path, "{id}") != 1 {
		return cleanupCandidate{}, errors.New("cleanup path template is unsafe")
	}
	path := strings.Replace(auth.path, "{id}", url.PathEscape(handle.resourceID), 1)
	base, err := url.Parse(baseURL)
	if err != nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return cleanupCandidate{}, errors.New("invalid cleanup base URL")
	}
	target := base.ResolveReference(&url.URL{Path: path})
	if target.RawQuery != "" || target.Fragment != "" || !scope.Match(target.String(), auth.test.policy.origins, auth.test.policy.paths) {
		return cleanupCandidate{}, errors.New("cleanup target is outside configured scope")
	}
	auth.used = true
	return cleanupCandidate{method: "DELETE", url: target.String(), test: auth.test, handle: handle}, nil
}

func authorizeCleanupExecution(scanner *Scanner, runID string, actor config.Identity, operation config.Operation, candidate cleanupCandidate) (*cleanupExecutionAuthorization, error) {
	if scanner == nil || candidate.test == nil || candidate.handle == nil || candidate.handle.proof == nil ||
		candidate.handle.proof.test != candidate.test || candidate.test.runID != runID || candidate.test.operationID != operation.ID ||
		candidate.test.actor != actor.ID || candidate.test.resource != operation.Resource || candidate.method != http.MethodDelete ||
		candidate.handle.cleanupPath != candidate.test.cleanupPath || !scope.Match(candidate.url, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(candidate.url, candidate.test.policy.origins, candidate.test.policy.paths) {
		return nil, errors.New("cleanup target does not match the proven current-test resource")
	}
	target, _ := url.Parse(candidate.url)
	origin := target.Scheme + "://" + target.Host
	return &cleanupExecutionAuthorization{scanner: scanner, test: candidate.test, handle: candidate.handle,
		runID: runID, operationID: operation.ID, identity: actor.ID, method: http.MethodDelete, url: candidate.url, origin: origin}, nil
}

func (auth *cleanupExecutionAuthorization) matches(scanner *Scanner, identity config.Identity, spec requestSpec) bool {
	if auth == nil || scanner == nil || auth.scanner != scanner || auth.test == nil || auth.handle == nil ||
		auth.handle.proof == nil || auth.handle.proof.test != auth.test || auth.handle.proof.resourceID != auth.handle.resourceID ||
		auth.handle.cleanupPath != auth.test.cleanupPath || auth.handle.operationID != auth.operationID ||
		auth.handle.actor != auth.identity || auth.handle.resource != auth.test.resource || auth.test.runID != auth.runID ||
		auth.test.operationID != auth.operationID || spec.runID != auth.runID || spec.operationID != auth.operationID ||
		identity.ID != auth.identity || auth.test.actor != identity.ID || spec.Method != auth.method || spec.URL != auth.url ||
		len(spec.Body) != 0 || len(spec.Headers) != 0 || len(spec.queryKeys) != 0 || spec.ContentType != "" || spec.cleanupAuth != auth || spec.attackDeleteAuth != nil || !scanner.cfg.Mutations.Enabled ||
		!allowedCleanupTemplate(auth.test.cleanupPath, scanner.cfg.Mutations.CleanupPaths) ||
		!scope.Match(spec.URL, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(spec.URL, auth.test.policy.origins, auth.test.policy.paths) {
		return false
	}
	path := strings.Replace(auth.test.cleanupPath, "{id}", url.PathEscape(auth.handle.resourceID), 1)
	base, err := url.Parse(auth.origin)
	if err != nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return false
	}
	want := base.ResolveReference(&url.URL{Path: path}).String()
	return want == auth.url && strings.Count(auth.test.cleanupPath, "{id}") == 1 && !strings.ContainsAny(auth.test.cleanupPath, "?#%\\") &&
		!strings.Contains(auth.test.cleanupPath, "..") && safeResourceID.MatchString(auth.handle.resourceID)
}

func (auth *cleanupExecutionAuthorization) consume() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.used {
		return false
	}
	auth.used = true
	return true
}

func authorizeControlledMutation(scanner *Scanner, runID string, actor config.Identity, operation config.Operation,
	handle *controlledResourceHandle, state *controlledStateProof, relationshipProof []RelationshipProof, target string, body []byte, restoration bool) (*controlledMutationAuthorization, error) {
	method := config.NormalizeMethod(operation.Method)
	if scanner == nil || handle == nil || handle.proof == nil || state == nil || state.handle != handle || state.test != handle.proof.test ||
		state.field != operation.Verification.Field || runID != state.test.runID || operation.ControlledResourceOperationID != state.test.operationID ||
		operation.ID == "" || operation.Resource != state.test.resource || actor.ID != operation.Actor || method != "PUT" && method != "PATCH" ||
		!containsAllowedMethod(scanner.cfg.Mutations.AllowedMethods, method) || !allowedConfiguredPath(operation.Path, scanner.cfg.Mutations.AllowedPaths) ||
		!scope.Match(target, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) || !scope.Match(target, state.test.policy.origins, state.test.policy.paths) ||
		len(body) == 0 || len(body) > 16*1024 || !json.Valid(body) {
		return nil, errors.New("controlled PUT/PATCH authorization gates were not satisfied")
	}
	expectedURL := scanner.endpoint(strings.Replace(operation.Path, "{id}", url.PathEscape(handle.resourceID), 1))
	if target != expectedURL || strings.Count(operation.Path, "{id}") != 1 {
		return nil, errors.New("controlled update target is not bound to the proven resource")
	}
	if operation.Classification == "RELATIONSHIP" {
		if operation.Relationship == "" || len(relationshipProof) != 1 || relationshipProof[0].Name != operation.Relationship || relationshipProof[0].Boundary != "different" || relationshipProof[0].ActorContextRef == "" || relationshipProof[0].ResourceContextRef == "" {
			return nil, errors.New("controlled update relationship boundary proof is required")
		}
	} else if len(relationshipProof) != 0 {
		return nil, errors.New("unexpected relationship proof for controlled update")
	}

	if !restoration {
		encoded, _ := json.Marshal(operation.RequestBody)
		desired, ok := readJSONField(encoded, operation.Verification.Field)
		if !ok || jsonEqual(desired, state.value) {
			return nil, errors.New("desired state is absent or already present")
		}
		if !bytes.Equal(encoded, body) {
			return nil, errors.New("controlled mutation body changed")
		}
	} else {
		if operation.RestoreBody == nil {
			return nil, errors.New("restoration body is not configured")
		}
		encoded, _ := json.Marshal(operation.RestoreBody)
		rendered, err := replaceRestoreState(encoded, operation.Verification.Field, state.value)
		if err != nil || !bytes.Equal(rendered, body) {
			return nil, errors.New("restoration body does not match the captured pre-state")
		}
	}
	if !restoration {
		scanner.mu.Lock()
		available := scanner.mutationUsed < scanner.cfg.Mutations.RequestBudget
		scanner.mu.Unlock()
		if !available {
			return nil, errors.New("mutation request budget is exhausted")
		}
	}
	bodyHash := sha256.Sum256(body)
	return &controlledMutationAuthorization{scanner: scanner, test: state.test, handle: handle, state: state, runID: runID, operationID: operation.ID,
		relationshipProof: append([]RelationshipProof(nil), relationshipProof...), classification: operation.Classification,
		identity: actor.ID, method: method, url: target, operationPath: operation.Path, bodyDigest: hex.EncodeToString(bodyHash[:]), stateDigest: state.digest, restoration: restoration}, nil
}

func (auth *controlledMutationAuthorization) matches(scanner *Scanner, identity config.Identity, spec requestSpec) bool {
	if auth == nil || scanner == nil || auth.scanner != scanner || auth.test == nil || auth.handle == nil || auth.state == nil || auth.handle.proof == nil ||
		auth.state.test != auth.test || auth.state.handle != auth.handle || auth.state.field == "" ||
		auth.handle.proof.test != auth.test || auth.handle.resourceID != auth.handle.proof.resourceID || auth.runID != auth.test.runID ||
		spec.runID != auth.runID || spec.operationID != auth.operationID || identity.ID != auth.identity || spec.Method != auth.method || spec.URL != auth.url ||
		len(spec.Body) == 0 || len(spec.Body) > 16*1024 || spec.ContentType != "application/json" || spec.mutationAuth != auth ||
		len(spec.Headers) != 0 || len(spec.queryKeys) != 0 || !scanner.cfg.Mutations.Enabled || !containsAllowedMethod(scanner.cfg.Mutations.AllowedMethods, auth.method) ||
		spec.operationPath != auth.operationPath || !allowedConfiguredPath(spec.operationPath, scanner.cfg.Mutations.AllowedPaths) || !scope.Match(spec.URL, scanner.cfg.Target.AllowedOrigins, scanner.cfg.Target.AllowedPaths) ||
		!scope.Match(spec.URL, auth.test.policy.origins, auth.test.policy.paths) {
		return false
	}
	if auth.classification == "RELATIONSHIP" && (len(auth.relationshipProof) != 1 || auth.relationshipProof[0].Name == "" || auth.relationshipProof[0].Boundary != "different" || auth.relationshipProof[0].ActorContextRef == "" || auth.relationshipProof[0].ResourceContextRef == "") ||
		auth.classification != "RELATIONSHIP" && len(auth.relationshipProof) != 0 {
		return false
	}
	path := strings.Replace(spec.operationPath, "{id}", url.PathEscape(auth.handle.resourceID), 1)
	want := scanner.endpoint(path)
	if want != auth.url || strings.Count(spec.operationPath, "{id}") != 1 {
		return false
	}
	digest := sha256.Sum256(spec.Body)
	stateBytes, stateErr := json.Marshal(auth.state.value)
	if stateErr != nil {
		return false
	}
	stateDigest := sha256.Sum256(append([]byte(auth.state.field+"\x00"), stateBytes...))
	return hex.EncodeToString(digest[:]) == auth.bodyDigest && hex.EncodeToString(stateDigest[:]) == auth.stateDigest
}

func (auth *controlledMutationAuthorization) consume() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if auth.used {
		return false
	}
	auth.used = true
	return true
}

func (auth *controlledMutationAuthorization) wasDispatched() bool {
	if auth == nil {
		return false
	}
	auth.mu.Lock()
	defer auth.mu.Unlock()
	return auth.used
}

func containsAllowedMethod(methods []string, method string) bool {
	for _, v := range methods {
		if config.NormalizeMethod(v) == method {
			return true
		}
	}
	return false
}

func readJSONField(body []byte, field string) (any, bool) {
	root, err := decodeJSON(body)
	if err != nil {
		return nil, false
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, false
	}
	return jsonPath(object, field)
}

func jsonEqual(a, b any) bool {
	if left, ok := a.(json.Number); ok {
		if right, ok := b.(json.Number); ok {
			leftRat, leftOK := new(big.Rat).SetString(left.String())
			rightRat, rightOK := new(big.Rat).SetString(right.String())
			if leftOK && rightOK {
				return leftRat.Cmp(rightRat) == 0
			}
		}
	}
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(x, y)
}

func replaceRestoreState(body []byte, field string, value any) ([]byte, error) {
	root, err := decodeJSON(body)
	if err != nil {
		return nil, err
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("restore body is invalid")
	}
	if !replaceJSONValue(object, field, "${KURO_PREVIOUS_STATE}", value) {
		return nil, errors.New("restore state placeholder is invalid")
	}
	return json.Marshal(object)
}

func replaceJSONValue(root map[string]any, field string, expected, value any) bool {
	parts := strings.Split(field, ".")
	current := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			return false
		}
		current = next
	}
	last := parts[len(parts)-1]
	if current[last] != expected {
		return false
	}
	current[last] = value
	return true
}

func proveControlledState(test *mutationTestIdentity, handle *controlledResourceHandle, operation config.Operation, rawURL string, status int, body []byte) (*controlledStateProof, error) {
	if test == nil || handle == nil || handle.proof == nil || handle.proof.test != test || handle.resourceID != handle.proof.resourceID ||
		operation.ControlledResourceOperationID != test.operationID || operation.Verification.Type != "RESOURCE_STATE" ||
		status < 200 || status >= 300 || strings.Count(operation.Verification.Path, "{id}") != 1 ||
		!safeResourceID.MatchString(handle.resourceID) {
		return nil, errors.New("controlled resource state is not proven")
	}
	u, urlErr := url.Parse(rawURL)
	if urlErr != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != strings.Replace(operation.Verification.Path, "{id}", url.PathEscape(handle.resourceID), 1) || !scope.Match(rawURL, test.policy.origins, test.policy.paths) {
		return nil, errors.New("controlled state URL is outside test scope")
	}
	root, err := decodeJSON(body)
	if err != nil {
		return nil, err
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("state response is incomplete")
	}
	complete, ok := jsonPath(object, operation.Verification.BaselineCompleteField)
	if !ok || complete != true {
		return nil, errors.New("controlled state response is incomplete")
	}
	if operation.Verification.ResourceIDField != test.idField || operation.Verification.MarkerField != test.markerField {
		return nil, errors.New("controlled state proof fields do not match the setup marker and ID")
	}
	ids, markers, matching := 0, 0, 0
	walkObjects(root, func(item map[string]any) {
		id, hasID := jsonPath(item, test.idField)
		marker, hasMarker := jsonPath(item, test.markerField)
		idMatches := hasID && id == handle.resourceID
		markerMatches := hasMarker && marker == test.marker
		if idMatches {
			ids++
		}
		if markerMatches {
			markers++
		}
		if idMatches && markerMatches {
			matching++
		}
	})
	if ids != 1 || markers != 1 || matching != 1 {
		return nil, errors.New("controlled state marker and resource ID are missing, ambiguous, or mismatched")
	}
	value, ok := jsonPath(object, operation.Verification.Field)
	if !ok || !safeStateValue(value) {
		return nil, errors.New("configured state field is missing or unsupported")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte(operation.Verification.Field+"\x00"), encoded...))
	return &controlledStateProof{test: test, handle: handle, field: operation.Verification.Field, value: value, digest: hex.EncodeToString(digest[:])}, nil
}

func safeStateValue(value any) bool {
	switch value.(type) {
	case string, bool, json.Number:
		return true
	default:
		return false
	}
}

func controlledUpdateBody(test *mutationTestIdentity, operation config.Operation) ([]byte, error) {
	if test == nil || operation.ControlledResourceOperationID != test.operationID || config.NormalizeMethod(operation.Method) != "PUT" && config.NormalizeMethod(operation.Method) != "PATCH" ||
		operation.ContentType != "application/json" {
		return nil, errors.New("controlled update template is invalid")
	}
	body, err := json.Marshal(operation.RequestBody)
	if err != nil || len(body) == 0 || len(body) > 16*1024 || !json.Valid(body) {
		return nil, errors.New("controlled update body is invalid")
	}
	value, ok := readJSONField(body, operation.Verification.Field)
	if !ok || !safeStateValue(value) {
		return nil, errors.New("controlled update desired state is missing")
	}
	return body, nil
}

func allowedCleanupTemplate(candidate string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if candidate == allowed || strings.HasSuffix(allowed, "/*") && strings.HasPrefix(candidate, strings.TrimSuffix(allowed, "*")) {
			return true
		}
	}
	return false
}

func decodeJSON(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if len(body) == 0 {
		return nil, fmt.Errorf("invalid JSON")
	}
	root, err := decodeJSONValue(decoder)
	if err != nil {
		return nil, fmt.Errorf("invalid or ambiguous JSON")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("multiple JSON values")
	}
	return root, nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return nil, keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate object key")
				}
				child, childErr := decodeJSONValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				object[key] = child
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("invalid object")
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				child, childErr := decodeJSONValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				array = append(array, child)
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("invalid array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter")
		}
	default:
		return token, nil
	}
}

func countMarkerMatches(root any, field, marker string) int {
	count := 0
	walkObjects(root, func(object map[string]any) {
		if value, ok := jsonPath(object, field); ok && value == marker {
			count++
		}
	})
	return count
}

func walkObjects(value any, visit func(map[string]any)) {
	switch value := value.(type) {
	case map[string]any:
		visit(value)
		for _, child := range value {
			walkObjects(child, visit)
		}
	case []any:
		for _, child := range value {
			walkObjects(child, visit)
		}
	}
}

func jsonPath(root map[string]any, field string) (any, bool) {
	var current any = root
	for _, part := range strings.Split(field, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func safeIDValue(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, safeResourceID.MatchString(value)
	case json.Number:
		return value.String(), safeResourceID.MatchString(value.String())
	default:
		return "", false
	}
}
