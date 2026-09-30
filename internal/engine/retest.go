package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/openapi"
	"github.com/kurokagi/kurokagi/internal/scope"
)

// RetestInput accepts a semantic fingerprint and optional non-secret semantic
// selectors. Historical credentials, scope, request bodies, and capabilities
// are never ingested; ResourceRef is inert legacy-hash material only. The
// selected condition is resolved against the current configuration.
type RetestInput struct {
	SchemaVersion  string `json:"schema_version"`
	Fingerprint    string `json:"finding_fingerprint"`
	Classification string `json:"classification,omitempty"`
	Resource       string `json:"resource,omitempty"`
	Victim         string `json:"victim_identity,omitempty"`
	Actor          string `json:"accessing_identity,omitempty"`
	Relationship   string `json:"relationship,omitempty"`
	Method         string `json:"method,omitempty"`
	Path           string `json:"path,omitempty"`
	// ResourceRef is accepted only as inert legacy fingerprint material. It is
	// never used to construct a request; current discovery supplies the ID.
	ResourceRef string `json:"resource_ref,omitempty"`
}

// RetestResult records one targeted retest outcome and its current evidence summary.
type RetestResult struct {
	SchemaVersion      string    `json:"schema_version"`
	SourceFingerprint  string    `json:"source_fingerprint"`
	CurrentFingerprint string    `json:"current_fingerprint,omitempty"`
	Outcome            string    `json:"outcome"`
	Classification     string    `json:"classification,omitempty"`
	Operation          string    `json:"operation,omitempty"`
	Method             string    `json:"method,omitempty"`
	Expectation        string    `json:"current_expectation,omitempty"`
	Verification       string    `json:"verification_summary,omitempty"`
	ReasonCode         string    `json:"reason_code"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
	Completion         string    `json:"completion_state"`
	Cleanup            string    `json:"cleanup_state,omitempty"`
	CleanupRequired    bool      `json:"cleanup_required,omitempty"`
	CleanupAttempted   bool      `json:"cleanup_attempted,omitempty"`
}

// Retest executes one current semantic condition, with no historical evidence
// or runtime identifier used as authority.
func (s *Scanner) Retest(ctx context.Context, input RetestInput) RetestResult {
	started := time.Now().UTC()
	r := RetestResult{SchemaVersion: "1", SourceFingerprint: input.Fingerprint, Outcome: "NOT_TESTABLE", ReasonCode: "INVALID_INPUT", StartedAt: started, Completion: "complete"}
	finish := func() RetestResult { r.FinishedAt = time.Now().UTC(); return r }
	if ctx.Err() != nil {
		setRetestError(&r, ctx.Err())
		return finish()
	}
	if input.SchemaVersion != "1" {
		return finish()
	}
	if len(input.Fingerprint) != 64 {
		return finish()
	}
	if _, err := hex.DecodeString(input.Fingerprint); err != nil {
		return finish()
	}
	var selected *config.Operation
	for i := range s.cfg.Operations {
		op := &s.cfg.Operations[i]
		method := config.NormalizeMethod(op.Method)
		resource := op.Resource
		if resource == "" {
			resource = "operation:" + op.ID
		}
		fingerprint := functionFinding(op.Classification, op.ID, op.Actor, op.Owner, resource, op.Relationship, method, op.Path, "").Fingerprint
		if fingerprint == input.Fingerprint {
			selected = op
			break
		}
	}
	if selected != nil {
		method := config.NormalizeMethod(selected.Method)
		if method == http.MethodPost {
			return s.retestPost(ctx, input, *selected, &r, finish)
		}
		if method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			return s.retestControlledMutation(ctx, input, *selected, &r, finish)
		}
		return s.retestOperation(ctx, input, *selected, &r, finish)
	}
	return s.retestResource(ctx, input, &r, finish)
}

func (s *Scanner) retestControlledMutation(ctx context.Context, input RetestInput, op config.Operation, r *RetestResult, finish func() RetestResult) RetestResult {
	method := config.NormalizeMethod(op.Method)
	r.CurrentFingerprint, r.Classification, r.Operation, r.Method, r.Expectation = input.Fingerprint, op.Classification, op.ID, method, op.Access
	resource := op.Resource
	if resource == "" {
		resource = "operation:" + op.ID
	}
	if input.Classification != "" && input.Classification != op.Classification || input.Resource != "" && input.Resource != resource || input.Actor != "" && input.Actor != op.Actor || input.Victim != "" && input.Victim != op.Owner || input.Relationship != "" && input.Relationship != op.Relationship || input.Method != "" && config.NormalizeMethod(input.Method) != method || input.Path != "" && input.Path != op.Path {
		r.ReasonCode = "SEMANTIC_MISMATCH"
		return finish()
	}
	if !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, method) || !allowedConfiguredPath(op.Path, s.cfg.Mutations.AllowedPaths) {
		r.ReasonCode = "MUTATION_DISABLED"
		return finish()
	}
	setupIndex := -1
	for i := range s.cfg.Operations {
		if s.cfg.Operations[i].ID == op.ControlledResourceOperationID && config.NormalizeMethod(s.cfg.Operations[i].Method) == http.MethodPost {
			setupIndex = i
			break
		}
	}
	if setupIndex < 0 {
		r.ReasonCode = "CONTROLLED_SETUP_MISSING"
		return finish()
	}
	setup := s.cfg.Operations[setupIndex]
	if setup.Access != "ALLOWED" || setup.Resource != op.Resource || !postAllowed(s.cfg.Mutations.AllowedMethods) || !allowedConfiguredPath(setup.Path, s.cfg.Mutations.AllowedPaths) {
		r.ReasonCode = "CONTROLLED_SETUP_UNAVAILABLE"
		return finish()
	}
	if method == http.MethodDelete && !setup.Disposable {
		r.ReasonCode = "DISPOSABLE_RESOURCE_REQUIRED"
		return finish()
	}
	if op.Access != "DENIED" && op.Access != "ALLOWED" && op.Access != "UNKNOWN" {
		r.ReasonCode = "EXPECTATION_UNSUPPORTED"
		return finish()
	}
	if op.Access != "DENIED" {
		r.ReasonCode = "EXPECTATION_NOT_DENIED"
		return finish()
	}
	setupActor, setupOK := identityByID(s.cfg.Identities, setup.Actor)
	actor, actorOK := identityByID(s.cfg.Identities, op.Actor)
	if !setupOK || !actorOK {
		r.ReasonCode = "ACTOR_MISSING"
		return finish()
	}
	if !scope.Match(s.endpoint(setup.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(setup.Verification.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(setup.Verification.CleanupPath), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(op.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(op.Verification.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		r.ReasonCode = "OUT_OF_SCOPE"
		return finish()
	}
	doc, err := openapi.Load(s.cfg.OpenAPI.Path)
	if err != nil || !doc.HasOperation(setup.Path, http.MethodPost) || !doc.HasGet(setup.Verification.Path) || !doc.HasOperation(op.Path, method) || !doc.HasGet(op.Verification.Path) {
		r.ReasonCode = "VERIFICATION_UNAVAILABLE"
		return finish()
	}
	if method == http.MethodDelete {
		if !controlledDeleteLifecycleBudgetAvailable(s) {
			r.ReasonCode = "BUDGET_EXHAUSTED"
			return finish()
		}
	} else if !controlledUpdateLifecycleBudgetAvailable(s, op) {
		r.ReasonCode = "BUDGET_EXHAUSTED"
		return finish()
	}
	started := r.StartedAt.Format(time.RFC3339Nano)
	runHash := sha256.Sum256([]byte(input.Fingerprint + "\x00" + started))
	runID := hex.EncodeToString(runHash[:12])
	setupOutcome := s.executeControlledPost(ctx, runID, doc, setupActor, setup, setup.Resource, http.MethodPost+" "+setup.Path, true)
	if setupOutcome.handle == nil || setupOutcome.proof == nil || setupOutcome.test == nil {
		r.ReasonCode = "CONTROLLED_SETUP_UNVERIFIED"
		if ctx.Err() != nil {
			setRetestError(r, ctx.Err())
		}
		return finish()
	}
	var outcome controlledPostOutcome
	if method == http.MethodDelete {
		outcome = s.executeControlledDelete(ctx, runID, doc, actor, op, setup, setupOutcome, resource, method+" "+op.Path)
	} else {
		outcome = s.executeControlledUpdate(ctx, runID, doc, actor, op, setup, setupOutcome, resource, method+" "+op.Path)
	}
	r.Cleanup, r.CleanupRequired, r.CleanupAttempted = outcome.coverage.Cleanup, outcome.coverage.CleanupRequired, outcome.coverage.CleanupAttempted
	if outcome.coverage.Cleanup != "CLEANUP_SUCCEEDED" && outcome.coverage.Cleanup != "CLEANUP_NOT_REQUIRED" || outcome.coverage.Restoration != "" && outcome.coverage.Restoration != "RESTORATION_SUCCEEDED" && outcome.coverage.Restoration != "RESTORATION_NOT_REQUIRED" {
		r.Completion = "partial"
	}
	if outcome.finding != nil && op.Access == "DENIED" {
		r.Outcome, r.ReasonCode = "STILL_PRESENT", "REPRODUCED"
		r.Verification = "fresh controlled resource proof and verified forbidden state transition"
		return finish()
	}
	if !outcome.executed {
		r.Outcome, r.ReasonCode = "NOT_TESTABLE", "MUTATION_NOT_DISPATCHED"
		if ctx.Err() != nil {
			setRetestError(r, ctx.Err())
		}
		return finish()
	}
	if method == http.MethodDelete {
		if outcome.coverage.DeleteState == string(deleteResourcePresent) && outcome.mutationStatus == http.StatusForbidden && op.Access == "DENIED" {
			r.Outcome, r.ReasonCode = "FIXED", "CURRENTLY_DENIED"
			r.Verification = "explicit current denial and fresh proof that the controlled resource remains"
			return finish()
		}
		if outcome.coverage.DeleteState == string(deleteResourceAbsent) {
			r.Verification = "fresh controlled resource was verified absent after the attack DELETE"
		} else {
			r.Verification = "post-DELETE controlled resource state could not be established"
		}
	} else {
		if outcome.verifiedUnchanged && outcome.mutationStatus == http.StatusForbidden && op.Access == "DENIED" {
			r.Outcome, r.ReasonCode = "FIXED", "CURRENTLY_DENIED"
			r.Verification = "explicit current denial and complete verification that controlled state remained unchanged"
			return finish()
		}
		if outcome.finding == nil {
			r.Verification = "complete controlled state verification did not prove the expected forbidden transition"
		}
	}
	r.Outcome, r.ReasonCode, r.Completion = "INCONCLUSIVE", "STATE_AMBIGUOUS", "partial"
	if ctx.Err() != nil {
		setRetestError(r, ctx.Err())
	}
	return finish()
}

func (s *Scanner) retestPost(ctx context.Context, input RetestInput, op config.Operation, r *RetestResult, finish func() RetestResult) RetestResult {
	r.CurrentFingerprint = input.Fingerprint
	r.Classification = op.Classification
	r.Operation = op.ID
	r.Method = http.MethodPost
	r.Expectation = op.Access
	resource := op.Resource
	if resource == "" {
		resource = "operation:" + op.ID
	}
	if input.Classification != "" && input.Classification != op.Classification || input.Resource != "" && input.Resource != resource || input.Actor != "" && input.Actor != op.Actor || input.Victim != "" && input.Victim != op.Owner || input.Relationship != "" && input.Relationship != op.Relationship || input.Method != "" && config.NormalizeMethod(input.Method) != http.MethodPost || input.Path != "" && input.Path != op.Path {
		r.ReasonCode = "SEMANTIC_MISMATCH"
		return finish()
	}
	if !s.cfg.Mutations.Enabled || !postAllowed(s.cfg.Mutations.AllowedMethods) || !allowedConfiguredPath(op.Path, s.cfg.Mutations.AllowedPaths) {
		r.ReasonCode = "MUTATION_DISABLED"
		return finish()
	}
	if !scope.Match(s.endpoint(op.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(op.Verification.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(s.endpoint(op.Verification.CleanupPath), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		r.ReasonCode = "OUT_OF_SCOPE"
		return finish()
	}
	actor, ok := identityByID(s.cfg.Identities, op.Actor)
	if !ok {
		r.ReasonCode = "ACTOR_MISSING"
		return finish()
	}
	if op.Access != "DENIED" && op.Access != "ALLOWED" && op.Access != "UNKNOWN" {
		r.ReasonCode = "EXPECTATION_UNSUPPORTED"
		return finish()
	}
	doc, err := openapi.Load(s.cfg.OpenAPI.Path)
	if err != nil || !doc.HasOperation(op.Path, http.MethodPost) || !doc.HasGet(op.Verification.Path) {
		r.ReasonCode = "VERIFICATION_UNAVAILABLE"
		return finish()
	}
	if !controlledPostRetestBudgetAvailable(s) {
		r.ReasonCode = "BUDGET_EXHAUSTED"
		return finish()
	}
	started := r.StartedAt.Format(time.RFC3339Nano)
	runHash := sha256.Sum256([]byte(input.Fingerprint + "\x00" + started))
	runID := hex.EncodeToString(runHash[:12])
	out := s.executeControlledPost(ctx, runID, doc, actor, op, resource, http.MethodPost+" "+op.Path, true)
	if out.proof != nil && out.handle != nil {
		s.cleanupRetestPost(runID, actor, op, &out)
	}
	r.Cleanup = out.coverage.Cleanup
	r.CleanupRequired = out.coverage.CleanupRequired
	r.CleanupAttempted = out.coverage.CleanupAttempted
	if out.coverage.Cleanup != "" && out.coverage.Cleanup != "CLEANUP_SUCCEEDED" && out.coverage.Cleanup != "CLEANUP_NOT_REQUIRED" {
		r.Completion = "partial"
	}
	if out.proof != nil {
		r.Verification = "fresh marker-bound controlled resource creation verified"
		if op.Access == "DENIED" {
			r.Outcome = "STILL_PRESENT"
			r.ReasonCode = "REPRODUCED"
		} else {
			r.Outcome = "NOT_TESTABLE"
			r.ReasonCode = "EXPECTATION_NOT_DENIED"
		}
		if out.coverage.Cleanup != "CLEANUP_SUCCEEDED" {
			r.Completion = "partial"
		}
		return finish()
	}
	if out.verifiedAbsent {
		r.Verification = "complete current state verification confirmed the generated marker is absent"
		if op.Access == "DENIED" && out.postStatus == http.StatusForbidden {
			r.Outcome = "FIXED"
			r.ReasonCode = "CURRENTLY_DENIED"
			return finish()
		}
		if op.Access != "DENIED" {
			r.Outcome = "NOT_TESTABLE"
			r.ReasonCode = "EXPECTATION_NOT_DENIED"
			return finish()
		}
	}
	if !out.executed && (out.coverage.State == "UNSUPPORTED" || out.coverage.State == "SKIPPED") {
		if ctx.Err() != nil {
			setRetestError(r, ctx.Err())
		} else {
			r.Outcome = "NOT_TESTABLE"
			r.ReasonCode = "POST_NOT_AUTHORIZED"
		}
		return finish()
	}
	r.Outcome = "INCONCLUSIVE"
	r.Completion = "partial"
	if ctx.Err() != nil {
		setRetestError(r, ctx.Err())
		return finish()
	}
	if !out.executed {
		r.Outcome = "NOT_TESTABLE"
		r.Completion = "complete"
		r.ReasonCode = "BASELINE_INCOMPLETE"
	} else if out.verifiedAbsent {
		r.ReasonCode = "DENIAL_NOT_ESTABLISHED"
	} else {
		r.ReasonCode = "STATE_AMBIGUOUS"
	}
	return finish()
}

func controlledPostRetestBudgetAvailable(s *Scanner) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Baseline, one POST, post-state verification, cleanup DELETE, cleanup GET.
	return s.cfg.Limits.MaxRequests-s.used >= 5 && s.cfg.Mutations.RequestBudget-s.mutationUsed >= 1 && s.cfg.Mutations.CleanupRequestBudget-s.cleanupUsed >= 2
}

func (s *Scanner) cleanupRetestPost(runID string, actor config.Identity, op config.Operation, out *controlledPostOutcome) {
	resourceAuth, err := cleanupAuthorizationFromHandle(out.test, out.handle)
	var candidate cleanupCandidate
	var authorization *cleanupExecutionAuthorization
	if err == nil {
		candidate, err = constructCleanupCandidate(resourceAuth, out.handle, s.base.Scheme+"://"+s.base.Host)
	}
	if err == nil {
		authorization, err = authorizeCleanupExecution(s, runID, actor, op, candidate)
	}
	if err != nil {
		out.coverage.Cleanup = "NOT_POSSIBLE"
		out.coverage.CleanupRequired = true
		out.warnings = append(out.warnings, ScanError{Code: CodeScopeRejected, Message: "controlled state was proven but cleanup authorization could not be safely prepared"})
		return
	}
	verificationURL := s.endpoint(op.Verification.Path)
	out.coverage.Cleanup = s.executeControlledCleanup(runID, actor, op, candidate, authorization, out.proof, verificationURL, out)
}

func (s *Scanner) retestOperation(ctx context.Context, input RetestInput, op config.Operation, r *RetestResult, finish func() RetestResult) RetestResult {
	r.CurrentFingerprint = input.Fingerprint
	r.Classification, r.Operation = op.Classification, op.ID
	r.Method, r.Expectation = config.NormalizeMethod(op.Method), op.Access
	operationResource := op.Resource
	if operationResource == "" {
		operationResource = "operation:" + op.ID
	}
	if input.Classification != "" && input.Classification != op.Classification || input.Resource != "" && input.Resource != operationResource || input.Actor != "" && input.Actor != op.Actor || input.Victim != "" && input.Victim != op.Owner || input.Relationship != "" && input.Relationship != op.Relationship || input.Method != "" && config.NormalizeMethod(input.Method) != r.Method || input.Path != "" && input.Path != op.Path {
		r.ReasonCode = "SEMANTIC_MISMATCH"
		return finish()
	}
	if r.Method == http.MethodPost {
		return s.retestPost(ctx, input, op, r, finish)
	}
	if r.Method != http.MethodGet || op.Verification.Type != "RESPONSE_FIELD" || op.Access != "DENIED" || strings.ContainsAny(op.Path, "{}") {
		r.ReasonCode = "LIFECYCLE_UNSUPPORTED"
		return finish()
	}
	actor, ok := identityByID(s.cfg.Identities, op.Actor)
	if !ok {
		r.ReasonCode = "ACTOR_MISSING"
		return finish()
	}
	doc, err := openapi.Load(s.cfg.OpenAPI.Path)
	if err != nil || !doc.HasOperation(op.Path, http.MethodGet) {
		r.ReasonCode = "VERIFICATION_UNAVAILABLE"
		return finish()
	}
	if !scope.Match(s.endpoint(op.Path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		r.ReasonCode = "OUT_OF_SCOPE"
		return finish()
	}
	status, body, _, err := s.execute(ctx, actor, requestSpec{Method: http.MethodGet, URL: s.endpoint(op.Path)})
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		setRetestError(r, err)
		return finish()
	}
	if status >= 200 && status < 300 && configuredSuccess(body, op.Verification.Field) {
		r.Outcome = "STILL_PRESENT"
		r.ReasonCode = "REPRODUCED"
		r.Verification = "current configured success evidence verified"
		return finish()
	}
	if status == http.StatusForbidden {
		r.Outcome = "FIXED"
		r.ReasonCode = "CURRENTLY_DENIED"
		r.Verification = "current explicit forbidden response verified"
		return finish()
	}
	r.Outcome, r.ReasonCode, r.Completion = "INCONCLUSIVE", "VERIFICATION_INCOMPLETE", "partial"
	return finish()
}

type retestResourceTarget struct {
	resource     config.Resource
	actor, owner string
	relationship string
}

func (s *Scanner) retestResource(ctx context.Context, input RetestInput, r *RetestResult, finish func() RetestResult) RetestResult {
	if input.Method != "" && config.NormalizeMethod(input.Method) != http.MethodGet {
		r.ReasonCode = "METHOD_UNSUPPORTED"
		return finish()
	}
	if input.Path != "" && input.Path != strings.TrimSpace(input.Path) {
		r.ReasonCode = "SEMANTIC_MISMATCH"
		return finish()
	}
	var target *retestResourceTarget
	for _, resource := range s.cfg.Resources {
		if input.Resource != "" && input.Resource != resource.Name || input.Classification != "" && input.Classification != resource.Classification {
			continue
		}
		if input.Path != "" && input.Path != resource.Detail {
			continue
		}
		for _, owner := range s.cfg.Identities {
			for _, actor := range s.cfg.Identities {
				if owner.ID == actor.ID || input.Actor != "" && input.Actor != actor.ID || input.Victim != "" && input.Victim != owner.ID {
					continue
				}
				relations := []string{""}
				if resource.Classification == "RELATIONSHIP" {
					relations = nil
					for _, relation := range resource.Relationships {
						relations = append(relations, relation.Name)
					}
				}
				for _, relation := range relations {
					if input.Relationship != "" && input.Relationship != relation {
						continue
					}
					expected := expectation(s.cfg, actor.ID, owner.ID, resource.Name, relation, http.MethodGet)
					semantic := finding(resource.Classification, resource.Name, "", owner.ID, actor.ID, relation, resource.Detail, "").Fingerprint
					legacy := input.ResourceRef != "" && finding(resource.Classification, resource.Name, input.ResourceRef, owner.ID, actor.ID, relation, resource.Detail, "").Fingerprint == input.Fingerprint
					if expected != "DENIED" {
						continue
					}
					if semantic == input.Fingerprint || legacy {
						candidate := &retestResourceTarget{resource: resource, actor: actor.ID, owner: owner.ID, relationship: relation}
						if target != nil {
							r.ReasonCode = "SEMANTIC_AMBIGUOUS"
							return finish()
						}
						target = candidate
					}
				}
			}
		}
	}
	// Semantic selectors can identify an intentionally changed expectation even
	// when the current DENIED rule no longer matches the old fingerprint.
	if target == nil && input.Resource != "" && input.Actor != "" && input.Victim != "" {
		for _, res := range s.cfg.Resources {
			if res.Name != input.Resource || input.Classification != "" && res.Classification != input.Classification {
				continue
			}
			if _, ok := identityByID(s.cfg.Identities, input.Actor); !ok {
				r.ReasonCode = "ACTOR_MISSING"
				return finish()
			}
			if _, ok := identityByID(s.cfg.Identities, input.Victim); !ok {
				r.ReasonCode = "ACTOR_MISSING"
				return finish()
			}
			if input.Relationship != "" && !relationshipConfigured(res, input.Relationship) {
				r.ReasonCode = "RELATIONSHIP_MISSING"
				return finish()
			}
			r.ReasonCode = "EXPECTATION_NOT_DENIED"
			return finish()
		}
	}
	if target == nil {
		r.ReasonCode = "SEMANTIC_CONDITION_MISSING"
		return finish()
	}
	r.CurrentFingerprint = finding(target.resource.Classification, target.resource.Name, "", target.owner, target.actor, target.relationship, target.resource.Detail, "").Fingerprint
	r.Classification = target.resource.Classification
	r.Operation = target.resource.Name
	r.Method = http.MethodGet
	r.Expectation = "DENIED"
	if !identityExists(s.cfg.Identities, target.actor) {
		r.ReasonCode = "ACTOR_MISSING"
		return finish()
	}
	doc, err := openapi.Load(s.cfg.OpenAPI.Path)
	if err != nil || !doc.HasGet(target.resource.Collection) || !doc.HasGet(target.resource.Detail) {
		r.ReasonCode = "VERIFICATION_UNAVAILABLE"
		return finish()
	}
	collectionURL := s.endpoint(target.resource.Collection)
	sampleValues := map[string]string{}
	for _, identifier := range resourceIdentifiers(target.resource) {
		sampleValues[identifier.Parameter] = "scope-check"
	}
	sampleDetail, pathErr := detailPath(target.resource.Detail, sampleValues)
	if pathErr != nil {
		r.ReasonCode = "VERIFICATION_UNAVAILABLE"
		return finish()
	}
	detailTemplateURL := s.endpoint(sampleDetail)
	if !scope.Match(collectionURL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(detailTemplateURL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		r.ReasonCode = "OUT_OF_SCOPE"
		return finish()
	}
	actor, _ := identityByID(s.cfg.Identities, target.actor)
	owners, candidates, verifyValues, verifyCounts, complete, err := s.discoverRetestOwnership(ctx, target.resource, target.owner)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		setRetestError(r, err)
		return finish()
	}
	if !complete {
		r.Outcome = "INCONCLUSIVE"
		r.Completion = "partial"
		r.ReasonCode = "DISCOVERY_INCOMPLETE"
		return finish()
	}
	var object *candidate
	for i := range candidates[target.owner] {
		item := &candidates[target.owner][i]
		if len(owners[item.ID]) == 1 && owners[item.ID][target.owner] {
			if object == nil || item.ID < object.ID {
				object = item
			}
		}
	}
	if object == nil {
		if len(candidates[target.owner]) > 0 {
			r.Outcome, r.Completion, r.ReasonCode = "INCONCLUSIVE", "partial", "OWNERSHIP_AMBIGUOUS"
			return finish()
		}
		r.ReasonCode = "CURRENT_RESOURCE_UNAVAILABLE"
		return finish()
	}
	if verifyValues[target.owner][object.ID] == "" || countDistinct(verifyCounts) < 2 {
		r.Outcome = "INCONCLUSIVE"
		r.Completion = "partial"
		r.ReasonCode = "OWNERSHIP_AMBIGUOUS"
		return finish()
	}
	if target.relationship != "" {
		proofs, ok := relationshipBoundaries(actor.Contexts, target.resource.Relationships, object.RelationshipValues)
		if !ok {
			r.Outcome = "INCONCLUSIVE"
			r.Completion = "partial"
			r.ReasonCode = "RELATIONSHIP_INCOMPLETE"
			return finish()
		}
		boundary := false
		for _, p := range proofs {
			if p.Name == target.relationship && p.Boundary == "different" {
				boundary = true
			}
		}
		if !boundary {
			r.ReasonCode = "RELATIONSHIP_BOUNDARY_MISSING"
			return finish()
		}
	}
	path, err := detailPath(target.resource.Detail, object.PathValues)
	if err != nil {
		r.ReasonCode = "IDENTIFIER_UNSAFE"
		return finish()
	}
	if !scope.Match(s.endpoint(path), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		r.ReasonCode = "OUT_OF_SCOPE"
		return finish()
	}
	status, body, _, err := s.request(ctx, actor, s.endpoint(path))
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		setRetestError(r, err)
		return finish()
	}
	if status == http.StatusUnauthorized {
		r.Outcome = "INCONCLUSIVE"
		r.Completion = "partial"
		r.ReasonCode = "AUTHENTICATION_REJECTED"
		return finish()
	}
	if status == http.StatusForbidden || status == http.StatusNotFound {
		r.Outcome = "FIXED"
		r.ReasonCode = "CURRENTLY_DENIED"
		r.Verification = "fresh owner-exclusive resource discovery plus explicit detail denial"
		return finish()
	}
	if status < 200 || status >= 300 {
		r.Outcome = "INCONCLUSIVE"
		r.Completion = "partial"
		r.ReasonCode = "TARGET_RESPONSE_AMBIGUOUS"
		return finish()
	}
	ref, ids, rels, valid := extractResourceRef(body, resourceIdentifiers(target.resource), resourceRelationships(target.resource))
	verify, verifyFields, verifyOK := extractVerificationDigest(body, resourceVerificationFields(target.resource))
	ownerVerify := verifyValues[target.owner][object.ID]
	proof := valid && ref == object.ID && relationshipsEqual(object.RelationshipValues, rels) && verifyOK && !valuesIntersect(ids, verifyFields) && verify != "" && ownerVerify != "" && verify == ownerVerify && verifyCounts[verificationValue(ownerVerify)] == 1
	if proof {
		r.Outcome = "STILL_PRESENT"
		r.ReasonCode = "REPRODUCED"
		r.Verification = "fresh owner-exclusive discovery and matching resource identity/verification proof"
		return finish()
	}
	r.Outcome = "INCONCLUSIVE"
	r.Completion = "partial"
	r.ReasonCode = "VERIFICATION_INCOMPLETE"
	return finish()
}

func (s *Scanner) discoverRetestOwnership(ctx context.Context, res config.Resource, owner string) (map[string]map[string]bool, map[string][]candidate, map[string]map[string]string, map[string]int, bool, error) {
	owners := map[string]map[string]bool{}
	all := map[string][]candidate{}
	values := map[string]map[string]string{}
	counts := map[string]int{}
	complete := true
	for _, id := range s.cfg.Identities {
		list, pages, done, err := s.discoverCollection(ctx, id, res)
		if err != nil {
			return owners, all, values, counts, false, err
		}
		if !done || len(pages) == 0 || pages[len(pages)-1].Status < 200 || pages[len(pages)-1].Status >= 300 {
			complete = false
			continue
		}
		if len(list) > s.cfg.Limits.MaxObjects {
			complete = false
			list = list[:s.cfg.Limits.MaxObjects]
		}
		all[id.ID] = list
		values[id.ID] = map[string]string{}
		for _, item := range list {
			if !safePathIdentifierValues(item.PathValues) {
				complete = false
				continue
			}
			if owners[item.ID] == nil {
				owners[item.ID] = map[string]bool{}
			}
			owners[item.ID][id.ID] = true
			values[id.ID][item.ID] = item.Verify
			if item.Verify != "" {
				counts[verificationValue(item.Verify)]++
			}
		}
	}
	if owner == "" {
		complete = false
	}
	return owners, all, values, counts, complete, nil
}

func identityByID(ids []config.Identity, id string) (config.Identity, bool) {
	for _, x := range ids {
		if x.ID == id {
			return x, true
		}
	}
	return config.Identity{}, false
}
func identityExists(ids []config.Identity, id string) bool { _, ok := identityByID(ids, id); return ok }
func relationshipConfigured(r config.Resource, name string) bool {
	for _, x := range r.Relationships {
		if x.Name == name {
			return true
		}
	}
	return false
}
func countDistinct(counts map[string]int) int { return len(counts) }
func setRetestError(r *RetestResult, err error) {
	r.Outcome = "INCONCLUSIVE"
	r.Completion = "partial"
	switch {
	case errors.Is(err, context.Canceled):
		r.ReasonCode = "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		r.ReasonCode = "NETWORK_TIMEOUT"
	case strings.Contains(err.Error(), "budget exhausted"):
		r.ReasonCode = "BUDGET_EXHAUSTED"
	case strings.Contains(err.Error(), "outside configured scope"):
		r.Outcome = "NOT_TESTABLE"
		r.Completion = "complete"
		r.ReasonCode = "OUT_OF_SCOPE"
	default:
		r.ReasonCode = "TARGET_UNAVAILABLE"
	}
}
