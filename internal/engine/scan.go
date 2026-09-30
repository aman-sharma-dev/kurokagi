package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/openapi"
	"github.com/kurokagi/kurokagi/internal/scope"
)

var errRestorationInconclusive = errors.New("controlled state restoration could not be verified")

// Version is the build's displayed version string.
var Version = "0.1.0-dev"

// Result is the versioned machine-readable output from one scan.
type Result struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          map[string]string `json:"tool"`
	RunID         string            `json:"run_id"`
	Target        TargetMetadata    `json:"target"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Status        string            `json:"status"`
	Completion    string            `json:"completion_state"`
	Capabilities  []string          `json:"capabilities_exercised"`
	Coverage      []Coverage        `json:"coverage"`
	Findings      []Finding         `json:"findings"`
	Evidence      []Evidence        `json:"evidence"`
	Errors        []ScanError       `json:"errors"`
	Warnings      []ScanError       `json:"warnings"`
}

// TargetMetadata contains the sanitized target metadata included in a result.
type TargetMetadata struct {
	Origin string `json:"origin"`
}

// ScanError is a sanitized structured warning or error.
type ScanError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

// Coverage describes the checks attempted and their completion or cleanup state.
type Coverage struct {
	Identity         string `json:"identity"`
	Resource         string `json:"resource"`
	Operation        string `json:"operation"`
	State            string `json:"state"`
	Reason           string `json:"reason,omitempty"`
	Cleanup          string `json:"cleanup_state,omitempty"`
	CleanupRequired  bool   `json:"cleanup_required,omitempty"`
	CleanupAttempted bool   `json:"cleanup_attempted,omitempty"`
	Restoration      string `json:"restoration_state,omitempty"`
	DeleteTested     bool   `json:"delete_tested,omitempty"`
	DeleteState      string `json:"delete_state,omitempty"`
}

// Finding is a reproducible authorization result with a stable semantic fingerprint.
type Finding struct {
	Fingerprint       string              `json:"fingerprint"`
	Type              string              `json:"type"`
	Severity          string              `json:"severity"`
	Resource          string              `json:"resource"`
	ResourceRef       string              `json:"resource_ref,omitempty"`
	Relationship      string              `json:"relationship,omitempty"`
	RelationshipProof []RelationshipProof `json:"relationship_proof,omitempty"`
	VictimIdentity    string              `json:"victim_identity"`
	AccessingIdentity string              `json:"accessing_identity"`
	Method            string              `json:"method"`
	Path              string              `json:"path"`
	EvidenceIDs       []string            `json:"evidence_ids"`
}

// RelationshipProof records hashed relationship-boundary comparison evidence.
type RelationshipProof struct {
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	ActorContextRef    string `json:"actor_context_ref"`
	ResourceContextRef string `json:"resource_context_ref"`
	Boundary           string `json:"boundary"`
}

// Evidence contains sanitized request/response metadata supporting a result.
type Evidence struct {
	ID                 string   `json:"id"`
	Identity           string   `json:"identity"`
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	Status             int      `json:"status"`
	ResourceRef        string   `json:"resource_ref,omitempty"`
	DifferentialFields []string `json:"differential_fields,omitempty"`
	BodySHA256         string   `json:"body_sha256,omitempty"`
	ContentType        string   `json:"content_type,omitempty"`
	Note               string   `json:"note,omitempty"`
}
type candidate struct {
	ID                 string
	Verify             string
	PathValues         map[string]string
	RelationshipValues map[string]string
	Baseline           map[string]any
}
type pageObservation struct {
	Status      int
	Body        []byte
	ContentType string
}

// requestSpec is the transport boundary. Mutations require internal capabilities
// bound to the controlled-resource lifecycle before any write reaches the wire.
type requestSpec struct {
	Method           string
	URL              string
	Headers          http.Header
	Body             []byte
	ContentType      string
	queryKeys        []string
	postAuth         *postExecutionAuthorization
	cleanupAuth      *cleanupExecutionAuthorization
	mutationAuth     *controlledMutationAuthorization
	attackDeleteAuth *controlledDeleteAuthorization
	operationID      string
	operationPath    string
	runID            string
	cleanupBudget    bool
}

// Scanner executes a validated configuration under its configured scope and limits.
type Scanner struct {
	cfg          config.Config
	client       *http.Client
	base         *url.URL
	credentials  map[string][]CredentialProvider
	mu           sync.Mutex
	used         int
	mutationUsed int
	cleanupUsed  int
	gate         chan struct{}
	interval     time.Duration
	next         time.Time
}

func expectation(c config.Config, identity, owner, resource, relationship, method string) string {
	method = config.NormalizeMethod(method)
	if method == "" {
		method = "GET"
	}
	methodMatches := func(rule config.Expectation) bool {
		configured := config.NormalizeMethod(rule.Method)
		if configured == "" {
			configured = "GET"
		}
		return configured == method
	}
	for _, rule := range c.Expectations {
		if rule.Identity == identity && rule.Owner == owner && rule.Resource == resource && rule.Relationship == relationship && relationship != "" && methodMatches(rule) {
			return rule.Access
		}
	}
	for _, rule := range c.Expectations {
		if rule.Identity == identity && rule.Owner == owner && rule.Resource == resource && rule.Relationship == "" && owner != "" && methodMatches(rule) {
			return rule.Access
		}
	}
	for _, rule := range c.Expectations {
		if rule.Identity == identity && rule.Owner == "" && rule.Resource == resource && rule.Relationship == relationship && relationship != "" && methodMatches(rule) {
			return rule.Access
		}
	}
	for _, rule := range c.Expectations {
		if rule.Identity == identity && rule.Owner == "" && rule.Resource == resource && rule.Relationship == "" && methodMatches(rule) {
			return rule.Access
		}
	}
	return "UNKNOWN"
}

// New creates a scanner from a validated configuration.
func New(c config.Config) (*Scanner, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, e := url.Parse(c.Target.BaseURL)
	if e != nil {
		return nil, e
	}
	timeout := 10 * time.Second
	if x, e := time.ParseDuration(c.Limits.Timeout); e == nil {
		timeout = x
	}
	cl := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	providers := make(map[string][]CredentialProvider, len(c.Identities))
	for _, identity := range c.Identities {
		providers[identity.ID] = credentialProviders(identity)
	}
	s := &Scanner{cfg: c, client: cl, base: b, credentials: providers, gate: make(chan struct{}, c.Limits.Concurrency)}
	if c.Limits.RequestsPerSecond > 0 {
		s.interval = time.Duration(float64(time.Second) / c.Limits.RequestsPerSecond)
	}
	return s, nil
}
func (s *Scanner) request(ctx context.Context, identity config.Identity, raw string) (int, []byte, string, error) {
	return s.requestWithQuery(ctx, identity, raw, nil)
}

func (s *Scanner) requestWithQuery(ctx context.Context, identity config.Identity, raw string, allowedQueryKeys []string) (int, []byte, string, error) {
	return s.execute(ctx, identity, requestSpec{Method: http.MethodGet, URL: raw, queryKeys: allowedQueryKeys})
}

func (s *Scanner) execute(ctx context.Context, identity config.Identity, spec requestSpec) (int, []byte, string, error) {
	spec.Method = config.NormalizeMethod(spec.Method)
	safety, supported := config.MethodSafety(spec.Method)
	if !supported {
		return 0, nil, "", fmt.Errorf("unsupported HTTP method")
	}
	if safety != config.SafetyReadOnly {
		postAuthorized := spec.Method == http.MethodPost && spec.postAuth.matches(s, identity, spec)
		cleanupAuthorized := spec.Method == http.MethodDelete && spec.cleanupAuth.matches(s, identity, spec)
		updateAuthorized := (spec.Method == http.MethodPut || spec.Method == http.MethodPatch) && spec.mutationAuth.matches(s, identity, spec)
		attackDeleteAuthorized := spec.Method == http.MethodDelete && spec.attackDeleteAuth.matches(s, identity, spec)
		if !postAuthorized && !cleanupAuthorized && !updateAuthorized && !attackDeleteAuthorized {
			return 0, nil, "", fmt.Errorf("mutating operation execution is disabled")
		}
		status, body, contentType, _, err := s.requestOnce(ctx, identity, spec)
		return status, body, contentType, err
	}
	if len(spec.Body) != 0 || spec.postAuth != nil || spec.cleanupAuth != nil || spec.mutationAuth != nil || spec.attackDeleteAuth != nil {
		return 0, nil, "", fmt.Errorf("GET request bodies are disabled")
	}
	if spec.URL == "" {
		return 0, nil, "", fmt.Errorf("request URL is required")
	}
	current := spec.URL
	redirects := 0
	for {
		currentSpec := spec
		currentSpec.URL = current
		status, body, contentType, location, err := s.requestOnce(ctx, identity, currentSpec)
		if err != nil {
			return status, body, contentType, err
		}
		if s.cfg.Limits.RedirectPolicy != "same_origin" || !isRedirect(status) || location == "" {
			return status, body, contentType, nil
		}
		if redirects >= 5 {
			return status, body, contentType, nil
		}
		base, baseErr := url.Parse(current)
		next, nextErr := url.Parse(location)
		if baseErr != nil || nextErr != nil {
			return status, body, contentType, nil
		}
		next = base.ResolveReference(next)
		if !scope.MatchWithQuery(next.String(), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths, spec.queryKeys) || !scope.SameOrigin(current, next.String()) {
			return status, body, contentType, nil
		}
		current = next.String()
		redirects++
	}
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// requestOnce accounts for one actual outgoing wire request.
func (s *Scanner) requestOnce(ctx context.Context, identity config.Identity, spec requestSpec) (int, []byte, string, string, error) {
	safety, supported := config.MethodSafety(spec.Method)
	if !supported {
		return 0, nil, "", "", fmt.Errorf("unsupported HTTP method")
	}
	postAuthorized := spec.Method == http.MethodPost && spec.postAuth.matches(s, identity, spec)
	cleanupAuthorized := spec.Method == http.MethodDelete && spec.cleanupAuth.matches(s, identity, spec)
	updateAuthorized := (spec.Method == http.MethodPut || spec.Method == http.MethodPatch) && spec.mutationAuth.matches(s, identity, spec)
	attackDeleteAuthorized := spec.Method == http.MethodDelete && spec.attackDeleteAuth.matches(s, identity, spec)
	if safety != config.SafetyReadOnly && !postAuthorized && !cleanupAuthorized && !updateAuthorized && !attackDeleteAuthorized || spec.Method == http.MethodGet && (len(spec.Body) != 0 || spec.postAuth != nil || spec.cleanupAuth != nil || spec.mutationAuth != nil || spec.attackDeleteAuth != nil) || spec.Method != http.MethodGet && !postAuthorized && !cleanupAuthorized && !updateAuthorized && !attackDeleteAuthorized {
		return 0, nil, "", "", fmt.Errorf("mutating operation execution is disabled")
	}
	if postAuthorized && (len(spec.Body) == 0 || len(spec.Body) > 16*1024 || spec.ContentType != "application/json") {
		return 0, nil, "", "", fmt.Errorf("controlled POST request is invalid")
	}
	if updateAuthorized && (len(spec.Body) == 0 || len(spec.Body) > 16*1024 || spec.ContentType != "application/json" || !json.Valid(spec.Body)) {
		return 0, nil, "", "", fmt.Errorf("controlled PUT/PATCH request is invalid")
	}
	if spec.cleanupBudget && (spec.Method != http.MethodGet || len(spec.Body) != 0) {
		return 0, nil, "", "", fmt.Errorf("invalid cleanup verification request")
	}
	if !scope.MatchWithQuery(spec.URL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths, spec.queryKeys) {
		return 0, nil, "", "", fmt.Errorf("request outside configured scope")
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return 0, nil, "", "", ctx.Err()
	}
	defer func() { <-s.gate }()
	s.mu.Lock()
	var wait time.Duration
	if s.interval > 0 {
		now := time.Now()
		slot := now
		if s.next.After(slot) {
			slot = s.next
		}
		wait = time.Until(slot)
		s.next = slot.Add(s.interval)
	}
	s.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, nil, "", "", ctx.Err()
		case <-t.C:
		}
	}
	var requestBody io.Reader
	if len(spec.Body) > 0 {
		requestBody = strings.NewReader(string(spec.Body))
	}
	req, e := http.NewRequestWithContext(ctx, spec.Method, spec.URL, requestBody)
	if e != nil {
		return 0, nil, "", "", fmt.Errorf("invalid request URL")
	}
	if (cleanupAuthorized || attackDeleteAuthorized) && req.Body == nil {
		// net/http may transparently replay bodyless idempotent requests after a
		// reused-connection failure. A non-replayable zero-length body disables
		// that transport behavior while keeping the DELETE entity empty.
		req.Body = io.NopCloser(strings.NewReader(""))
		req.ContentLength = 0
		req.GetBody = nil
	}
	for key, values := range spec.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if spec.ContentType != "" {
		req.Header.Set("Content-Type", spec.ContentType)
	}
	for _, provider := range s.credentials[identity.ID] {
		if err := provider.Apply(ctx, req); err != nil {
			return 0, nil, "", "", fmt.Errorf("credential provider could not prepare request")
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, "", "", err
	}
	if attackDeleteAuthorized && !spec.attackDeleteAuth.matches(s, identity, spec) {
		return 0, nil, "", "", fmt.Errorf("controlled DELETE pre-state authorization expired before dispatch")
	}
	s.mu.Lock()
	if s.used >= s.cfg.Limits.MaxRequests {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("request budget exhausted")
	}
	if postAuthorized && s.mutationUsed >= s.cfg.Mutations.RequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("mutation request budget exhausted")
	}
	if postAuthorized && !spec.postAuth.consume() {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("controlled POST authorization was already used")
	}
	if cleanupAuthorized && s.cleanupUsed >= s.cfg.Mutations.CleanupRequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("cleanup request budget exhausted")
	}
	if updateAuthorized && spec.mutationAuth.restoration && s.cleanupUsed >= s.cfg.Mutations.CleanupRequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("restoration request budget exhausted")
	}
	if updateAuthorized && !spec.mutationAuth.restoration && s.mutationUsed >= s.cfg.Mutations.RequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("mutation request budget exhausted")
	}
	if attackDeleteAuthorized && s.mutationUsed >= s.cfg.Mutations.RequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("mutation request budget exhausted")
	}
	if spec.cleanupBudget && s.cleanupUsed >= s.cfg.Mutations.CleanupRequestBudget {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("cleanup request budget exhausted")
	}
	if cleanupAuthorized && !spec.cleanupAuth.consume() {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("cleanup authorization was already used")
	}
	if attackDeleteAuthorized && !spec.attackDeleteAuth.consume() {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("controlled DELETE authorization was already used")
	}
	if updateAuthorized && !spec.mutationAuth.consume() {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("controlled mutation authorization was already used")
	}
	s.used++
	if postAuthorized {
		s.mutationUsed++
	}
	if cleanupAuthorized {
		s.cleanupUsed++
	}
	if attackDeleteAuthorized {
		s.mutationUsed++
	}
	if updateAuthorized {
		if spec.mutationAuth.restoration {
			s.cleanupUsed++
		} else {
			s.mutationUsed++
		}
	}
	if spec.cleanupBudget {
		s.cleanupUsed++
	}
	s.mu.Unlock()
	resp, e := s.client.Do(req)
	if e != nil {
		if errors.Is(e, context.DeadlineExceeded) {
			return 0, nil, "", "", context.DeadlineExceeded
		}
		if errors.Is(e, context.Canceled) {
			return 0, nil, "", "", context.Canceled
		}
		return 0, nil, "", "", fmt.Errorf("HTTP request failed")
	}
	defer resp.Body.Close()
	contentType := safeContentType(resp.Header.Get("Content-Type"))
	location := ""
	if isRedirect(resp.StatusCode) {
		location = resp.Header.Get("Location")
	}
	limited := io.LimitReader(resp.Body, s.cfg.Limits.MaxResponseBytes+1)
	body, e := io.ReadAll(limited)
	if e != nil {
		return resp.StatusCode, nil, contentType, "", fmt.Errorf("response read failed")
	}
	if int64(len(body)) > s.cfg.Limits.MaxResponseBytes {
		return resp.StatusCode, nil, contentType, "", fmt.Errorf("response exceeded configured size limit")
	}
	return resp.StatusCode, body, contentType, location, nil
}

func safeContentType(value string) string {
	value = strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	switch strings.ToLower(mediaType) {
	case "application/json", "application/problem+json", "application/xml", "text/xml", "text/plain", "text/html", "application/yaml", "text/yaml", "application/octet-stream":
		return strings.ToLower(mediaType)
	default:
		return ""
	}
}
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	start := time.Now().UTC()
	r := Result{SchemaVersion: "2", Tool: map[string]string{"name": "Kurokagi", "version": Version}, Target: TargetMetadata{Origin: s.base.Scheme + "://" + s.base.Host}, StartedAt: start, Status: "completed", Completion: "complete", Capabilities: []string{"horizontal_object_authorization"}, Coverage: []Coverage{}, Findings: []Finding{}, Evidence: []Evidence{}, Errors: []ScanError{}, Warnings: []ScanError{}}
	runHash := sha256.Sum256([]byte(start.Format(time.RFC3339Nano) + "\x00" + s.base.Scheme + "://" + s.base.Host))
	r.RunID = hex.EncodeToString(runHash[:12])
	doc, e := openapi.Load(s.cfg.OpenAPI.Path)
	if e != nil {
		return r, e
	}
	_ = doc
	for _, res := range s.cfg.Resources {
		owners := map[string]map[string]bool{}
		if !doc.HasGet(res.Collection) || !doc.HasGet(strings.ReplaceAll(res.Detail, "{id}", "{id}")) {
			r.Coverage = append(r.Coverage, Coverage{Resource: res.Name, Operation: "GET", State: "UNSUPPORTED", Reason: "OpenAPI must define collection and detail GET operations"})
			continue
		}
		r.Capabilities = append(r.Capabilities, strings.ToLower(res.Classification))
		visible := map[string][]candidate{}
		verifyValues := map[string]map[string]string{}
		verifyCounts := map[string]int{}
		collectionComplete := map[string]bool{}
		for _, id := range s.cfg.Identities {
			candidates, pages, complete, err := s.discoverCollection(ctx, id, res)
			unauthorized := false
			for pageIndex, page := range pages {
				if page.Status == http.StatusUnauthorized {
					unauthorized = true
				}
				r.Evidence = append(r.Evidence, evidence(id.ID, "GET", res.Collection, page.Status, page.Body, page.ContentType, fmt.Sprintf("collection discovery page %d", pageIndex+1)))
			}
			if err != nil {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "FAILED", Reason: "collection request failed or was bounded"})
				r.Errors = append(r.Errors, safeRequestError(err))
				continue
			}
			if unauthorized {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "FAILED", Reason: "authentication was rejected"})
				r.Errors = append(r.Errors, ScanError{Code: CodeAuthFailed, Message: "target rejected configured authentication"})
				continue
			}
			if len(pages) == 0 || pages[len(pages)-1].Status < 200 || pages[len(pages)-1].Status >= 300 {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "INCONCLUSIVE", Reason: "collection response did not establish visible object IDs"})
				continue
			}
			for _, item := range candidates {
				if item.Verify != "" {
					verifyCounts[verificationValue(item.Verify)]++
				}
			}
			bounded := !complete
			if len(candidates) > s.cfg.Limits.MaxObjects {
				candidates = candidates[:s.cfg.Limits.MaxObjects]
				bounded = true
			}
			if verifyValues[id.ID] == nil {
				verifyValues[id.ID] = map[string]string{}
			}
			for _, item := range candidates {
				if !safePathIdentifierValues(item.PathValues) {
					bounded = true
					continue
				}
				if owners[item.ID] == nil {
					owners[item.ID] = map[string]bool{}
				}
				owners[item.ID][id.ID] = true
				visible[id.ID] = append(visible[id.ID], item)
				if prior, ok := verifyValues[id.ID][item.ID]; ok && prior != item.Verify {
					verifyValues[id.ID][item.ID] = ""
				} else {
					verifyValues[id.ID][item.ID] = item.Verify
				}
			}
			coverage := Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "TESTED"}
			if bounded {
				coverage.State = "INCONCLUSIVE"
				coverage.Reason = "collection response established no usable candidate IDs or exceeded configured bounds"
			}
			collectionComplete[id.ID] = !bounded
			r.Coverage = append(r.Coverage, coverage)
		}
		allCollectionsComplete := true
		for _, id := range s.cfg.Identities {
			if !collectionComplete[id.ID] {
				allCollectionsComplete = false
			}
		}
		distinctVerifyValues := 0
		for _, count := range verifyCounts {
			if count > 0 {
				distinctVerifyValues++
			}
		}
		for _, victim := range s.cfg.Identities {
			if !allCollectionsComplete {
				for _, actor := range s.cfg.Identities {
					if actor.ID != victim.ID {
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "collection discovery was incomplete; ownership was not established"})
					}
				}
				continue
			}
			for _, object := range visible[victim.ID] {
				objectID := object.ID
				if len(owners[objectID]) != 1 {
					for _, actor := range s.cfg.Identities {
						if actor.ID != victim.ID {
							r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "resource visibility does not establish a unique victim identity"})
						}
					}
					continue
				}
				for _, actor := range s.cfg.Identities {
					if actor.ID == victim.ID {
						continue
					}
					path, pathErr := detailPath(res.Detail, object.PathValues)
					if pathErr != nil {
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "resource identifier could not be placed safely in the detail path"})
						continue
					}
					raw := s.endpoint(path)
					status, body, ct, err := s.request(ctx, actor, raw)
					if err != nil {
						state := "FAILED"
						if ctx.Err() != nil {
							state = "INCONCLUSIVE"
						}
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: state, Reason: "request failed or execution was bounded"})
						if state == "FAILED" {
							r.Errors = append(r.Errors, safeRequestError(err))
						}
						continue
					}
					gotRef, idValues, detailRelations, valid := extractResourceRef(body, resourceIdentifiers(res), resourceRelationships(res))
					verify, verifyValuesFound, verifyOK := extractVerificationDigest(body, resourceVerificationFields(res))
					victimValue := verifyValues[victim.ID][objectID]
					relationMatch := relationshipsEqual(object.RelationshipValues, detailRelations)
					match := allCollectionsComplete && distinctVerifyValues >= 2 && valid && gotRef == objectID && relationMatch && verifyOK && !valuesIntersect(idValues, verifyValuesFound) && verify != "" && victimValue != "" && verify == victimValue && verifyCounts[victimValue] == 1
					boundaryProofs, boundaryComplete := relationshipBoundaries(actor.Contexts, res.Relationships, object.RelationshipValues)
					boundaryMismatch := false
					for _, proof := range boundaryProofs {
						if proof.Boundary == "different" {
							boundaryMismatch = true
						}
					}
					displayPath := res.Detail
					ev := evidenceForResource(actor.ID, "GET", displayPath, status, body, ct, "cross-identity detail response evaluated", objectID)
					ev.DifferentialFields = compareJSONFields(object.Baseline, body, res.IgnoreFields)
					r.Evidence = append(r.Evidence, ev)
					expected := expectation(s.cfg, actor.ID, victim.ID, res.Name, "", http.MethodGet)
					deniedRelationship := ""
					if res.Classification == "RELATIONSHIP" && boundaryComplete {
						for _, proof := range boundaryProofs {
							if proof.Boundary == "different" {
								relationExpectation := expectation(s.cfg, actor.ID, victim.ID, res.Name, proof.Name, http.MethodGet)
								expected = relationExpectation
								if relationExpectation == "DENIED" {
									deniedRelationship = proof.Name
									break
								}
							}
						}
					}
					switch {
					case status == http.StatusUnauthorized:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "FAILED", Reason: "authentication was rejected"})
						r.Errors = append(r.Errors, ScanError{Code: CodeAuthFailed, Message: "target rejected configured authentication"})
					case status >= 200 && status < 300 && match && expected == "DENIED" && (res.Classification != "RELATIONSHIP" || deniedRelationship != ""):
						f := finding(res.Classification, res.Name, objectID, victim.ID, actor.ID, deniedRelationship, displayPath, ev.ID)
						if deniedRelationship != "" {
							f.RelationshipProof = boundaryProofs
						}
						merged := false
						for i := range r.Findings {
							if r.Findings[i].Fingerprint == f.Fingerprint {
								r.Findings[i].EvidenceIDs = append(r.Findings[i].EvidenceIDs, ev.ID)
								if r.Findings[i].ResourceRef != f.ResourceRef {
									r.Findings[i].ResourceRef = ""
								}
								merged = true
								break
							}
						}
						if !merged {
							r.Findings = append(r.Findings, f)
						}
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED"})
					case status == 403 || status == 404:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED", Reason: "access denied"})
					case status >= 200 && status < 300 && match && expected == "ALLOWED":
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED", Reason: "access matched explicit ALLOWED expectation"})
					case status >= 200 && status < 300 && match && res.Classification == "RELATIONSHIP" && boundaryComplete && !boundaryMismatch:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED", Reason: "configured relationship context did not cross a boundary"})
					case status >= 200 && status < 300 && match && res.Classification == "RELATIONSHIP" && boundaryComplete && boundaryMismatch && expected == "ALLOWED":
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED", Reason: "cross-boundary access matched explicit ALLOWED expectation"})
					case status >= 200 && status < 300 && match && res.Classification == "RELATIONSHIP" && !boundaryComplete:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "actor or resource relationship context is incomplete"})
					case status >= 200 && status < 300 && match && expected == "UNKNOWN":
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "resource access was proven but authorization expectation is UNKNOWN"})
					case status >= 200 && status < 300:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "successful response did not prove a unique victim resource was returned"})
					default:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "response did not establish allow or deny"})
					}
				}
			}
		}
	}
	identities := make(map[string]config.Identity, len(s.cfg.Identities))
	for _, identity := range s.cfg.Identities {
		identities[identity.ID] = identity
	}
	verticalExercised := false
	setupByID := map[string]config.Operation{}
	dependentSetups := map[string]bool{}
	for _, configured := range s.cfg.Operations {
		setupByID[configured.ID] = configured
		if method := config.NormalizeMethod(configured.Method); method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			dependentSetups[configured.ControlledResourceOperationID] = true
		}
	}
	for _, op := range s.cfg.Operations {
		method := config.NormalizeMethod(op.Method)
		if method == http.MethodPost && dependentSetups[op.ID] {
			continue
		}
		operationLabel := method + " " + op.Path
		operationResource := "operation:" + op.ID
		if op.Resource != "" {
			operationResource = op.Resource
		}
		safety, supported := config.MethodSafety(method)
		if !supported {
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "configured HTTP method is unsupported"})
			continue
		}
		if safety != config.SafetyReadOnly {
			if method == http.MethodPost {
				outcome := s.executeControlledPost(ctx, r.RunID, doc, identities[op.Actor], op, operationResource, operationLabel, false)
				r.Coverage = append(r.Coverage, outcome.coverage)
				r.Evidence = append(r.Evidence, outcome.evidence...)
				r.Errors = append(r.Errors, outcome.errors...)
				r.Warnings = append(r.Warnings, outcome.warnings...)
				if outcome.finding != nil {
					r.Findings = append(r.Findings, *outcome.finding)
				}
				verticalExercised = verticalExercised || outcome.executed
			} else if method == http.MethodPut || method == http.MethodPatch {
				setup, exists := setupByID[op.ControlledResourceOperationID]
				if !exists || !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, method) {
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "only policy-authorized controlled PUT/PATCH is available; other mutations remain disabled"})
					continue
				}
				if !controlledUpdateLifecycleBudgetAvailable(s, op) {
					setupResource := setup.Resource
					setupLabel := config.NormalizeMethod(setup.Method) + " " + setup.Path
					r.Coverage = append(r.Coverage, Coverage{Identity: setup.Actor, Resource: setupResource, Operation: setupLabel, State: "INCONCLUSIVE", Reason: "global, mutation, or cleanup budget cannot cover the complete controlled update lifecycle"})
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "INCONCLUSIVE", Reason: "controlled update lifecycle budget is insufficient; no setup or update request was sent"})
					continue
				}
				setupResource := setup.Resource
				setupLabel := config.NormalizeMethod(setup.Method) + " " + setup.Path
				setupOutcome := s.executeControlledPost(ctx, r.RunID, doc, identities[setup.Actor], setup, setupResource, setupLabel, true)
				r.Coverage = append(r.Coverage, setupOutcome.coverage)
				r.Evidence = append(r.Evidence, setupOutcome.evidence...)
				r.Errors = append(r.Errors, setupOutcome.errors...)
				r.Warnings = append(r.Warnings, setupOutcome.warnings...)
				if setupOutcome.finding != nil {
					r.Findings = append(r.Findings, *setupOutcome.finding)
				}
				if setupOutcome.handle == nil || setupOutcome.proof == nil || setupOutcome.test == nil {
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "INCONCLUSIVE", Reason: "controlled setup did not prove a test-created resource"})
					continue
				}
				updateOutcome := s.executeControlledUpdate(ctx, r.RunID, doc, identities[op.Actor], op, setup, setupOutcome, operationResource, operationLabel)
				if len(r.Coverage) > 0 {
					r.Coverage[len(r.Coverage)-1].Cleanup = updateOutcome.coverage.Cleanup
					r.Coverage[len(r.Coverage)-1].CleanupAttempted = updateOutcome.coverage.CleanupAttempted
					r.Coverage[len(r.Coverage)-1].Restoration = updateOutcome.coverage.Restoration
				}
				r.Coverage = append(r.Coverage, updateOutcome.coverage)
				r.Evidence = append(r.Evidence, updateOutcome.evidence...)
				r.Errors = append(r.Errors, updateOutcome.errors...)
				r.Warnings = append(r.Warnings, updateOutcome.warnings...)
				if updateOutcome.finding != nil {
					r.Findings = append(r.Findings, *updateOutcome.finding)
				}
				verticalExercised = verticalExercised || updateOutcome.executed
			} else if method == http.MethodDelete {
				setup, exists := setupByID[op.ControlledResourceOperationID]
				if !exists || !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, http.MethodDelete) || !allowedConfiguredPath(op.Path, s.cfg.Mutations.AllowedPaths) {
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "SKIPPED_BY_POLICY", Reason: "controlled DELETE attack is disabled by method and path policy"})
					continue
				}
				if !controlledDeleteLifecycleBudgetAvailable(s) {
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "INCONCLUSIVE", Reason: "global, mutation, or cleanup budget cannot cover the complete controlled DELETE lifecycle"})
					continue
				}
				setupLabel := http.MethodPost + " " + setup.Path
				setupOutcome := s.executeControlledPost(ctx, r.RunID, doc, identities[setup.Actor], setup, setup.Resource, setupLabel, true)
				r.Coverage = append(r.Coverage, setupOutcome.coverage)
				r.Evidence = append(r.Evidence, setupOutcome.evidence...)
				r.Errors = append(r.Errors, setupOutcome.errors...)
				r.Warnings = append(r.Warnings, setupOutcome.warnings...)
				if setupOutcome.handle == nil || setupOutcome.proof == nil || setupOutcome.test == nil {
					r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "NO_DISPOSABLE_RESOURCE", Reason: "controlled POST did not positively prove a disposable scanner-created resource"})
					continue
				}
				deleteOutcome := s.executeControlledDelete(ctx, r.RunID, doc, identities[op.Actor], op, setup, setupOutcome, operationResource, operationLabel)
				if len(r.Coverage) > 0 {
					r.Coverage[len(r.Coverage)-1].Cleanup = deleteOutcome.coverage.Cleanup
					r.Coverage[len(r.Coverage)-1].CleanupRequired = deleteOutcome.coverage.CleanupRequired
					r.Coverage[len(r.Coverage)-1].CleanupAttempted = deleteOutcome.coverage.CleanupAttempted
				}
				r.Coverage = append(r.Coverage, deleteOutcome.coverage)
				r.Evidence = append(r.Evidence, deleteOutcome.evidence...)
				r.Errors = append(r.Errors, deleteOutcome.errors...)
				r.Warnings = append(r.Warnings, deleteOutcome.warnings...)
				if deleteOutcome.finding != nil {
					r.Findings = append(r.Findings, *deleteOutcome.finding)
				}
				verticalExercised = verticalExercised || deleteOutcome.executed
			} else {
				r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "only policy-authorized controlled POST is available; other mutations remain disabled"})
			}
			continue
		}
		if strings.ContainsAny(op.Path, "{}") {
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "operation path template has no configured parameter values"})
			continue
		}
		if op.Verification.Type != "RESPONSE_FIELD" {
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "configured verification strategy is not implemented for read-only operations"})
			continue
		}
		if !doc.HasOperation(op.Path, method) {
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "UNSUPPORTED", Reason: "OpenAPI does not define the configured operation"})
			r.Warnings = append(r.Warnings, ScanError{Code: CodeUnsupportedOperation, Message: "configured authorization operation is absent from OpenAPI"})
			continue
		}
		status, body, ct, err := s.execute(ctx, identities[op.Actor], requestSpec{Method: method, URL: s.endpoint(op.Path)})
		if err != nil {
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "FAILED", Reason: "operation request failed or was bounded"})
			r.Errors = append(r.Errors, safeRequestError(err))
			continue
		}
		verticalExercised = true
		ev := evidence(op.Actor, method, op.Path, status, body, ct, "configured operation success evidence evaluated")
		r.Evidence = append(r.Evidence, ev)
		verified := status >= 200 && status < 300 && configuredSuccess(body, op.Verification.Field)
		switch {
		case status == http.StatusUnauthorized:
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "FAILED", Reason: "authentication was rejected"})
			r.Errors = append(r.Errors, ScanError{Code: CodeAuthFailed, Message: "target rejected configured authentication"})
		case verified && op.Access == "DENIED":
			f := functionFinding(op.Classification, op.ID, op.Actor, op.Owner, operationResource, op.Relationship, method, op.Path, ev.ID)
			r.Findings = append(r.Findings, f)
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "TESTED", Reason: "explicitly denied operation returned configured success evidence"})
		case verified && op.Access == "ALLOWED":
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "TESTED", Reason: "operation returned configured success evidence"})
		case status == 401 || status == 403 || status == 404:
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "TESTED", Reason: "operation was rejected"})
		default:
			r.Coverage = append(r.Coverage, Coverage{Identity: op.Actor, Resource: operationResource, Operation: operationLabel, State: "INCONCLUSIVE", Reason: "response did not establish configured operation success or denial"})
		}
	}
	if verticalExercised {
		r.Capabilities = append(r.Capabilities, "vertical_function_authorization")
	}
	if ctx.Err() != nil {
		r.Status = "cancelled"
		r.Completion = "cancelled"
		r.Errors = append(r.Errors, ScanError{Code: CodeCancelled, Message: "scan was cancelled before completion"})
	} else if len(r.Errors) > 0 {
		r.Completion = "partial"
	}
	if r.Completion != "cancelled" {
		for _, c := range r.Coverage {
			if c.State == "INCONCLUSIVE" || c.State == "INCOMPLETE_PRE_DELETE_PROOF" || c.State == "ATTACK_INCONCLUSIVE" || c.State == "FAILED" || c.State == "UNSUPPORTED" || c.Cleanup == "NOT_POSSIBLE" || c.Cleanup == "CLEANUP_FAILED" || c.Cleanup == "CLEANUP_INCONCLUSIVE" || c.Restoration == "RESTORATION_FAILED" || c.Restoration == "RESTORATION_INCONCLUSIVE" {
				r.Completion = "partial"
				break
			}
		}
	}
	if len(r.Findings) > 0 && ctx.Err() == nil {
		r.Status = "findings"
	}
	sort.Slice(r.Errors, func(i, j int) bool {
		return string(r.Errors[i].Code)+"\x00"+r.Errors[i].Message < string(r.Errors[j].Code)+"\x00"+r.Errors[j].Message
	})
	sort.Slice(r.Warnings, func(i, j int) bool {
		return string(r.Warnings[i].Code)+"\x00"+r.Warnings[i].Message < string(r.Warnings[j].Code)+"\x00"+r.Warnings[j].Message
	})
	sort.Strings(r.Capabilities)
	r.FinishedAt = time.Now().UTC()
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Fingerprint < r.Findings[j].Fingerprint })
	sort.Slice(r.Coverage, func(i, j int) bool {
		a, b := r.Coverage[i], r.Coverage[j]
		return strings.Join([]string{a.Identity, a.Resource, a.Operation, a.State, a.Cleanup, a.Reason}, "\x00") < strings.Join([]string{b.Identity, b.Resource, b.Operation, b.State, b.Cleanup, b.Reason}, "\x00")
	})
	sort.Slice(r.Evidence, func(i, j int) bool {
		a, b := r.Evidence[i], r.Evidence[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Identity < b.Identity
	})
	return r, nil
}

func controlledDeleteLifecycleBudgetAvailable(s *Scanner) bool {
	if s == nil || !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, http.MethodDelete) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Setup baseline + POST + proof GET, pre-delete GET, one attack, post-state GET;
	// cleanup DELETE + cleanup verification remain within the lifecycle budgets.
	return s.cfg.Limits.MaxRequests-s.used >= 8 && s.cfg.Mutations.RequestBudget-s.mutationUsed >= 2 &&
		s.cfg.Mutations.CleanupRequestBudget-s.cleanupUsed >= 3
}

func controlledUpdateLifecycleBudgetAvailable(s *Scanner, operation config.Operation) bool {
	cleanupNeeded := 2
	if operation.RestoreBody != nil {
		cleanupNeeded = 4
	}
	globalNeeded := 6 + cleanupNeeded // setup baseline/POST/proof, update pre-state/write/post-state, plus restoration/removal lifecycle
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Limits.MaxRequests-s.used >= globalNeeded && s.cfg.Mutations.RequestBudget-s.mutationUsed >= 2 && s.cfg.Mutations.CleanupRequestBudget-s.cleanupUsed >= cleanupNeeded
}

type controlledPostOutcome struct {
	coverage             Coverage
	finding              *Finding
	evidence             []Evidence
	errors               []ScanError
	warnings             []ScanError
	executed             bool
	postStatus           int
	mutationStatus       int
	verifiedAbsent       bool
	verifiedUnchanged    bool
	verificationComplete bool
	test                 *mutationTestIdentity
	proof                *controlledResourceProof
	handle               *controlledResourceHandle
}

func (s *Scanner) executeControlledPost(ctx context.Context, runID string, doc openapi.Document, actor config.Identity, operation config.Operation, resource, label string, holdForUpdate bool) controlledPostOutcome {
	out := controlledPostOutcome{coverage: Coverage{Identity: operation.Actor, Resource: resource, Operation: label}}
	finish := func(state, reason string) controlledPostOutcome {
		out.coverage.State, out.coverage.Reason = state, reason
		return out
	}
	if !s.cfg.Mutations.Enabled {
		return finish("UNSUPPORTED", "controlled POST mutations are disabled")
	}
	if !postAllowed(s.cfg.Mutations.AllowedMethods) || !allowedConfiguredPath(operation.Path, s.cfg.Mutations.AllowedPaths) ||
		operation.Access == "" {
		return finish("UNSUPPORTED", "POST lacks explicit method, path, or authorization policy")
	}
	if strings.ContainsAny(operation.Path, "{}") || !doc.HasOperation(operation.Path, http.MethodPost) || !doc.HasGet(operation.Verification.Path) {
		return finish("UNSUPPORTED", "OpenAPI must define the configured POST and safe verification GET")
	}
	s.mu.Lock()
	mutationBudgetAvailable := s.mutationUsed < s.cfg.Mutations.RequestBudget
	s.mu.Unlock()
	if !mutationBudgetAvailable {
		out.errors = append(out.errors, ScanError{Code: CodeMutationBudgetExhausted, Message: "configured mutation request budget was exhausted"})
		return finish("INCONCLUSIVE", "mutation request budget is exhausted")
	}
	if err := ctx.Err(); err != nil {
		out.errors = append(out.errors, safeRequestError(err))
		return finish("SKIPPED", "scan was cancelled before POST authorization")
	}
	policy := proofPolicy{origins: s.cfg.Target.AllowedOrigins, paths: s.cfg.Target.AllowedPaths,
		mutationPaths: s.cfg.Mutations.AllowedPaths, cleanupPaths: s.cfg.Mutations.CleanupPaths}
	test, err := newMutationTestIdentity(runID, operation, policy)
	if err != nil {
		return finish("UNSUPPORTED", "controlled POST lifecycle configuration is invalid")
	}
	body, err := controlledRequestBody(test, operation)
	if err != nil {
		return finish("UNSUPPORTED", "controlled POST body could not be safely rendered")
	}
	verificationURL := s.endpoint(operation.Verification.Path)
	baselineStatus, baselineBody, baselineType, err := s.request(ctx, actor, verificationURL)
	if err != nil {
		out.errors = append(out.errors, safeRequestError(err))
		return finish("INCONCLUSIVE", "complete pre-operation baseline could not be established")
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, baselineStatus, baselineBody, baselineType, "controlled POST baseline; completeness and marker absence evaluated"))
	baseline, err := establishMarkerBaseline(test, verificationURL, baselineStatus, baselineBody, operation.Verification, policy)
	if err != nil {
		return finish("INCONCLUSIVE", "baseline was incomplete or the generated marker was already present")
	}
	if err := ctx.Err(); err != nil {
		out.errors = append(out.errors, safeRequestError(err))
		return finish("SKIPPED", "scan was cancelled before POST dispatch")
	}
	postURL := s.endpoint(operation.Path)
	authorization, err := authorizeControlledPOST(s, runID, actor, operation, test, baseline, postURL, body)
	if err != nil {
		return finish("UNSUPPORTED", "controlled POST did not pass every execution gate")
	}
	status, _, _, postErr := s.execute(ctx, actor, requestSpec{Method: http.MethodPost, URL: postURL, Body: body,
		ContentType: "application/json", postAuth: authorization, operationID: operation.ID, runID: runID})
	out.executed = authorization.wasDispatched()
	out.postStatus = status
	if !out.executed {
		if postErr != nil {
			out.errors = append(out.errors, safeRequestError(postErr))
		}
		return finish("INCONCLUSIVE", "POST was not dispatched")
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodPost, operation.Path, status, nil, "", "controlled POST attempted; response status is not proof of state"))
	if postErr != nil {
		out.errors = append(out.errors, safeRequestError(postErr))
	}
	verificationCtx := ctx
	var verificationCancel context.CancelFunc
	if ctx.Err() != nil {
		if !holdForUpdate {
			out.errors = append(out.errors, safeRequestError(ctx.Err()))
			out.coverage.Cleanup = "NOT_POSSIBLE"
			return finish("INCONCLUSIVE", "POST may have created state, but cancellation prevented verification; cleanup is not available")
		}
		verificationCtx, verificationCancel = context.WithTimeout(context.Background(), mustCleanupDuration(s.cfg.Mutations.CleanupTimeout))
		defer verificationCancel()
		out.errors = append(out.errors, safeRequestError(ctx.Err()))
	}
	verifyStatus, verifyBody, verifyType, verifyErr := s.request(verificationCtx, actor, verificationURL)
	if verifyErr != nil && holdForUpdate && ctx.Err() != nil {
		boundedCtx, boundedCancel := context.WithTimeout(context.Background(), mustCleanupDuration(s.cfg.Mutations.CleanupTimeout))
		verifyStatus, verifyBody, verifyType, verifyErr = s.request(boundedCtx, actor, verificationURL)
		boundedCancel()
	}
	if verifyErr != nil {
		out.errors = append(out.errors, safeRequestError(verifyErr))
		out.coverage.Cleanup = "NOT_POSSIBLE"
		return finish("INCONCLUSIVE", "post-operation verification failed; created state could not be established")
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, verifyStatus, verifyBody, verifyType, "controlled resource verification; generated marker evaluated"))
	if _, absentErr := establishMarkerBaseline(test, verificationURL, verifyStatus, verifyBody, operation.Verification, policy); absentErr == nil {
		out.verifiedAbsent = true
		out.verificationComplete = true
		out.coverage.Cleanup = "CLEANUP_NOT_REQUIRED"
	}
	proof, proofErr := proveObservedResource(test, baseline, verificationURL, verifyStatus, verifyBody, operation.Verification, policy)
	if proofErr != nil {
		if !out.verifiedAbsent {
			out.coverage.Cleanup = "NOT_POSSIBLE"
			out.warnings = append(out.warnings, ScanError{Code: CodeUnsupportedOperation, Message: "POST may have created state, but controlled-resource proof failed and cleanup cannot be safely targeted"})
		}
		return finish("INCONCLUSIVE", "post-operation verification did not prove exactly one controlled resource")
	}
	out.verificationComplete = true
	out.coverage.CleanupRequired = true
	handle, handleErr := controlledHandleFromProof(proof)
	out.test, out.proof, out.handle = test, proof, handle
	if holdForUpdate && handleErr == nil {
		out.coverage.Cleanup = "HELD_FOR_CONTROLLED_OPERATION"
		out.coverage.Reason = "controlled resource proof retained for its explicitly linked mutation lifecycle"
		out.coverage.State = "TESTED"
		return out
	}
	cleanupErr := handleErr
	var candidate cleanupCandidate
	var cleanupAuthorization *cleanupExecutionAuthorization
	if cleanupErr == nil {
		resourceAuthorization, authErr := cleanupAuthorizationFromHandle(test, handle)
		cleanupErr = authErr
		if cleanupErr == nil {
			candidate, cleanupErr = constructCleanupCandidate(resourceAuthorization, handle, s.base.Scheme+"://"+s.base.Host)
		}
		if cleanupErr == nil {
			cleanupAuthorization, cleanupErr = authorizeCleanupExecution(s, runID, actor, operation, candidate)
		}
	}
	if cleanupErr != nil {
		out.coverage.Cleanup = "NOT_POSSIBLE"
		warningCode := CodeScopeRejected
		if handleErr != nil {
			warningCode = CodeInternalError
		}
		out.warnings = append(out.warnings, ScanError{Code: warningCode, Message: "controlled state was proven but cleanup authorization could not be safely prepared"})
	} else {
		out.coverage.Cleanup = s.executeControlledCleanup(runID, actor, operation, candidate, cleanupAuthorization, proof, verificationURL, &out)
	}
	refHash := sha256.Sum256([]byte(operation.Resource + "\x00" + proof.resourceID))
	resourceRef := hex.EncodeToString(refHash[:12])
	out.evidence[len(out.evidence)-1].ResourceRef = resourceRef
	out.coverage.State = "TESTED"
	switch operation.Access {
	case "DENIED":
		finding := functionFinding(operation.Classification, operation.ID, operation.Actor, operation.Owner, resource,
			operation.Relationship, http.MethodPost, operation.Path, out.evidence[len(out.evidence)-1].ID)
		finding.ResourceRef = resourceRef
		out.finding = &finding
		out.coverage.Reason = "explicitly denied POST created a positively verified controlled resource"
	case "ALLOWED":
		out.coverage.Reason = "controlled resource was verified for an explicitly allowed POST"
	default:
		out.coverage.Reason = "controlled resource was verified, but the authorization expectation is unknown"
	}
	if out.coverage.Cleanup != "CLEANUP_SUCCEEDED" {
		out.coverage.Reason += "; controlled resource cleanup did not complete successfully"
	}
	return out
}

type controlledDeleteResourceState string

const (
	deleteResourcePresent controlledDeleteResourceState = "RESOURCE_PRESENT"
	deleteResourceAbsent  controlledDeleteResourceState = "RESOURCE_ABSENT"
	deleteResourceUnknown controlledDeleteResourceState = "RESOURCE_STATE_UNKNOWN"
)

func proveControlledDeleteState(test *mutationTestIdentity, handle *controlledResourceHandle, strategy config.VerificationStrategy, rawURL string, status int, body []byte) (controlledDeleteResourceState, *controlledDeletePreProof) {
	if test == nil || handle == nil || handle.proof == nil || handle.proof.test != test || handle.resourceID != handle.proof.resourceID ||
		strategy.Type != "RESOURCE_ABSENT" || strategy.ResourceIDField != test.idField || strategy.MarkerField != test.markerField ||
		strategy.BaselineCompleteField != test.baselineCompleteField || strings.Count(strategy.Path, "{id}") != 1 || status < 200 || status >= 300 {
		return deleteResourceUnknown, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != strings.Replace(strategy.Path, "{id}", url.PathEscape(handle.resourceID), 1) || !validControlledField(strategy.ResourceIDField) ||
		!scope.Match(rawURL, test.policy.origins, test.policy.paths) {
		return deleteResourceUnknown, nil
	}
	root, err := decodeJSON(body)
	if err != nil {
		return deleteResourceUnknown, nil
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return deleteResourceUnknown, nil
	}
	complete, ok := jsonPath(obj, strategy.BaselineCompleteField)
	if !ok || complete != true {
		return deleteResourceUnknown, nil
	}
	matching, idSeen, markerSeen := 0, 0, 0
	walkObjects(root, func(item map[string]any) {
		id, hasID := jsonPath(item, strategy.ResourceIDField)
		marker, hasMarker := jsonPath(item, strategy.MarkerField)
		idMatches := hasID && id == handle.resourceID
		markerMatches := hasMarker && marker == test.marker
		if idMatches {
			idSeen++
		}
		if markerMatches {
			markerSeen++
		}
		if idMatches && markerMatches {
			matching++
		}
	})
	if matching == 1 && idSeen == 1 && markerSeen == 1 {
		responseDigest := sha256.Sum256(body)
		proof := &controlledDeletePreProof{test: test, handle: handle, verificationURL: rawURL, verificationPath: strategy.Path,
			resourceID: handle.resourceID, responseDigest: hex.EncodeToString(responseDigest[:]), observedAt: time.Now(), state: deleteResourcePresent}
		return deleteResourcePresent, proof
	}
	if matching == 0 && idSeen == 0 && markerSeen == 0 {
		return deleteResourceAbsent, nil
	}
	return deleteResourceUnknown, nil
}

func controlledDeleteRelationshipProof(c config.Config, operation config.Operation, handle *controlledResourceHandle, body []byte) ([]RelationshipProof, bool) {
	if operation.Classification != "RELATIONSHIP" {
		return nil, true
	}
	var relation *config.Relationship
	for i := range c.Resources {
		if c.Resources[i].Name != operation.Resource {
			continue
		}
		for j := range c.Resources[i].Relationships {
			if c.Resources[i].Relationships[j].Name == operation.Relationship {
				relation = &c.Resources[i].Relationships[j]
				break
			}
		}
	}
	var actor, owner *config.Identity
	for i := range c.Identities {
		if c.Identities[i].ID == operation.Actor {
			actor = &c.Identities[i]
		}
		if c.Identities[i].ID == operation.Owner {
			owner = &c.Identities[i]
		}
	}
	if relation == nil || actor == nil || owner == nil || handle == nil {
		return nil, false
	}
	root, err := decodeJSON(body)
	if err != nil {
		return nil, false
	}
	var resourceContext string
	matches := 0
	walkObjects(root, func(object map[string]any) {
		id, hasID := jsonPath(object, handle.proof.test.idField)
		marker, hasMarker := jsonPath(object, handle.proof.test.markerField)
		if !hasID || id != handle.resourceID || !hasMarker || marker != handle.proof.test.marker {
			return
		}
		value, found := jsonPath(object, relation.Field)
		text, valid := scalarString(value)
		if found && valid && strings.TrimSpace(text) != "" {
			matches++
			resourceContext = text
		}
	})
	actorContext, actorOK := actor.Contexts[relation.Name]
	ownerContext, ownerOK := owner.Contexts[relation.Name]
	if matches != 1 || !actorOK || !ownerOK || actorContext == resourceContext || ownerContext != resourceContext {
		return nil, false
	}
	return []RelationshipProof{{Name: relation.Name, Kind: relation.Kind,
		ActorContextRef:    tupleDigest([]string{relation.Name}, []string{actorContext}, false),
		ResourceContextRef: tupleDigest([]string{relation.Name}, []string{resourceContext}, false), Boundary: "different"}}, true
}

func (s *Scanner) executeControlledDelete(ctx context.Context, runID string, doc openapi.Document, actor config.Identity,
	operation, setup config.Operation, setupOutcome controlledPostOutcome, resource, label string) (out controlledPostOutcome) {
	out.coverage = Coverage{Identity: operation.Actor, Resource: resource, Operation: label, CleanupRequired: true, DeleteState: string(deleteResourceUnknown)}
	finish := func(state, reason string) controlledPostOutcome {
		out.coverage.State, out.coverage.Reason = state, reason
		return out
	}
	if setupOutcome.handle == nil || setupOutcome.proof == nil || setupOutcome.test == nil || operation.ControlledResourceOperationID != setup.ID {
		out.coverage.CleanupRequired = false
		return finish("NO_DISPOSABLE_RESOURCE", "a current lifecycle ControlledResourceHandle is required")
	}
	setupActor := config.Identity{}
	for _, configured := range s.cfg.Identities {
		if configured.ID == setup.Actor {
			setupActor = configured
			break
		}
	}
	resourceAuthorization, err := cleanupAuthorizationFromHandle(setupOutcome.test, setupOutcome.handle)
	var plannedCleanup cleanupCandidate
	var cleanupAuth *cleanupExecutionAuthorization
	if err == nil {
		plannedCleanup, err = constructCleanupCandidate(resourceAuthorization, setupOutcome.handle, s.base.Scheme+"://"+s.base.Host)
	}
	if err == nil {
		cleanupAuth, err = authorizeCleanupExecution(s, runID, setupActor, setup, plannedCleanup)
	}
	if err != nil {
		return finish("INCONCLUSIVE", "proof-bound fallback cleanup could not be planned before the DELETE attack")
	}
	cleanup := func() {
		out.coverage.Cleanup = s.executeControlledCleanup(runID, setupActor, setup, plannedCleanup, cleanupAuth, setupOutcome.proof, s.endpoint(setup.Verification.Path), &out)
	}
	if !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, http.MethodDelete) || !allowedConfiguredPath(operation.Path, s.cfg.Mutations.AllowedPaths) {
		out.coverage.CleanupRequired = true
		out.coverage.State = "SKIPPED_BY_POLICY"
		out.coverage.Reason = "controlled DELETE attack is disabled by explicit policy"
		cleanup()
		return out
	}
	if !doc.HasOperation(operation.Path, http.MethodDelete) || !doc.HasGet(operation.Verification.Path) || !doc.HasGet(setup.Verification.Path) {
		out.coverage.State = "INCONCLUSIVE"
		out.coverage.Reason = "OpenAPI must define the controlled DELETE and safe pre/post state GETs"
		cleanup()
		return out
	}
	target := s.endpoint(strings.Replace(operation.Path, "{id}", url.PathEscape(setupOutcome.handle.resourceID), 1))
	verifyURL := s.endpoint(strings.Replace(operation.Verification.Path, "{id}", url.PathEscape(setupOutcome.handle.resourceID), 1))
	if !scope.Match(target, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(verifyURL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		out.coverage.State, out.coverage.Reason = "INCONCLUSIVE", "controlled DELETE or verification target is outside scope"
		cleanup()
		return out
	}
	if ctx.Err() != nil {
		out.errors = append(out.errors, safeRequestError(ctx.Err()))
		out.coverage.State, out.coverage.Reason = "SKIPPED", "scan was cancelled before attack DELETE"
		cleanup()
		return out
	}
	// The creator identity establishes the live pre-state; the configured actor is
	// used only for the one authorization attack.
	preStatus, preBody, preType, preErr := s.request(ctx, setupActor, verifyURL)
	if preErr != nil {
		out.errors = append(out.errors, safeRequestError(preErr))
		out.coverage.State, out.coverage.Reason = "INCOMPLETE_PRE_DELETE_PROOF", "current resource existence could not be established"
		cleanup()
		return out
	}
	out.evidence = append(out.evidence, evidence(setup.Actor, http.MethodGet, operation.Verification.Path, preStatus, preBody, preType, "controlled DELETE pre-state; exact marker, resource ID, and completeness evaluated"))
	preState, preProof := proveControlledDeleteState(setupOutcome.test, setupOutcome.handle, operation.Verification, verifyURL, preStatus, preBody)
	if preType != "application/json" && preType != "application/problem+json" || preState != deleteResourcePresent {
		out.coverage.State, out.coverage.Reason = "INCOMPLETE_PRE_DELETE_PROOF", "exact controlled marker and resource ID were not positively established immediately before DELETE"
		cleanup()
		return out
	}
	relationshipProof, relationshipOK := controlledDeleteRelationshipProof(s.cfg, operation, setupOutcome.handle, preBody)
	if !relationshipOK {
		out.coverage.State, out.coverage.Reason = "INCOMPLETE_PRE_DELETE_PROOF", "controlled resource relationship does not prove the configured owner and actor boundary"
		cleanup()
		return out
	}
	attackAuth, err := authorizeControlledDelete(s, runID, actor, operation, setup, setupOutcome.handle, preProof, relationshipProof, target)
	if err != nil {
		out.coverage.State, out.coverage.Reason = "SKIPPED_BY_POLICY", "DELETE attack capability could not be issued under all explicit gates"
		cleanup()
		return out
	}
	if ctx.Err() != nil {
		out.errors = append(out.errors, safeRequestError(ctx.Err()))
		out.coverage.State, out.coverage.Reason = "SKIPPED", "scan was cancelled before attack DELETE dispatch"
		cleanup()
		return out
	}
	status, _, _, attackErr := s.execute(ctx, actor, requestSpec{Method: http.MethodDelete, URL: target, attackDeleteAuth: attackAuth,
		operationID: operation.ID, operationPath: operation.Path, runID: runID})
	out.executed = attackAuth.wasConsumed()
	out.mutationStatus = status
	out.coverage.DeleteTested = out.executed
	if out.executed {
		out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodDelete, operation.Path, status, nil, "", "one controlled authorization DELETE attempted; status does not establish resource removal"))
	}
	if attackErr != nil {
		out.errors = append(out.errors, safeRequestError(attackErr))
	}
	if !out.executed {
		out.coverage.State, out.coverage.Reason = "INCONCLUSIVE", "attack DELETE was not dispatched"
		cleanup()
		return out
	}
	verifyCtx, cancel := context.WithTimeout(context.Background(), mustCleanupDuration(s.cfg.Mutations.CleanupTimeout))
	defer cancel()
	postStatus, postBody, postType, postErr := s.execute(verifyCtx, setupActor, requestSpec{Method: http.MethodGet, URL: verifyURL, cleanupBudget: true})
	postState := deleteResourceUnknown
	if postErr != nil {
		out.errors = append(out.errors, safeRequestError(postErr))
	} else {
		out.evidence = append(out.evidence, evidence(setup.Actor, http.MethodGet, operation.Verification.Path, postStatus, postBody, postType, "controlled DELETE post-state; exact marker, resource ID, and completeness evaluated"))
		if postType == "application/json" || postType == "application/problem+json" {
			postState, _ = proveControlledDeleteState(setupOutcome.test, setupOutcome.handle, operation.Verification, verifyURL, postStatus, postBody)
		}
	}
	out.coverage.DeleteState = string(postState)
	switch postState {
	case deleteResourceAbsent:
		out.coverage.Cleanup = "CLEANUP_NOT_REQUIRED"
		out.coverage.CleanupRequired = false
		out.coverage.State = "VERIFIED_ABSENT"
		out.coverage.Reason = "resource positively existed before attack DELETE and was positively absent afterward"
		refHash := sha256.Sum256([]byte(operation.Resource + "\x00" + setupOutcome.handle.resourceID))
		resourceRef := hex.EncodeToString(refHash[:12])
		if len(out.evidence) > 0 {
			out.evidence[len(out.evidence)-1].ResourceRef = resourceRef
		}
		if operation.Access == "DENIED" {
			out.coverage.State = "VERIFIED_DENIED_DELETION"
			finding := functionFinding(operation.Classification, operation.ID, operation.Actor, operation.Owner, resource, operation.Relationship, http.MethodDelete, operation.Path, out.evidence[len(out.evidence)-1].ID)
			finding.ResourceRef = resourceRef
			finding.RelationshipProof = relationshipProof
			out.finding = &finding
		}
	case deleteResourcePresent:
		out.coverage.State = "TESTED"
		out.coverage.Reason = "safe GET verified that the controlled resource remains after attack DELETE"
		cleanup()
	case deleteResourceUnknown:
		out.coverage.State = "ATTACK_INCONCLUSIVE"
		out.coverage.Reason = "resource existence after attack DELETE could not be determined; no cleanup DELETE was sent"
	}
	return out
}

func (s *Scanner) executeControlledUpdate(ctx context.Context, runID string, doc openapi.Document, actor config.Identity, operation, setup config.Operation,
	setupOutcome controlledPostOutcome, resource, label string) (out controlledPostOutcome) {
	out.coverage = Coverage{Identity: operation.Actor, Resource: resource, Operation: label, CleanupRequired: true}
	var plannedCleanup cleanupCandidate
	var plannedCleanupAuth *cleanupExecutionAuthorization
	cleanupReady := false
	defer func() {
		if !cleanupReady {
			out.coverage.Cleanup = "NOT_POSSIBLE"
			out.warnings = append(out.warnings, ScanError{Code: CodeScopeRejected, Message: "controlled resource cleanup could not be planned before update"})
			return
		}
		setupActor := config.Identity{}
		for _, identity := range s.cfg.Identities {
			if identity.ID == setup.Actor {
				setupActor = identity
				break
			}
		}
		out.coverage.Cleanup = s.executeControlledCleanup(runID, setupActor, setup, plannedCleanup, plannedCleanupAuth, setupOutcome.proof, s.endpoint(setup.Verification.Path), &out)
	}()
	finish := func(state, reason string) controlledPostOutcome {
		out.coverage.State = state
		out.coverage.Reason = reason
		return out
	}
	if !s.cfg.Mutations.Enabled || !containsAllowedMethod(s.cfg.Mutations.AllowedMethods, config.NormalizeMethod(operation.Method)) || !allowedConfiguredPath(operation.Path, s.cfg.Mutations.AllowedPaths) {
		return finish("UNSUPPORTED", "controlled PUT/PATCH is not explicitly allowlisted")
	}
	if setupOutcome.handle == nil || setupOutcome.proof == nil || setupOutcome.test == nil || operation.ControlledResourceOperationID != setup.ID || operation.Resource != setup.Resource {
		return finish("INCONCLUSIVE", "valid controlled-resource handle is required before PUT/PATCH")
	}
	setupActor := config.Identity{}
	for _, identity := range s.cfg.Identities {
		if identity.ID == setup.Actor {
			setupActor = identity
			break
		}
	}
	resourceAuth, cleanupErr := cleanupAuthorizationFromHandle(setupOutcome.test, setupOutcome.handle)
	if cleanupErr == nil {
		plannedCleanup, cleanupErr = constructCleanupCandidate(resourceAuth, setupOutcome.handle, s.base.Scheme+"://"+s.base.Host)
	}
	if cleanupErr == nil {
		plannedCleanupAuth, cleanupErr = authorizeCleanupExecution(s, runID, setupActor, setup, plannedCleanup)
	}
	if cleanupErr != nil {
		return finish("UNSUPPORTED", "proof-bound fallback cleanup could not be planned before update")
	}
	cleanupReady = true
	if !doc.HasOperation(operation.Path, operation.Method) || !doc.HasGet(operation.Verification.Path) {
		return finish("UNSUPPORTED", "OpenAPI must define the configured PUT/PATCH and safe state-verification GET")
	}
	body, err := controlledUpdateBody(setupOutcome.test, operation)
	if err != nil {
		return finish("UNSUPPORTED", "controlled PUT/PATCH body could not be safely rendered")
	}
	desired, ok := readJSONField(body, operation.Verification.Field)
	if !ok || !safeStateValue(desired) {
		return finish("UNSUPPORTED", "configured desired state is not a supported scalar")
	}
	targetPath := strings.Replace(operation.Path, "{id}", url.PathEscape(setupOutcome.handle.resourceID), 1)
	statePath := strings.Replace(operation.Verification.Path, "{id}", url.PathEscape(setupOutcome.handle.resourceID), 1)
	targetURL, stateURL := s.endpoint(targetPath), s.endpoint(statePath)
	if strings.ContainsAny(targetPath, "{}") || strings.ContainsAny(statePath, "{}") || !scope.Match(targetURL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.Match(stateURL, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		return finish("UNSUPPORTED", "controlled update or verification target is outside scope")
	}
	if ctx.Err() != nil {
		out.errors = append(out.errors, safeRequestError(ctx.Err()))
		return finish("SKIPPED", "scan was cancelled before PUT/PATCH")
	}
	beforeStatus, beforeBody, beforeType, beforeErr := s.request(ctx, actor, stateURL)
	if beforeErr != nil {
		out.errors = append(out.errors, safeRequestError(beforeErr))
		return finish("INCONCLUSIVE", "complete controlled-resource pre-state could not be established")
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, beforeStatus, beforeBody, beforeType, "controlled mutation pre-state; completeness and configured state evaluated"))
	if beforeType != "application/json" && beforeType != "application/problem+json" {
		return finish("INCONCLUSIVE", "controlled mutation pre-state was not JSON")
	}
	before, err := proveControlledState(setupOutcome.test, setupOutcome.handle, operation, stateURL, beforeStatus, beforeBody)
	if err != nil {
		return finish("INCONCLUSIVE", "complete and unambiguous controlled-resource pre-state is required")
	}
	relationshipProof, relationshipOK := controlledDeleteRelationshipProof(s.cfg, operation, setupOutcome.handle, beforeBody)
	if !relationshipOK {
		return finish("INCONCLUSIVE", "controlled update relationship boundary proof is incomplete")
	}
	if jsonEqual(before.value, desired) {
		out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
		return finish("INCONCLUSIVE", "requested state already existed; no-op mutation was not sent")
	}
	var restorationBody []byte
	var restorationAuth *controlledMutationAuthorization
	if operation.RestoreBody != nil {
		template, marshalErr := json.Marshal(operation.RestoreBody)
		if marshalErr == nil {
			restorationBody, marshalErr = replaceRestoreState(template, operation.Verification.Field, before.value)
		}
		if marshalErr == nil {
			restorationAuth, marshalErr = authorizeControlledMutation(s, runID, actor, operation, setupOutcome.handle, before, relationshipProof, targetURL, restorationBody, true)
		}
		if marshalErr != nil {
			out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
			return finish("UNSUPPORTED", "controlled restoration could not be planned before update")
		}
	}
	if ctx.Err() != nil {
		out.errors = append(out.errors, safeRequestError(ctx.Err()))
		out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
		return finish("SKIPPED", "scan was cancelled before PUT/PATCH dispatch")
	}
	auth, err := authorizeControlledMutation(s, runID, actor, operation, setupOutcome.handle, before, relationshipProof, targetURL, body, false)
	if err != nil {
		out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
		return finish("UNSUPPORTED", "controlled mutation capability could not be issued")
	}
	status, _, _, mutationErr := s.execute(ctx, actor, requestSpec{Method: config.NormalizeMethod(operation.Method), URL: targetURL, Body: body, ContentType: "application/json", mutationAuth: auth, operationID: operation.ID, operationPath: operation.Path, runID: runID})
	out.executed = auth.wasDispatched()
	out.mutationStatus = status
	out.evidence = append(out.evidence, evidence(operation.Actor, config.NormalizeMethod(operation.Method), operation.Path, status, nil, "", "controlled mutation attempted; response status and body are not proof of state change"))
	if mutationErr != nil {
		out.errors = append(out.errors, safeRequestError(mutationErr))
	}
	potentiallyChanged := out.executed
	var after *controlledStateProof
	if potentiallyChanged {
		verifyCtx, cancel := context.WithTimeout(context.Background(), mustCleanupDuration(s.cfg.Mutations.CleanupTimeout))
		defer cancel()
		afterStatus, afterBody, afterType, afterErr := s.request(verifyCtx, actor, stateURL)
		if afterErr != nil {
			out.errors = append(out.errors, safeRequestError(afterErr))
		} else {
			out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, afterStatus, afterBody, afterType, "controlled mutation post-state; complete state and expected transition evaluated"))
			if afterType == "application/json" || afterType == "application/problem+json" {
				after, _ = proveControlledState(setupOutcome.test, setupOutcome.handle, operation, stateURL, afterStatus, afterBody)
			}
		}
	}
	verifiedTransition := after != nil && jsonEqual(after.value, desired) && !jsonEqual(before.value, after.value)
	stateUnchanged := after != nil && jsonEqual(after.value, before.value)
	out.verifiedUnchanged = stateUnchanged
	if verifiedTransition {
		out.coverage.State = "TESTED"
		out.coverage.Reason = "safe GET verified the configured state transition after controlled PUT/PATCH"
		refHash := sha256.Sum256([]byte(operation.Resource + "\x00" + setupOutcome.handle.resourceID))
		resourceRef := hex.EncodeToString(refHash[:])
		if len(out.evidence) > 0 {
			out.evidence[len(out.evidence)-1].ResourceRef = resourceRef
		}
		if operation.Access == "DENIED" {
			finding := functionFinding(operation.Classification, operation.ID, operation.Actor, operation.Owner, resource, operation.Relationship, config.NormalizeMethod(operation.Method), operation.Path, out.evidence[len(out.evidence)-1].ID)
			finding.ResourceRef = resourceRef
			finding.RelationshipProof = relationshipProof
			out.finding = &finding
		}
	} else if stateUnchanged {
		out.coverage.State = "TESTED"
		out.coverage.Reason = "safe GET verified that the configured state did not change"
	} else if potentiallyChanged {
		out.coverage.State = "INCONCLUSIVE"
		out.coverage.Reason = "post-mutation state could not prove the configured transition"
	} else {
		out.coverage.State = "INCONCLUSIVE"
		out.coverage.Reason = "controlled PUT/PATCH was not dispatched"
	}
	if !potentiallyChanged || stateUnchanged {
		out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
		return out
	}
	if operation.RestoreBody == nil {
		out.coverage.Restoration = "RESTORATION_NOT_REQUIRED"
		return out
	}
	if err := s.restoreControlledState(runID, actor, operation, setupOutcome, before, targetURL, stateURL, restorationBody, restorationAuth, &out); err != nil {
		out.coverage.Restoration = "RESTORATION_FAILED"
		if errors.Is(err, errRestorationInconclusive) {
			out.coverage.Restoration = "RESTORATION_INCONCLUSIVE"
		}
		out.warnings = append(out.warnings, ScanError{Code: CodeUnsupportedOperation, Message: "controlled resource restoration failed or could not be verified"})
	}
	return out
}

func mustCleanupDuration(raw string) time.Duration {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > 10*time.Second {
		return time.Second
	}
	return d
}

func (s *Scanner) restoreControlledState(runID string, actor config.Identity, operation config.Operation, setupOutcome controlledPostOutcome, before *controlledStateProof, targetURL, stateURL string, body []byte, auth *controlledMutationAuthorization, out *controlledPostOutcome) error {
	ctx, cancel := context.WithTimeout(context.Background(), mustCleanupDuration(s.cfg.Mutations.CleanupTimeout))
	defer cancel()
	status, _, _, restoreErr := s.execute(ctx, actor, requestSpec{Method: config.NormalizeMethod(operation.Method), URL: targetURL, Body: body, ContentType: "application/json", mutationAuth: auth, operationID: operation.ID, operationPath: operation.Path, runID: runID})
	out.evidence = append(out.evidence, evidence(operation.Actor, config.NormalizeMethod(operation.Method), operation.Path, status, nil, "", "controlled state restoration attempted; safe GET verification required"))
	if restoreErr != nil {
		out.warnings = append(out.warnings, safeRequestError(restoreErr))
	}
	verifyStatus, verifyBody, verifyType, verifyErr := s.execute(ctx, actor, requestSpec{Method: http.MethodGet, URL: stateURL, cleanupBudget: true})
	if verifyErr != nil {
		return errRestorationInconclusive
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, verifyStatus, verifyBody, verifyType, "controlled restoration verification; original configured state evaluated"))
	if verifyType != "application/json" && verifyType != "application/problem+json" {
		return errRestorationInconclusive
	}
	restored, err := proveControlledState(setupOutcome.test, setupOutcome.handle, operation, stateURL, verifyStatus, verifyBody)
	if err != nil {
		return errRestorationInconclusive
	}
	if !jsonEqual(restored.value, before.value) {
		return errors.New("original state was not restored")
	}
	out.coverage.Restoration = "RESTORATION_SUCCEEDED"
	return nil
}

func (s *Scanner) executeControlledCleanup(runID string, actor config.Identity, operation config.Operation, candidate cleanupCandidate,
	authorization *cleanupExecutionAuthorization, proof *controlledResourceProof, verificationURL string, out *controlledPostOutcome) string {
	duration, err := time.ParseDuration(s.cfg.Mutations.CleanupTimeout)
	if err != nil || duration <= 0 || duration > 10*time.Second {
		out.warnings = append(out.warnings, ScanError{Code: CodeUnsupportedOperation, Message: "controlled cleanup timeout is invalid"})
		return "NOT_POSSIBLE"
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	out.coverage.CleanupAttempted = true
	status, _, _, deleteErr := s.execute(ctx, actor, requestSpec{Method: http.MethodDelete, URL: candidate.url,
		cleanupAuth: authorization, operationID: operation.ID, runID: runID})
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodDelete, operation.Verification.CleanupPath, status, nil, "", "controlled cleanup attempted; status is not proof of removal"))
	if deleteErr != nil {
		out.warnings = append(out.warnings, safeRequestError(deleteErr))
	}
	verifyStatus, verifyBody, verifyType, verifyErr := s.execute(ctx, actor, requestSpec{Method: http.MethodGet, URL: verificationURL, cleanupBudget: true})
	if verifyErr != nil {
		out.warnings = append(out.warnings, safeRequestError(verifyErr))
		return "CLEANUP_INCONCLUSIVE"
	}
	out.evidence = append(out.evidence, evidence(operation.Actor, http.MethodGet, operation.Verification.Path, verifyStatus, verifyBody, verifyType, "controlled cleanup verification; complete state and resource absence evaluated"))
	if verifyType != "application/json" && verifyType != "application/problem+json" {
		return "CLEANUP_INCONCLUSIVE"
	}
	root, decodeErr := decodeJSON(verifyBody)
	object, ok := root.(map[string]any)
	if decodeErr != nil || !ok || verifyStatus < 200 || verifyStatus >= 300 {
		return "CLEANUP_INCONCLUSIVE"
	}
	complete, present := jsonPath(object, operation.Verification.BaselineCompleteField)
	if !present || complete != true {
		return "CLEANUP_INCONCLUSIVE"
	}
	markerMatches := countMarkerMatches(root, operation.Verification.MarkerField, proof.test.marker)
	idPresent := false
	walkObjects(root, func(item map[string]any) {
		if value, found := jsonPath(item, operation.Verification.ResourceIDField); found {
			if value == proof.resourceID {
				idPresent = true
			}
		}
	})
	if markerMatches == 0 && !idPresent {
		return "CLEANUP_SUCCEEDED"
	}
	out.warnings = append(out.warnings, ScanError{Code: CodeUnsupportedOperation, Message: "controlled resource remains after cleanup verification"})
	return "CLEANUP_FAILED"
}

func configuredSuccess(body []byte, field string) bool {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return false
	}
	value, ok := jsonFieldPath(root, field)
	if !ok {
		value, ok = jsonFieldPath(root, "data."+field)
	}
	if !ok {
		return false
	}
	switch value := value.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case bool:
		return value
	case float64:
		return value > 0
	default:
		return false
	}
}

func (s *Scanner) discoverCollection(ctx context.Context, identity config.Identity, resource config.Resource) ([]candidate, []pageObservation, bool, error) {
	pagination := resource.Pagination
	maxPages, pageSize := 1, 0
	allowedKeys := []string{}
	if pagination != nil {
		maxPages, pageSize = pagination.MaxPages, pagination.PageSize
		switch pagination.Type {
		case "page":
			allowedKeys = []string{pagination.PageParam, pagination.PageSizeParam}
		case "offset":
			allowedKeys = []string{pagination.OffsetParam, pagination.LimitParam}
		case "cursor":
			allowedKeys = []string{pagination.CursorParam}
		}
	}
	all := make([]candidate, 0)
	pages := make([]pageObservation, 0, maxPages)
	seenIDs := map[string]bool{}
	seenCursors := map[string]bool{}
	cursor := ""
	for pageIndex := 0; pageIndex < maxPages; pageIndex++ {
		endpoint := s.endpoint(resource.Collection)
		if pagination != nil {
			parsed, err := url.Parse(endpoint)
			if err != nil {
				return all, pages, false, fmt.Errorf("invalid collection URL")
			}
			query := parsed.Query()
			switch pagination.Type {
			case "page":
				query.Set(pagination.PageParam, strconv.Itoa(pagination.StartPage+pageIndex))
				query.Set(pagination.PageSizeParam, strconv.Itoa(pageSize))
			case "offset":
				query.Set(pagination.OffsetParam, strconv.Itoa(pageIndex*pageSize))
				query.Set(pagination.LimitParam, strconv.Itoa(pageSize))
			case "cursor":
				if cursor != "" {
					query.Set(pagination.CursorParam, cursor)
				}
			}
			parsed.RawQuery = query.Encode()
			endpoint = parsed.String()
		}
		status, body, contentType, err := s.requestWithQuery(ctx, identity, endpoint, allowedKeys)
		if err != nil {
			return all, pages, false, err
		}
		pages = append(pages, pageObservation{Status: status, Body: body, ContentType: contentType})
		if status < 200 || status >= 300 {
			return all, pages, false, nil
		}
		pageCandidates, err := extractResourceCandidates(body, resourceIdentifiers(resource), resourceVerificationFields(resource), resourceRelationships(resource))
		if err != nil {
			return all, pages, false, nil
		}
		if len(pageCandidates) > pageSize && pagination != nil {
			return all, pages, false, nil
		}
		for _, item := range pageCandidates {
			if seenIDs[item.ID] {
				return all, pages, false, nil
			}
			seenIDs[item.ID] = true
			all = append(all, item)
			if len(all) > s.cfg.Limits.MaxObjects {
				return all[:s.cfg.Limits.MaxObjects], pages, false, nil
			}
		}
		if pagination == nil {
			return all, pages, len(all) > 0, nil
		}
		switch pagination.Type {
		case "page", "offset":
			if len(pageCandidates) < pageSize {
				return all, pages, len(all) > 0, nil
			}
		case "cursor":
			nextValue, found := jsonFieldPathFromBytes(body, pagination.NextCursorField)
			if !found || nextValue == nil {
				return all, pages, len(all) > 0, nil
			}
			next, ok := scalarString(nextValue)
			if !ok || next == "" {
				return all, pages, false, nil
			}
			if seenCursors[next] {
				return all, pages, false, nil
			}
			seenCursors[next] = true
			cursor = next
		}
		if pageIndex+1 == maxPages {
			return all, pages, false, nil
		}
	}
	return all, pages, false, nil
}

func jsonFieldPathFromBytes(body []byte, field string) (any, bool) {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return nil, false
	}
	return jsonFieldPath(root, field)
}

func functionFinding(classification, operation, actor, owner, resource, relationship, method, path, evidenceID string) Finding {
	method = config.NormalizeMethod(method)
	key := strings.Join([]string{strings.ToLower(classification), operation, actor, owner, resource, relationship, method, path}, "\x00")
	hash := sha256.Sum256([]byte(key))
	if resource == "" {
		resource = "operation:" + operation
	}
	return Finding{Fingerprint: hex.EncodeToString(hash[:]), Type: classification, Severity: "high", Resource: resource, Relationship: relationship, VictimIdentity: owner, AccessingIdentity: actor, Method: method, Path: path, EvidenceIDs: []string{evidenceID}}
}

func safeRequestError(err error) ScanError {
	message := "outbound request could not be completed"
	code := CodeTargetUnreachable
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ScanError{Code: CodeTimeout, Message: "configured request timeout was reached"}
		}
		if errors.Is(err, context.Canceled) {
			return ScanError{Code: CodeCancelled, Message: "scan was cancelled before completion"}
		}
		switch err.Error() {
		case "request budget exhausted":
			code, message = CodeRequestBudgetExhausted, "configured request budget was exhausted"
		case "mutation request budget exhausted":
			code, message = CodeMutationBudgetExhausted, "configured mutation request budget was exhausted"
		case "response exceeded configured size limit":
			code, message = CodeResponseTooLarge, "response exceeded configured size limit"
		case "request outside configured scope":
			code, message = CodeScopeRejected, "request was rejected by configured scope"
		}
	}
	return ScanError{Code: code, Message: message}
}
func (s *Scanner) endpoint(path string) string {
	u := *s.base
	u.Path = strings.TrimSuffix(s.base.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	u.RawPath = ""
	return u.String()
}
func extractCandidates(b []byte, idField, verifyField string) ([]candidate, error) {
	return extractResourceCandidates(b, []config.IdentifierField{{Path: idField, Parameter: "id"}}, []string{verifyField}, nil)
}

func extractResourceCandidates(b []byte, identifiers []config.IdentifierField, verificationFields []string, relationships []config.Relationship) ([]candidate, error) {
	var v any
	if e := json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	var arr []any
	switch x := v.(type) {
	case []any:
		arr = x
	case map[string]any:
		if items, unique := collectionItems(x, 0); unique {
			arr = items
		}
	}
	ids := []candidate{}
	seen := map[string]bool{}
	for _, it := range arr {
		object, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("collection item is not an object")
		}
		pathValues := make(map[string]string, len(identifiers))
		identifierValues := make(map[string]string, len(identifiers))
		paths := make([]string, 0, len(identifiers))
		values := make([]string, 0, len(identifiers))
		for _, field := range identifiers {
			value, found := explicitField(object, field.Path)
			text, valid := scalarString(value)
			if !found || !valid {
				return nil, fmt.Errorf("collection item identifier is incomplete")
			}
			pathValues[field.Parameter] = text
			identifierValues[field.Path] = text
			paths = append(paths, field.Path)
			values = append(values, text)
		}
		relationshipValues := make(map[string]string, len(relationships))
		for _, relation := range relationships {
			value, found := explicitField(object, relation.Field)
			text, valid := scalarString(value)
			if !found || !valid || strings.TrimSpace(text) == "" {
				return nil, fmt.Errorf("collection relationship evidence is incomplete")
			}
			relationshipValues[relation.Name] = text
		}
		resourceRef := tupleDigest(paths, values, false)
		verifyPaths := make([]string, 0, len(verificationFields))
		verifyRaw := make(map[string]string, len(verificationFields))
		verifyValues := make([]string, 0, len(verificationFields))
		completeVerification := len(verificationFields) > 0
		for _, field := range verificationFields {
			value, found := explicitField(object, field)
			text, valid := scalarString(value)
			if !found || !valid || strings.TrimSpace(text) == "" {
				completeVerification = false
				break
			}
			verifyPaths = append(verifyPaths, field)
			verifyRaw[field] = text
			verifyValues = append(verifyValues, text)
		}
		verifyDigest := ""
		if completeVerification && !valuesIntersect(identifierValues, verifyRaw) {
			verifyDigest = tupleDigest(verifyPaths, verifyValues, true)
		}
		if seen[resourceRef] {
			return nil, fmt.Errorf("duplicate candidate identifier tuple")
		}
		seen[resourceRef] = true
		ids = append(ids, candidate{ID: resourceRef, Verify: verifyDigest, PathValues: pathValues, RelationshipValues: relationshipValues, Baseline: object})
	}
	return ids, nil
}

func resourceIdentifiers(resource config.Resource) []config.IdentifierField {
	if len(resource.IdentifierFields) > 0 {
		return resource.IdentifierFields
	}
	return []config.IdentifierField{{Path: resource.IDField, Parameter: "id"}}
}

func resourceVerificationFields(resource config.Resource) []string {
	if len(resource.VerificationFields) > 0 {
		return resource.VerificationFields
	}
	return []string{resource.VerifyField}
}

func resourceRelationships(resource config.Resource) []config.Relationship {
	return resource.Relationships
}

func explicitField(object any, field string) (any, bool) {
	value, ok := jsonFieldPath(object, field)
	if !ok {
		value, ok = jsonFieldPath(object, "data."+field)
	}
	return value, ok
}

func tupleDigest(paths, values []string, normalize bool) string {
	hash := sha256.New()
	for i, field := range paths {
		value := values[i]
		if normalize {
			value = verificationValue(value)
		}
		_, _ = fmt.Fprintf(hash, "%d:%s%d:%s", len(field), field, len(value), value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func extractResourceRef(body []byte, identifiers []config.IdentifierField, relationships []config.Relationship) (string, map[string]string, map[string]string, bool) {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return "", nil, nil, false
	}
	paths := make([]string, 0, len(identifiers))
	values := make([]string, 0, len(identifiers))
	byPath := make(map[string]string, len(identifiers))
	for _, field := range identifiers {
		value, found := explicitField(root, field.Path)
		text, valid := scalarString(value)
		if !found || !valid {
			return "", nil, nil, false
		}
		paths = append(paths, field.Path)
		values = append(values, text)
		byPath[field.Path] = text
	}
	relationValues := make(map[string]string, len(relationships))
	for _, relation := range relationships {
		value, found := explicitField(root, relation.Field)
		text, valid := scalarString(value)
		if !found || !valid || strings.TrimSpace(text) == "" {
			return "", nil, nil, false
		}
		relationValues[relation.Name] = text
	}
	return tupleDigest(paths, values, false), byPath, relationValues, len(paths) > 0
}

func extractRelationships(body []byte, relationships []config.Relationship) (map[string]string, bool) {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return nil, false
	}
	values := make(map[string]string, len(relationships))
	for _, relation := range relationships {
		value, found := explicitField(root, relation.Field)
		text, valid := scalarString(value)
		if !found || !valid || strings.TrimSpace(text) == "" {
			return values, false
		}
		values[relation.Name] = text
	}
	return values, true
}

func relationshipsEqual(expected, actual map[string]string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for name, value := range expected {
		if actual[name] != value {
			return false
		}
	}
	return true
}

func relationshipBoundaries(contexts map[string]string, relations []config.Relationship, values map[string]string) ([]RelationshipProof, bool) {
	proofs := make([]RelationshipProof, 0, len(relations))
	complete := true
	for _, relation := range relations {
		actorValue, actorOK := contexts[relation.Name]
		resourceValue, resourceOK := values[relation.Name]
		if !actorOK || !resourceOK {
			complete = false
			continue
		}
		boundary := "same"
		if actorValue != resourceValue {
			boundary = "different"
		}
		proofs = append(proofs, RelationshipProof{
			Name: relation.Name, Kind: relation.Kind,
			ActorContextRef:    tupleDigest([]string{relation.Name}, []string{actorValue}, false),
			ResourceContextRef: tupleDigest([]string{relation.Name}, []string{resourceValue}, false),
			Boundary:           boundary,
		})
	}
	return proofs, complete
}

func extractVerificationDigest(body []byte, fields []string) (string, map[string]string, bool) {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return "", nil, false
	}
	values := make([]string, 0, len(fields))
	byPath := make(map[string]string, len(fields))
	for _, field := range fields {
		value, found := explicitField(root, field)
		text, valid := scalarString(value)
		if !found || !valid || strings.TrimSpace(text) == "" {
			return "", nil, false
		}
		values = append(values, text)
		byPath[field] = text
	}
	return tupleDigest(fields, values, true), byPath, len(fields) > 0
}

// compareJSONFields produces path-only differential evidence. Response values
// are never copied into results, and this comparison is not an authorization
// decision by itself.
func compareJSONFields(baseline map[string]any, response []byte, ignored []string) []string {
	var actual any
	if len(baseline) == 0 || json.Unmarshal(response, &actual) != nil {
		return nil
	}
	paths := make([]string, 0)
	var walk func(any, any, string)
	walk = func(left, right any, path string) {
		for _, skip := range ignored {
			if path == skip || strings.HasPrefix(path, skip+".") {
				return
			}
		}
		lm, lok := left.(map[string]any)
		rm, rok := right.(map[string]any)
		if lok && rok {
			keys := make(map[string]bool, len(lm)+len(rm))
			for k := range lm {
				keys[k] = true
			}
			for k := range rm {
				keys[k] = true
			}
			ordered := make([]string, 0, len(keys))
			for k := range keys {
				ordered = append(ordered, k)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				l, lfound := lm[key]
				r, rfound := rm[key]
				child := key
				if path != "" {
					child = path + "." + key
				}
				if !lfound || !rfound {
					paths = append(paths, child)
				} else {
					walk(l, r, child)
				}
			}
			return
		}
		la, lok := left.([]any)
		ra, rok := right.([]any)
		if lok && rok {
			limit := len(la)
			if len(ra) > limit {
				limit = len(ra)
			}
			for i := 0; i < limit; i++ {
				child := strconv.Itoa(i)
				if path != "" {
					child = path + "." + child
				}
				if i >= len(la) || i >= len(ra) {
					paths = append(paths, child)
				} else {
					walk(la[i], ra[i], child)
				}
			}
			return
		}
		if !reflect.DeepEqual(left, right) {
			paths = append(paths, path)
		}
	}
	walk(baseline, actual, "")
	sort.Strings(paths)
	return paths
}

func valuesIntersect(left, right map[string]string) bool {
	values := make(map[string]bool, len(left))
	for _, value := range left {
		values[verificationValue(value)] = true
	}
	for _, value := range right {
		if values[verificationValue(value)] {
			return true
		}
	}
	return false
}

func collectionItems(object map[string]any, depth int) ([]any, bool) {
	if depth > 4 {
		return nil, false
	}
	var found []any
	foundCount := 0
	for _, key := range []string{"data", "items", "results"} {
		switch value := object[key].(type) {
		case []any:
			found, foundCount = value, foundCount+1
		case map[string]any:
			if nested, ok := collectionItems(value, depth+1); ok {
				found, foundCount = nested, foundCount+1
			}
		}
	}
	return found, foundCount == 1
}
func scalarString(v any) (string, bool) {
	switch v.(type) {
	case string, float64, bool:
		return fmt.Sprint(v), true
	default:
		return "", false
	}
}

func verificationValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
func extractOne(b []byte, field string) (string, bool) {
	var root any
	if json.Unmarshal(b, &root) != nil {
		return "", false
	}
	x, ok := jsonFieldPath(root, field)
	if !ok {
		if data, found := jsonFieldPath(root, "data."+field); found {
			x, ok = data, true
		}
	}
	if !ok {
		return "", false
	}
	result, ok := scalarString(x)
	return result, ok
}

// jsonFieldPath reads an explicit dot-separated path through JSON objects.
// It does not guess field names, traverse arrays, or infer ownership semantics.
func jsonFieldPath(value any, field string) (any, bool) {
	parts := strings.Split(field, ".")
	if field == "" {
		return nil, false
	}
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return value, true
}
func safeID(x string) bool {
	if x == "" || len(x) >= 256 || x == "." || x == ".." {
		return false
	}
	for _, r := range x {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_.~", r)) {
			return false
		}
	}
	return true
}

func safePathIdentifierValues(values map[string]string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !safeID(value) {
			return false
		}
	}
	return true
}

func detailPath(template string, values map[string]string) (string, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	path := template
	for _, key := range keys {
		value := values[key]
		if !safeID(value) {
			return "", fmt.Errorf("unsafe path identifier")
		}
		path = strings.ReplaceAll(path, "{"+key+"}", value)
	}
	if strings.ContainsAny(path, "{}") {
		return "", fmt.Errorf("unresolved detail path parameter")
	}
	return path, nil
}
func evidence(identity, method, path string, status int, b []byte, ct, note string) Evidence {
	h := sha256.Sum256(b)
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", identity, method, path, status, hex.EncodeToString(h[:]))
	idHash := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(idHash[:8])
	return Evidence{ID: "ev-" + id, Identity: identity, Method: method, Path: path, Status: status, BodySHA256: hex.EncodeToString(h[:]), ContentType: ct, Note: note}
}
func evidenceForResource(identity, method, path string, status int, b []byte, ct, note, resourceRef string) Evidence {
	item := evidence(identity, method, path, status, b, ct, note)
	hash := sha256.Sum256([]byte(item.ID + "\x00" + resourceRef))
	item.ID = "ev-" + hex.EncodeToString(hash[:8])
	item.ResourceRef = resourceRef
	return item
}
func finding(classification, resource, resourceRef, victim, actor, relationship, path, eid string) Finding {
	// The fingerprint identifies the semantic authorization condition. The
	// discovered resource identifier remains report/evidence metadata only.
	key := strings.Join([]string{strings.ToLower(classification), resource, victim, actor, relationship, "GET", path}, "\x00")
	h := sha256.Sum256([]byte(key))
	return Finding{Fingerprint: hex.EncodeToString(h[:]), Type: classification, Severity: "high", Resource: resource, ResourceRef: resourceRef, Relationship: relationship, VictimIdentity: victim, AccessingIdentity: actor, Method: "GET", Path: path, EvidenceIDs: []string{eid}}
}
