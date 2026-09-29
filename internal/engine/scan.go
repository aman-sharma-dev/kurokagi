package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kurokagi/kurokagi/internal/config"
	"github.com/kurokagi/kurokagi/internal/openapi"
	"github.com/kurokagi/kurokagi/internal/scope"
)

const Version = "0.1.0-dev"

type Result struct {
	SchemaVersion string            `json:"schema_version"`
	Scanner       map[string]string `json:"scanner"`
	Target        string            `json:"target"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Status        string            `json:"status"`
	Coverage      []Coverage        `json:"coverage"`
	Findings      []Finding         `json:"findings"`
	Evidence      []Evidence        `json:"evidence"`
	Errors        []string          `json:"errors"`
}
type Coverage struct {
	Identity  string `json:"identity"`
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
}
type Finding struct {
	Fingerprint       string   `json:"fingerprint"`
	Type              string   `json:"type"`
	Severity          string   `json:"severity"`
	Resource          string   `json:"resource"`
	VictimIdentity    string   `json:"victim_identity"`
	AccessingIdentity string   `json:"accessing_identity"`
	Method            string   `json:"method"`
	Path              string   `json:"path"`
	EvidenceIDs       []string `json:"evidence_ids"`
}
type Evidence struct {
	ID          string `json:"id"`
	Identity    string `json:"identity"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ResourceID  string `json:"resource_id,omitempty"`
	BodySHA256  string `json:"body_sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Note        string `json:"note,omitempty"`
}
type candidate struct{ ID, Verify string }
type Scanner struct {
	cfg      config.Config
	client   *http.Client
	base     *url.URL
	mu       sync.Mutex
	used     int
	gate     chan struct{}
	interval time.Duration
	next     time.Time
}

func expectation(c config.Config, identity, resource string) string {
	for _, e := range c.Expectations {
		if e.Identity == identity && e.Resource == resource {
			return e.Access
		}
	}
	return "UNKNOWN"
}

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
	s := &Scanner{cfg: c, client: cl, base: b, gate: make(chan struct{}, c.Limits.Concurrency)}
	if c.Limits.RequestsPerSecond > 0 {
		s.interval = time.Duration(float64(time.Second) / c.Limits.RequestsPerSecond)
	}
	return s, nil
}
func (s *Scanner) request(ctx context.Context, identity config.Identity, raw string) (int, []byte, string, error) {
	current := raw
	redirects := 0
	for {
		status, body, contentType, location, err := s.requestOnce(ctx, identity, current)
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
		if !scope.Match(next.String(), s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) || !scope.SameOrigin(current, next.String()) {
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
func (s *Scanner) requestOnce(ctx context.Context, identity config.Identity, raw string) (int, []byte, string, string, error) {
	if !scope.Match(raw, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
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
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return 0, nil, "", "", fmt.Errorf("invalid request URL")
	}
	for k, v := range identity.Headers {
		req.Header.Set(k, v)
	}
	s.mu.Lock()
	if s.used >= s.cfg.Limits.MaxRequests {
		s.mu.Unlock()
		return 0, nil, "", "", fmt.Errorf("request budget exhausted")
	}
	s.used++
	s.mu.Unlock()
	resp, e := s.client.Do(req)
	if e != nil {
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
	r := Result{SchemaVersion: "1", Scanner: map[string]string{"name": "Kurokagi", "version": Version}, Target: s.base.Scheme + "://" + s.base.Host, StartedAt: start, Status: "completed", Coverage: []Coverage{}, Findings: []Finding{}, Evidence: []Evidence{}, Errors: []string{}}
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
		visible := map[string][]candidate{}
		verifyValues := map[string]map[string]string{}
		verifyCounts := map[string]int{}
		collectionComplete := map[string]bool{}
		for _, id := range s.cfg.Identities {
			u := s.endpoint(res.Collection)
			st, body, ct, err := s.request(ctx, id, u)
			if err != nil {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "FAILED", Reason: "collection request failed or was bounded"})
				r.Errors = append(r.Errors, "collection request failed for identity "+id.ID)
				continue
			}
			candidates, err := extractCandidates(body, res.IDField, res.VerifyField)
			if err != nil || st < 200 || st >= 300 {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "INCONCLUSIVE", Reason: "collection response did not establish visible object IDs"})
				continue
			}
			for _, item := range candidates {
				if item.Verify != "" {
					verifyCounts[verificationValue(item.Verify)]++
				}
			}
			bounded := false
			if len(candidates) > s.cfg.Limits.MaxObjects {
				candidates = candidates[:s.cfg.Limits.MaxObjects]
				bounded = true
			}
			if verifyValues[id.ID] == nil {
				verifyValues[id.ID] = map[string]string{}
			}
			for _, item := range candidates {
				if !safeID(item.ID) {
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
			ev := evidence(id.ID, "GET", res.Collection, st, body, ct, "bounded collection visibility established candidate IDs")
			r.Evidence = append(r.Evidence, ev)
			coverage := Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "TESTED"}
			if bounded {
				coverage.State = "INCONCLUSIVE"
				coverage.Reason = "some collection IDs were skipped by configured bounds or safe-ID checks"
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
					path := strings.Replace(res.Detail, "{id}", url.PathEscape(objectID), 1)
					raw := s.endpoint(path)
					status, body, ct, err := s.request(ctx, actor, raw)
					if err != nil {
						state := "FAILED"
						if ctx.Err() != nil {
							state = "INCONCLUSIVE"
						}
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: state, Reason: "request failed or execution was bounded"})
						if state == "FAILED" {
							r.Errors = append(r.Errors, "cross-identity request failed for "+actor.ID)
						}
						continue
					}
					got, valid := extractOne(body, res.IDField)
					verify, verifyOK := extractOne(body, res.VerifyField)
					verify = verificationValue(verify)
					victimValue := verifyValues[victim.ID][objectID]
					match := allCollectionsComplete && distinctVerifyValues >= 2 && valid && got == objectID && verifyOK && verify != "" && verify != "<nil>" && verify != verificationValue(objectID) && victimValue != "" && victimValue != verificationValue(objectID) && verify == victimValue && verifyCounts[victimValue] == 1
					displayPath := res.Detail
					ev := evidence(actor.ID, "GET", displayPath, status, body, ct, "cross-identity detail response evaluated")
					r.Evidence = append(r.Evidence, ev)
					expected := expectation(s.cfg, actor.ID, res.Name)
					switch {
					case status >= 200 && status < 300 && match && expected == "DENIED":
						f := finding(res.Name, victim.ID, actor.ID, displayPath, ev.ID)
						merged := false
						for i := range r.Findings {
							if r.Findings[i].Fingerprint == f.Fingerprint {
								r.Findings[i].EvidenceIDs = append(r.Findings[i].EvidenceIDs, ev.ID)
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
	if ctx.Err() != nil {
		r.Status = "cancelled"
	}
	if len(r.Findings) > 0 {
		r.Status = "findings"
	}
	r.FinishedAt = time.Now().UTC()
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].Fingerprint < r.Findings[j].Fingerprint })
	sort.Slice(r.Coverage, func(i, j int) bool {
		a, b := r.Coverage[i], r.Coverage[j]
		return strings.Join([]string{a.Identity, a.Resource, a.Operation, a.State, a.Reason}, "\x00") < strings.Join([]string{b.Identity, b.Resource, b.Operation, b.State, b.Reason}, "\x00")
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
func (s *Scanner) endpoint(path string) string {
	u := *s.base
	u.Path = strings.TrimSuffix(s.base.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	u.RawPath = ""
	return u.String()
}
func extractCandidates(b []byte, idField, verifyField string) ([]candidate, error) {
	var v any
	if e := json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	var arr []any
	switch x := v.(type) {
	case []any:
		arr = x
	case map[string]any:
		for _, k := range []string{"data", "items", "results"} {
			if a, ok := x[k].([]any); ok {
				arr = a
				break
			}
		}
	}
	ids := []candidate{}
	seen := map[string]bool{}
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			if id, ok := scalarString(m[idField]); ok {
				verify, _ := scalarString(m[verifyField])
				verify = verificationValue(verify)
				if seen[id] {
					return nil, fmt.Errorf("duplicate candidate ID")
				}
				seen[id] = true
				ids = append(ids, candidate{ID: id, Verify: verify})
			}
		}
	}
	return ids, nil
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
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return "", false
	}
	x, ok := m[field]
	if !ok {
		if d, ok := m["data"].(map[string]any); ok {
			x, ok = d[field]
		}
	}
	if !ok {
		return "", false
	}
	value, ok := scalarString(x)
	return value, ok
}
func safeID(x string) bool {
	if x == "" || len(x) >= 256 || x == "." || x == ".." {
		return false
	}
	for _, r := range x {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.~", r)) {
			return false
		}
	}
	return true
}
func evidence(identity, method, path string, status int, b []byte, ct, note string) Evidence {
	h := sha256.Sum256(b)
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", identity, method, path, status, hex.EncodeToString(h[:]))
	idHash := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(idHash[:8])
	return Evidence{ID: "ev-" + id, Identity: identity, Method: method, Path: path, Status: status, BodySHA256: hex.EncodeToString(h[:]), ContentType: ct, Note: note}
}
func finding(resource, victim, actor, path, eid string) Finding {
	key := strings.Join([]string{"bola", resource, victim, actor, "GET", path}, "\x00")
	h := sha256.Sum256([]byte(key))
	return Finding{Fingerprint: hex.EncodeToString(h[:]), Type: "BOLA", Severity: "high", Resource: resource, VictimIdentity: victim, AccessingIdentity: actor, Method: "GET", Path: path, EvidenceIDs: []string{eid}}
}
