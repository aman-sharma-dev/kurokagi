package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func New(c config.Config) (*Scanner, error) {
	b, e := url.Parse(c.Target.BaseURL)
	if e != nil {
		return nil, e
	}
	timeout := 10 * time.Second
	if x, e := time.ParseDuration(c.Limits.Timeout); e == nil {
		timeout = x
	}
	policy := c.Limits.RedirectPolicy
	cl := &http.Client{Timeout: timeout}
	if policy == "none" {
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	} else {
		cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 || !scope.Match(req.URL.String(), c.Target.AllowedOrigins, c.Target.AllowedPaths) {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	s := &Scanner{cfg: c, client: cl, base: b, gate: make(chan struct{}, c.Limits.Concurrency)}
	if c.Limits.RequestsPerSecond > 0 {
		s.interval = time.Duration(float64(time.Second) / c.Limits.RequestsPerSecond)
	}
	return s, nil
}
func (s *Scanner) request(ctx context.Context, identity config.Identity, raw string) (int, []byte, string, error) {
	if !scope.Match(raw, s.cfg.Target.AllowedOrigins, s.cfg.Target.AllowedPaths) {
		return 0, nil, "", fmt.Errorf("request outside configured scope")
	}
	s.mu.Lock()
	if s.used >= s.cfg.Limits.MaxRequests {
		s.mu.Unlock()
		return 0, nil, "", fmt.Errorf("request budget exhausted")
	}
	s.used++
	if s.interval > 0 {
		wait := time.Until(s.next)
		if wait > 0 {
			s.mu.Unlock()
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return 0, nil, "", ctx.Err()
			case <-t.C:
			}
			s.mu.Lock()
		}
		s.next = time.Now().Add(s.interval)
	}
	s.mu.Unlock()
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return 0, nil, "", ctx.Err()
	}
	defer func() { <-s.gate }()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return 0, nil, "", e
	}
	for k, v := range identity.Headers {
		if strings.Contains(strings.ToLower(k), "authorization") || strings.Contains(strings.ToLower(k), "cookie") || strings.Contains(strings.ToLower(k), "key") {
			req.Header.Set(k, v)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, e := s.client.Do(req)
	if e != nil {
		return 0, nil, "", fmt.Errorf("HTTP request failed (%s)", req.URL.Redacted())
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, s.cfg.Limits.MaxResponseBytes+1)
	body, e := io.ReadAll(limited)
	if e != nil {
		return resp.StatusCode, nil, resp.Header.Get("Content-Type"), fmt.Errorf("response read failed")
	}
	if int64(len(body)) > s.cfg.Limits.MaxResponseBytes {
		return resp.StatusCode, nil, resp.Header.Get("Content-Type"), fmt.Errorf("response exceeded configured size limit")
	}
	return resp.StatusCode, body, resp.Header.Get("Content-Type"), nil
}
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	start := time.Now().UTC()
	r := Result{SchemaVersion: "1", Scanner: map[string]string{"name": "Kurokagi", "version": Version}, Target: s.base.Scheme + "://" + s.base.Host, StartedAt: start, Status: "completed", Coverage: []Coverage{}, Findings: []Finding{}, Evidence: []Evidence{}, Errors: []string{}}
	doc, e := openapi.Load(s.cfg.OpenAPI.Path)
	if e != nil {
		return r, e
	}
	_ = doc
	owners := map[string]string{}
	objectCount := 0
	for _, res := range s.cfg.Resources {
		if !doc.HasGet(res.Collection) || !doc.HasGet(strings.ReplaceAll(res.Detail, "{id}", "{id}")) {
			r.Coverage = append(r.Coverage, Coverage{Resource: res.Name, Operation: "GET", State: "UNSUPPORTED", Reason: "OpenAPI must define collection and detail GET operations"})
			continue
		}
		visible := map[string][]string{}
		for _, id := range s.cfg.Identities {
			u := s.endpoint(res.Collection)
			st, body, ct, err := s.request(ctx, id, u)
			if err != nil {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "FAILED", Reason: "collection request failed or was bounded"})
				r.Errors = append(r.Errors, "collection request failed for identity "+id.ID)
				continue
			}
			ids, err := extract(body, res.IDField)
			if err != nil || st < 200 || st >= 300 {
				r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "INCONCLUSIVE", Reason: "collection response did not establish visible object IDs"})
				continue
			}
			if len(ids) > s.cfg.Limits.MaxObjects {
				ids = ids[:s.cfg.Limits.MaxObjects]
			}
			for _, x := range ids {
				if !safeID(x) {
					continue
				}
				if _, ok := owners[x]; !ok {
					owners[x] = id.ID
				}
				visible[id.ID] = append(visible[id.ID], x)
			}
			ev := evidence(id.ID, "GET", res.Collection, st, body, ct, "bounded collection visibility established candidate IDs")
			r.Evidence = append(r.Evidence, ev)
			r.Coverage = append(r.Coverage, Coverage{Identity: id.ID, Resource: res.Name, Operation: "discover", State: "TESTED"})
			objectCount += len(ids)
		}
		for _, victim := range s.cfg.Identities {
			for _, objectID := range visible[victim.ID] {
				for _, actor := range s.cfg.Identities {
					if actor.ID == victim.ID {
						continue
					}
					path := strings.Replace(res.Detail, "{id}", url.PathEscape(objectID), 1)
					if !doc.HasGet(path) { /* parameterized OpenAPI template is checked below */
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
							r.Errors = append(r.Errors, "cross-identity request failed for "+actor.ID)
						}
						continue
					}
					got, valid := extractOne(body, res.IDField)
					match := valid && got == objectID
					if res.VerifyField != "" {
						match = match && containsValue(body, res.VerifyField, objectID)
					}
					ev := evidence(actor.ID, "GET", path, status, body, ct, "cross-identity detail response evaluated")
					ev.ResourceID = got
					r.Evidence = append(r.Evidence, ev)
					switch {
					case status >= 200 && status < 300 && match:
						f := finding(res.Name, victim.ID, actor.ID, path, objectID, ev.ID)
						r.Findings = append(r.Findings, f)
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED"})
					case status == 403 || status == 404:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "TESTED", Reason: "access denied"})
					case status >= 200 && status < 300:
						r.Coverage = append(r.Coverage, Coverage{Identity: actor.ID, Resource: res.Name, Operation: "cross_identity", State: "INCONCLUSIVE", Reason: "successful response did not prove requested victim object was returned"})
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
	_ = objectCount
	return r, nil
}
func (s *Scanner) endpoint(path string) string {
	u := *s.base
	u.Path = strings.TrimSuffix(s.base.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	u.RawPath = ""
	return u.String()
}
func extract(b []byte, field string) ([]string, error) {
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
	ids := []string{}
	seen := map[string]bool{}
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			if id, ok := m[field]; ok {
				z := fmt.Sprint(id)
				if !seen[z] {
					seen[z] = true
					ids = append(ids, z)
				}
			}
		}
	}
	return ids, nil
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
	return fmt.Sprint(x), true
}
func containsValue(b []byte, field, value string) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	v, ok := m[field]
	return ok && fmt.Sprint(v) == value
}
func safeID(x string) bool { return x != "" && len(x) < 256 && !strings.ContainsAny(x, "/\\?#%") }
func evidence(identity, method, path string, status int, b []byte, ct, note string) Evidence {
	h := sha256.Sum256(b)
	id := hex.EncodeToString(h[:8])
	return Evidence{ID: "ev-" + id, Identity: identity, Method: method, Path: path, Status: status, BodySHA256: hex.EncodeToString(h[:]), ContentType: ct, Note: note}
}
func finding(resource, victim, actor, path, obj, eid string) Finding {
	key := strings.Join([]string{"bola", resource, victim, actor, "GET", path, obj}, "\x00")
	h := sha256.Sum256([]byte(key))
	return Finding{Fingerprint: hex.EncodeToString(h[:]), Type: "BOLA", Severity: "high", Resource: resource, VictimIdentity: victim, AccessingIdentity: actor, Method: "GET", Path: path, EvidenceIDs: []string{eid}}
}
