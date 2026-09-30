package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kurokagi/kurokagi/internal/strictjson"
	"gopkg.in/yaml.v3"
)

// Config is a fully validated Kurokagi scan configuration.
type Config struct {
	SchemaVersion string `json:"schema_version" yaml:"schema_version"`
	Target        Target `json:"target" yaml:"target"`
	OpenAPI       struct {
		Path string `json:"path" yaml:"path"`
	} `json:"openapi" yaml:"openapi"`
	Identities   []Identity     `json:"identities" yaml:"identities"`
	Resources    []Resource     `json:"resources" yaml:"resources"`
	Expectations []Expectation  `json:"expectations" yaml:"expectations"`
	Operations   []Operation    `json:"operations,omitempty" yaml:"operations,omitempty"`
	Mutations    MutationPolicy `json:"mutations,omitempty" yaml:"mutations,omitempty"`
	Limits       Limits         `json:"limits" yaml:"limits"`
}

// Target defines the request destination and mandatory network scope.
type Target struct {
	BaseURL        string   `json:"base_url" yaml:"base_url"`
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedPaths   []string `json:"allowed_paths" yaml:"allowed_paths"`
}

// Identity defines an actor, its credentials, and relationship contexts.
type Identity struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Role        string            `json:"role,omitempty" yaml:"role,omitempty"`
	Headers     map[string]string `json:"headers" yaml:"headers"`
	Credentials []Credential      `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	Contexts    map[string]string `json:"contexts,omitempty" yaml:"contexts,omitempty"`
}

// Credential describes one supported identity credential source.
type Credential struct {
	Type  string `json:"type" yaml:"type"`
	Name  string `json:"name,omitempty" yaml:"name,omitempty"`
	Value string `json:"value" yaml:"value"`
}

// Resource defines collection/detail discovery and resource evidence mapping.
type Resource struct {
	Name               string            `json:"name" yaml:"name"`
	Classification     string            `json:"classification" yaml:"classification"`
	Collection         string            `json:"collection" yaml:"collection"`
	Detail             string            `json:"detail" yaml:"detail"`
	IDField            string            `json:"id_field" yaml:"id_field"`
	IdentifierFields   []IdentifierField `json:"identifier_fields,omitempty" yaml:"identifier_fields,omitempty"`
	VerifyField        string            `json:"verify_field,omitempty" yaml:"verify_field,omitempty"`
	VerificationFields []string          `json:"verification_fields,omitempty" yaml:"verification_fields,omitempty"`
	Ownership          string            `json:"ownership" yaml:"ownership"`
	Pagination         *Pagination       `json:"pagination,omitempty" yaml:"pagination,omitempty"`
	Relationships      []Relationship    `json:"relationships,omitempty" yaml:"relationships,omitempty"`
	IgnoreFields       []string          `json:"ignore_fields,omitempty" yaml:"ignore_fields,omitempty"`
}

// Relationship maps a resource JSON field to a named authorization boundary.
type Relationship struct {
	Name  string `json:"name" yaml:"name"`
	Kind  string `json:"kind" yaml:"kind"`
	Field string `json:"field" yaml:"field"`
}

// IdentifierField maps a response value to a detail-request parameter.
type IdentifierField struct {
	Path      string `json:"path" yaml:"path"`
	Parameter string `json:"parameter" yaml:"parameter"`
}

// Pagination configures an explicitly bounded collection pagination model.
type Pagination struct {
	Type            string `json:"type" yaml:"type"`
	PageParam       string `json:"page_param,omitempty" yaml:"page_param,omitempty"`
	PageSizeParam   string `json:"page_size_param,omitempty" yaml:"page_size_param,omitempty"`
	OffsetParam     string `json:"offset_param,omitempty" yaml:"offset_param,omitempty"`
	LimitParam      string `json:"limit_param,omitempty" yaml:"limit_param,omitempty"`
	CursorParam     string `json:"cursor_param,omitempty" yaml:"cursor_param,omitempty"`
	NextCursorField string `json:"next_cursor_field,omitempty" yaml:"next_cursor_field,omitempty"`
	StartPage       int    `json:"start_page,omitempty" yaml:"start_page,omitempty"`
	PageSize        int    `json:"page_size" yaml:"page_size"`
	MaxPages        int    `json:"max_pages" yaml:"max_pages"`
}

// Expectation states the configured access policy for an actor and resource.
type Expectation struct {
	Identity     string `json:"identity" yaml:"identity"`
	Owner        string `json:"owner,omitempty" yaml:"owner,omitempty"`
	Resource     string `json:"resource" yaml:"resource"`
	Relationship string `json:"relationship,omitempty" yaml:"relationship,omitempty"`
	Method       string `json:"method,omitempty" yaml:"method,omitempty"`
	Access       string `json:"access" yaml:"access"`
}

// Operation declares an OpenAPI operation and its authorization verification.
type Operation struct {
	ID                            string               `json:"id" yaml:"id"`
	Path                          string               `json:"path" yaml:"path"`
	Method                        string               `json:"method" yaml:"method"`
	Actor                         string               `json:"actor" yaml:"actor"`
	Owner                         string               `json:"owner,omitempty" yaml:"owner,omitempty"`
	Resource                      string               `json:"resource,omitempty" yaml:"resource,omitempty"`
	Relationship                  string               `json:"relationship,omitempty" yaml:"relationship,omitempty"`
	Access                        string               `json:"access" yaml:"access"`
	Classification                string               `json:"classification" yaml:"classification"`
	Verification                  VerificationStrategy `json:"verification" yaml:"verification"`
	RequestBody                   any                  `json:"request_body,omitempty" yaml:"request_body,omitempty"`
	ContentType                   string               `json:"content_type,omitempty" yaml:"content_type,omitempty"`
	ControlledResourceOperationID string               `json:"controlled_resource_operation_id,omitempty" yaml:"controlled_resource_operation_id,omitempty"`
	Disposable                    bool                 `json:"disposable,omitempty" yaml:"disposable,omitempty"`
	RestoreBody                   any                  `json:"restore_body,omitempty" yaml:"restore_body,omitempty"`
}

// Safety returns the effect category derived from the operation's method.
func (o Operation) Safety() SafetyClassification {
	safety, _ := MethodSafety(o.Method)
	return safety
}

// VerificationStrategy specifies the positive response or state evidence to check.
type VerificationStrategy struct {
	Type                  string `json:"type" yaml:"type"`
	Field                 string `json:"field,omitempty" yaml:"field,omitempty"`
	Path                  string `json:"path,omitempty" yaml:"path,omitempty"`
	MarkerField           string `json:"marker_field,omitempty" yaml:"marker_field,omitempty"`
	ResourceIDField       string `json:"resource_id_field,omitempty" yaml:"resource_id_field,omitempty"`
	RequestMarkerField    string `json:"request_marker_field,omitempty" yaml:"request_marker_field,omitempty"`
	BaselineCompleteField string `json:"baseline_complete_field,omitempty" yaml:"baseline_complete_field,omitempty"`
	CleanupPath           string `json:"cleanup_path,omitempty" yaml:"cleanup_path,omitempty"`
}

// MutationPolicy controls opt-in mutation methods, paths, and request budgets.
type MutationPolicy struct {
	Enabled              bool     `json:"enabled" yaml:"enabled"`
	AllowedMethods       []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`
	AllowedPaths         []string `json:"allowed_paths,omitempty" yaml:"allowed_paths,omitempty"`
	CleanupPaths         []string `json:"cleanup_paths,omitempty" yaml:"cleanup_paths,omitempty"`
	RequestBudget        int      `json:"request_budget,omitempty" yaml:"request_budget,omitempty"`
	CleanupRequestBudget int      `json:"cleanup_request_budget,omitempty" yaml:"cleanup_request_budget,omitempty"`
	CleanupTimeout       string   `json:"cleanup_timeout,omitempty" yaml:"cleanup_timeout,omitempty"`
}

// SafetyClassification is the derived effect category of an HTTP method.
type SafetyClassification string

// SafetyReadOnly, SafetyMutating, and SafetyDestructive classify supported HTTP methods.
const (
	SafetyReadOnly    SafetyClassification = "READ_ONLY"
	SafetyMutating    SafetyClassification = "MUTATING"
	SafetyDestructive SafetyClassification = "DESTRUCTIVE"
)

// NormalizeMethod trims and uppercases an HTTP method name.
func NormalizeMethod(method string) string { return strings.ToUpper(strings.TrimSpace(method)) }

// MethodSafety returns the derived safety class and whether method is supported.
func MethodSafety(method string) (SafetyClassification, bool) {
	switch NormalizeMethod(method) {
	case "GET":
		return SafetyReadOnly, true
	case "POST", "PUT", "PATCH":
		return SafetyMutating, true
	case "DELETE":
		return SafetyDestructive, true
	default:
		return "", false
	}
}

func validVerification(strategy VerificationStrategy) bool {
	switch strategy.Type {
	case "RESPONSE_FIELD":
		return validFieldPath(strategy.Field)
	case "RESOURCE_ABSENT":
		return strategy.Field == "" || validFieldPath(strategy.Field)
	case "RESOURCE_EXISTS":
		return strategy.Path == "" || validResourcePath(strategy.Path, false)
	case "RESOURCE_STATE":
		return validFieldPath(strategy.Field)
	default:
		return false
	}
}

// Limits bounds network work and response processing for a scan.
type Limits struct {
	Timeout           string  `json:"timeout" yaml:"timeout"`
	MaxRequests       int     `json:"max_requests" yaml:"max_requests"`
	Concurrency       int     `json:"concurrency" yaml:"concurrency"`
	RequestsPerSecond float64 `json:"requests_per_second" yaml:"requests_per_second"`
	MaxResponseBytes  int64   `json:"max_response_bytes" yaml:"max_response_bytes"`
	MaxObjects        int     `json:"max_objects" yaml:"max_objects"`
	RedirectPolicy    string  `json:"redirect_policy" yaml:"redirect_policy"`
}

// Load reads, strictly decodes, expands environment references, and validates a configuration file.
func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	isYAML := strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml")
	if isYAML {
		d := yaml.NewDecoder(bytes.NewReader(b))
		d.KnownFields(true)
		e = d.Decode(&c)
		if e == nil {
			var extra any
			if x := d.Decode(&extra); x != io.EOF {
				if x == nil {
					e = fmt.Errorf("multiple YAML documents are not supported")
				} else {
					e = x
				}
			}
		}
	} else {
		if e = strictjson.RejectDuplicateKeys(b); e != nil {
			return Config{}, fmt.Errorf("parse configuration: invalid JSON document")
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		e = d.Decode(&c)
		if e == nil {
			var extra any
			if x := d.Decode(&extra); x != io.EOF {
				if x == nil {
					e = fmt.Errorf("trailing JSON data")
				} else {
					e = x
				}
			}
		}
	}
	if e != nil {
		format := "JSON"
		if isYAML {
			format = "YAML"
		}
		return c, fmt.Errorf("parse configuration: invalid %s document", format)
	}
	if e = c.Validate(); e != nil {
		return c, e
	}
	for i := range c.Identities {
		for k, v := range c.Identities[i].Headers {
			x, err := ExpandEnv(v)
			if err != nil {
				return Config{}, fmt.Errorf("identity %q header %q: %w", c.Identities[i].ID, k, err)
			}
			c.Identities[i].Headers[k] = x
			if strings.ContainsAny(x, "\r\n") {
				return Config{}, fmt.Errorf("identity %q header %q expands to an invalid value", c.Identities[i].ID, k)
			}
		}
		for j := range c.Identities[i].Credentials {
			credential := &c.Identities[i].Credentials[j]
			value, err := ExpandEnv(credential.Value)
			if err != nil {
				return Config{}, fmt.Errorf("identity %q credential provider %d: %w", c.Identities[i].ID, j+1, err)
			}
			credential.Value = value
			if strings.ContainsAny(value, "\r\n") {
				return Config{}, fmt.Errorf("identity %q credential provider %d expands to an invalid value", c.Identities[i].ID, j+1)
			}
		}
	}
	return c, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandEnv expands supported ${NAME} references without exposing values in errors.
func ExpandEnv(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("invalid environment variable reference")
			}
			ref := s[i : i+2+end+1]
			match := envRef.FindStringSubmatch(ref)
			if match == nil {
				return "", fmt.Errorf("invalid environment variable reference")
			}
			value, ok := os.LookupEnv(match[1])
			if !ok {
				return "", fmt.Errorf("required environment variable %s is not set", match[1])
			}
			out.WriteString(value)
			i += len(ref)
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String(), nil
}
func (c Config) Validate() error {
	if c.SchemaVersion != "3" {
		return fmt.Errorf("schema_version must be \"3\"")
	}
	u, e := url.Parse(c.Target.BaseURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("target.base_url must be an absolute HTTP(S) URL")
	}
	if len(c.Target.AllowedOrigins) == 0 || len(c.Target.AllowedPaths) == 0 {
		return fmt.Errorf("target.allowed_origins and allowed_paths must be explicit")
	}
	for _, p := range c.Target.AllowedPaths {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "?#") {
			return fmt.Errorf("target.allowed_paths must contain safe absolute path prefixes")
		}
	}
	for _, o := range c.Target.AllowedOrigins {
		x, e := url.Parse(o)
		if e != nil || x.Host == "" || x.Path != "" || x.RawQuery != "" || x.Fragment != "" || x.User != nil || (x.Scheme != "http" && x.Scheme != "https") {
			return fmt.Errorf("invalid allowed origin")
		}
	}
	baseAllowed := false
	for _, o := range c.Target.AllowedOrigins {
		x, _ := url.Parse(o)
		if x != nil && strings.EqualFold(x.Scheme, u.Scheme) && strings.EqualFold(x.Host, u.Host) {
			baseAllowed = true
		}
	}
	if !baseAllowed {
		return fmt.Errorf("target.base_url origin must be listed in target.allowed_origins")
	}
	if len(c.Identities) < 2 || len(c.Identities) > 8 {
		return fmt.Errorf("between two and eight identities are required")
	}
	seen := map[string]bool{}
	for _, i := range c.Identities {
		if i.ID == "" || seen[i.ID] {
			return fmt.Errorf("identity IDs must be non-empty and unique")
		}
		canonicalHeaders := map[string]bool{}
		for k, v := range i.Headers {
			if !validHeaderName(k) || strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("identity %q has an invalid header", i.ID)
			}
			canonical := http.CanonicalHeaderKey(k)
			if canonicalHeaders[canonical] {
				return fmt.Errorf("identity %q has duplicate header names after case folding", i.ID)
			}
			canonicalHeaders[canonical] = true
		}
		for _, credential := range i.Credentials {
			name := credential.Name
			switch credential.Type {
			case "header":
				if !validHeaderName(name) {
					return fmt.Errorf("identity %q has an invalid header credential", i.ID)
				}
			case "bearer":
				if name != "" {
					return fmt.Errorf("identity %q has an invalid bearer credential", i.ID)
				}
				name = "Authorization"
			case "cookie":
				if !validCookieName(name) {
					return fmt.Errorf("identity %q has an invalid cookie credential", i.ID)
				}
				name = "Cookie"
			default:
				return fmt.Errorf("identity %q has an unsupported credential provider", i.ID)
			}
			canonical := http.CanonicalHeaderKey(name)
			if canonicalHeaders[canonical] {
				return fmt.Errorf("identity %q has duplicate credential headers", i.ID)
			}
			canonicalHeaders[canonical] = true
			if credential.Value == "" || strings.ContainsAny(credential.Value, "\r\n") {
				return fmt.Errorf("identity %q has an invalid credential value", i.ID)
			}
			if credential.Type == "cookie" {
				if err := (&http.Cookie{Name: credential.Name, Value: credential.Value}).Valid(); err != nil {
					return fmt.Errorf("identity %q has an invalid cookie credential", i.ID)
				}
			}
		}
		seen[i.ID] = true
		for contextName, value := range i.Contexts {
			if !validQueryParameterName(contextName) || value == "" || strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("identity %q has invalid authorization context", i.ID)
			}
		}
	}
	if c.OpenAPI.Path == "" {
		return fmt.Errorf("openapi.path is required")
	}
	if len(c.Resources) == 0 {
		return fmt.Errorf("at least one explicit resource mapping is required")
	}
	resourceSeen := map[string]bool{}
	for _, r := range c.Resources {
		identifiers := configuredIdentifiers(r)
		verificationFields := configuredVerificationFields(r)
		if r.Name == "" || (r.Classification != "BOLA" && r.Classification != "IDOR" && r.Classification != "RELATIONSHIP") || !validResourcePath(r.Collection, false) || !validResourcePath(r.Detail, true) || len(identifiers) == 0 || len(verificationFields) == 0 || r.Ownership != "collection_visibility" || (r.Classification == "RELATIONSHIP" && len(r.Relationships) == 0) {
			return fmt.Errorf("resource %q needs collection, detail, distinct id_field and verify_field, and ownership: collection_visibility", r.Name)
		}
		if len(r.IdentifierFields) > 0 && r.IDField != "" || len(r.VerificationFields) > 0 && r.VerifyField != "" {
			return fmt.Errorf("resource %q must use either legacy singular paths or the explicit field lists", r.Name)
		}
		params := map[string]bool{}
		identifierPaths := map[string]bool{}
		for _, identifier := range identifiers {
			if !validFieldPath(identifier.Path) || !validQueryParameterName(identifier.Parameter) || params[identifier.Parameter] || identifierPaths[identifier.Path] {
				return fmt.Errorf("resource %q identifier fields are invalid", r.Name)
			}
			params[identifier.Parameter] = true
			identifierPaths[identifier.Path] = true
		}
		if !detailParametersMatch(r.Detail, params) {
			return fmt.Errorf("resource %q detail path parameters must match identifier fields", r.Name)
		}
		seenVerification := map[string]bool{}
		for _, field := range verificationFields {
			if !validFieldPath(field) || seenVerification[field] || identifierPaths[field] {
				return fmt.Errorf("resource %q verification fields are invalid", r.Name)
			}
			seenVerification[field] = true
		}
		if resourceSeen[r.Name] {
			return fmt.Errorf("resource names must be unique")
		}
		resourceSeen[r.Name] = true
		relationNames := map[string]bool{}
		for _, relation := range r.Relationships {
			if !validQueryParameterName(relation.Name) || !validFieldPath(relation.Field) || relationNames[relation.Name] || !validRelationshipKind(relation.Kind) {
				return fmt.Errorf("resource %q relationship configuration is invalid", r.Name)
			}
			relationNames[relation.Name] = true
		}
		ignoredFields := map[string]bool{}
		for _, field := range r.IgnoreFields {
			if !validFieldPath(field) || ignoredFields[field] {
				return fmt.Errorf("resource %q ignored comparison fields are invalid", r.Name)
			}
			ignoredFields[field] = true
		}
		if p := r.Pagination; p != nil {
			if p.PageSize <= 0 || p.PageSize > c.Limits.MaxObjects || p.MaxPages <= 0 || p.MaxPages > c.Limits.MaxRequests || p.MaxPages > c.Limits.MaxObjects/p.PageSize {
				return fmt.Errorf("resource %q pagination bounds are invalid", r.Name)
			}
			switch p.Type {
			case "page":
				if !validQueryParameterName(p.PageParam) || !validQueryParameterName(p.PageSizeParam) || p.PageParam == p.PageSizeParam || p.StartPage < 0 {
					return fmt.Errorf("resource %q page pagination parameters are invalid", r.Name)
				}
			case "offset":
				if !validQueryParameterName(p.OffsetParam) || !validQueryParameterName(p.LimitParam) || p.OffsetParam == p.LimitParam {
					return fmt.Errorf("resource %q offset pagination parameters are invalid", r.Name)
				}
			case "cursor":
				if !validQueryParameterName(p.CursorParam) || !validFieldPath(p.NextCursorField) {
					return fmt.Errorf("resource %q cursor pagination parameters are invalid", r.Name)
				}
			default:
				return fmt.Errorf("resource %q pagination type is unsupported", r.Name)
			}
		}
	}
	ids, resources := map[string]bool{}, map[string]bool{}
	for _, i := range c.Identities {
		ids[i.ID] = true
	}
	for _, r := range c.Resources {
		resources[r.Name] = true
	}
	seenExpectation := map[string]bool{}
	for _, x := range c.Expectations {
		method := x.Method
		if method == "" {
			method = "GET"
		}
		if _, supported := MethodSafety(method); !supported {
			return fmt.Errorf("authorization expectation has an unsupported HTTP method")
		}
		if !ids[x.Identity] || !resources[x.Resource] || (x.Access != "ALLOWED" && x.Access != "DENIED" && x.Access != "UNKNOWN") {
			return fmt.Errorf("invalid authorization expectation")
		}
		if x.Owner != "" && !ids[x.Owner] {
			return fmt.Errorf("invalid authorization expectation")
		}
		if x.Relationship != "" {
			found := false
			for _, resource := range c.Resources {
				if resource.Name == x.Resource {
					for _, relation := range resource.Relationships {
						if relation.Name == x.Relationship {
							found = true
						}
					}
				}
			}
			if !found {
				return fmt.Errorf("invalid relationship authorization expectation")
			}
		}
		key := x.Identity + "\x00" + x.Owner + "\x00" + x.Resource + "\x00" + x.Relationship + "\x00" + NormalizeMethod(method)
		if seenExpectation[key] {
			return fmt.Errorf("duplicate authorization expectation")
		}
		seenExpectation[key] = true
	}
	operationIDs := map[string]bool{}
	for _, op := range c.Operations {
		method := NormalizeMethod(op.Method)
		if _, supported := MethodSafety(method); !supported || op.ID == "" || operationIDs[op.ID] || !ids[op.Actor] || !validOperationPath(op.Path) || !validVerification(op.Verification) || !validOperationClassification(op.Classification) || (op.Access != "ALLOWED" && op.Access != "DENIED" && op.Access != "UNKNOWN") {
			return fmt.Errorf("invalid authorization operation")
		}
		if op.Owner != "" && !ids[op.Owner] {
			return fmt.Errorf("authorization operation has unknown owner")
		}
		if op.Resource != "" && !resources[op.Resource] {
			return fmt.Errorf("authorization operation has unknown resource")
		}
		if op.Relationship != "" {
			found := false
			for _, resource := range c.Resources {
				if resource.Name == op.Resource {
					for _, relation := range resource.Relationships {
						if relation.Name == op.Relationship {
							found = true
						}
					}
				}
			}
			if !found {
				return fmt.Errorf("authorization operation has unknown relationship")
			}
		}
		inScope := false
		for _, prefix := range c.Target.AllowedPaths {
			p := strings.TrimSuffix(prefix, "*")
			if op.Path == strings.TrimSuffix(p, "/") || strings.HasPrefix(op.Path, p) {
				inScope = true
				break
			}
		}
		if !inScope {
			return fmt.Errorf("authorization operation is outside configured path scope")
		}
		operationIDs[op.ID] = true
	}
	if c.Limits.Timeout == "" {
		c.Limits.Timeout = "10s"
	}
	duration, e := time.ParseDuration(c.Limits.Timeout)
	if e != nil || duration <= 0 {
		return fmt.Errorf("invalid limits.timeout")
	}
	if c.Limits.MaxRequests <= 0 || c.Limits.Concurrency <= 0 || c.Limits.MaxResponseBytes <= 0 || c.Limits.MaxObjects <= 0 {
		return fmt.Errorf("limits max_requests, concurrency, max_response_bytes and max_objects must be positive")
	}
	if c.Limits.RequestsPerSecond < 0 || c.Limits.RequestsPerSecond > 1000 || math.IsNaN(c.Limits.RequestsPerSecond) || math.IsInf(c.Limits.RequestsPerSecond, 0) {
		return fmt.Errorf("limits.requests_per_second must be finite and between 0 and 1000")
	}
	if c.Limits.RedirectPolicy != "same_origin" && c.Limits.RedirectPolicy != "none" {
		return fmt.Errorf("limits.redirect_policy must be same_origin or none")
	}
	if err := validateMutationPolicy(c); err != nil {
		return err
	}
	return nil
}

func validOperationClassification(classification string) bool {
	switch classification {
	case "BFLA", "BOLA", "IDOR", "RELATIONSHIP":
		return true
	default:
		return false
	}
}

func validateMutationPolicy(c Config) error {
	p := c.Mutations
	if !p.Enabled {
		return nil
	}
	if len(p.AllowedMethods) == 0 || p.RequestBudget <= 0 || p.RequestBudget > c.Limits.MaxRequests || p.CleanupRequestBudget < 3 || p.CleanupRequestBudget > c.Limits.MaxRequests {
		return fmt.Errorf("enabled mutation policy requires explicit methods and bounded attack/cleanup request budgets")
	}
	allowedMethods := map[string]bool{}
	for _, raw := range p.AllowedMethods {
		method := NormalizeMethod(raw)
		if (method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE") || allowedMethods[method] {
			return fmt.Errorf("mutation allowed_methods may contain unique POST, PUT, PATCH, and DELETE methods only")
		}
		allowedMethods[method] = true
	}
	duration, err := time.ParseDuration(p.CleanupTimeout)
	if err != nil || duration <= 0 || duration > 10*time.Second {
		return fmt.Errorf("mutation cleanup_timeout must be between 1ns and 10s")
	}
	if len(p.AllowedPaths) == 0 || len(p.CleanupPaths) == 0 {
		return fmt.Errorf("enabled mutation policy requires explicit allowed_paths and cleanup_paths")
	}
	for _, pattern := range p.AllowedPaths {
		if !validMutationPathPattern(pattern) {
			return fmt.Errorf("mutation allowed path pattern is invalid")
		}
	}
	for _, pattern := range p.CleanupPaths {
		if !validMutationPathPattern(pattern) {
			return fmt.Errorf("mutation cleanup path pattern is invalid")
		}
	}
	postOperations := 0
	updatesBySetup := map[string]bool{}
	operationsByID := map[string]Operation{}
	for _, op := range c.Operations {
		operationsByID[op.ID] = op
	}
	for _, op := range c.Operations {
		method := NormalizeMethod(op.Method)
		if method == "POST" {
			postOperations++
			if op.Classification == "RELATIONSHIP" || op.Resource == "" {
				return fmt.Errorf("controlled POST requires an explicit BFLA/BOLA/IDOR resource classification")
			}
			if !allowedMethods["POST"] || !matchesMutationPath(p.AllowedPaths, op.Path) || !matchesConfiguredPath(c.Target.AllowedPaths, op.Path) {
				return fmt.Errorf("POST operation is not allowed by mutation and target path policies")
			}
			if op.Access == "" || op.Verification.Type != "RESOURCE_EXISTS" || !validPostResourceExists(op.Verification) || !matchesMutationPath(p.CleanupPaths, op.Verification.CleanupPath) || !matchesConfiguredPath(c.Target.AllowedPaths, op.Verification.Path) || !matchesConfiguredPath(c.Target.AllowedPaths, op.Verification.CleanupPath) {
				return fmt.Errorf("POST operation requires explicit expectation, resource-exists verification, and in-scope cleanup configuration")
			}
			if op.Classification != "BFLA" && (op.Owner == "" || op.Resource == "") {
				return fmt.Errorf("POST object authorization requires explicit owner and resource")
			}
			if op.Classification == "RELATIONSHIP" && op.Relationship == "" {
				return fmt.Errorf("POST relationship authorization requires an explicit relationship")
			}
			if err := validateControlledJSONBody(op); err != nil {
				return err
			}
			var object any
			body, _ := json.Marshal(op.RequestBody)
			_ = json.Unmarshal(body, &object)
			marker, ok := configuredJSONPath(object, op.Verification.RequestMarkerField)
			if !ok || marker != "${KURO_TEST_MARKER}" {
				return fmt.Errorf("POST operation body must contain the controlled marker placeholder")
			}
			continue
		}
		if method != "PUT" && method != "PATCH" {
			if method == "DELETE" {
				if !allowedMethods[method] {
					continue // Ordinary DELETE declarations stay valid but non-executable.
				}
				if op.ControlledResourceOperationID == "" || !matchesMutationPath(p.AllowedPaths, op.Path) ||
					!matchesConfiguredPath(c.Target.AllowedPaths, strings.Replace(op.Path, "{id}", "controlled-id", 1)) || strings.Count(op.Path, "{id}") != 1 ||
					strings.ContainsAny(strings.Replace(op.Path, "{id}", "", 1), "{}") {
					return fmt.Errorf("DELETE attack must be explicitly allowlisted and target one controlled-resource ID")
				}
				setup, ok := operationsByID[op.ControlledResourceOperationID]
				if !ok || NormalizeMethod(setup.Method) != "POST" || setup.Access != "ALLOWED" || !setup.Disposable || setup.Resource == "" || setup.Resource != op.Resource ||
					!matchesConfiguredPath(c.Target.AllowedPaths, strings.Replace(op.Verification.Path, "{id}", "controlled-id", 1)) ||
					!docPathAbsentVerification(op.Verification, setup.Verification) {
					return fmt.Errorf("DELETE attack requires a linked allowed POST setup and scoped RESOURCE_ABSENT verification")
				}
				if op.Classification == "RELATIONSHIP" && op.Relationship == "" || op.Classification != "BFLA" && op.Owner == "" {
					return fmt.Errorf("DELETE attack requires explicit owner/resource or relationship classification")
				}
				if op.Classification != "BFLA" && op.Actor == op.Owner {
					return fmt.Errorf("controlled object DELETE requires a different attack actor and owner")
				}
				if p.RequestBudget < 2 || p.CleanupRequestBudget < 3 {
					return fmt.Errorf("controlled DELETE lifecycle requires attack and bounded cleanup budgets")
				}
				continue
			}
			continue
		}
		if !allowedMethods[method] || op.ControlledResourceOperationID == "" || updatesBySetup[op.ControlledResourceOperationID] {
			return fmt.Errorf("PUT/PATCH requires an explicitly allowlisted method and unique controlled POST setup operation")
		}
		setup, ok := operationsByID[op.ControlledResourceOperationID]
		if !ok || NormalizeMethod(setup.Method) != "POST" || setup.Resource != op.Resource || setup.Access != "ALLOWED" {
			return fmt.Errorf("PUT/PATCH setup must reference an explicitly ALLOWED POST for the same resource")
		}
		updatesBySetup[op.ControlledResourceOperationID] = true
		if !matchesMutationPath(p.AllowedPaths, op.Path) || !matchesConfiguredPath(c.Target.AllowedPaths, strings.Replace(op.Path, "{id}", "controlled-id", 1)) || strings.Count(op.Path, "{id}") != 1 || strings.ContainsAny(strings.Replace(op.Path, "{id}", "", 1), "{}") {
			return fmt.Errorf("PUT/PATCH target must be one scoped, allowlisted controlled-resource path")
		}
		if !docPathStateVerification(op.Verification) || !validFieldPath(op.Verification.ResourceIDField) || op.Verification.ResourceIDField != setup.Verification.ResourceIDField || op.Verification.MarkerField != setup.Verification.MarkerField || !matchesConfiguredPath(c.Target.AllowedPaths, strings.Replace(op.Verification.Path, "{id}", "controlled-id", 1)) || strings.Count(op.Verification.Path, "{id}") != 1 || strings.ContainsAny(strings.Replace(op.Verification.Path, "{id}", "", 1), "{}") {
			return fmt.Errorf("PUT/PATCH requires scoped RESOURCE_STATE safe-GET verification")
		}
		if op.Classification == "RELATIONSHIP" {
			if op.Relationship == "" || op.Owner == "" || op.Actor == op.Owner || !configuredRelationship(c.Resources, op.Resource, op.Relationship) {
				return fmt.Errorf("PUT/PATCH relationship authorization requires a mapped relationship and distinct actor and owner")
			}
		} else if op.Classification != "BFLA" && op.Classification != "BOLA" && op.Classification != "IDOR" || op.Classification != "BFLA" && (op.Owner == "" || op.Resource == "") {
			return fmt.Errorf("PUT/PATCH requires explicit BFLA/BOLA/IDOR or mapped relationship classification")
		}
		if err := validateControlledJSONBody(op); err != nil {
			return err
		}
		if !bodyPathHasScalar(op.RequestBody, op.Verification.Field) {
			return fmt.Errorf("PUT/PATCH desired body must set the configured state field")
		}
		if op.RestoreBody != nil {
			if err := validateRestoreBody(op.RestoreBody, op.Verification.Field); err != nil {
				return err
			}
			if p.CleanupRequestBudget < 4 {
				return fmt.Errorf("restoration requires at least four bounded cleanup requests")
			}
		}
	}
	if postOperations == 0 {
		return fmt.Errorf("enabled mutation policy requires at least one explicitly configured POST setup operation")
	}
	if len(updatesBySetup) > 0 && p.RequestBudget < 2 {
		return fmt.Errorf("controlled PUT/PATCH lifecycle requires budget for setup and one attack mutation")
	}
	for _, op := range c.Operations {
		if method := NormalizeMethod(op.Method); method == "PUT" || method == "PATCH" {
			if !updatesBySetup[op.ControlledResourceOperationID] {
				return fmt.Errorf("PUT/PATCH setup could not be linked safely")
			}
		}
	}
	return nil
}

func docPathAbsentVerification(strategy VerificationStrategy, setup VerificationStrategy) bool {
	return strategy.Type == "RESOURCE_ABSENT" && validResourcePath(strings.Replace(strategy.Path, "{id}", "controlled-id", 1), false) &&
		strings.Count(strategy.Path, "{id}") == 1 && validFieldPath(strategy.BaselineCompleteField) &&
		strategy.BaselineCompleteField == setup.BaselineCompleteField && strategy.ResourceIDField == setup.ResourceIDField &&
		strategy.MarkerField == setup.MarkerField
}

func docPathStateVerification(strategy VerificationStrategy) bool {
	return strategy.Type == "RESOURCE_STATE" && validResourcePath(strings.Replace(strategy.Path, "{id}", "controlled-id", 1), false) && validFieldPath(strategy.Field) && validFieldPath(strategy.MarkerField) && validFieldPath(strategy.BaselineCompleteField)
}

func validateControlledJSONBody(op Operation) error {
	contentType, _, parseErr := mime.ParseMediaType(op.ContentType)
	body, marshalErr := json.Marshal(op.RequestBody)
	if parseErr != nil || contentType != "application/json" || strings.TrimSpace(op.ContentType) != "application/json" || marshalErr != nil || len(body) == 0 || len(body) > 16*1024 {
		return fmt.Errorf("%s operation requires a valid application/json body no larger than 16 KiB", NormalizeMethod(op.Method))
	}
	var root any
	if json.Unmarshal(body, &root) != nil {
		return fmt.Errorf("%s request body must be valid JSON", NormalizeMethod(op.Method))
	}
	if _, ok := root.(map[string]any); !ok {
		return fmt.Errorf("%s request body must be a JSON object", NormalizeMethod(op.Method))
	}
	return nil
}

func bodyPathHasScalar(body any, field string) bool {
	encoded, err := json.Marshal(body)
	if err != nil {
		return false
	}
	var root any
	if json.Unmarshal(encoded, &root) != nil {
		return false
	}
	value, ok := configuredJSONPath(root, field)
	if !ok || value == nil {
		return false
	}
	switch value.(type) {
	case string, bool, float64:
		return true
	default:
		return false
	}
}

func validateRestoreBody(body any, field string) error {
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) == 0 || len(encoded) > 16*1024 {
		return fmt.Errorf("restore_body must be valid JSON no larger than 16 KiB")
	}
	var root any
	if json.Unmarshal(encoded, &root) != nil {
		return fmt.Errorf("restore_body must be valid JSON")
	}
	value, ok := configuredJSONPath(root, field)
	if !ok || value != "${KURO_PREVIOUS_STATE}" {
		return fmt.Errorf("restore_body must place ${KURO_PREVIOUS_STATE} at the configured state field")
	}
	return nil
}

func validPostResourceExists(strategy VerificationStrategy) bool {
	return validResourcePath(strategy.Path, false) && validFieldPath(strategy.MarkerField) && validFieldPath(strategy.ResourceIDField) && validFieldPath(strategy.RequestMarkerField) && validFieldPath(strategy.BaselineCompleteField) && validOperationPath(strategy.CleanupPath) && detailParametersMatch(strategy.CleanupPath, map[string]bool{"id": true})
}

func configuredJSONPath(root any, path string) (any, bool) {
	current := root
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, path != ""
}

func validMutationPathPattern(pattern string) bool {
	if strings.Contains(pattern, "*") {
		if !strings.HasSuffix(pattern, "/*") || strings.Count(pattern, "*") != 1 {
			return false
		}
		base := strings.TrimSuffix(pattern, "*")
		return strings.TrimSuffix(base, "/") != "" && validResourcePath(strings.TrimSuffix(base, "/"), false)
	}
	return validOperationPath(pattern)
}

func matchesMutationPath(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pattern == path {
			return true
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

func containsMethod(methods []string, target string) bool {
	for _, method := range methods {
		if NormalizeMethod(method) == target {
			return true
		}
	}
	return false
}

func matchesConfiguredPath(patterns []string, path string) bool {
	for _, pattern := range patterns {
		prefix := strings.TrimSuffix(pattern, "*")
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

func configuredIdentifiers(r Resource) []IdentifierField {
	if len(r.IdentifierFields) > 0 {
		return r.IdentifierFields
	}
	if r.IDField != "" {
		return []IdentifierField{{Path: r.IDField, Parameter: "id"}}
	}
	return nil
}

func configuredVerificationFields(r Resource) []string {
	if len(r.VerificationFields) > 0 {
		return r.VerificationFields
	}
	if r.VerifyField != "" {
		return []string{r.VerifyField}
	}
	return nil
}

var pathParameter = regexp.MustCompile(`\{([A-Za-z0-9_.~-]+)\}`)

func detailParametersMatch(detail string, expected map[string]bool) bool {
	found := map[string]bool{}
	for _, match := range pathParameter.FindAllStringSubmatch(detail, -1) {
		if found[match[1]] || !expected[match[1]] {
			return false
		}
		found[match[1]] = true
	}
	if strings.ContainsAny(pathParameter.ReplaceAllString(detail, ""), "{}") || len(found) != len(expected) {
		return false
	}
	return true
}

func validOperationPath(value string) bool {
	if value == "" {
		return false
	}
	clean := pathParameter.ReplaceAllString(value, "operation-id")
	if strings.ContainsAny(clean, "{}") {
		return false
	}
	return validResourcePath(clean, false)
}

func validFieldPath(field string) bool {
	if field == "" {
		return false
	}
	for _, part := range strings.Split(field, ".") {
		if part == "" || strings.ContainsAny(part, "[]") {
			return false
		}
	}
	return true
}

func validQueryParameterName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-.~", r)) {
			return false
		}
	}
	return true
}

func validRelationshipKind(kind string) bool {
	switch kind {
	case "tenant", "organization", "workspace", "project", "parent", "child":
		return true
	default:
		return false
	}
}

func configuredRelationship(resources []Resource, resourceName, relationshipName string) bool {
	for _, resource := range resources {
		if resource.Name != resourceName {
			continue
		}
		for _, relationship := range resource.Relationships {
			if relationship.Name == relationshipName {
				return true
			}
		}
	}
	return false
}

func validResourcePath(value string, allowID bool) bool {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "?#@\\\x00;=:") || strings.Contains(value, "://") {
		return false
	}
	lower := strings.ToLower(value)
	for _, encoded := range []string{"%25", "%2e", "%2f", "%5c", "%00", "%3f", "%23", "%40", "%3a", "%3b", "%3d"} {
		if strings.Contains(lower, encoded) {
			return false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	if strings.Contains(value, "{id}") && !allowID {
		return false
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return http.CanonicalHeaderKey(name) != ""
}
