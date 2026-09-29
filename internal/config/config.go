package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SchemaVersion string `json:"schema_version" yaml:"schema_version"`
	Target        Target `json:"target" yaml:"target"`
	OpenAPI       struct {
		Path string `json:"path" yaml:"path"`
	} `json:"openapi" yaml:"openapi"`
	Identities   []Identity    `json:"identities" yaml:"identities"`
	Resources    []Resource    `json:"resources" yaml:"resources"`
	Expectations []Expectation `json:"expectations" yaml:"expectations"`
	Limits       Limits        `json:"limits" yaml:"limits"`
}
type Target struct {
	BaseURL        string   `json:"base_url" yaml:"base_url"`
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins"`
	AllowedPaths   []string `json:"allowed_paths" yaml:"allowed_paths"`
}
type Identity struct {
	ID      string            `json:"id" yaml:"id"`
	Name    string            `json:"name" yaml:"name"`
	Role    string            `json:"role,omitempty" yaml:"role,omitempty"`
	Headers map[string]string `json:"headers" yaml:"headers"`
}
type Resource struct {
	Name        string `json:"name" yaml:"name"`
	Collection  string `json:"collection" yaml:"collection"`
	Detail      string `json:"detail" yaml:"detail"`
	IDField     string `json:"id_field" yaml:"id_field"`
	VerifyField string `json:"verify_field,omitempty" yaml:"verify_field,omitempty"`
	Ownership   string `json:"ownership" yaml:"ownership"`
}
type Expectation struct {
	Identity string `json:"identity" yaml:"identity"`
	Resource string `json:"resource" yaml:"resource"`
	Access   string `json:"access" yaml:"access"`
}
type Limits struct {
	Timeout           string  `json:"timeout" yaml:"timeout"`
	MaxRequests       int     `json:"max_requests" yaml:"max_requests"`
	Concurrency       int     `json:"concurrency" yaml:"concurrency"`
	RequestsPerSecond float64 `json:"requests_per_second" yaml:"requests_per_second"`
	MaxResponseBytes  int64   `json:"max_response_bytes" yaml:"max_response_bytes"`
	MaxObjects        int     `json:"max_objects" yaml:"max_objects"`
	RedirectPolicy    string  `json:"redirect_policy" yaml:"redirect_policy"`
}

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
	}
	return c, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

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
	if c.SchemaVersion != "1" {
		return fmt.Errorf("schema_version must be \"1\"")
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
		seen[i.ID] = true
	}
	if c.OpenAPI.Path == "" {
		return fmt.Errorf("openapi.path is required")
	}
	if len(c.Resources) == 0 {
		return fmt.Errorf("at least one explicit resource mapping is required")
	}
	resourceSeen := map[string]bool{}
	for _, r := range c.Resources {
		if r.Name == "" || !validResourcePath(r.Collection, false) || !validResourcePath(r.Detail, true) || !strings.Contains(r.Detail, "{id}") || r.IDField == "" || r.VerifyField == "" || r.VerifyField == r.IDField || r.Ownership != "collection_visibility" {
			return fmt.Errorf("resource %q needs collection, detail, distinct id_field and verify_field, and ownership: collection_visibility", r.Name)
		}
		if resourceSeen[r.Name] {
			return fmt.Errorf("resource names must be unique")
		}
		resourceSeen[r.Name] = true
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
		if !ids[x.Identity] || !resources[x.Resource] || (x.Access != "ALLOWED" && x.Access != "DENIED" && x.Access != "UNKNOWN") {
			return fmt.Errorf("invalid authorization expectation")
		}
		key := x.Identity + "\x00" + x.Resource
		if seenExpectation[key] {
			return fmt.Errorf("duplicate authorization expectation")
		}
		seenExpectation[key] = true
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
	return nil
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
