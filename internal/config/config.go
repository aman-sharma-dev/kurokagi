package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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
	Identities []Identity `json:"identities" yaml:"identities"`
	Resources  []Resource `json:"resources" yaml:"resources"`
	Limits     Limits     `json:"limits" yaml:"limits"`
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
	if strings.EqualFold(strings.TrimPrefix(strings.ToLower(path), "."), "yaml") {
		e = yaml.Unmarshal(b, &c)
	} else if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		e = yaml.Unmarshal(b, &c)
	} else {
		e = json.Unmarshal(b, &c)
	}
	if e != nil {
		return c, fmt.Errorf("parse configuration: %w", e)
	}
	if e = c.Validate(); e != nil {
		return c, e
	}
	return c, nil
}
func (c Config) Validate() error {
	if c.SchemaVersion != "1" {
		return fmt.Errorf("schema_version must be \"1\"")
	}
	u, e := url.Parse(c.Target.BaseURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("target.base_url must be an absolute HTTP(S) URL")
	}
	if len(c.Target.AllowedOrigins) == 0 || len(c.Target.AllowedPaths) == 0 {
		return fmt.Errorf("target.allowed_origins and allowed_paths must be explicit")
	}
	for _, o := range c.Target.AllowedOrigins {
		x, e := url.Parse(o)
		if e != nil || x.Host == "" || (x.Scheme != "http" && x.Scheme != "https") {
			return fmt.Errorf("invalid allowed origin %q", o)
		}
	}
	if len(c.Identities) < 2 {
		return fmt.Errorf("at least two identities are required")
	}
	seen := map[string]bool{}
	for _, i := range c.Identities {
		if i.ID == "" || seen[i.ID] {
			return fmt.Errorf("identity IDs must be non-empty and unique")
		}
		seen[i.ID] = true
	}
	if c.OpenAPI.Path == "" {
		return fmt.Errorf("openapi.path is required")
	}
	if len(c.Resources) == 0 {
		return fmt.Errorf("at least one explicit resource mapping is required")
	}
	for _, r := range c.Resources {
		if r.Collection == "" || r.Detail == "" || r.IDField == "" || r.Ownership != "collection_visibility" {
			return fmt.Errorf("resource %q needs collection, detail, id_field and ownership: collection_visibility", r.Name)
		}
	}
	if c.Limits.Timeout == "" {
		c.Limits.Timeout = "10s"
	}
	if _, e := time.ParseDuration(c.Limits.Timeout); e != nil {
		return fmt.Errorf("invalid limits.timeout")
	}
	if c.Limits.MaxRequests <= 0 || c.Limits.Concurrency <= 0 || c.Limits.MaxResponseBytes <= 0 || c.Limits.MaxObjects <= 0 {
		return fmt.Errorf("limits max_requests, concurrency, max_response_bytes and max_objects must be positive")
	}
	if c.Limits.RequestsPerSecond < 0 {
		return fmt.Errorf("limits.requests_per_second cannot be negative")
	}
	if c.Limits.RedirectPolicy != "same_origin" && c.Limits.RedirectPolicy != "none" {
		return fmt.Errorf("limits.redirect_policy must be same_origin or none")
	}
	return nil
}
