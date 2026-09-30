package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandEnvDoesNotRevealValues(t *testing.T) {
	_ = os.Unsetenv("KURO_TEST_MISSING")
	got, err := ExpandEnv("Bearer ${KURO_TEST_MISSING}")
	if err == nil || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("got %q, err %v", got, err)
	}
	_ = os.Setenv("KURO_TEST_SECRET", "sensitive-token")
	defer os.Unsetenv("KURO_TEST_SECRET")
	got, err = ExpandEnv("Bearer ${KURO_TEST_SECRET}")
	if err != nil || got != "Bearer sensitive-token" {
		t.Fatalf("got %q err %v", got, err)
	}
}
func TestLoadYAMLExpandsHeaderAndValidatesExpectation(t *testing.T) {
	_ = os.Setenv("KURO_TOKEN", "sample")
	defer os.Unsetenv("KURO_TOKEN")
	body := `schema_version: "3"
target:
  base_url: http://localhost:8080
  allowed_origins: [http://localhost:8080]
  allowed_paths: [/api]
openapi: {path: spec.json}
identities:
  - id: a
    headers:
      Authorization: '${KURO_TOKEN}'
    credentials:
      - {type: cookie, name: session, value: '${KURO_TOKEN}'}
      - {type: header, name: X-Env-Token, value: '${KURO_TOKEN}'}
  - id: b
    headers:
      Authorization: fixed
resources:
  - name: docs
    classification: BOLA
    collection: /api/docs
    detail: /api/docs/{id}
    id_field: id
    verify_field: name
    ownership: collection_visibility
expectations:
  - {identity: b, resource: docs, access: DENIED}
limits: {timeout: 1s, max_requests: 10, concurrency: 2, max_response_bytes: 1024, max_objects: 4, redirect_policy: none}
`
	p := filepath.Join(t.TempDir(), "config.yaml")
	_ = os.WriteFile(p, []byte(body), 0600)
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.Identities[0].Headers["Authorization"] != "sample" || c.Identities[0].Credentials[0].Value != "sample" || c.Identities[0].Credentials[1].Value != "sample" || c.Expectations[0].Access != "DENIED" {
		t.Fatalf("unexpected config %+v", c)
	}
}

func TestLoadRejectsDuplicateJSONKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "duplicate.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"3","schema_version":"3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("duplicate configuration key was not rejected as malformed JSON: %v", err)
	}
}

func TestLoadEnvironmentExpansionCases(t *testing.T) {
	set := func(name, value string) {
		t.Helper()
		if err := os.Setenv(name, value); err != nil {
			t.Fatal(err)
		}
	}
	set("KURO_ENV_ONE", "alpha")
	set("KURO_ENV_TWO", "beta")
	set("KURO_ENV_EMPTY", "")
	set("KURO_ENV_CRLF", "safe\r\nInjected: yes")
	defer func() {
		for _, name := range []string{"KURO_ENV_ONE", "KURO_ENV_TWO", "KURO_ENV_EMPTY", "KURO_ENV_CRLF"} {
			_ = os.Unsetenv(name)
		}
	}()

	loadHeader := func(value string) (Config, error) {
		t.Helper()
		body := `schema_version: "3"
target:
  base_url: http://localhost:8080
  allowed_origins: [http://localhost:8080]
  allowed_paths: [/api]
openapi: {path: spec.json}
identities:
  - id: a
    headers:
      Authorization: '` + value + `'
  - id: b
    headers:
      Authorization: fixed
resources:
  - name: docs
    classification: BOLA
    collection: /api/docs
    detail: /api/docs/{id}
    id_field: id
    verify_field: name
    ownership: collection_visibility
limits:
  timeout: 1s
  max_requests: 10
  concurrency: 2
  max_response_bytes: 1024
  max_objects: 4
  redirect_policy: none
`
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return Load(p)
	}

	c, err := loadHeader(`${KURO_ENV_ONE}${KURO_ENV_TWO}`)
	if err != nil || c.Identities[0].Headers["Authorization"] != "alphabeta" {
		got := ""
		if len(c.Identities) > 0 {
			got = c.Identities[0].Headers["Authorization"]
		}
		t.Fatalf("adjacent/multiple references: value=%q err=%v", got, err)
	}
	c, err = loadHeader(`prefix-${KURO_ENV_EMPTY}-suffix`)
	if err != nil || c.Identities[0].Headers["Authorization"] != "prefix--suffix" {
		got := ""
		if len(c.Identities) > 0 {
			got = c.Identities[0].Headers["Authorization"]
		}
		t.Fatalf("empty environment value: value=%q err=%v", got, err)
	}
	if _, err = loadHeader(`${KURO_ENV_ONE`); err == nil {
		t.Fatal("malformed environment reference accepted")
	}
	if _, err = loadHeader(`${KURO_ENV_CRLF}`); err == nil {
		t.Fatal("CR/LF environment expansion accepted")
	}
}

func TestRejectsCaseInsensitiveDuplicateHeaders(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Authorization": "one", "authorization": "two"},
		{"X-API-Key": "one", "x-api-key": "two"},
	} {
		c := validConfig()
		c.Identities[0].Headers = headers
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted colliding header names: %#v", headers)
		}
	}
}

func validConfig() Config {
	var c Config
	c.SchemaVersion = "3"
	c.Target = Target{BaseURL: "http://localhost:8080", AllowedOrigins: []string{"http://localhost:8080"}, AllowedPaths: []string{"/api"}}
	c.Identities = []Identity{{ID: "a", Headers: map[string]string{"Authorization": "one"}}, {ID: "b", Headers: map[string]string{"Authorization": "two"}}}
	c.Resources = []Resource{{Name: "docs", Classification: "BOLA", Collection: "/api/docs", Detail: "/api/docs/{id}", IDField: "id", VerifyField: "name", Ownership: "collection_visibility"}}
	c.Limits = Limits{Timeout: "1s", MaxRequests: 10, Concurrency: 2, MaxResponseBytes: 1024, MaxObjects: 4, RedirectPolicy: "none"}
	c.OpenAPI.Path = "spec.json"
	return c
}

func TestConfigSchemaV2RequiresExplicitUpgrade(t *testing.T) {
	c := validConfig()
	c.SchemaVersion = "2"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("schema v2 was not rejected explicitly: %v", err)
	}
}

func TestResourceMappingsArePathOnly(t *testing.T) {
	for _, value := range []string{"/api/docs?token=CANARY", "/api/docs#fragment", "//user:pass@example/docs", "/api/user:pass@example/docs", "/api/user:pass", "/api/key=secret", "/api/docs;token=secret", "/api/docs%3Ftoken=secret", "/api/docs%40user", "/api/docs%25253fsecret"} {
		c := validConfig()
		c.Resources[0].Collection = value
		if err := c.Validate(); err == nil {
			t.Errorf("accepted non-path resource mapping %q", value)
		}
	}
}

func FuzzExplicitJSONFieldPaths(f *testing.F) {
	for _, seed := range []string{"id", "data.resource.id", "", ".id", "id.", "a..b", "items[0].id"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		_ = validFieldPath(value)
	})
}

func FuzzLoadConfigNeverPanics(f *testing.F) {
	f.Add("config.json", []byte(`{"schema_version":"3","schema_version":"3"}`))
	f.Add("config.yaml", []byte("schema_version: ["))
	f.Add("config.json", []byte(`{"schema_version":"3"}`))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			ext = ".json"
		}
		path := filepath.Join(t.TempDir(), "fuzz"+ext)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = Load(path)
	})
}

func TestExplicitPaginationConfigurations(t *testing.T) {
	valid := []*Pagination{
		{Type: "page", PageParam: "page", PageSizeParam: "size", StartPage: 1, PageSize: 2, MaxPages: 2},
		{Type: "offset", OffsetParam: "offset", LimitParam: "limit", PageSize: 2, MaxPages: 2},
		{Type: "cursor", CursorParam: "cursor", NextCursorField: "meta.next", PageSize: 2, MaxPages: 2},
	}
	for _, pagination := range valid {
		c := validConfig()
		c.Resources[0].Pagination = pagination
		if err := c.Validate(); err != nil {
			t.Errorf("valid pagination rejected: %+v: %v", pagination, err)
		}
	}
	invalid := []Pagination{
		{Type: "page", PageParam: "page", PageSizeParam: "size", PageSize: 3, MaxPages: 2},
		{Type: "page", PageParam: "page", PageSizeParam: "page", PageSize: 1, MaxPages: 1},
		{Type: "cursor", CursorParam: "cursor", NextCursorField: "", PageSize: 1, MaxPages: 1},
		{Type: "cursor", CursorParam: "cursor&token=x", NextCursorField: "next", PageSize: 1, MaxPages: 1},
	}
	for _, pagination := range invalid {
		c := validConfig()
		c.Resources[0].Pagination = &pagination
		if err := c.Validate(); err == nil {
			t.Errorf("invalid pagination accepted: %+v", pagination)
		}
	}
}

func TestCompositeResourceConfiguration(t *testing.T) {
	c := validConfig()
	r := &c.Resources[0]
	r.IDField = ""
	r.VerifyField = ""
	r.Detail = "/api/orgs/{org}/docs/{doc}"
	r.IdentifierFields = []IdentifierField{{Path: "organization.id", Parameter: "org"}, {Path: "document.key", Parameter: "doc"}}
	r.VerificationFields = []string{"metadata.version", "content.title"}
	if err := c.Validate(); err != nil {
		t.Fatalf("composite resource rejected: %v", err)
	}
	r.Detail = "/api/orgs/{org}/docs/{id}"
	if err := c.Validate(); err == nil {
		t.Fatal("unmatched composite identifier parameters accepted")
	}
}
