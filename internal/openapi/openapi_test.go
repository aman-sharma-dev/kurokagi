package openapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeSpec(t *testing.T, content string) string {
	return writeSpecAs(t, "spec.yaml", content)
}
func writeSpecAs(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestLoadJSONAndYAML(t *testing.T) {
	for _, tc := range []struct{ name, file, body string }{{"json", "spec.json", `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"paths":{"/docs":{"get":{}}}}`}, {"yaml", "spec.yaml", "openapi: 3.1.0\ninfo:\n  title: Fixture\n  version: '1'\npaths:\n  /docs:\n    get: {}\n"}, {"flow yaml", "flow.yaml", "{openapi: '3.1.0', info: {title: Fixture, version: '1'}, paths: {/docs: {get: {}}}}"}} {
		t.Run(tc.name, func(t *testing.T) {
			d, e := Load(writeSpecAs(t, tc.file, tc.body))
			if e != nil || !d.HasGet("/docs") {
				t.Fatalf("doc=%+v err=%v", d, e)
			}
		})
	}
}
func TestLoadRejectsMalformedAndUnsupported(t *testing.T) {
	for _, body := range []string{`{"openapi":"3.0.3",`, "openapi: [bad", "openapi: 2.0.0\ninfo: {title: X, version: '1'}\npaths:\n  /x:\n    get: {}\n", "openapi: 3.0.3\ninfo: {title: X, version: '1'}\npaths: {}\n", "openapi: 3.0.3\npaths:\n  /x: null\n"} {
		if _, e := Load(writeSpec(t, body)); e == nil {
			t.Errorf("accepted invalid spec: %q", body)
		}
	}
}

func TestHasGetIsCaseSensitive(t *testing.T) {
	d := Document{Paths: map[string]map[string]json.RawMessage{
		"/Docs": {"get": json.RawMessage(`{}`)},
	}}
	if !d.HasGet("/Docs") || d.HasGet("/docs") {
		t.Fatal("OpenAPI path matching must be case-sensitive")
	}
}
