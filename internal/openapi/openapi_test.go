package openapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	for _, body := range []string{`{"openapi":"3.0.3",`, `{"openapi":"3.0.3","openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{"/x":{"get":{}}}}`, "openapi: [bad", "openapi: 2.0.0\ninfo: {title: X, version: '1'}\npaths:\n  /x:\n    get: {}\n", "openapi: 3.0.3\ninfo: {title: X, version: '1'}\npaths: {}\n", "openapi: 3.0.3\npaths:\n  /x: null\n"} {
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

func TestLocalReferencesResolveAndExposeOperationMetadata(t *testing.T) {
	body := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"servers":[{"url":"https://example.invalid"}],"components":{"parameters":{"id":{"name":"id","in":"path","required":true,"schema":{"type":"string"}}},"responses":{"ok":{"description":"ok"}}},"paths":{"/docs/{id}":{"parameters":[{"$ref":"#/components/parameters/id"}],"get":{"operationId":"getDoc","responses":{"200":{"$ref":"#/components/responses/ok"}}}}}}`
	d, err := Load(writeSpecAs(t, "local-ref.json", body))
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := d.Metadata("/docs/{id}", "GET")
	if !ok || metadata.OperationID != "getDoc" || len(metadata.Parameters) != 1 || len(metadata.Responses) == 0 || len(d.Servers) == 0 {
		t.Fatalf("resolved metadata missing: %+v", metadata)
	}
}

func TestExternalReferencesCyclesAndInvalidPointersRejected(t *testing.T) {
	for _, ref := range []string{"https://attacker.invalid/spec.json#/Thing", "#/components/schemas/Loop", "#/components/schemas/Bad~2Token"} {
		components := `{"responses":{"ok":{"description":"ok"}}}`
		if ref == "#/components/schemas/Loop" {
			components = `{"schemas":{"Loop":{"$ref":"#/components/schemas/Loop"}}}`
		} else if strings.HasPrefix(ref, "#") {
			components = `{"schemas":{"Bad~2Token":{"type":"string"}}}`
		}
		body := `{"openapi":"3.0.3","info":{"title":"Fixture","version":"1"},"components":` + components + `,"paths":{"/docs":{"get":{"responses":{"200":{"$ref":"` + ref + `"}}}}}}`
		_, err := Load(writeSpecAs(t, "ref.json", body))
		if err == nil {
			t.Errorf("accepted external ref %q", ref)
		}
	}
}

func FuzzLoadOpenAPIDoesNotPanic(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"openapi":"3.0.3","info":{"title":"fuzz","version":"1"},"paths":{"/x":{"get":{}}}}`),
		[]byte(`{"openapi":"3.0.3","paths":{"/x":{"get":{"$ref":"#/components/x~2"}}}}`),
		[]byte("openapi: ["),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "fuzz.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = Load(path)
	})
}
