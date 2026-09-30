package scope

import (
	"net"
	"net/url"
	"path"
	"strings"
	"testing"
)

func TestMatchScopeBoundaries(t *testing.T) {
	origins := []string{"https://api.example:8443"}
	paths := []string{"/api/v1"}
	good := []string{"https://api.example:8443/api/v1", "https://api.example:8443/api/v1/docs", "https://api.example:8443/api/v1/a%20b"}
	for _, u := range good {
		if !Match(u, origins, paths) {
			t.Errorf("expected in scope: %s", u)
		}
	}
	bad := []string{
		"https://evil.example:8443/api/v1", "http://api.example:8443/api/v1", "https://api.example/api/v1", "https://api.example:8443/api/v10",
		"https://api.example:8443/api/v1/../admin", "https://api.example:8443/api/v1/%2e%2e/admin", "https://api.example:8443/api/v1%2f..%2fadmin",
		"https://api.example:8443/api/v1/%252e%252e/admin", "https://api.example:8443/api/v1/%252fadmin", "https://api.example:8443/api/v1/%255cadmin",
		"https://api.example:8443/api/v1/%2500", "https://api.example:8443/api/v1/%2fadmin", "https://api.example:8443/api/v1/%5cadmin",
		"https://api.example:8443/api//v1", "https://api.example:8443//api/v1", "https://api.example:8443/api/v1/", "https://u@api.example:8443/api/v1",
		"https://api.example:8443/api/v1?token=secret", "https://api.example:8443/api/v1#fragment",
	}
	for _, u := range bad {
		if Match(u, origins, paths) {
			t.Errorf("unexpectedly in scope: %s", u)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	if !SameOrigin("https://api.example/path", "https://api.example:443/other") {
		t.Fatal("effective default ports should match")
	}
	if SameOrigin("https://api.example/path", "http://api.example/path") {
		t.Fatal("different schemes must not match")
	}
}

func TestMatchWithQueryRequiresExactAllowlist(t *testing.T) {
	origins, paths := []string{"https://api.example"}, []string{"/api"}
	if Match("https://api.example/api/items?page=2", origins, paths) {
		t.Fatal("ordinary scope matcher must continue to reject query strings")
	}
	if !MatchWithQuery("https://api.example/api/items?page=2&size=20", origins, paths, []string{"page", "size"}) {
		t.Fatal("explicit pagination parameters should be allowed")
	}
	for _, raw := range []string{
		"https://api.example/api/items?page=2&token=secret",
		"https://api.example/api/items?page=1&page=2",
		"https://api.example/api/items?page=%zz",
	} {
		if MatchWithQuery(raw, origins, paths, []string{"page", "size"}) {
			t.Errorf("query outside explicit allowlist accepted: %s", raw)
		}
	}
}

func FuzzMatchRejectsUnsafeURLShapes(f *testing.F) {
	for _, raw := range []string{
		"http://example.test/api/items", "http://example.test/api/../admin",
		"http://example.test/api/%2e%2e/admin", "http://example.test/api/%252fadmin",
		"http://user:pass@example.test/api/items", "http://example.test/api/items?token=x",
		"https://example.test/api/items", "http://example.test.evil/api/items",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := Match(raw, []string{"http://example.test"}, []string{"/api"})
		if got {
			u, err := url.Parse(raw)
			if err != nil || u == nil {
				t.Fatalf("accepted unparsable URL: %q", raw)
			}
			port := "80"
			if u.Port() != "" {
				port = u.Port()
			}
			decoded, decodeErr := url.PathUnescape(u.EscapedPath())
			if decodeErr != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.EqualFold(u.Hostname(), "example.test") || port != "80" || net.ParseIP(u.Hostname()) != nil || dangerousEscape(u.EscapedPath()) || strings.ContainsAny(decoded, "\\\x00") || path.Clean(decoded) != decoded {
				t.Fatalf("unsafe URL accepted: %q", raw)
			}
			for _, segment := range strings.Split(decoded, "/") {
				if segment == "." || segment == ".." {
					t.Fatalf("traversal accepted: %q", raw)
				}
			}
		}
	})
}
