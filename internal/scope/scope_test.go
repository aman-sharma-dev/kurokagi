package scope

import "testing"

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
