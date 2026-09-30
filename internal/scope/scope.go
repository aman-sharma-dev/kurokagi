package scope

import (
	"net/url"
	"path"
	"strings"
)

// Match reports whether raw is within one of the configured origins and path prefixes.
func Match(raw string, origins, paths []string) bool {
	return match(raw, origins, paths, nil)
}

// MatchWithQuery validates an in-scope URL while allowing only explicit query
// parameter names. The ordinary Match API remains query-free by default.
// MatchWithQuery applies scope checks and an optional exact query-key allowlist.
func MatchWithQuery(raw string, origins, paths, allowedQueryKeys []string) bool {
	return match(raw, origins, paths, allowedQueryKeys)
}

func match(raw string, origins, paths, allowedQueryKeys []string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	if u.RawQuery != "" || u.ForceQuery {
		if len(allowedQueryKeys) == 0 {
			return false
		}
		allowed := make(map[string]bool, len(allowedQueryKeys))
		for _, key := range allowedQueryKeys {
			allowed[key] = true
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(query) == 0 || (u.ForceQuery && u.RawQuery == "") {
			return false
		}
		for key, values := range query {
			if !allowed[key] || len(values) != 1 {
				return false
			}
		}
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return false
	}
	decoded, err := url.PathUnescape(u.EscapedPath())
	if err != nil || dangerousEscape(u.EscapedPath()) || strings.ContainsAny(decoded, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	if path.Clean(decoded) != decoded {
		return false
	}
	ok := false
	for _, o := range origins {
		x, e := url.Parse(o)
		if e == nil && strings.EqualFold(x.Scheme, u.Scheme) && sameHost(x, u) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, p := range paths {
		p = strings.TrimSuffix(p, "*")
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(decoded, p) {
				return true
			}
		} else if decoded == p || strings.HasPrefix(decoded, p+"/") {
			return true
		}
	}
	return false
}

// dangerousEscape rejects encoded syntax that would become path structure if
// another component decoded the path again. Escaped percent signs are also
// rejected so this rule does not need recursive decoding.
func dangerousEscape(escaped string) bool {
	for i := 0; i+2 < len(escaped); i++ {
		if escaped[i] != '%' {
			continue
		}
		code := strings.ToLower(escaped[i+1 : i+3])
		switch code {
		case "25", "2e", "2f", "5c", "00":
			return true
		}
		i += 2
	}
	return false
}

// SameOrigin compares HTTP origins using effective default ports.
// SameOrigin reports whether two absolute URLs have the same normalized origin.
func SameOrigin(a, b string) bool {
	x, errX := url.Parse(a)
	y, errY := url.Parse(b)
	return errX == nil && errY == nil && strings.EqualFold(x.Scheme, y.Scheme) && sameHost(x, y)
}

func sameHost(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}
