package scope

import (
	"net/url"
	"strings"
)

func Match(raw string, origins, paths []string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Host == "" {
		return false
	}
	origin := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	ok := false
	for _, o := range origins {
		x, e := url.Parse(o)
		if e == nil && strings.EqualFold(x.Scheme, u.Scheme) && strings.EqualFold(x.Host, u.Host) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, p := range paths {
		p = strings.TrimSuffix(p, "*")
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(u.EscapedPath(), p) {
				return true
			}
		} else if u.EscapedPath() == p || strings.HasPrefix(u.EscapedPath(), p+"/") {
			return true
		}
	}
	_ = origin
	return false
}
