package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Document struct {
	OpenAPI string                                `json:"openapi"`
	Paths   map[string]map[string]json.RawMessage `json:"paths"`
}

func Load(path string) (Document, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Document{}, e
	}
	var d Document
	if e = json.Unmarshal(b, &d); e != nil {
		return d, fmt.Errorf("OpenAPI JSON parse: %w", e)
	}
	if len(d.Paths) == 0 {
		return d, fmt.Errorf("OpenAPI document has no paths or is not JSON (v0.1 supports JSON OpenAPI)")
	}
	for p, ops := range d.Paths {
		if !strings.HasPrefix(p, "/") {
			return d, fmt.Errorf("invalid OpenAPI path %q", p)
		}
		for m := range ops {
			switch strings.ToLower(m) {
			case "get", "post", "put", "patch", "delete", "options", "head", "parameters", "summary", "description", "servers":
			default:
				return d, fmt.Errorf("invalid operation %s %s", m, p)
			}
		}
	}
	return d, nil
}
func (d Document) HasGet(path string) bool {
	for p, ops := range d.Paths {
		if strings.EqualFold(p, path) && ops["get"] != nil {
			return true
		}
	}
	return false
}
