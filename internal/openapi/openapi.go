package openapi

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Document struct {
	OpenAPI string                                `json:"openapi"`
	Info    json.RawMessage                       `json:"info"`
	Paths   map[string]map[string]json.RawMessage `json:"paths"`
}

var versionPattern = regexp.MustCompile(`^3\.(0|1)\.[0-9]+$`)

func Load(path string) (Document, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Document{}, e
	}
	var d Document
	trim := strings.TrimSpace(string(b))
	ext := strings.ToLower(filepath.Ext(path))
	useJSON := ext == ".json" || (ext != ".yaml" && ext != ".yml" && strings.HasPrefix(trim, "{"))
	if useJSON {
		if e = json.Unmarshal(b, &d); e != nil {
			return d, fmt.Errorf("OpenAPI JSON document is invalid")
		}
	} else {
		var raw any
		if e = yaml.Unmarshal(b, &raw); e != nil {
			return d, fmt.Errorf("OpenAPI YAML document is invalid")
		}
		j, err := json.Marshal(raw)
		if err != nil {
			return d, fmt.Errorf("OpenAPI YAML conversion failed")
		}
		if e = json.Unmarshal(j, &d); e != nil {
			return d, fmt.Errorf("OpenAPI structure is invalid")
		}
	}
	if !versionPattern.MatchString(d.OpenAPI) {
		return d, fmt.Errorf("unsupported OpenAPI version (supported: 3.0.x and 3.1.x)")
	}
	var info map[string]json.RawMessage
	if json.Unmarshal(d.Info, &info) != nil || info == nil || len(info["title"]) == 0 || len(info["version"]) == 0 {
		return d, fmt.Errorf("OpenAPI info.title and info.version are required")
	}
	if len(d.Paths) == 0 {
		return d, fmt.Errorf("OpenAPI document has no paths")
	}
	for p, ops := range d.Paths {
		if !strings.HasPrefix(p, "/") {
			return d, fmt.Errorf("invalid OpenAPI path")
		}
		if ops == nil {
			return d, fmt.Errorf("invalid OpenAPI path item")
		}
		for m := range ops {
			switch strings.ToLower(m) {
			case "get", "post", "put", "patch", "delete", "options", "head", "trace", "parameters", "summary", "description", "servers", "$ref":
			default:
				return d, fmt.Errorf("invalid OpenAPI path operation")
			}
			if strings.EqualFold(m, "get") || strings.EqualFold(m, "post") || strings.EqualFold(m, "put") || strings.EqualFold(m, "patch") || strings.EqualFold(m, "delete") || strings.EqualFold(m, "options") || strings.EqualFold(m, "head") || strings.EqualFold(m, "trace") {
				var operation map[string]json.RawMessage
				if json.Unmarshal(ops[m], &operation) != nil || operation == nil {
					return d, fmt.Errorf("invalid OpenAPI operation object")
				}
			}
		}
	}
	return d, nil
}
func (d Document) HasGet(path string) bool {
	ops, ok := d.Paths[path]
	return ok && ops["get"] != nil
}
