package openapi

import (
	"encoding/json"
	"fmt"
	"github.com/kurokagi/kurokagi/internal/strictjson"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Document contains scanner-relevant metadata loaded from an OpenAPI document.
type Document struct {
	OpenAPI    string                                `json:"openapi"`
	Info       json.RawMessage                       `json:"info"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Servers    json.RawMessage                       `json:"servers,omitempty"`
	Components json.RawMessage                       `json:"components,omitempty"`
	Security   json.RawMessage                       `json:"security,omitempty"`
}

// OperationMetadata records whether a method/path pair is declared by the document.
type OperationMetadata struct {
	OperationID string            `json:"operationId,omitempty"`
	Parameters  []json.RawMessage `json:"parameters,omitempty"`
	RequestBody json.RawMessage   `json:"requestBody,omitempty"`
	Responses   json.RawMessage   `json:"responses,omitempty"`
	Security    json.RawMessage   `json:"security,omitempty"`
}

var versionPattern = regexp.MustCompile(`^3\.(0|1)\.[0-9]+$`)

// Load reads a bounded OpenAPI JSON or YAML document and resolves local references.
func Load(path string) (Document, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Document{}, e
	}
	var d Document
	trim := strings.TrimSpace(string(b))
	ext := strings.ToLower(filepath.Ext(path))
	useJSON := ext == ".json" || (ext != ".yaml" && ext != ".yml" && strings.HasPrefix(trim, "{"))
	var root any
	if useJSON {
		if err := strictjson.RejectDuplicateKeys(b); err != nil {
			return d, fmt.Errorf("OpenAPI JSON document is invalid")
		}
		if e = json.Unmarshal(b, &d); e != nil {
			return d, fmt.Errorf("OpenAPI JSON document is invalid")
		}
		if e = json.Unmarshal(b, &root); e != nil {
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
		if e = json.Unmarshal(j, &root); e != nil {
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
	// Resolve only local JSON-Pointer references. No URL or filesystem ref is ever fetched.
	resolved, err := resolveLocalRefs(root, root, map[string]bool{}, 0)
	if err != nil {
		return d, fmt.Errorf("OpenAPI local reference is invalid")
	}
	resolvedJSON, err := json.Marshal(resolved)
	if err != nil || json.Unmarshal(resolvedJSON, &d) != nil {
		return d, fmt.Errorf("OpenAPI resolved structure is invalid")
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

func resolveLocalRefs(value, document any, stack map[string]bool, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("reference depth exceeded")
	}
	switch node := value.(type) {
	case map[string]any:
		if raw, ok := node["$ref"]; ok {
			ref, ok := raw.(string)
			if !ok || !strings.HasPrefix(ref, "#/") {
				return nil, fmt.Errorf("external or invalid ref")
			}
			if stack[ref] {
				return nil, fmt.Errorf("reference cycle")
			}
			parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
			target := document
			for _, part := range parts {
				decoded, valid := decodePointerToken(part)
				if !valid {
					return nil, fmt.Errorf("invalid JSON pointer token")
				}
				part = decoded
				object, ok := target.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("bad pointer")
				}
				target, ok = object[part]
				if !ok {
					return nil, fmt.Errorf("missing pointer")
				}
			}
			stack[ref] = true
			resolved, err := resolveLocalRefs(target, document, stack, depth+1)
			delete(stack, ref)
			if err != nil {
				return nil, err
			}
			resolvedObject, ok := resolved.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("ref target is not object")
			}
			merged := make(map[string]any, len(resolvedObject)+len(node)-1)
			for key, child := range resolvedObject {
				merged[key] = child
			}
			for key, child := range node {
				if key != "$ref" {
					mergeValue, err := resolveLocalRefs(child, document, stack, depth+1)
					if err != nil {
						return nil, err
					}
					merged[key] = mergeValue
				}
			}
			return merged, nil
		}
		out := make(map[string]any, len(node))
		for key, child := range node {
			resolved, err := resolveLocalRefs(child, document, stack, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = resolved
		}
		return out, nil
	case []any:
		out := make([]any, len(node))
		for i, child := range node {
			resolved, err := resolveLocalRefs(child, document, stack, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	default:
		return value, nil
	}
}

func decodePointerToken(token string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(token); i++ {
		if token[i] != '~' {
			out.WriteByte(token[i])
			continue
		}
		if i+1 >= len(token) {
			return "", false
		}
		i++
		switch token[i] {
		case '0':
			out.WriteByte('~')
		case '1':
			out.WriteByte('/')
		default:
			return "", false
		}
	}
	return out.String(), true
}
func (d Document) HasGet(path string) bool {
	ops, ok := d.Paths[path]
	return ok && ops["get"] != nil
}

func (d Document) HasOperation(path, method string) bool {
	ops, ok := d.Paths[path]
	return ok && ops[strings.ToLower(method)] != nil
}

// OperationMetadata returns resolved scanner-relevant operation fields and
// combines path-level parameters with operation-level parameters.
func (d Document) Metadata(path, method string) (OperationMetadata, bool) {
	item, ok := d.Paths[path]
	if !ok {
		return OperationMetadata{}, false
	}
	var operation map[string]json.RawMessage
	if json.Unmarshal(item[strings.ToLower(method)], &operation) != nil || operation == nil {
		return OperationMetadata{}, false
	}
	var metadata OperationMetadata
	_ = json.Unmarshal(operation["operationId"], &metadata.OperationID)
	metadata.RequestBody = operation["requestBody"]
	metadata.Responses = operation["responses"]
	metadata.Security = operation["security"]
	var pathParams []json.RawMessage
	_ = json.Unmarshal(item["parameters"], &pathParams)
	var opParams []json.RawMessage
	_ = json.Unmarshal(operation["parameters"], &opParams)
	metadata.Parameters = append(pathParams, opParams...)
	return metadata, true
}
