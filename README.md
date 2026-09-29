# Kurokagi

Kurokagi (`kuro`) is an independent Go authorization scanner. v0.1 focuses on conservative, horizontal BOLA checks over explicitly configured OpenAPI GET endpoints. Only scan systems for which you have written authorization.

## Build and run

```sh
go build -o kuro ./cmd/kuro
./kuro --help
./kuro validate -config examples/config.yaml
./kuro scan -config examples/config.yaml -out result.json
```

The sample target is localhost; replace it only with an authorized environment. Header values may reference `${NAME}` environment variables. Expansion is literal and deterministic; unset variables fail validation by variable name without printing a value. Configured headers are never included in scan output.

Exit codes: `0` completed without findings, `1` findings, `2` configuration/usage error, `3` execution/output failure, `5` cancellation.

## v0.1 boundaries

The scanner supports a bounded subset of OpenAPI 3.0.x and 3.1.x in JSON or YAML; this is not full OpenAPI specification validation. Configure each collection/detail pair and distinct `id_field` and `verify_field` explicitly. A detail response proves a victim resource only when its ID matches the collection candidate and its non-empty verification value matches that candidate's value, which must be unique across all observed collection candidates. Shared or missing verification values, duplicate candidate IDs, and ID-only echoes are inconclusive. This is a conservative configured comparison, not heuristic ownership inference. Collection visibility establishes candidate ownership only when that ID appears in exactly one identity's collection; shared visibility is inconclusive. No role-name policy inference is made. Add `expectations` entries keyed by identity and resource with `ALLOWED`, `DENIED`, or `UNKNOWN`; omitted entries mean `UNKNOWN`. Each entry describes that identity's cross-identity access expectation for the resource. Only proven access to a unique victim resource by an identity explicitly expected to be denied can produce a finding. A generic success, mismatched body, malformed JSON, or unknown expectation is inconclusive. 403/404 are recorded as tested denial evidence. Findings and coverage are separate in schema version 1 JSON.

The engine separates config, OpenAPI, scope, execution/evaluation and result models. Future strategies can add richer ownership rules, explicit operation authorization expectations, vertical/BFLA checks and safe write-operation policies without treating BOLA as the engine itself. GraphQL, Postman/HAR, dynamic sessions, pagination and baseline retesting are roadmap items, not supported features.

## Safety and limitations

TLS verification is Go's default. Origins and path prefixes are mandatory. Resource mappings accept path components only and reject queries, fragments, userinfo, and credential-like URL components. Scope rejects encoded path syntax that could become a dot segment, separator, backslash, or NUL after another decoding layer; it does not recursively decode paths. `redirect_policy` is required and must be `none` or `same_origin`. Under `same_origin`, each redirect hop must remain on the same origin and inside the configured path scope. Every hop consumes request budget and rate pacing. Requests, concurrency, timeout, response bytes and object count are bounded; context cancellation is supported. Evidence contains response SHA-256 hashes and allowlisted content type plus identity, method, status, note, and the configured path template; it omits bodies and response-controlled resource IDs. Errors intentionally omit server-provided text and headers.

v0.1 does not infer ownership from arbitrary response fields, follow pagination, resolve external `$ref`, test write operations or vertical authorization, or guarantee safe semantics for every API. Validate mappings and authorization semantics against a controlled staging fixture before testing a real target. Independent security review and broader adversarial validation are needed before a public v0.1.0 release.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go test -bench=. ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
