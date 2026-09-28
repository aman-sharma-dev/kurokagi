# Kurokagi

Kurokagi (`kuro`) is an independent Go authorization scanner. v0.1 focuses on conservative, horizontal BOLA checks over explicitly configured OpenAPI GET endpoints. Only scan systems for which you have written authorization.

## Build and run

```sh
go build -o kuro ./cmd/kuro
./kuro --help
./kuro validate -config examples/config.yaml
./kuro scan -config examples/config.yaml -out result.json
```

The sample target is localhost; replace it only with an authorized environment. Example header values can reference `${NAME}` environment variables. The scanner expands these references at load time and never prints configured headers. Avoid committing literal credentials.

Exit codes: `0` completed without findings, `1` findings, `2` configuration/usage error, `3` execution/output failure, `5` cancellation.

## v0.1 boundaries

OpenAPI input currently supports JSON documents. Configure each collection/detail pair explicitly. Collection visibility establishes candidate ownership; no role-name policy inference is made. Active probes use GET only. A finding requires a successful detail response whose configured ID field equals the victim candidate ID. A generic success, mismatched body, malformed JSON, or unproven response is inconclusive. 403/404 are recorded as tested denial evidence. Findings and coverage are separate in schema version 1 JSON.

The engine separates config, OpenAPI, scope, execution/evaluation and result models. Future strategies can add richer ownership rules, explicit operation authorization expectations, vertical/BFLA checks and safe write-operation policies without treating BOLA as the engine itself. GraphQL, Postman/HAR, dynamic sessions, pagination and baseline retesting are roadmap items, not supported features.

## Safety and limitations

TLS verification is Go's default. Origins and path prefixes are mandatory, credentials in URL userinfo are rejected by scope matching, redirects are disabled by default and can only follow in-scope URLs under `same_origin`. Requests, concurrency, timeout, response bytes and object count are bounded; context cancellation is supported. Evidence stores response hashes and minimal identity/path/status metadata, not response bodies. Errors intentionally omit server-provided text and headers.

v0.1 does not infer ownership from arbitrary response fields, follow pagination, support OpenAPI YAML, resolve `$ref`, model explicit ALLOWED/DENIED/UNKNOWN policy matrices, or guarantee safe semantics for every API. Validate mappings and authorization semantics against a controlled staging fixture before testing a real target. Independent security review and broader adversarial validation are needed before a public v0.1.0 release.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
go test -bench=. ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
