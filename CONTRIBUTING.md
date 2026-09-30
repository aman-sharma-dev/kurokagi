# Contributing

Thank you for helping improve Kurokagi. Changes should keep the scanner conservative, deterministic, and safe to operate.

## Development setup

- Go 1.23 or newer (see [`go.mod`](go.mod))
- Git

Clone the repository using its public Git URL and change into the checkout, then build and validate it:

```sh
git clone <repository-url>
cd kurokagi
go build ./...
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Format Go packages with:

```sh
go fmt ./...
```

Fuzz targets can be run for a bounded interval, for example:

```sh
go test ./internal/scope -run '^$' -fuzz FuzzMatchRejectsUnsafeURLShapes -fuzztime 10s
```

Run target-facing or mutation-enabled integration tests only against local controlled fixtures. Never use production or real user data for mutation testing.

## Repository layout

- `cmd/kuro`: CLI, input parsing, and command-level tests.
- `internal/config`: strict config schema and validation.
- `internal/openapi`: bounded OpenAPI document loader.
- `internal/scope`: URL scope checks.
- `internal/engine`: discovery, authorization evaluation, controlled mutation, retesting, and engine tests.
- `internal/strictjson`: duplicate-key JSON rejection.
- `examples`: safe localhost example configuration and OpenAPI document.
- `docs`: configuration, architecture, result schema, and retesting references.

## Change expectations

- Keep security behavior covered by tests. Add regression tests for security fixes.
- Preserve deterministic findings and semantic fingerprints.
- Do not put credentials, cookies, authorization headers, API keys, response bodies, or other secrets into evidence, fixtures, examples, logs, or output.
- Do not weaken origin/path scope, mutation capabilities, budgets, state verification, cleanup, or restoration protections.
- Use local controlled servers for network behavior tests; tests must not contact arbitrary targets.
- Keep user-facing documentation aligned with actual behavior and schema versions.

Significant architectural changes should start with an issue or discussion so the use case and security impact can be reviewed before implementation.

## Pull requests

Keep pull requests focused. Explain what changed and why, summarize security impact, and list validation performed. Include tests for behavior changes and update relevant documentation. For changes affecting scope, credentials, mutation, cleanup/restoration, evidence, fingerprints, or result schemas, explain the security implications explicitly in the pull request.
