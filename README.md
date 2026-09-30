# Kurokagi

**Authorization security testing for modern APIs.**

Kurokagi (`kuro`) is a standalone Go tool for checking whether API access matches explicitly configured authorization expectations. It focuses on authorization assurance rather than acting as a general-purpose vulnerability scanner.

> Only scan systems you own or have explicit permission to test. Start with a local or staging environment. Mutations can change application state, and cleanup is best effort.

## What Kurokagi tests

- **BOLA** (Broken Object Level Authorization) and **IDOR** (Insecure Direct Object Reference): whether one identity can read a resource uniquely observed for another identity.
- **Horizontal authorization:** access checks between identities at similar privilege levels.
- **Vertical authorization / BFLA** (Broken Function Level Authorization): configured GET operations whose response contains explicitly configured positive evidence.
- **Relationship boundaries:** explicit tenant, organization, workspace, project, parent, or child context mappings.
- **OpenAPI-driven checks:** operation declarations are checked against the configured scope; OpenAPI metadata does not define authorization policy or the request destination.
- Multiple configured identities, ownership/resource discovery, bounded pagination, and targeted retesting of semantic findings.
- Opt-in controlled POST, PUT/PATCH, and disposable-resource DELETE lifecycles. These use scanner-created resources, fresh state proof, bounded requests, and verification.

Kurokagi does not infer policy from a successful status code alone. Its evidence flow is:

```text
expectation → request → verification → evidence → finding
```

For a controlled mutation, it is:

```text
controlled resource → mutation → state verification → restoration or cleanup
```

## Safety model

Mutations are disabled unless explicitly enabled and constrained by method and path allowlists. Mutating authorization checks require a current scanner-created resource, a generated test marker, complete safe-GET state proof, and a one-use internal capability. Destructive authorization DELETE additionally requires that the setup operation declare the resource disposable. Cleanup DELETE is a separate, proof-bound capability and cannot be used as an ordinary authorization operation.

Kurokagi enforces origin and path scope, bounded request and lifecycle budgets, rate/concurrency/timeout/response limits, and context cancellation. Mutation requests are sent once: they are not automatically retried and mutation redirects are not followed. Restoration and cleanup are verified where configured, bounded, and best effort. A failed or uncertain cleanup can leave state behind; an interrupted request may have reached the target even if no response was received. These controls reduce risk but do not make mutation testing risk-free.

Use enabled mutation configurations only against local controlled fixtures or an explicitly authorized staging/test environment. Read [the detailed safety and configuration reference](docs/configuration.md) before enabling them.

## Installation

Kurokagi requires Go 1.23 or newer. Clone the repository from its published Git URL, enter the checkout, then build:

```sh
go build ./cmd/kuro
```

This writes `kuro.exe` on Windows and `kuro` on Unix-like systems. The repository currently documents source builds; it does not provide a package-manager installation.

Official prebuilt binaries will be attached to [GitHub Releases](https://github.com/aman-sharma-dev/kurokagi/releases) after the first tagged release. No binary release has been published yet. Until then, build from source using the command above.

## Quick start

The included example targets `127.0.0.1` and uses environment variables for credentials. First validate it with temporary local values (this command does not contact the API):

```powershell
$env:ALICE_TOKEN = 'local-validation-placeholder'
$env:BOB_TOKEN = 'local-validation-placeholder'
go run ./cmd/kuro validate -config examples/config.yaml
Remove-Item Env:ALICE_TOKEN, Env:BOB_TOKEN
```

The example OpenAPI document describes the API shape; it does not run an API server. To scan, start a local API implementing the example paths, set credentials for dedicated test identities, and run in the same shell. For example, set `ALICE_TOKEN` and `BOB_TOKEN` in PowerShell as shown below, using values for your local test API:

```powershell
$env:ALICE_TOKEN = 'your-local-test-token-for-alice'
$env:BOB_TOKEN = 'your-local-test-token-for-bob'
go run ./cmd/kuro scan -config examples/config.yaml -out result.json
Remove-Item Env:ALICE_TOKEN, Env:BOB_TOKEN
```

Review the configuration and replace the target only with an authorized environment.

The sample config demonstrates a read-only BOLA check. Run `kuro --help` for the available commands. See the [full configuration guide](docs/configuration.md) for operations and controlled mutations.

## Configuration

Configuration schema version 3 is strict: unknown fields and duplicate JSON keys are rejected, and schema v2 requires an explicit upgrade. The important sections are:

- `target`: base URL, allowed origins, and allowed path prefixes.
- `identities`: separate actors, credentials (including `${ENV_VAR}` values), and relationship contexts.
- `resources`: OpenAPI collection/detail paths, BOLA/IDOR/relationship classification, identifier and verification fields, ownership model, relationships, and optional bounded pagination.
- `expectations`: explicit `ALLOWED`, `DENIED`, or `UNKNOWN` policy per identity/resource/method, optionally tied to an owner or relationship. Only proven access under `DENIED` can create a finding.
- `operations`: explicit OpenAPI-declared authorization checks and verification strategies.
- `mutations`: opt-in method/path and cleanup allowlists with lifecycle budgets for controlled POST/PUT/PATCH/disposable DELETE.
- `limits`: request count, concurrency, rate, timeout, response bytes, object count, and redirect policy.

The [configuration reference](docs/configuration.md) documents the fields and mutation lifecycles. The [architecture guide](docs/architecture.md) describes evidence and safety boundaries.

## Scanning

The commands below assume `kuro` is on `PATH`.

```sh
kuro validate -config config.yaml
kuro scan -config config.yaml [-out result.json]
```

`validate` checks the config and OpenAPI document without making target requests. `scan` runs configured discovery and operations. Findings require explicit policy and positive verification; ambiguous or incomplete observations are inconclusive.

## Retesting

Retest one previous Kurokagi finding or a versioned semantic fingerprint input against the current configuration:

```sh
kuro retest -config config.yaml -finding finding.json [-out retest.json]
```

Retesting is targeted; it does not run a full scan or replay historical bodies, credentials, resource IDs, or capabilities. It resolves the current operation and policy, then uses fresh discovery or a new controlled-resource lifecycle. Mutation retesting has the same opt-in requirements and environment risks as mutation scanning.

Outcomes are:

- `STILL_PRESENT`: fresh evidence reproduces an authorization effect forbidden by the current `DENIED` expectation.
- `FIXED`: the test dispatched the mutation, observed an HTTP 403, and verified the protected state remained unchanged (for DELETE, the resource remained).
- `INCONCLUSIVE`: available evidence could not establish either result. Timeout, cancellation, network failure, incomplete proof, and unknown state do **not** mean fixed.
- `NOT_TESTABLE`: current policy or configuration did not permit a valid test to begin.

See [retesting semantics and output](docs/retesting.md).

## Output and findings

Scan output is machine-readable JSON (schema version 2); retest output uses schema version 1. Findings are separate from coverage and include stable semantic fingerprints, classification, identities, operation metadata, and references to evidence. Coverage and `completion_state` distinguish complete, partial, and cancelled runs. Evidence avoids response bodies and response-controlled resource IDs; configured secret values are not serialized. Result schemas are in [`docs/result-schema.json`](docs/result-schema.json) and [`docs/retest-result-schema.json`](docs/retest-result-schema.json).

CLI exit codes: `0` complete without findings, `1` findings, `2` configuration/usage error, `3` runtime/target failure, `4` partial or inconclusive execution, and `5` cancellation. A nonzero exit code should be interpreted with the JSON result.

## What Kurokagi does not do

Kurokagi is not a generic scanner for SQL injection, XSS, SSRF, CVEs, or malware. It does not infer authorization policy from status codes, roles, names, hierarchy, or OpenAPI security metadata. OpenAPI support is a bounded scanner-relevant subset, not full conformance validation; external references are not fetched.

## Security and responsible use

Use Kurokagi only on systems you own or have explicit permission to test. Treat scan and retest output as evidence for human review, not a guarantee that an application is secure. Report vulnerabilities in Kurokagi itself using [SECURITY.md](SECURITY.md). For findings in an application you tested, follow that application's security disclosure process and applicable program rules.

## Contributing

Bug reports, focused fixes, tests, and documentation improvements are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. For security-sensitive behavior, include regression tests and explain the impact.

## License and attribution

Kurokagi is licensed under the [Apache License 2.0](LICENSE).

Kurokagi — Copyright Aman Sharma.
