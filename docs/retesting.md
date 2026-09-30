# Retesting

`kuro retest -config <file> -finding <json> [-out <file>]` performs one targeted retest per unique finding fingerprint. It does not run a scan or replay historical request data. Current configuration supplies actors, paths, expectations, request templates, scope, and mutation policy. Finding inputs are versioned semantic selectors; historical resource references are inert and ignored for current requests. Unknown input fields, including credentials, bodies, and capabilities, are rejected.

Supported conditions are configured fixed-path GET operations; discovered BOLA, IDOR, and relationship reads; controlled POST; linked controlled PUT/PATCH; and linked controlled DELETE. Mutation retests first create a new marker-bound resource under the current explicitly allowed POST setup. Updates verify a complete pre-state, skip a no-op, send one method-specific mutation, verify the resulting state, and restore the previous scalar state or use the setup's proof-bound cleanup. DELETE requires a current setup marked `disposable: true`, exact marker and ID proof immediately before its one attack DELETE, and complete safe-GET verification afterward. A verified absent resource is never cleanup-deleted; a verified remaining resource may receive only the distinct proof-bound cleanup DELETE. Unknown state is not destructively guessed.

Relationship mutation checks require the configured actor/owner context boundary and a live relationship value on the newly created resource. BFLA, BOLA, IDOR, and relationship mutations use the current operation's configured classification and expectation. Mutation execution requires explicit enabled method/path allowlists, in-scope targets, complete OpenAPI declarations, available global and lifecycle budgets, and single-use internal capabilities. Redirects are not followed and mutation requests are not retried.

Outcomes are:

- `STILL_PRESENT`: fresh positive proof reproduces the forbidden authorization effect under a current `DENIED` expectation.
- `FIXED`: the attack mutation was dispatched, a current 403 denial was observed, and complete safe verification positively showed the protected state unchanged (for DELETE, the controlled resource remains).
- `INCONCLUSIVE`: the test began but denial or resulting state could not be established. Timeout, cancellation, target errors, incomplete proof, and unknown state never mean fixed.
- `NOT_TESTABLE`: current policy or configuration could not legitimately start the relevant authorization test, including missing actors, setup, scope, allowlist, disposable declaration, or sufficient budget.

Cleanup and restoration are bounded and best effort. Failure is surfaced as partial completion without erasing a positively proven finding. An inconclusive DELETE post-state does not trigger cleanup because presence has not been proved. Only local controlled fixtures should be used for enabled mutation testing.

Retest JSON is an object with `schema_version: "1"` and a `results` array. Each result contains source/current fingerprints, one outcome, deterministic reason code, current semantic metadata, verification summary, completion state, and cleanup state when applicable. Timestamps are metadata and never affect fingerprints. CLI exits retain the documented mapping: 0 complete without findings, 1 with findings, 2 invalid input/configuration, 3 runtime/target failure, 4 partial/inconclusive, and 5 cancellation.
