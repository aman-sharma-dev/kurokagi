# Changelog

## Unreleased

- Kurokagi provides bounded OpenAPI-driven authorization checks for BOLA, IDOR, relationship boundaries, and explicitly verified GET operations across configured identities.
- Configuration schema v3 defines explicit operations, expectations, verification strategies, and resource mappings. Scan results use JSON schema version 2; targeted retest results use version 1.
- Opt-in controlled POST, PUT/PATCH, and disposable-resource DELETE lifecycles require generated markers, fresh state proof, explicit scope and method/path allowlists, bounded budgets, and verified cleanup/restoration where configured.
- Targeted retesting resolves semantic findings against current policy and fresh state; historical request data does not authorize execution.
- Scope, response, pagination, request, and mutation limits are enforced. Mutation requests are not retried and mutation redirects are not followed.
- Documentation now includes configuration, architecture, retesting, result schemas, responsible disclosure, contribution guidance, and Apache-2.0 licensing.
