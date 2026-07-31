# AO Covenant Agent Instructions

## Status And Role

AO Covenant is the active policy and trust component for AO. It owns contract validation, fail-closed policy decisions, exact-digest approval tickets, tamper-evident event records, evidence verification and revocation, and public policy schemas.

Covenant evaluates declared authority; it does not create undeclared scope, execute side effects, mutate target repositories, coordinate portfolio work, or publish merely because validation succeeds.

## Sources Of Truth

- [docs/threat-model.md](docs/threat-model.md) and [docs/release-threat-model-matrix.md](docs/release-threat-model-matrix.md) define protected assets, trust boundaries, and release threats.
- [docs/public-api-stability.md](docs/public-api-stability.md), [docs/public-schema-changelog.md](docs/public-schema-changelog.md), and `schemas/` define public contract ownership and compatibility.
- `internal/policy/`, `internal/approval/`, `internal/verify/`, `internal/schema/`, and their tests are authoritative for implemented decisions and validation. [REFERENCE.md](REFERENCE.md) is the current command reference.
- [docs/public-readiness.md](docs/public-readiness.md), `scripts/release-readiness.sh`, and [`.github/workflows/ci.yml`](.github/workflows/ci.yml) define baseline and non-publishing readiness checks.

## Ownership And Boundaries

- Decide fail closed on unknown side effects, missing evidence, invalid trust material, revoked artifacts, or authority beyond the declared contract.
- Bind approvals to the exact contract, action, resource, path scope, identity, expiry, and digest. Any drift requires a new decision; a prior ticket must not be generalized.
- Preserve the distinction between validation, policy decision, approval, verification, and execution. None alone permits AO2 side effects, repository mutation, provider access, release, or publication.
- Treat `internal/**/testdata`, `examples/`, release fixtures, and known-good baselines as contracts. Keep valid and invalid cases distinct and never weaken a rejection to obtain readiness.
- Keep generated runs, keys, bundles, release packages, reports, and binaries under ignored `.covenant/`, `bin/`, `demo-output/`, or `dist/`. Never commit private keys, credentials, bearer values, account identifiers, machine-local paths, or private incident details.
- Release, deployment, publication, live mutation, credentialed operation, permission changes, and direct-main changes require separate explicit authority and all policy, rollback, signature, provenance, and consumer gates.

## Working Method

- Change the smallest policy or contract surface and preserve deterministic decisions, exact digests, revocation, redaction, path containment, schema compatibility, and auditability.
- Add negative tests for missing approvals, expired or mismatched tickets, unknown effects, invalid signatures, revoked bundles, unsafe paths, and over-broad claims.
- Update this file in the same pull request when durable commands, architecture, ownership, or authority boundaries change.

## Verification

- Policy and approval changes: `go test ./internal/policy ./internal/approval -count=1`.
- Schema or CLI changes: `go test ./internal/schema ./internal/cli -count=1`.
- Format relevant Go source with `gofmt -d cmd internal schemas`; run `go test ./... -count=1`, `go vet ./...`, and `CGO_ENABLED=0 go build -o bin/covenant ./cmd/covenant`.
- Run `scripts/check-license-policy.sh` and `scripts/check-public-repo-policy.sh` for every tracked change. Run `scripts/release-readiness.sh` only for release-facing or readiness behavior; it is a local non-publishing gate and grants no release authority.
- For instruction changes run `python3 ../ao-architecture/scripts/verify_agent_instruction_layout.py --workspace-root .. --repository ao-covenant`. Always run `git diff --check`.

## Evidence And Completion

- Record source heads, commands and exits, contract and action digests, decision or approval identity, expiry, revocation state, and relevant evidence digests. Report skipped, unavailable, or failed checks explicitly.
- Completion requires focused and broad gates, green pull-request CI, clean synchronized `main`, and task-branch cleanup. A policy allow or readiness result does not widen the task's authority.
