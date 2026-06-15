# AO Covenant Public Schema Changelog

AO Covenant is pre-1.0, but public JSON schemas are already automation-facing
contracts. This changelog records schema families, compatibility expectations,
and consumer checks for schema-backed command output, release fixtures, bundles,
and release-readiness artifacts.

Use this changelog with the [public API stability policy](public-api-stability.md)
and [public readiness index](public-readiness.md).

## Scope

This changelog covers public schema IDs under `schemas/`, JSON command output
with a documented `schema_version`, stable release fixtures, bundle inspection
results, release reports, and the public release-readiness summary artifact.

It does not cover unexported Go APIs, undocumented CLI text, temporary generated
files, or local `.covenant/` layouts unless another public doc explicitly
promotes that surface.

## Compatibility Rules

Additive schemas may be introduced with new schema IDs when they do not change
the meaning of existing schema-backed output.

Compatible changes to an existing `*.v1` schema may add optional fields, clarify
descriptions, or document previously accepted values. Readers should ignore
unknown optional fields unless a schema says otherwise.

Breaking schema changes require a new schema ID version, a compatibility note in
public docs, and a pull request description that names affected consumers,
fixtures, or release artifacts.

Breaking schema changes include removing required fields, renaming fields,
changing field types, narrowing accepted values in a way that invalidates public
fixtures, or changing the documented meaning of a `schema_version`.

## Schema History

Initial contract and evidence schemas define the core local orchestration data:

- `covenant.contract.v1`
- `covenant.task.v1`
- `covenant.event.v1`
- `covenant.evidence-pack.v1`
- `covenant.evidence-bundle.v1`

Policy, approval, verification, and closure schemas expose operator decisions
and run integrity:

- `covenant.policy-decision.v1`
- `covenant.policy-explain-result.v1`
- `covenant.approval-ticket.v1`
- `covenant.verify-result.v1`
- `covenant.closure-matrix.v1`

Schema automation exposes catalog, export, and validation results for external
CI and tool integration:

- `covenant.schema-catalog-result.v1`
- `covenant.schema-export-result.v1`
- `covenant.schema-validation-report.v1`

Release automation exposes release package, verification, report, diff, and
fixture inventory data:

- `covenant.release-manifest.v1`
- `covenant.release-package-result.v1`
- `covenant.release-verify-result.v1`
- `covenant.release-report-result.v1`
- `covenant.release-diff-result.v1`
- `covenant.release-fixture-index.v1`
- `covenant.release-replacement-policy.v1`

Bundle and provenance automation exposes offline evidence inspection, signature
metadata, public key data, and bundle reports:

- `covenant.bundle-inspect-result.v1`
- `covenant.bundle-report-result.v1`
- `covenant.bundle-signature.v1`
- `covenant.bundle-public-key.v1`

## Release Readiness Summary

The `Release Readiness` workflow publishes a non-sensitive
`release-readiness-summary.json` artifact using
`covenant.release-readiness-summary.v1`. The summary is intended for public
automation that needs to inspect smoke-gate status without downloading generated
release workspaces, signing keys, bundles, checksums, or manifests.

Consumers can validate a downloaded summary with:

```sh
covenant schema validate --schema covenant.release-readiness-summary.v1 --file release-readiness-summary.json
```

## Consumer Actions

List public schemas and their repository paths:

```sh
covenant schema catalog
covenant schema catalog --json
```

Export the embedded schema set from the binary being tested:

```sh
covenant schema export --out /tmp/ao-covenant-schemas
```

Validate schema-backed JSON output by its embedded `schema_version`:

```sh
covenant schema validate --file /tmp/ao-covenant-output.json
covenant schema validate --dir /tmp/ao-covenant-fixtures
```

Automation should prefer schema-backed JSON output over human-readable text
parsing. When a schema-backed document changes, compare the schema ID, fixture
refresh command, and public docs in the same pull request.

## Maintainer Checklist

When adding, removing, renaming, or changing public schemas:

- update this public schema changelog
- update the [public API stability policy](public-api-stability.md) when the
  stability level or compatibility rule changes
- update README or release docs when consumers need a new command, fixture, or
  validation path
- update schema, CLI, fixture, or public-doc tests in the same pull request
- run `go test -count=1 ./internal/schema ./internal/cli`
- run `./scripts/release-readiness.sh` for release-facing schema changes
- document whether the change is additive or breaking in the pull request
