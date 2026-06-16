# AO Covenant Public API Stability

AO Covenant is pre-1.0, but it already exposes surfaces that external users and
automation can depend on. This policy defines which surfaces are stable,
experimental, or internal before 1.0.

Use this policy with the [public readiness index](public-readiness.md), the
[public schema changelog](public-schema-changelog.md), the
[release verification walkthrough](release-verification.md), `CONTRIBUTING.md`,
and the schemas published under `schemas/`.

## Stability Levels

Stable surfaces are documented, covered by tests, and intended for external
users or automation. Changes to stable surfaces must update docs, tests, and any
affected fixtures in the same pull request.

Experimental surfaces are useful but still subject to change before 1.0. A
surface is experimental when it is marked experimental, missing from this
policy, or only exposed through implementation details rather than public docs.

Internal surfaces support AO Covenant implementation and tests. Internal
package APIs, helper functions, private fixtures, temporary generated files, and
undocumented command internals are not public contracts.

## Stable Surfaces

The following surfaces are stable unless a narrower section below says
otherwise:

- public documentation linked from the README security model
- public JSON schemas under `schemas/`
- schema-backed JSON command output with a documented `schema_version`
- release fixture examples under `internal/schema/testdata/release-fixtures/`
- documented release report and release diff fixtures used by public tests
- release asset names and metadata described by the release docs
- repository contribution, security, governance, and release-readiness rules

Stable means AO Covenant treats consumer-visible changes as deliberate changes.
It does not mean no change can happen before 1.0.

## Experimental Surfaces

The following surfaces are experimental unless promoted by this policy:

- undocumented CLI text formatting
- undocumented JSON fields
- unexported Go packages and symbols
- local `.covenant/` output layout outside documented evidence or release
  artifacts
- generated files used only as temporary local build or test output
- examples that are not covered by schema, fixture, or public-doc tests

Experimental surfaces may change in ordinary feature work. If external users
start depending on one, promote it by documenting the surface and adding tests.

## CLI Commands

CLI commands are stable when the command, flags, behavior, and output contract
are documented in README or `docs/` and covered by tests.

Human-readable text output may evolve unless the text output is explicitly
listed as stable or covered by a fixture test. JSON output with `schema_version`
is the preferred automation contract. Automation should read JSON fields from
schema-backed output rather than parsing human text.

Errors are stable when tests assert their code, format, or failure behavior.
Other wording may be improved before 1.0.

## Public Schemas

Files under `schemas/` are public. Schema IDs, schema filenames, and documented
`schema_version` values are automation-facing contracts.

Compatible schema changes may add optional fields, add enum values when readers
are expected to ignore unknown values, clarify descriptions, or tighten
documentation without changing accepted valid data.

Breaking schema changes require one of the following:

- a new `schema_version`
- a compatibility note in the public docs and pull request
- a migration path when existing public fixtures or release artifacts are
  affected

Schema-backed JSON output should remain discoverable through:

```sh
covenant schema catalog
covenant schema catalog --json
covenant schema export --out /tmp/ao-covenant-schemas
```

## Fixtures And Reports

Release fixtures under `internal/schema/testdata/release-fixtures/` are stable
public examples for consumers that need to test release JSON without building a
release package.

Release report and release diff fixtures are stable when README or docs name the
fixture directory and the fixture is covered by tests. Text report fixtures are
stable only for the command/report shape they intentionally pin. Other
human-readable text can change before 1.0.

Release attestation fixtures under
`internal/cli/testdata/release-attestation-fixtures/` are stable public examples
for consumers that need to test manifest and platform-binary attestation
handling without calling GitHub.

When fixture-backed output changes, update the fixture, schema if applicable,
refresh command, and public docs together.

## Release Artifacts

Published release assets are stable public surfaces once a release is tagged.
This includes:

- platform archive names
- `manifest.json`
- `SHA256SUMS`
- `release-signature.json`
- `covenant-release-public-key.json`
- provenance and verification reports documented by release docs

Consumers should verify these artifacts with the
[release verification walkthrough](release-verification.md). Maintainers should
not publish a release when checksum, signature, attestation, provenance, or
release-readiness expectations fail.

## Change Process

Pull requests that change stable public surfaces must:

- update the relevant public docs
- update public-doc, schema, fixture, or CLI tests
- document consumer-visible behavior in the pull request
- run the release-readiness or baseline checks named by the public readiness
  index

If a surface is intended to remain experimental, the pull request should say so
explicitly when the change could be mistaken for a public contract.

## Pre-1.0 Compatibility

Before 1.0, compatibility promises must be explicit. Treat any undocumented
surface as experimental, even when it appears in source code or test data.

Maintainers should prefer small compatibility-preserving changes for stable
surfaces. When a breaking change is necessary, the change should be documented,
tested, and visible in the pull request before merge.
