# AO Covenant Public Readiness

Use this index before publishing, tagging, or asking external users to install
AO Covenant. It links the public-facing docs and verification commands that
must stay discoverable.

## Install And Platform Support

Public releases must document Ubuntu, macOS, and Windows install paths in the
[install guide](install.md). The guide must include checksum verification before
copying a binary into the user path.

Local check:

```sh
go test -count=1 ./cmd/covenant -run TestReleaseReadinessScriptRunsSmokeGate
```

## Release Verification

Consumers should verify release assets before installation with the
[release verification walkthrough](release-verification.md). The walkthrough
covers release downloads, `SHA256SUMS`, AO Covenant release signatures, GitHub
artifact attestations, provenance reports, and failure handling. The
[public release known-good baseline](public-release-known-good-baseline.md)
defines the expected release asset set, platform coverage, verification output,
schema validation, replacement policy, and sensitive-material exclusions.
The [release attestation coverage map](release-attestation-coverage.md)
defines which public release assets require direct GitHub attestations and
which are covered by AO Covenant signature and checksum verification.
The
[release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)
provide stable public examples for passing and failing attestation trust
decisions.
The
[release replacement preflight fixtures](../internal/cli/testdata/release-replacement-preflight-fixtures)
provide stable public examples for replacement conflict inputs, generated
policy output, and fail-closed diagnostics.
The [release consumer smoke script](../scripts/release-consumer-smoke.sh)
provides a single consumer-facing command for downloaded release directories
using only public release assets and an installed `covenant` binary.
The
[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)
provides the same consumer-facing command path with PowerShell-native checksum
verification. Both scripts write `release-consumer-smoke.json` with schema
`covenant.release-consumer-smoke-result.v1` after the public release verify,
report, inspect, schema validation, and optional attestation checks pass.
Maintainers should run the [release dry-run checklist](release-dry-run.md)
before tagging or manually dispatching a public release. Use the
[release rollback runbook](release-rollback.md) before replacing, withdrawing,
or correcting published release assets. Use the
[release replacement preflight script](../scripts/release-replacement-preflight.sh)
to simulate existing-asset conflicts and validate `release-replacement-policy.json`
before a replacement publish path. The release workflow uploads
`release-replacement-preflight-report.json` with schema
`covenant.release-replacement-preflight-report.v1` as a CI audit artifact.
Manual release workflow dispatches default to `dry_run=true`, which uploads
workflow artifacts only and skips release publishing, attestations, and
post-release smoke verification. The dry-run path uploads
`release-dry-run-artifact-audit.json` with schema
`covenant.release-dry-run-artifact-audit.v1` to record required artifacts,
checksums, platform counts, and the non-publishing trust boundary. Use the
[release note template](release-note-template.md) before publishing normal
release notes, replacement notices, withdrawal notices, or security-sensitive
release summaries. Use the [release note fixtures](release-note-fixtures.md)
as stable examples for common public release-note cases.

Local check:

```sh
go test -count=1 ./internal/cli -run TestReleaseVerificationWalkthroughIsLinkedAndComplete
go test -count=1 ./internal/cli -run TestReleaseConsumerSmokeScriptIsLinkedAndComplete
go test -count=1 ./internal/cli -run TestReleaseConsumerSmokePowerShellScriptIsLinkedAndComplete
```

## Security And Disclosure

The [threat model](threat-model.md) defines protected assets, trust boundaries,
mitigations, operator responsibilities, and non-goals. The
[security policy](../SECURITY.md) defines private reporting, public issue
limits, severity guidance, secret leakage handling, and supported-version scope.
The [security advisory routing guide](security-advisory-routing.md) defines
private-first reporting and minimal public report expectations for
security-sensitive issues. The
[security advisory maintainer checklist](security-advisory-maintainer-checklist.md)
defines private triage, containment, verification, safe disclosure, and closure
steps.

Local check:

```sh
go test -count=1 ./internal/cli -run 'TestPublicThreatModelDocumentationIsLinkedAndComplete|TestSecurityPolicyDocumentsPublicDisclosureProcess'
```

## Public Schemas And Automation

Automation consumers rely on embedded public schemas and stable fixture output.
The [public API stability policy](public-api-stability.md) defines which CLI
commands, JSON schemas, release fixtures, reports, and release artifacts are
stable before 1.0. The [public schema changelog](public-schema-changelog.md)
records schema families, compatibility rules, and consumer validation actions.
The schema catalog must remain available from the binary:

```sh
covenant schema catalog
covenant schema catalog --json
covenant schema export --out /tmp/ao-covenant-schemas
```

Local check:

```sh
go test -count=1 ./internal/cli -run TestPublicAPIStabilityPolicyIsLinkedAndComplete
go test -count=1 ./internal/schema ./internal/cli
```

## Local Release-Readiness Gate

Run the release-readiness smoke gate before public release work:

```sh
./scripts/release-readiness.sh
```

The script writes generated artifacts to `.covenant/release-readiness` by
default. Redirect it with `COVENANT_RELEASE_READINESS_DIR` when the output
should live outside the repository.

Local check:

```sh
tmpdir="$(mktemp -d)"
COVENANT_RELEASE_READINESS_DIR="$tmpdir" ./scripts/release-readiness.sh
rm -rf "$tmpdir"
```

The scheduled/manual `Release Readiness` GitHub Actions workflow runs the same
gate with read-only repository permissions and does not publish release assets.
The public
[Release Readiness workflow](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)
uses a manual `workflow_dispatch` trigger, a weekly scheduled run, and
read-only `contents: read` permission so external users can inspect whether the
public smoke gate is healthy without treating it as a release publisher.
It uploads only a non-sensitive `release-readiness-summary.json` artifact with
status, release metadata, check names, and aggregate counts; it does not upload
the generated workspace, signing keys, bundles, checksums, manifest entries, or
release files.
The summary is a public automation artifact using
`covenant.release-readiness-summary.v1` and can be checked after download:

```sh
covenant schema validate --schema covenant.release-readiness-summary.v1 --file release-readiness-summary.json
```

## Repository Hygiene

The repository must not publish generated local AO Covenant artifacts, private
key files, PEM private-key blocks, or machine-specific home paths. Ignore rules
and tracked-file scans enforce that boundary.
The [dependency review guide](dependency-review.md) defines Go module and
GitHub Actions supply-chain review expectations before dependency, workflow, or
permission changes are merged.

Local check:

```sh
go test -count=1 ./internal/cli -run 'TestRepositoryIgnoreRulesCoverSensitiveLocalArtifacts|TestTrackedRepositoryFilesDoNotContainLocalSecretsOrMachinePaths'
```

## Baseline Verification

Run the full local baseline before opening a public-facing PR:

```sh
go test -count=1 ./...
go vet ./...
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml
git diff --check
```

Protected `main` requires the GitHub Actions matrix to pass on Ubuntu, macOS,
and Windows before merge.

## Contribution Flow

Use the [contributor guide](../CONTRIBUTING.md) for local setup, required
checks, branch and pull request rules, release-readiness expectations,
documentation expectations, repository hygiene, and public schema expectations.
GitHub issue and pull request templates route public bugs, release verification
failures, security-sensitive reports, and PR verification evidence into the
same public-readiness expectations.
Use the [code of conduct](../CODE_OF_CONDUCT.md) and
[governance](../GOVERNANCE.md) docs for issue behavior, maintainer decision
scope, and pre-1.0 project expectations.
