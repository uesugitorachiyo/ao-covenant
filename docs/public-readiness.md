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
artifact attestations, provenance reports, and failure handling.

Local check:

```sh
go test -count=1 ./internal/cli -run TestReleaseVerificationWalkthroughIsLinkedAndComplete
```

## Security And Disclosure

The [threat model](threat-model.md) defines protected assets, trust boundaries,
mitigations, operator responsibilities, and non-goals. The
[security policy](../SECURITY.md) defines private reporting, public issue
limits, severity guidance, secret leakage handling, and supported-version scope.

Local check:

```sh
go test -count=1 ./internal/cli -run 'TestPublicThreatModelDocumentationIsLinkedAndComplete|TestSecurityPolicyDocumentsPublicDisclosureProcess'
```

## Public Schemas And Automation

Automation consumers rely on embedded public schemas and stable fixture output.
The [public API stability policy](public-api-stability.md) defines which CLI
commands, JSON schemas, release fixtures, reports, and release artifacts are
stable before 1.0. The schema catalog must remain available from the binary:

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
