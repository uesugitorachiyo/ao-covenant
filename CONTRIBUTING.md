# Contributing To AO Covenant

AO Covenant is pre-1.0 and local-first. Contributions should preserve the
project's core promises: deterministic contracts, fail-closed policy behavior,
evidence-bound execution, verifiable release artifacts, and public automation
schemas.

Start with the [public readiness index](docs/public-readiness.md), the
[threat model](docs/threat-model.md), the [security policy](SECURITY.md), and
the [security advisory routing guide](docs/security-advisory-routing.md) before
changing public behavior. Maintainers handling private reports should use the
[security advisory maintainer checklist](docs/security-advisory-maintainer-checklist.md).

Follow the [code of conduct](CODE_OF_CONDUCT.md) and
[governance](GOVERNANCE.md) docs when opening issues, discussing scope, or
requesting maintainer decisions.

Use the GitHub issue templates for bug reports, release verification failures,
and security-sensitive routing. The pull request template lists the required
public-readiness, sensitive-material, and verification checks for proposed
changes.

## Local Setup

Use Go 1.26 or newer. Work from a clean checkout on a feature branch:

```sh
git checkout main
git pull --ff-only origin main
git checkout -b slice-name
go version
```

No generated `.covenant/`, `dist/`, private key, or local release-readiness
output should be committed.

## Required Local Checks

Run these checks before opening a pull request:

```sh
go test -count=1 ./...
go vet ./...
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml
git diff --check
```

For public docs changes, run the focused public-docs test that covers the file
you touched, then run the full baseline above.

## Branch And Pull Request Rules

The protected `main` branch requires pull requests. Do not push directly to
`main`.

Use a feature branch and open a pull request. Pull requests must keep scope
small enough to review, include the relevant local verification commands in the
description, and wait for the required GitHub Actions matrix to pass on Ubuntu,
macOS, and Windows before merge.

Prefer squash merges for slice work so `main` remains linear and readable.

## Release-Readiness Gate

Run the release-readiness gate before release-facing changes and after changes
that affect contracts, bundles, schemas, release packaging, verification,
workflow files, or public release docs:

```sh
./scripts/release-readiness.sh
```

To keep generated output outside the repository:

```sh
tmpdir="$(mktemp -d)"
COVENANT_RELEASE_READINESS_DIR="$tmpdir" ./scripts/release-readiness.sh
rm -rf "$tmpdir"
```

## Documentation Expectations

Public behavior changes should update the public docs in the same pull request.
Common link points are:

- [public readiness index](docs/public-readiness.md)
- [dependency review guide](docs/dependency-review.md)
- [install guide](docs/install.md)
- [release operations](docs/release.md)
- [release dry-run checklist](docs/release-dry-run.md)
- [release verification walkthrough](docs/release-verification.md)
- [threat model](docs/threat-model.md)
- [security policy](SECURITY.md)
- [security advisory routing guide](docs/security-advisory-routing.md)
- [security advisory maintainer checklist](docs/security-advisory-maintainer-checklist.md)

When adding a public doc, add or update a guard in
`internal/cli/public_docs_test.go` so the document and key links remain
discoverable.

## Security And Repository Hygiene

Do not commit private keys, credentials, production evidence bundles, generated
local `.covenant/` output, local machine paths, or unreleased sensitive release
artifacts. Use synthetic fixtures for tests and examples.

Run the repository hygiene guard when changing ignore rules, fixtures, release
docs, or generated artifacts:

```sh
go test -count=1 ./internal/cli -run 'TestRepositoryIgnoreRulesCoverSensitiveLocalArtifacts|TestTrackedRepositoryFilesDoNotContainLocalSecretsOrMachinePaths'
```

Report suspected vulnerabilities through the [security policy](SECURITY.md).

## Public Schema Expectations

Public JSON output must have a stable `schema_version` and a schema under
`schemas/` when it is intended for automation. Use the
[public API stability policy](docs/public-api-stability.md) to decide whether a
CLI command, JSON schema, release fixture, report, or release artifact is
stable, experimental, or internal. Schema-backed command output should remain
exportable and discoverable:

```sh
covenant schema catalog
covenant schema catalog --json
covenant schema export --out /tmp/ao-covenant-schemas
```

When changing public schemas or fixture-backed release outputs, update tests and
fixtures in the same pull request and document any consumer-visible change.

## Dependency And Supply-Chain Expectations

Use the [dependency review guide](docs/dependency-review.md) when changing
`go.mod`, `go.sum`, GitHub Actions versions, workflow permissions, release
attestation behavior, or artifact upload behavior. Dependency pull requests
should explain why the change is needed and include the relevant verification
commands.
