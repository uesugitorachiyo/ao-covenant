# AO Covenant Dependency Review

AO Covenant depends on a small Go module set and a small GitHub Actions surface.
Dependency changes are public-readiness changes because they can affect local
execution, release packaging, artifact attestations, and consumer trust.

Use this guide with the [public readiness index](public-readiness.md), the
[security policy](../SECURITY.md), and `CONTRIBUTING.md`.

## Go Module Dependencies

Go dependencies are declared in `go.mod` and locked by `go.sum`. Reviewers
should treat changes to either file as supply-chain changes, even when the code
diff is small.

Before merging a Go dependency change:

- explain why the dependency is needed or why the version changed
- prefer standard library code when it keeps the implementation simple
- avoid adding dependencies for narrow helper behavior
- verify the module path, version, license, and maintenance state
- inspect transitive dependency changes in `go.sum`
- keep the Go toolchain aligned with `go.mod`

Useful local commands:

```sh
go list -m all
go mod tidy
go mod verify
go test -count=1 ./...
go vet ./...
```

Do not commit local module cache paths, vendored copies, generated archives, or
temporary dependency experiment files.

## GitHub Actions Dependencies

Workflow dependencies are declared in `.github/workflows/*.yml`. AO Covenant
currently uses:

- `actions/checkout@v6`
- `actions/setup-go@v6`
- `actions/attest-build-provenance@v4`
- `actions/upload-artifact@v7.0.1`

Action updates should be reviewed like code changes. Check the upstream release
notes, permissions requested by the action, whether the action is still
maintained, and whether the new version changes artifact, cache, token, or
attestation behavior.

Workflows should keep using `go-version-file: go.mod` so CI and release jobs
use the same Go toolchain as local development.

Validate workflow syntax locally:

```sh
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml
```

## Workflow Permissions

Workflow permissions should stay minimal and explicit.

The CI and release-readiness workflows should use read-only `contents: read`.
The release workflow needs elevated permissions only for release publication and
provenance:

- `contents: write`
- `id-token: write`
- `attestations: write`

Do not broaden permissions for convenience. A workflow permission change should
state the exact operation that requires it and should be reviewed against the
threat model before merge.

## Update Process

Keep dependency changes small and reviewable:

1. Update one dependency family at a time where practical.
2. Run `go mod tidy` after Go module changes.
3. Run `go mod verify` after module changes.
4. Parse changed workflow YAML before opening the pull request.
5. Update public docs when a dependency change affects install, release,
   verification, provenance, schemas, or public automation behavior.
6. Run `./scripts/release-readiness.sh` for release-facing dependency or
   workflow changes.

Pull requests should include the dependency being changed, the reason for the
change, user or release impact, and the verification commands that were run.

## Review Checklist

Reviewers should confirm:

- `go.mod` and `go.sum` changes are expected
- no unrelated dependencies were added by `go mod tidy`
- GitHub Actions versions are intentional
- workflow permissions did not broaden unexpectedly
- release, attestation, and artifact behavior still match the release docs
- the baseline checks pass on Ubuntu, macOS, and Windows
- public documentation and fixtures are updated when consumer-visible behavior
  changes

Baseline local verification:

```sh
go test -count=1 ./...
go vet ./...
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml
git diff --check
```

## Security Response

If a dependency issue may affect signing keys, release artifacts, verification,
local execution, private data, or provenance, treat it as security-sensitive.
Use the [security policy](../SECURITY.md) for private reporting and avoid
posting exploit details, credentials, production evidence, unreleased bundles,
or local paths in public issues.

Security fixes may update dependencies quickly, but they still need protected
branch review, CI, and clear release or mitigation notes when public users are
affected.
