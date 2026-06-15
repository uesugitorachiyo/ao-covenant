# AO Covenant Release Dry Run

Use this checklist before tagging a public release or manually dispatching the
release workflow. It validates the local release package path without
publishing anything.

Use this with [release operations](release.md), the
[release verification walkthrough](release-verification.md), and the public
readiness index.

## Scope

A release dry run exercises local packaging, signing, verification, reporting,
inspection, and schema validation. It does not publish anything and does not create a tag, GitHub release, attestation, or public release asset.

The dry run should use synthetic or disposable signing material unless the
maintainer is explicitly testing release-key handling. Do not commit private keys, generated dry-run output, `.covenant/` workspaces, `dist/` directories, or
local machine paths.

## Prerequisites

Start from a clean checkout:

```sh
git checkout main
git pull --ff-only origin main
git status --short
go version
```

Run the local baseline:

```sh
go test -count=1 ./...
go vet ./...
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml
git diff --check
```

Prepare a local signing key. Use the real `COVENANT_RELEASE_SIGNING_KEY` only
when testing release-key handling; otherwise create a disposable key:

```sh
tmpdir="$(mktemp -d)"
go run ./cmd/covenant bundle keygen \
  --private "$tmpdir/covenant-release-private-key.json" \
  --public "$tmpdir/covenant-release-public-key.json"
export COVENANT_RELEASE_SIGNING_KEY="$(cat "$tmpdir/covenant-release-private-key.json")"
```

## Local Dry Run

Run the release-readiness smoke gate first. It exercises compile, lint, run,
verify, policy, bundle, release package, release verify, release inspect, and
schema validation paths in one local workspace.

```sh
tmpdir="$(mktemp -d)"
COVENANT_RELEASE_READINESS_DIR="$tmpdir/release-readiness" \
  COVENANT_RELEASE_VERSION=v0.1.0-dry-run \
  COVENANT_RELEASE_COMMIT="$(git rev-parse --short HEAD)" \
  COVENANT_RELEASE_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./scripts/release-readiness.sh
```

Review the non-sensitive summary:

```sh
cat "$tmpdir/release-readiness/release-readiness-summary.json"
```

## Package Without Publishing

Package release artifacts into a temp directory. This mirrors the release
workflow package command but does not upload artifacts or create a GitHub
release.

```sh
version=v0.1.0-dry-run
commit="$(git rev-parse HEAD)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dist="$tmpdir/dist"
mkdir -p "$dist"
printf '%s' "$COVENANT_RELEASE_SIGNING_KEY" > "$tmpdir/covenant-release-private-key.json"
jq '{schema_version:"covenant.bundle-public-key.v1", algorithm:.algorithm, public_key:.public_key}' \
  "$tmpdir/covenant-release-private-key.json" \
  > "$tmpdir/covenant-release-public-key.json"

go run ./cmd/covenant release package \
  --source . \
  --out "$dist" \
  --version "$version" \
  --commit "$commit" \
  --date "$date" \
  --sign-key "$tmpdir/covenant-release-private-key.json" \
  --target linux/amd64 \
  --target linux/arm64 \
  --target darwin/amd64 \
  --target darwin/arm64 \
  --target windows/amd64 \
  --json > "$dist/release-package.json"

cp "$tmpdir/covenant-release-public-key.json" "$dist/covenant-release-public-key.json"
```

## Verify Dry-Run Assets

Verify checksums, manifest metadata, signature status, and binary metadata:

```sh
(cd "$dist" && sha256sum -c SHA256SUMS)

go run ./cmd/covenant release verify \
  --dir "$dist" \
  --public-key "$dist/covenant-release-public-key.json" \
  --json > "$dist/release-verify.json"
```

On macOS, use `shasum -a 256 -c SHA256SUMS` instead of `sha256sum`.

Schema-validate generated JSON that declares a public `schema_version`:

```sh
find "$dist" -maxdepth 1 -name '*.json' -print | sort > "$tmpdir/dry-run-schema-files.txt"
go run ./cmd/covenant schema validate \
  --files-from "$tmpdir/dry-run-schema-files.txt" \
  --json \
  --out "$dist/schema-validation.json"
```

## Review Reports

Generate and inspect reports before any tag is created:

```sh
go run ./cmd/covenant release report \
  --dir "$dist" \
  --public-key "$dist/covenant-release-public-key.json"

go run ./cmd/covenant release report \
  --dir "$dist" \
  --public-key "$dist/covenant-release-public-key.json" \
  --json > "$dist/release-report.json"

go run ./cmd/covenant release inspect \
  --dir "$dist" \
  --public-key "$dist/covenant-release-public-key.json" \
  --json > "$dist/release-inspect.json"
```

Review:

- expected version, commit, date, and target list
- `manifest.json`, `SHA256SUMS`, and `release-signature.json`
- `covenant-release-public-key.json` presence
- release package, verify, report, inspect, and schema-validation JSON
- absence of private keys, local paths, and generated workspace files in any
  committed diff

## Cleanup

Remove temporary output after review:

```sh
rm -rf "$tmpdir"
git status --short
```

Do not proceed to tagging or workflow dispatch if any dry-run verification
fails. Fix the issue, rerun the dry run, and only then follow the release
operations document.
