# AO Covenant Release Rollback And Replacement Runbook

Use this runbook when a published AO Covenant release asset must be replaced,
withdrawn, or corrected after publication. Use it with the
[release operations](release.md), [release verification walkthrough](release-verification.md),
[release dry-run checklist](release-dry-run.md), and
[security policy](../SECURITY.md). Draft consumer-facing text with the
[release note template](release-note-template.md).

## Scope

This runbook covers public release assets, checksums, manifests, release
signatures, provenance reports, attestations, SBOMs, and public release notes.
It does not cover private key rotation by itself; use the security policy and
security advisory maintainer checklist when signing material or credentials may
be exposed.

Do not silently overwrite release assets. Consumers must be able to understand
whether they can keep using an existing download, need to verify again, or must
replace a downloaded binary.

The current `.github/workflows/release.yml` has no replacement or clobber
path. It fails closed when either the requested tag or release exists.
Replacement inputs and reports described below document the historical manual
preflight tooling; they do not authorize the current workflow to overwrite a
release. Withdraw or supersede a defective current release with a new version.

## Decision Flow

Choose the smallest action that protects users and preserves release history:

1. If the release is unpublished or only locally staged, stop publishing, fix
   the issue, rerun the release dry run, and publish a clean release.
2. If published assets are correct but release notes are incomplete, update the
   release notes and add a clear consumer notice.
3. If one or more published assets are wrong, withdraw or supersede the release
   with a new version; do not overwrite it through the current workflow.
4. If the release cannot be trusted, mark the release as withdrawn or
   prerelease, publish a consumer notice, and prepare a corrected version.
5. If tampering, signing-key exposure, credential exposure, or provenance
   compromise is suspected, stop public detail expansion and follow the
   security policy.

## Replace Existing Assets

AO Covenant release assets are immutable in the current workflow. The
following inputs belonged to the historical replacement preflight process:

- `replace_existing_assets=true`
- `replacement_reason`

They are not accepted by the current release workflow. Historical replacement
runs published
`release-replacement-policy.json` with schema
`covenant.release-replacement-policy.v1` so consumers can see which assets were
replaced and why.

Before replacing assets:

```sh
./scripts/release-readiness.sh
```

Use the [release replacement preflight script](../scripts/release-replacement-preflight.sh)
to simulate the conflict set without publishing when reviewing a replacement
incident. It is an offline evidence tool, not a release authorization path.
Write the existing asset names to a temporary file, point
`COVENANT_RELEASE_EXISTING_ASSETS_FILE` at it, and run the same replacement
historical gate. The
[release replacement preflight fixtures](../internal/cli/testdata/release-replacement-preflight-fixtures)
show stable example inputs, generated policy output, and fail-closed
diagnostics. Set `COVENANT_RELEASE_REPLACEMENT_REPORT_JSON` to write
`release-replacement-preflight-report.json` with schema
`covenant.release-replacement-preflight-report.v1` for audit review:

```sh
printf '%s\n' manifest.json ao-covenant_v0.1.0_linux_amd64 > /tmp/existing-release-assets.txt
DIST_DIR=dist \
VERSION=v0.1.0 \
REPLACE_EXISTING_ASSETS=true \
REPLACEMENT_REASON="public release correction" \
GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant \
GITHUB_RUN_ID=12345 \
GITHUB_RUN_ATTEMPT=1 \
COVENANT_RELEASE_EXISTING_ASSETS_FILE=/tmp/existing-release-assets.txt \
COVENANT_RELEASE_REPLACEMENT_REPORT_JSON=/tmp/release-replacement-preflight-report.json \
./scripts/release-replacement-preflight.sh
```

After replacement, download the release into an empty directory and run:

```sh
covenant release verify --dir . --public-key covenant-release-public-key.json
covenant release report --dir . --public-key covenant-release-public-key.json
covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json
gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant
```

## Roll Back Or Withdraw A Release

Use rollback or withdrawal when replacement would hide too much risk or when
the published version should no longer be installed.

Maintainer actions:

- update the GitHub release notes to state that the release is withdrawn or
  superseded
- mark the release as prerelease when appropriate
- publish the corrected version or replacement guidance
- keep old assets available only when needed for auditability and clearly
  label them as not recommended for new installs
- open a sanitized public issue or advisory when users need a durable tracking
  reference

Do not delete evidence needed to explain what changed unless removal is needed
to reduce exposed sensitive material.

## Consumer Notice Requirements

Consumers must be told what changed, who is affected, what to download, and what to verify.

A consumer notice should include:

- affected version and asset names
- whether existing downloads are safe, must be discarded, or must be
  re-verified
- the corrected version or replacement assets
- checksum, signature, attestation, and report verification commands
- whether `release-replacement-policy.json` is present
- whether the security policy or a security advisory applies

Do not include private keys, credentials, production evidence, unreleased bundles, or local machine paths in consumer notices, release notes, issues, advisories, pull requests, logs, screenshots, or workflow artifacts.
Use the [release note template](release-note-template.md) to keep replacement
and withdrawal notices consistent.

## Post-Action Verification

After replacement, rollback, or withdrawal:

```sh
gh release download "$VERSION" --repo uesugitorachiyo/ao-covenant --dir "verify-$VERSION"
cd "verify-$VERSION"
covenant release verify --dir . --public-key covenant-release-public-key.json
covenant release report --dir . --public-key covenant-release-public-key.json
gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant
```

Also confirm the public release page includes the consumer notice and that
GitHub Actions passed on Ubuntu, macOS, and Windows for the commit that
published the release or correction.

## Security Escalation

Escalate through the [security policy](../SECURITY.md) when rollback or
replacement involves signing material, release integrity, attestation
integrity, credentials, customer data, production evidence, or unreleased
bundles.

Keep public wording minimal until triage is complete. Public updates should
describe user action without repeating exploit details or secret values.
