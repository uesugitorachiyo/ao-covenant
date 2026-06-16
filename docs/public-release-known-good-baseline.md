# AO Covenant Public Release Known-Good Baseline

Use this baseline before trusting, announcing, replacing, or installing a public
AO Covenant release. It defines the minimum asset set and verification output
that should be present for a release to be considered known-good.

Use this document with the [release verification walkthrough](release-verification.md),
[release attestation coverage map](release-attestation-coverage.md),
[release consumer smoke script](../scripts/release-consumer-smoke.sh),
[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1),
[release note fixtures](release-note-fixtures.md),
[release rollback runbook](release-rollback.md), and
[security policy](../SECURITY.md).

## Scope

This baseline applies to public GitHub release assets, downloaded release
directories, release verification outputs, release reports, release inspection
results, replacement policy metadata, and public release notes.

It does not replace private security triage. If release integrity, signing
material, attestation integrity, credentials, customer data, production
evidence, or unreleased bundles are suspected to be exposed, stop public
expansion and follow the security policy.

## Required Release Assets

A known-good release directory contains these public files:

- `manifest.json`
- `SHA256SUMS`
- `release-signature.json`
- `covenant-release-public-key.json`
- one or more platform binaries or archives
- any published SBOM, attestation, provenance, report, or replacement policy
  files named by the release notes

The public key file is verification material only. It must not contain the
release private key.

## Platform Asset Baseline

Public releases should cover the supported operator platforms:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

Consumers should verify the exact platform asset they intend to install. A
release note should state when a platform asset is intentionally absent,
withdrawn, replaced, or superseded.

## Verification Output Baseline

Run these commands from the downloaded release directory:

```sh
covenant release verify --dir . --public-key covenant-release-public-key.json
covenant release report --dir . --public-key covenant-release-public-key.json
covenant release inspect --dir . --public-key covenant-release-public-key.json
gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant
```

Consumers can run the same baseline as a one-command smoke check:

```sh
../scripts/release-consumer-smoke.sh . --repo uesugitorachiyo/ao-covenant
```

On Windows PowerShell:

```powershell
..\scripts\release-consumer-smoke.ps1 . -Repo uesugitorachiyo/ao-covenant
```

Known-good output means:

- checksums match the downloaded files
- the AO Covenant release signature verifies
- manifest artifact names, sizes, and digests match downloaded assets
- the release report and inspection result show the expected version, commit,
  date, target platform, signature status, and provenance status
- GitHub artifact attestation verifies for artifacts used in the trust decision
- no unexpected replacement, withdrawal, or correction notice applies

## Schema Validation Baseline

Machine-readable release outputs must validate against their public schemas:

- `release-verify.json` uses `covenant.release-verify-result.v1`
- `release-report.json` uses `covenant.release-report-result.v1`
- `release-inspect.json` uses `covenant.release-inspect-result.v1`
- `release-replacement-policy.json`, when present, uses
  `covenant.release-replacement-policy.v1`

Validate output with:

```sh
covenant schema validate --file release-verify.json
covenant schema validate --file release-report.json
covenant schema validate --file release-inspect.json
covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json
```

Use `covenant schema catalog` and `covenant schema export` when automation needs
to pin the schema set bundled with a specific AO Covenant binary.

## Replacement Policy Baseline

If `release-replacement-policy.json` is present, treat the release as a
replacement or correction and review:

- affected version
- replacement reason
- replaced asset names
- GitHub repository, run ID, and run attempt
- release notes or consumer notice explaining required action

Validate the replacement policy before installing:

```sh
covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json
```

If the replacement policy is missing when release notes say assets were
replaced, stop and follow the release rollback runbook.

## Sensitive Material Exclusions

Known-good public releases and release notes must not include private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths.

Public release artifacts should also avoid exploit payloads, customer data,
private advisory details, temporary local workspaces, and generated
release-readiness work directories.

## Failure Handling

Stop and do not install the release when:

- checksums fail
- signature verification fails
- artifact attestation fails for an artifact you rely on
- schema validation fails for a machine-readable verification output
- a replacement, withdrawal, or correction notice is missing or inconsistent
- public assets contain private keys, credentials, production evidence bundles,
  unreleased bundles, or local machine paths

Use the release verification walkthrough for command-level troubleshooting, the
release rollback runbook for replacement or withdrawal decisions, and the
security policy for suspected tampering or sensitive material exposure.
