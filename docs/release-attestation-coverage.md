# AO Covenant Release Attestation Coverage

This map defines which public release assets are covered by GitHub artifact
attestations, which checks are enforced by AO Covenant release verification,
and which assets require extra consumer review.

## Scope

This applies to public GitHub release assets produced by
`.github/workflows/release.yml`, downloaded release directories, consumer smoke
scripts, release reports, release inspection output, and replacement metadata.

It does not authorize publishing private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths. If those materials appear in public release assets, stop distribution and follow the security policy.

## Required GitHub Attestations

The release workflow grants `attestations: write` and uses
`actions/attest-build-provenance@v4` with `subject-path: "dist/*"`. Every file
present under `dist/` at that step is expected to receive a direct GitHub
attestation before publication.

The workflow then runs post-release smoke verification and checks:

```sh
gh attestation verify smoke/manifest.json
```

Consumers should verify at least `manifest.json` and the exact platform binary
they intend to install. Automation that relies on SBOM, supplemental
provenance, release reports, or packaged attestation files should verify those
files too.

## Release Asset Coverage Matrix

| Asset | GitHub attestation expectation | AO Covenant verification expectation |
| --- | --- | --- |
| `manifest.json` | direct GitHub attestation from `dist/*`; consumer command: `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant` | covered by manifest signature and checksum verification through `covenant release verify` |
| platform binaries | direct GitHub attestation from `dist/*`; example command: `gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant` | covered by manifest signature and checksum verification before installation |
| `SHA256SUMS` | direct GitHub attestation from `dist/*` | used by consumer checksum verification and cross-checked with manifest entries |
| `release-signature.json` | direct GitHub attestation from `dist/*` | verifies the signed manifest with `covenant-release-public-key.json` |
| `covenant-release-public-key.json` | direct GitHub attestation from `dist/*` | public verification material only; it must not contain the private signing key |
| `release-package.json` | direct GitHub attestation from `dist/*` | release packaging evidence; consumers may archive it with the release report |
| `release-verify.json` | direct GitHub attestation from `dist/*` | machine-readable verification output using the public release-verify schema |
| `release-report.json` | direct GitHub attestation from `dist/*` | machine-readable release report using the public release-report schema |
| SBOM, provenance, and packaged attestation artifacts | direct GitHub attestation when present in `dist/*` | covered by manifest signature and checksum verification when included in the release manifest |
| `release-replacement-policy.json` | direct GitHub attestation from `dist/*` when replacement metadata is generated | schema-validated by the workflow with `covenant.release-replacement-policy.v1` and reviewed as replacement metadata |

## Consumer Verification

Preferred one-command smoke checks:

```sh
../scripts/release-consumer-smoke.sh . --repo uesugitorachiyo/ao-covenant
```

On Windows PowerShell:

```powershell
..\scripts\release-consumer-smoke.ps1 . -Repo uesugitorachiyo/ao-covenant
```

The Windows script lives at `scripts/release-consumer-smoke.ps1`; the shell
script lives at `scripts/release-consumer-smoke.sh`.

Manual minimum checks:

```sh
covenant release verify --dir . --public-key covenant-release-public-key.json
gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant
gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant
```

Use the platform binary name that matches your operating system and CPU. Treat
the manifest and installed binary as the minimum attestation set.

## Maintainer Checks

Maintainers must keep `.github/workflows/release.yml` and this map aligned when
changing release packaging, workflow permissions, attestation actions, release
asset names, or post-release smoke verification.

The expected workflow anchors are:

- `attestations: write`
- `actions/attest-build-provenance@v4`
- `Preflight release asset replacement`
- `subject-path: "dist/*"`
- `gh attestation verify smoke/manifest.json`
- `covenant-release-public-key.json`
- `release-replacement-policy.json`

Public docs and release notes must not claim stronger attestation coverage than
the workflow actually provides.

## Failure Handling

Stop and do not install, announce, replace, or promote a release when:

- `gh attestation verify` fails for `manifest.json`
- `gh attestation verify` fails for the platform binary being installed
- checksum or AO Covenant release-signature verification fails
- a release report, inspect result, or replacement policy fails schema
  validation
- published assets include private keys, credentials, production evidence
  bundles, unreleased bundles, or local machine paths

Use the release verification walkthrough for command-level failures, the release
rollback runbook for replacement or withdrawal decisions, and the security
policy for suspected tampering or sensitive material exposure.

## Non-Goals

This map does not prove the release signing key is trustworthy by itself.
Consumers must still verify the public key through the expected release trust
channel.

This map does not require consumers to verify every supplemental file when they
do not rely on that file. It defines the minimum attestation boundary for files
used in the trust decision.

This map does not replace private security triage for suspected compromise,
secret leakage, or sensitive material exposure.
