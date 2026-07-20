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
`actions/attest-build-provenance@v4` with
`subject-path: "bundle/release/*"` inside the protected live publisher. Every
file in the verified release inventory receives a direct GitHub attestation
before publication. Dry runs do not create attestations.

The workflow then runs post-release smoke verification and checks:

```sh
gh attestation verify downloaded/manifest.json --repo uesugitorachiyo/ao-covenant
```

Consumers should verify at least `manifest.json` and the exact platform binary
they intend to install. Automation that relies on SBOM, supplemental
provenance, release reports, or packaged attestation files should verify those
files too.

## Platform Binary Attestation Matrix

Consumer trust decisions must include `manifest.json` plus the exact platform binary being installed. Replace `v0.1.0` with the release version you downloaded.

| Platform | Target | Binary artifact | Attestation command |
| --- | --- | --- | --- |
| Ubuntu/Linux amd64 | `linux/amd64` | `ao-covenant_v0.1.0_linux_amd64` | `gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant` |
| macOS Intel | `darwin/amd64` | `ao-covenant_v0.1.0_darwin_amd64` | `gh attestation verify ao-covenant_v0.1.0_darwin_amd64 --repo uesugitorachiyo/ao-covenant` |
| Windows amd64 | `windows/amd64` | `ao-covenant_v0.1.0_windows_amd64.exe` | `gh attestation verify ao-covenant_v0.1.0_windows_amd64.exe --repo uesugitorachiyo/ao-covenant` |

Stable [release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)
provide public examples for a passing manifest-plus-binary trust decision,
missing binary attestation failure, and tampered manifest attestation failure.

## Release Asset Coverage Matrix

| Asset | GitHub attestation expectation | AO Covenant verification expectation |
| --- | --- | --- |
| `manifest.json` | direct GitHub attestation from `bundle/release/*`; consumer command: `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant` | covered by manifest signature and checksum verification through `covenant release verify` |
| platform binaries | direct GitHub attestation from `bundle/release/*`; example command: `gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant` | covered by manifest signature and checksum verification before installation |
| `SHA256SUMS` | direct GitHub attestation from `bundle/release/*` | used by consumer checksum verification and cross-checked with manifest entries |
| `release-signature.json` | direct GitHub attestation from `bundle/release/*` | verifies the signed manifest with `covenant-release-public-key.json` |
| `covenant-release-public-key.json` | direct GitHub attestation from `bundle/release/*` | public verification material only; it must not contain the private signing key |
| `release-package.json` | direct GitHub attestation from `bundle/release/*` | release packaging evidence; consumers may archive it with the release report |
| `release-verify.json` | direct GitHub attestation from `bundle/release/*` | machine-readable release verification output |
| `release-report.json` | direct GitHub attestation from `bundle/release/*` | machine-readable release report |
| `LICENSE` and `NOTICE` | direct GitHub attestation from `bundle/release/*` | required exact package files in the approved manifest |

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
- `environment: ao-covenant-release`
- `subject-path: "bundle/release/*"`
- `gh attestation verify downloaded/manifest.json`
- `covenant-release-public-key.json`

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
