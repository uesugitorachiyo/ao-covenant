# AO Covenant Release Threat Model Matrix

This matrix maps public-release attacks to AO Covenant controls, evidence, and
operator response. Use it with the [threat model](threat-model.md),
[release operations](release.md), [release verification walkthrough](release-verification.md),
[release dry-run checklist](release-dry-run.md),
[release attestation coverage map](release-attestation-coverage.md),
[release rollback runbook](release-rollback.md), and
[security policy](../SECURITY.md).

## Scope

This document covers AO Covenant public release creation, dry-run release
validation, replacement release handling, consumer verification, and public
release reporting.

It does not replace private security triage, branch protection, GitHub access
control, endpoint security, or key rotation. If signing material, credentials,
or production evidence may be exposed, follow the [security policy](../SECURITY.md)
and security advisory maintainer checklist before posting public details.

## Attack-To-Control Matrix

| Attack | Preventive controls | Detective evidence | Operator response |
| --- | --- | --- | --- |
| Signing key compromise | Keep `COVENANT_RELEASE_SIGNING_KEY` in repository secrets only; never commit private key files; derive and publish only `covenant-release-public-key.json`; require signed manifests for releases. | `covenant release verify`, `covenant release report`, public key fingerprint output, release signature status, and CI secret handling logs without secret values. | Stop publishing, rotate signing material, withdraw or replace affected releases, and route through the [security policy](../SECURITY.md). |
| Release artifact substitution | Publish `manifest.json`, `SHA256SUMS`, `release-signature.json`, platform binaries, and `covenant-release-public-key.json`; require consumers to verify checksums, manifest signature, and public key fingerprint. | `covenant release verify`, `covenant release inspect`, `release-report.json`, consumer-side checksum output, and `release-consumer-smoke.json`. | Treat mismatch as a failed release, do not install the binary, compare against the [public release known-good baseline](public-release-known-good-baseline.md), then use the rollback runbook. |
| Checksum or manifest tampering | Sign the release manifest; include every release artifact in `SHA256SUMS`; validate release JSON schemas; reject mismatched or unmanifested artifacts. | `covenant release verify`, `covenant release report`, `release-verify.json`, `release-report.json`, and schema validation output. | Halt installation or publication, regenerate artifacts from a clean tag, and document consumer action in release notes. |
| GitHub attestation gap | Generate GitHub artifact attestations only in the protected live publisher; document direct attestation requirements in the [release attestation coverage map](release-attestation-coverage.md). | `gh attestation verify manifest.json`, release workflow attestation step status, and consumer smoke output. | Block broad release promotion until attestation evidence is present or a documented exception is approved. |
| Unauthorized asset replacement | Fail closed when the tag or release already exists; provide no replacement, upload, or clobber path in release automation. | Publisher preflight status, immutable promotion plan, exact tag-target verification, and published asset digest verification. Historical `release-replacement-preflight-report.json` and `release-replacement-policy.json` fixtures remain available for incident analysis. | Use the [release rollback runbook](release-rollback.md), withdraw or supersede the release, and publish consumer guidance. |
| Dry-run publish confusion | Default manual workflow dispatch to `dry_run=true`; dry runs upload workflow artifacts only and skip the protected publisher, GitHub release creation, artifact attestations, and post-release smoke verification. | Immutable promotion plan with `publication_status=not_attempted`, all attempted flags false, private workflow artifacts, and no GitHub release mutation. | Treat dry-run artifacts as rehearsal evidence only; a live dispatch additionally requires exact confirmation and protected-environment approval. |
| Consumer verification bypass | Provide [release consumer smoke script](../scripts/release-consumer-smoke.sh) and [Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1); document manual verification commands for checksums, signatures, reports, and attestations. | `release-consumer-smoke.json`, `release-verify.json`, `release-report.json`, `release-inspect.json`, and consumer command output. | Ask consumers to rerun the smoke script or documented manual commands before trusting a binary. |
| Sensitive material exposure | Keep private keys, credentials, production evidence bundles, unreleased bundles, and local paths out of public assets and issues; use public fixtures and redacted reports. | Repository hygiene tests, `scripts/check-public-repo-policy.sh`, redaction checks, public docs safety warnings, `release-dry-run-artifact-audit.json` private-key checks, and issue-template routing. | Remove public exposure where possible, rotate affected secrets, route privately through the security process, and publish only minimal public status. |

## Required Evidence

Public-release review should collect or point to these artifacts before broad
distribution:

- `manifest.json`
- `SHA256SUMS`
- `release-signature.json`
- `covenant-release-public-key.json`
- `release-verify.json`
- `release-report.json`
- `release-consumer-smoke.json`
- `release-dry-run-artifact-audit.json` for dry-run release rehearsals
- `release-replacement-preflight-report.json` for replacement preflight audits
- `release-replacement-policy.json` for replacement releases
- GitHub Actions CI results for Ubuntu, macOS, and Windows
- GitHub artifact attestation verification output for assets that require
  direct attestations

## Operator Response

Use this response order when a release-control failure occurs:

1. Stop distribution or installation of the affected release asset.
2. Preserve non-sensitive evidence: failing command, release version, asset
   names, schema IDs, check names, and public workflow run links.
3. Avoid public private keys, token values, production evidence bundles,
   unreleased bundles, customer data, and local machine paths.
4. Follow the [release rollback runbook](release-rollback.md) for replacement,
   withdrawal, or correction decisions.
5. Follow the [security policy](../SECURITY.md) when compromise, tampering,
   credential exposure, or exploitability is suspected.
6. Draft public release notes with the [release note template](release-note-template.md)
   so consumers receive verification and action guidance without sensitive
   details.

## Residual Risk

These controls raise release assurance, but they do not prove that source code
is bug-free, that a developer endpoint was uncompromised, that GitHub itself
was not compromised, or that every downstream mirror preserves metadata.
Consumers still need to verify downloaded assets, and maintainers still need
private security triage for suspected compromise.
