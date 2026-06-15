# AO Covenant Release Note Template

Use this template when drafting GitHub release notes, replacement notices,
withdrawal notices, public advisory summaries, or corrected release notes. Pair
it with the [release operations](release.md), [release verification walkthrough](release-verification.md),
[release rollback runbook](release-rollback.md), and
[security policy](../SECURITY.md).

## Scope

Release notes must tell consumers what changed, who is affected, what to
download, what to verify, and whether any replacement, withdrawal, or
security-sensitive handling applies.

This template is for public release text. Keep private triage notes, exploit
details, secret values, sensitive evidence, customer data, and unreleased
material out of public release notes.

## Normal Release Notes

Use this block for ordinary public releases:

```md
## AO Covenant <version>

Summary:
- <one or two concise user-facing changes>

Affected version:
- <version or commit range>

Who is affected:
- <new installers, existing users, automation consumers, release verifiers, or no action needed>

Required consumer action:
- <install, upgrade, verify, refresh schema fixtures, or no action needed>

What to download:
- <platform archive names>
- manifest.json
- SHA256SUMS
- release-signature.json
- covenant-release-public-key.json

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`
```

## Replacement Or Withdrawal Notice

Use this block when release assets are replaced, corrected, superseded, or
withdrawn:

```md
## Release Notice For <version>

Status:
- <replaced, corrected, withdrawn, superseded, or prerelease only>

Affected version:
- <version and affected asset names>

Who is affected:
- <users who downloaded before timestamp, specific platform users, automation consumers, or all users>

Required consumer action:
- <discard old downloads, verify again, install corrected version, or stop using this version>

What to download:
- <corrected version or replacement asset list>

Replacement metadata:
- release-replacement-policy.json is <present or not present>
- replacement_reason: <short sanitized reason>

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`
```

Use the [release rollback runbook](release-rollback.md) before replacing,
withdrawing, or correcting public assets.

## Security-Sensitive Release Notes

Use this block when a release note needs to mention a security-sensitive fix
without exposing private details:

```md
## Security-Sensitive Release Note For <version>

Summary:
- <safe impact statement without exploit details>

Affected version:
- <affected public versions or commits>

Who is affected:
- <affected users or automation surfaces>

Required consumer action:
- <upgrade, rotate externally managed material, verify release assets, or follow advisory guidance>

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`

Security routing:
- See the security policy or private advisory for handling details.
```

Do not include exploit payloads or secret values. Do not include private keys, credentials, production evidence, unreleased bundles, or local machine paths in public release notes, public issues, pull requests, comments, logs, screenshots, workflow artifacts, or release assets.

## Verification Block

Every public release note should include enough verification guidance for a
consumer to check the downloaded assets:

```sh
covenant release verify --dir . --public-key covenant-release-public-key.json
covenant release report --dir . --public-key covenant-release-public-key.json
gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant
```

When a release-readiness artifact is referenced, validate it with:

```sh
covenant schema validate --schema covenant.release-readiness-summary.v1 --file release-readiness-summary.json
```

## Safe Wording Rules

- State user impact and required action before implementation detail.
- Use synthetic examples only.
- Say whether existing downloads can be kept, must be discarded, or must be
  verified again.
- Mention `release-replacement-policy.json` when assets were replaced through
  the guarded release workflow.
- Do not include exploit payloads or secret values.
- Do not include private keys, credentials, production evidence, unreleased bundles, or local machine paths.
- Link to private advisory routing only at a safe public level; do not repeat
  private advisory contents in release notes.

## Maintainer Checklist

Before publishing release notes:

- confirm the text names the affected version, who is affected, required
  consumer action, and what to download
- confirm the verification block includes checksum, signature, report, and
  attestation expectations where applicable
- confirm replacement or withdrawal notes follow the
  [release rollback runbook](release-rollback.md)
- confirm security-sensitive wording follows the [security policy](../SECURITY.md)
  and security advisory maintainer checklist
- remove private keys, credentials, production evidence, unreleased bundles,
  local machine paths, exploit payloads, and secret values
- confirm GitHub Actions passed on Ubuntu, macOS, and Windows for the release
  commit or correction commit
