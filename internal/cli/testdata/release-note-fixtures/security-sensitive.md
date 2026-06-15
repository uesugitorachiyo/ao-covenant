## Security-Sensitive Release Note For v0.1.0

Summary:
- This release contains a safe impact statement for a security-sensitive fix
  that affects public release verification behavior.

Affected version:
- v0.1.0

Who is affected:
- Users who verify release assets before installation and automation consumers
  that inspect release reports.

Required consumer action:
- Upgrade to the corrected version, verify the downloaded release assets, and
  follow any private advisory guidance if you received it through an approved
  private channel.

What to download:
- Current platform asset for your operating system
- manifest.json
- SHA256SUMS
- release-signature.json
- covenant-release-public-key.json

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`

Security routing:
- See the security policy or private advisory for handling details.
- Do not include exploit payloads or secret values.

Safety:
- Do not include private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths.
