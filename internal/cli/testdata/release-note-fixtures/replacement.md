## Release Notice For v0.1.0

Status:
- replaced

Summary:
- The v0.1.0 release assets were republished through the guarded replacement
  workflow because the original public notes omitted required verification
  guidance.

Affected version:
- v0.1.0

Who is affected:
- Users who downloaded v0.1.0 before 2026-06-15T12:00:00Z and automation
  consumers that cached the first published asset set.

Required consumer action:
- Discard old downloads, download the current v0.1.0 assets, and verify again
  before installing.

What to download:
- Current v0.1.0 platform asset for your operating system
- manifest.json
- SHA256SUMS
- release-signature.json
- covenant-release-public-key.json
- release-replacement-policy.json

Replacement metadata:
- release-replacement-policy.json is present.
- schema_version: covenant.release-replacement-policy.v1
- replacement_reason: public release note correction

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`

Safety:
- Do not include private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths.
