## AO Covenant v0.1.0

Summary:
- Adds public release verification documentation and schema-backed release
  automation examples.

Affected version:
- v0.1.0

Who is affected:
- New installers, existing users, release verifiers, and automation consumers.

Required consumer action:
- Install or upgrade when ready. No existing installation action is required.

What to download:
- ao-covenant_v0.1.0_linux_amd64
- ao-covenant_v0.1.0_linux_arm64
- ao-covenant_v0.1.0_darwin_amd64
- ao-covenant_v0.1.0_darwin_arm64
- ao-covenant_v0.1.0_windows_amd64.exe
- manifest.json
- SHA256SUMS
- release-signature.json
- covenant-release-public-key.json

Verification:
- Run `covenant release verify --dir . --public-key covenant-release-public-key.json`
- Run `covenant release report --dir . --public-key covenant-release-public-key.json`
- Run `gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant`

Safety:
- Do not include private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths.
