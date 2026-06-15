## Release Notice For v0.1.0

Status:
- withdrawn

Summary:
- v0.1.0 is withdrawn because the published release asset set is no longer the
  recommended install path.

Affected version:
- v0.1.0

Who is affected:
- Users who downloaded v0.1.0 and automation consumers that mirror public
  release assets.

Required consumer action:
- Stop using v0.1.0. Install the corrected release named in the current GitHub
  release notes.

What to download:
- The corrected replacement version named by the current public release notice
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
