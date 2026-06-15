# AO Covenant Release Operations

AO Covenant releases are built by `.github/workflows/release.yml` when a `v*`
tag is pushed, or manually through `workflow_dispatch`.

Existing release assets are immutable by default. AO Covenant fails closed
instead of overwriting assets when a manually dispatched workflow targets a
release that already has one or more matching asset names. Operators must set
`replace_existing_assets=true` and provide a `replacement_reason` to replace
existing assets. Replacement runs publish `release-replacement-policy.json`
alongside the release artifacts so the override is visible to consumers. Use
the [release rollback runbook](release-rollback.md) before replacing,
withdrawing, or correcting a published release.

Before pushing a tag or manually dispatching this workflow, run the
[release dry-run checklist](release-dry-run.md). The dry run packages, signs,
verifies, reports, inspects, and schema-validates release artifacts locally
without creating a tag, GitHub release, attestation, or public release asset.
Draft public release notes with the [release note template](release-note-template.md)
so normal releases, replacement notices, withdrawal notices, and
security-sensitive summaries include consumer action and verification guidance
without exposing private material.

The workflow requires one repository secret:

- `COVENANT_RELEASE_SIGNING_KEY`: the complete JSON contents of a
  `covenant.bundle-private-key.v1` private key file produced by
  `covenant bundle keygen`.

Do not commit the signing key. The workflow writes it to the runner temp
directory, sets mode `0600`, derives the public key file from it, and uses that
public key for `covenant release verify`.

Set the repository secret from a local private key file:

```sh
gh secret set COVENANT_RELEASE_SIGNING_KEY \
  --repo uesugitorachiyo/ao-covenant \
  < covenant-release-private-key.json
```

The release workflow performs these checks before publishing:

- runs `go test -count=1 ./...`
- runs `go vet ./...`
- builds Linux, macOS, and Windows artifacts with `covenant release package`
- signs the AO Covenant release manifest with the configured release key
- verifies the signed manifest and binaries with `covenant release verify`
- emits a machine-readable `covenant release report`
- publishes `covenant-release-public-key.json` for consumer verification
- generates GitHub artifact attestations for `dist/*`
- publishes new GitHub release assets, while existing asset replacement requires
  an explicit `replace_existing_assets` override and `replacement_reason`
- runs post-release smoke verification against the published GitHub release:
  downloads the release assets, runs `covenant release verify` with the
  published public key, and runs `gh attestation verify` for `manifest.json`

Consumers can verify downloaded release artifacts with the bundled checksums,
the signed AO Covenant manifest, and GitHub artifact attestations. Use the
[release verification walkthrough](release-verification.md) for the full
consumer checklist.

Download and verify an AO Covenant release:

```sh
version=v0.1.0
gh release download "$version" --repo uesugitorachiyo/ao-covenant --dir "ao-covenant-$version"
cd "ao-covenant-$version"
chmod +x ao-covenant_*
covenant release verify --dir . --public-key covenant-release-public-key.json
```

The `covenant-release-public-key.json` file is public verification material. It
does not contain the release private key.
