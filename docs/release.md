# AO Covenant Release Operations

AO Covenant releases are built by `.github/workflows/release.yml` when a `v*`
tag is pushed, or manually through `workflow_dispatch`.

The workflow requires one repository secret:

- `COVENANT_RELEASE_SIGNING_KEY`: the complete JSON contents of a
  `covenant.bundle-private-key.v1` private key file produced by
  `covenant bundle keygen`.

Do not commit the signing key. The workflow writes it to the runner temp
directory, sets mode `0600`, derives the public key file from it, and uses that
public key for `covenant release verify`.

The release workflow performs these checks before publishing:

- runs `go test -count=1 ./...`
- runs `go vet ./...`
- builds Linux, macOS, and Windows artifacts with `covenant release package`
- signs the AO Covenant release manifest with the configured release key
- verifies the signed manifest and binaries with `covenant release verify`
- emits a machine-readable `covenant release report`
- generates GitHub artifact attestations for `dist/*`
- publishes or updates the GitHub release assets

Consumers can verify downloaded release artifacts with the bundled checksums,
the signed AO Covenant manifest, and GitHub artifact attestations.
