# AO Covenant Release Verification

Use this walkthrough before installing an AO Covenant release binary from
GitHub or a mirror. It verifies the downloaded files with SHA-256 checksums, the
AO Covenant signed release manifest, GitHub artifact attestations, and the
release provenance report.

The `covenant-release-public-key.json` file is public verification material. It
does not contain the release private key.
Use the [public release known-good baseline](public-release-known-good-baseline.md)
to compare the downloaded asset set, platform coverage, schema-backed
verification outputs, and sensitive-material exclusions before install.
Use the [release attestation coverage map](release-attestation-coverage.md)
to decide which release files need direct GitHub artifact attestation checks
and which files are covered by AO Covenant signature and checksum verification.
If a release was replaced, withdrawn, or corrected after publication, review
the [release rollback runbook](release-rollback.md) and any release notice
before installing.
Consumers can run the
[release consumer smoke script](../scripts/release-consumer-smoke.sh) against a
downloaded release directory to perform the checksum, signature, schema, report,
inspection, and manifest attestation checks in one command.
Windows consumers can run the
[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)
for the same checks with PowerShell-native checksum verification.

## 1. Download Release Assets

Download a release into an empty directory:

```sh
version=v0.1.0
workdir="ao-covenant-$version"
mkdir -p "$workdir"
gh release download "$version" \
  --repo uesugitorachiyo/ao-covenant \
  --dir "$workdir"
cd "$workdir"
```

Optional one-command smoke check after download:

```sh
../scripts/release-consumer-smoke.sh . --repo uesugitorachiyo/ao-covenant
```

On Windows PowerShell:

```powershell
..\scripts\release-consumer-smoke.ps1 . -Repo uesugitorachiyo/ao-covenant
```

The directory should include:

- `manifest.json`
- `SHA256SUMS`
- `release-signature.json`
- `covenant-release-public-key.json`
- one or more `ao-covenant_<version>_<os>_<arch>` binaries
- any published SBOM, attestation, provenance, or report files

## 2. Verify SHA-256 Checksums

On Ubuntu or other Linux systems:

```sh
sha256sum -c SHA256SUMS
```

On macOS:

```sh
shasum -a 256 -c SHA256SUMS
```

On Windows PowerShell:

```powershell
$sums = Get-Content .\SHA256SUMS
foreach ($line in $sums) {
  $parts = $line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
  $expected = $parts[0].ToLower()
  $path = $parts[-1].TrimStart("*")
  $actual = (Get-FileHash ".\$path" -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected) { throw "checksum mismatch for $path" }
}
```

Do not install a binary if any checksum fails.

## 3. Verify AO Covenant Release Signature

Use the AO Covenant public key published with the release:

```sh
covenant release verify --dir . --public-key covenant-release-public-key.json
```

For automation, request JSON output:

```sh
covenant release verify \
  --dir . \
  --public-key covenant-release-public-key.json \
  --json > release-verify.json
```

This checks the release manifest, artifact sizes and digests, signature status,
and release metadata. Treat a failed verification result as a release integrity
failure.

## 4. Verify GitHub Artifact Attestations

Verify GitHub artifact attestations for the release files you intend to trust.
For example, verify the manifest:

```sh
gh attestation verify manifest.json \
  --repo uesugitorachiyo/ao-covenant
```

Verify the platform binary before installation:

```sh
gh attestation verify ao-covenant_v0.1.0_linux_amd64 \
  --repo uesugitorachiyo/ao-covenant
```

Use the matching binary name for your platform. Consumers should verify
`manifest.json` plus the exact platform binary being installed. Always replace `v0.1.0` with the release version you downloaded.

## Platform Binary Attestation Matrix

| Platform | Target | Binary artifact | Attestation command |
| --- | --- | --- | --- |
| Ubuntu/Linux amd64 | `linux/amd64` | `ao-covenant_v0.1.0_linux_amd64` | `gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant` |
| Ubuntu/Linux arm64 | `linux/arm64` | `ao-covenant_v0.1.0_linux_arm64` | `gh attestation verify ao-covenant_v0.1.0_linux_arm64 --repo uesugitorachiyo/ao-covenant` |
| macOS Intel | `darwin/amd64` | `ao-covenant_v0.1.0_darwin_amd64` | `gh attestation verify ao-covenant_v0.1.0_darwin_amd64 --repo uesugitorachiyo/ao-covenant` |
| macOS Apple Silicon | `darwin/arm64` | `ao-covenant_v0.1.0_darwin_arm64` | `gh attestation verify ao-covenant_v0.1.0_darwin_arm64 --repo uesugitorachiyo/ao-covenant` |
| Windows amd64 | `windows/amd64` | `ao-covenant_v0.1.0_windows_amd64.exe` | `gh attestation verify ao-covenant_v0.1.0_windows_amd64.exe --repo uesugitorachiyo/ao-covenant` |

Stable [release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)
show the expected pass case and common failure cases for consumer automation.

If a release includes SBOM, attestation, or supplemental provenance files,
verify those files as well when they are part of your trust decision. The
[release attestation coverage map](release-attestation-coverage.md) defines
the expected direct and indirect coverage for each public release asset.
If `release-replacement-policy.json` is present, verify its GitHub attestation
before relying on the replacement metadata:

```sh
gh attestation verify release-replacement-policy.json --repo uesugitorachiyo/ao-covenant
```

## 5. Review Provenance And Reports

Generate a human-readable release report:

```sh
covenant release report --dir . --public-key covenant-release-public-key.json
```

Generate machine-readable output for CI or archival review:

```sh
covenant release report \
  --dir . \
  --public-key covenant-release-public-key.json \
  --format json \
  --out release-report.json
```

For a compact offline inspection result:

```sh
covenant release inspect \
  --dir . \
  --public-key covenant-release-public-key.json \
  --json > release-inspect.json
```

Review the report for:

- expected version, commit, date, and target platform
- matching manifest, checksum, and signature status
- binary metadata for the platform you plan to install
- published SBOM, attestation, and supplemental provenance entries
- replacement policy evidence when release assets were intentionally replaced

## Failure Handling

Stop and do not install the binary if any of these checks fail:

- `SHA256SUMS` does not match a downloaded file
- `covenant release verify --dir . --public-key covenant-release-public-key.json`
  exits non-zero or reports an invalid signature
- `gh attestation verify` cannot verify an artifact you rely on
- the release report shows an unexpected target, commit, replacement policy, or
  missing provenance signal

When a failure may indicate tampering, report it through the
[security policy](../SECURITY.md). Include the release version, asset names,
commands run, and sanitized command output. Do not include credentials, private
keys, production evidence, or local paths that are not needed to reproduce the
issue.
