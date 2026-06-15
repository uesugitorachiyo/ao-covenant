# AO Covenant Install Guide

AO Covenant release artifacts are produced by:

```sh
go run ./cmd/covenant release package \
  --source . \
  --out dist \
  --version v0.1.0 \
  --commit "$(git rev-parse --short HEAD)" \
  --date "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

The release directory contains:

- `manifest.json`: version, commit, date, target, size, and SHA-256 metadata.
- `SHA256SUMS`: checksum file for command-line verification.
- `ao-covenant_<version>_<os>_<arch>` binaries.

Maintainers should use the signed release automation documented in
[`docs/release.md`](release.md) for public releases.

Before installing a downloaded public release, follow the
[release verification walkthrough](release-verification.md) for checksum,
signature, attestation, and provenance checks.

## Ubuntu

Verify the downloaded artifact:

```sh
cd dist
sha256sum -c SHA256SUMS
```

Install:

```sh
sudo install -m 0755 ao-covenant_v0.1.0_linux_amd64 /usr/local/bin/covenant
covenant version
```

Use `ao-covenant_v0.1.0_linux_arm64` on ARM64 systems.

## macOS

Verify the downloaded artifact:

```sh
cd dist
shasum -a 256 -c SHA256SUMS
```

Install:

```sh
sudo install -m 0755 ao-covenant_v0.1.0_darwin_arm64 /usr/local/bin/covenant
covenant version
```

Use `ao-covenant_v0.1.0_darwin_amd64` on Intel Macs.

## Windows

Verify the downloaded artifact in PowerShell:

```powershell
$artifact = "ao-covenant_v0.1.0_windows_amd64.exe"
$expected = (Select-String $artifact .\SHA256SUMS).Line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[0].ToLower()
$actual = (Get-FileHash ".\$artifact" -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "checksum mismatch for $artifact" }
```

Install:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
Copy-Item .\ao-covenant_v0.1.0_windows_amd64.exe "$env:USERPROFILE\bin\covenant.exe"
& "$env:USERPROFILE\bin\covenant.exe" version
```

Add `%USERPROFILE%\bin` to the user `PATH` if it is not already present.
