# AO Covenant

[![Release Readiness](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml/badge.svg)](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)

AO Covenant evaluates the contracts, policy decisions, approvals, and trust
records that govern AO work. It validates declared side effects, binds
decisions to exact inputs, and records evidence that can be verified or
revoked.

## Role In AO

- **Inputs:** Contracts, side-effect declarations, approval requests, trust
  material, and run evidence.
- **Outputs:** Policy decisions, approval tickets, event ledgers, verification
  results, and evidence packs.
- **Upstream:** AO Forge, AO2, and operators requesting approval.
- **Downstream:** AO Forge and AO2, plus observers and evaluators reading
  decision evidence.

See the [AO Architecture guide](https://github.com/uesugitorachiyo/ao-architecture)
and the
[AO Covenant component page](https://github.com/uesugitorachiyo/ao-architecture/blob/main/components/ao-covenant.md)
for the cross-repository flow.

## What Covenant Provides

- Public JSON schemas and embedded runtime validation.
- Deterministic brief compilation and contract digesting.
- Fail-closed policy decisions for declared side effects.
- Digest-bound approval tickets, artifacts, and input snapshots.
- Tamper-evident event ledgers and evidence packs.
- Offline bundle inspection, verification, and revocation support.
- Release manifests, checksums, signatures, and provenance reports.

## Quick Start

```bash
go test ./...
go run ./cmd/covenant version --json
go run ./cmd/covenant lint --brief examples/structured-release/brief.md
go run ./cmd/covenant compile \
  --brief examples/structured-release/brief.md \
  --out /tmp/ao-covenant-contract.json
go run ./cmd/covenant run \
  --contract /tmp/ao-covenant-contract.json \
  --workspace . \
  --out /tmp/ao-covenant-runs
```

The [full CLI and contract reference](REFERENCE.md) covers structured
authoring, policy evaluation, approvals, bundles, signatures, verification,
release packaging, and every example command.

## Current Release

[v0.1.1](https://github.com/uesugitorachiyo/ao-covenant/releases/tag/v0.1.1)
is the current published release, built from
`2fd72a0426a747868826581612fa1dc9727b53b9`.

Download [SHA256SUMS](https://github.com/uesugitorachiyo/ao-covenant/releases/download/v0.1.1/SHA256SUMS)
with one supported binary:

- [Linux amd64](https://github.com/uesugitorachiyo/ao-covenant/releases/download/v0.1.1/ao-covenant_v0.1.1_linux_amd64)
- [macOS Intel](https://github.com/uesugitorachiyo/ao-covenant/releases/download/v0.1.1/ao-covenant_v0.1.1_darwin_amd64)
- [Windows amd64](https://github.com/uesugitorachiyo/ao-covenant/releases/download/v0.1.1/ao-covenant_v0.1.1_windows_amd64.exe)

Verify only the binary you downloaded:

```sh
grep '  <asset-name>$' SHA256SUMS > SHA256SUMS.selected
sha256sum -c SHA256SUMS.selected # Linux
shasum -a 256 -c SHA256SUMS.selected # macOS
```

On Windows, run `Get-FileHash .\<asset-name> -Algorithm SHA256` and compare the
result with the matching `SHA256SUMS` line. Then follow the
[install guide](docs/install.md).
Source builds report `dev` until release metadata is injected.

## Documentation

- [Install](docs/install.md)
- [Threat Model](docs/threat-model.md)
- [Release Threat Model](docs/release-threat-model-matrix.md)
- [Release Verification](docs/release-verification.md)
- [Release Dry Run](docs/release-dry-run.md)
- [Release Rollback](docs/release-rollback.md)
- [Public Readiness](docs/public-readiness.md)
- [Public API Stability](docs/public-api-stability.md)
- [Public Schema Changelog](docs/public-schema-changelog.md)
- [Security Policy](SECURITY.md)
- [Full Reference](REFERENCE.md)

## Policy Boundary

Covenant evaluates declared authority; it does not create undeclared
authority. A successful validation result does not replace an approval ticket,
expand path scope, authorize provider access, or permit release publication.
Consumers must verify the exact contract digest and required evidence before
acting.

## Verification

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -o bin/covenant ./cmd/covenant
```

Release-specific consumer and readiness checks are indexed in
[Public Readiness](docs/public-readiness.md).

## License

AO Covenant is licensed under Apache 2.0. See [LICENSE](LICENSE).
