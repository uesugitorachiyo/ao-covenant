# AO Covenant Threat Model

AO Covenant is a local-first orchestration kernel for evidence-bound agent work.
It is designed to make agent activity reviewable, bounded, and verifiable. It
does not make arbitrary agent output safe by itself, and it does not replace
host operating system sandboxing, repository access control, or human review.
Inside the active AO2-first stack, AO Covenant is the policy and trust boundary:
AO2 owns governed execution, ao2-control-plane owns durable evidence observation,
AO Forge owns factory planning and gates, and AO Command owns read-only operator
status.

Use this model with the [security policy](../SECURITY.md), the signed
[release operations](release.md), and the install verification steps in
[install.md](install.md). Public-release attacks, controls, evidence, and
operator response are mapped in the
[release threat model matrix](release-threat-model-matrix.md).

## Protected Assets

AO Covenant is intended to protect the integrity and reviewability of these
assets:

- Contracts, contract digests, and digest sidecars.
- Event ledgers and evidence packs emitted by `covenant run`.
- Input snapshots and artifact digests for declared workspace reads and writes.
- Evidence bundles, bundle manifests, signatures, provenance reports, and
  revocation metadata.
- Release manifests, release signatures, checksums, public verification keys,
  supplemental provenance, and generated reports.
- Private signing keys, including local bundle private keys and the
  `COVENANT_RELEASE_SIGNING_KEY` repository secret.
- Local paths, workspace contents, command output, and other evidence material
  that may reveal user-specific or confidential data.

## Trust Boundaries

AO Covenant draws these trust boundaries:

- **User workspace:** The files under review or execution are untrusted input
  unless they have been inspected and verified by the operator.
- **Contract boundary:** A contract is the declared authority for reads, writes,
  task graph shape, obligations, and side effects. Runtime execution should not
  exceed the declared contract.
- **Policy boundary:** Policy evaluation is fail-closed. Denied or undeclared
  side effects must not be treated as implicit approval.
- **AO stack boundary:** AO Covenant decides policy and records trust evidence;
  it does not execute AO2 work, approve control-plane publication by upload, or
  replace AO Forge and AO Command ownership.
- **Adapter boundary:** Process execution and file writes flow through typed
  adapters so declared side effects can be captured as evidence.
- **Evidence boundary:** Evidence packs, bundles, reports, and release metadata
  are records of what AO Covenant observed. They are not a guarantee that the
  observed content is semantically correct.
- **Signing boundary:** Public keys verify signatures. Private signing keys are
  authority-bearing secrets and must stay outside source control and logs.
- **Release boundary:** GitHub release assets, checksums, AO Covenant release
  signatures, and GitHub artifact attestations are independently verifiable
  signals. Consumers should verify them before trusting binaries.
- **Host boundary:** AO Covenant runs on the local host. The host OS, filesystem
  permissions, shell, environment variables, installed tools, and network access
  remain part of the trusted computing base.

## Threats And Mitigations

| Threat | Mitigation |
| --- | --- |
| Contract tampering after review | Canonical contract digesting, digest sidecars, schema validation, and verification of evidence against recorded digests. |
| Undeclared file writes or side effects | Fail-closed policy decisions, declared side-effect checks, exact path validation, and evidence-bound adapter outputs. |
| Silent drift in run evidence | Tamper-evident event ledgers, artifact digests, input snapshot digests, and `covenant verify` recomputation. |
| Malicious or malformed evidence bundle | Offline bundle inspection, manifest checks, checksum validation, signature verification, and schema validation. |
| Stale or revoked approval material | Approval ticket validation, revocation list support, and bundle revocation inspection. |
| Signing-key exposure | Private signing keys are excluded from source control, release automation consumes `COVENANT_RELEASE_SIGNING_KEY` as a secret, and public key files are verification material only. |
| Release artifact replacement | Release automation fails closed when matching assets already exist unless `replace_existing_assets=true` and a replacement reason are supplied. |
| Binary substitution by a mirror or download path | Consumers can verify checksums, signed release manifests, public verification keys, and GitHub artifact attestations before installation. |
| Local path or confidential data leakage | Reports support redaction profiles and redaction policy files; security policy forbids committing real production evidence, local machine paths, and user-specific environment files. |
| Schema drift for automation consumers | Public schemas are embedded, exported, validated in tests, and covered by stable JSON fixtures. |

## Operator Responsibilities

Operators should:

- Keep private signing keys and `COVENANT_RELEASE_SIGNING_KEY` out of commits,
  logs, issue reports, and shared evidence bundles.
- Verify downloaded release artifacts before installation by following
  [install.md](install.md) and [release operations](release.md).
- Review generated contracts before running them, especially declared writes,
  process commands, task dependencies, and required obligations.
- Treat evidence packs and reports as potentially sensitive. Redact local paths,
  source material, command output, credentials, and customer data before sharing.
- Run `covenant lint`, `covenant verify`, `covenant bundle inspect`, and release
  verification commands as gates instead of relying on visual inspection alone.
- Prefer synthetic fixtures for public tests, issues, demos, and examples.

## Non-Goals

AO Covenant does not currently claim to:

- Provide a kernel-level sandbox or container escape protection.
- Prevent malicious code from consuming CPU, memory, disk, or network resources
  outside the controls provided by the host environment.
- Prove that generated source code, text, or agent reasoning is semantically
  correct.
- Protect secrets already exposed to child processes, shell startup files, or
  external tools invoked by the operator.
- Replace GitHub branch protection, CI policy, repository access control, secret
  scanning, endpoint security, or vulnerability disclosure process.
- Guarantee confidentiality of evidence packs, bundles, or reports after they
  are exported or shared.

## Reporting Security Issues

Report suspected vulnerabilities through the [security policy](../SECURITY.md).
Avoid posting exploit details, private keys, credentials, production evidence
packs, unreleased bundles, or local paths in public issues.
