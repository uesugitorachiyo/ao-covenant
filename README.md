# AO Covenant

[![Release Readiness](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml/badge.svg)](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)

AO Covenant is a local-first orchestration kernel for evidence-bound agent work.

AO Covenant currently builds the contract, policy, run, and evidence spine:

- public schema artifacts under `schemas/`
- embedded runtime schema validation for contracts, events, and evidence packs
- deterministic risky-change brief compilation
- fast brief and contract linting before compile/run
- canonical contract digesting
- fail-closed contract validation for scoped paths, portable IDs, task DAGs, and evaluator obligations
- strict policy decisions for declared side effects before task execution
- human-readable policy decision explanations for evidence packs and bundles
- approval ticket creation, inspection, validation, and contract attachment
- typed action adapter boundary for declared side effects
- digest-bound artifacts for declared workspace reads
- run-local input snapshots for every declared workspace read
- exact-match process sandbox allowlists with captured stdout/stderr artifacts
- local contract execution with a tamper-evident event ledger
- closure matrix evaluation for required obligations
- evidence pack emission with artifact, input snapshot, failure, and ledger digests
- verification that recomputes ledger, input snapshot, and artifact digests
- evidence bundle export, offline inspection, and provenance reports
- release packaging with embedded version metadata, manifest, and checksums

Security model:

- [Threat Model](docs/threat-model.md) defines protected assets, trust
  boundaries, mitigated threats, operator responsibilities, and non-goals.
- [Security Policy](SECURITY.md) defines private vulnerability reporting and
  sensitive material handling.
- [Security Advisory Routing](docs/security-advisory-routing.md) defines when
  to use private advisories and how to keep public reports minimal.
- [Release Verification](docs/release-verification.md) gives consumers a
  checksum, signature, attestation, and provenance walkthrough before install.
- [Public Release Known-Good Baseline](docs/public-release-known-good-baseline.md)
  defines the minimum public asset and verification output expectations for a
  trusted release.
- [Release Dry Run](docs/release-dry-run.md) defines the local pre-tag release
  packaging and verification checklist.
- [Release Rollback](docs/release-rollback.md) defines replacement, rollback,
  withdrawal, and consumer notice expectations for published assets.
- [Release Note Template](docs/release-note-template.md) defines safe public
  release note, replacement notice, and security-sensitive wording blocks.
- [Public Readiness](docs/public-readiness.md) indexes the public docs,
  verification gates, schema checks, repository hygiene checks, and the
  [Release Readiness workflow](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml).
- [Public API Stability](docs/public-api-stability.md) defines stable,
  experimental, and internal consumer surfaces before 1.0.
- [Public Schema Changelog](docs/public-schema-changelog.md) records public
  schema families, compatibility expectations, and consumer validation actions.
- [Dependency Review](docs/dependency-review.md) defines Go module and GitHub
  Actions supply-chain review expectations.
- [Contributing](CONTRIBUTING.md) defines local setup, required checks,
  protected-branch flow, docs expectations, and schema expectations.
- [Code of Conduct](CODE_OF_CONDUCT.md) and [Governance](GOVERNANCE.md) define
  collaboration expectations and pre-1.0 maintainer decision scope.

Stable release JSON examples live in
`internal/schema/testdata/release-fixtures/` and are validated against the
published schemas in tests so automation consumers can diff the public release
API surface without building a release package. These include redacted inspect,
report, and diff examples for consumers that must exercise partner-safe output
contracts; the redacted report fixture covers signature, attestation, SBOM, and
supplemental provenance evidence counts while masking paths and digests. Refresh
those fixtures from the release structs with
`COVENANT_UPDATE_RELEASE_FIXTURES=1 go test ./internal/release -run 'ReleaseJSONFixturesMatchGeneratedGoldenFiles' -count=1`.
The central fixture inventory lives at
`internal/cli/testdata/release-fixture-index.json`; it lists every release
fixture directory, expected files, and the refresh or validation command for
each fixture set, validates against `covenant.release-fixture-index.v1`, and is
covered by the schema exported through `covenant schema export`.
Stable `release report` text examples live in
`internal/cli/testdata/release-report-fixtures/`; refresh them with
`COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1 go test ./internal/cli -run 'ReleaseReportTextFixtures' -count=1`.
Stable `release report` SARIF examples live in
`internal/cli/testdata/release-report-sarif-fixtures/` and cover valid,
invalid, and baseline-suppressed findings; refresh them with
`COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1 go test ./internal/cli -run 'ReleaseReportSARIFFixtures' -count=1`.
Stable `release diff` SARIF examples live in
`internal/cli/testdata/release-diff-sarif-fixtures/` and cover matching,
changed, and baseline-suppressed drift; refresh them with
`COVENANT_UPDATE_RELEASE_DIFF_FIXTURES=1 go test ./internal/cli -run 'ReleaseDiffSARIFFixtures' -count=1`.

`covenant schema catalog` lists every public JSON schema embedded in the binary,
including the schema ID, filename, and repository path. Use `--json` to emit a
stable `schemas[]` catalog for automation with `schema_version:
covenant.schema-catalog-result.v1`, covered by the embedded public schema
exported by `covenant schema export`. `covenant schema export --out <dir>`
writes the same embedded schemas to a local directory and reports the written
paths as text or JSON. JSON export output includes `schema_version:
covenant.schema-export-result.v1` and is covered by the embedded public schema
exported by the same command. `covenant schema validate --file <path>` validates a JSON
document against the embedded public schema named by its `schema_version` field;
`covenant schema validate --dir <path>` recursively validates every `*.json`
document in a directory tree, ignores non-JSON files, and prints per-file
results using slash-separated paths relative to `<path>` plus aggregate `total`,
`valid_count`, and `invalid_count` counts. Batch text output also prints
`schema_summary=` lines for every schema family validated or skipped, and JSON
directory output includes the same aggregate count fields plus a stable
`schemas[]` per-schema breakdown. Pass repeated `--ignore <path>` values with
`--dir` to skip slash-separated relative files or directories such as generated
exports or vendored schema fixtures before validation begins; ignored JSON
documents are reported as `ignored=` text lines or JSON `ignored[]` entries
with `ignored_count`. Use
`covenant schema validate --files-from <path>` to validate a newline-delimited
manifest of slash-separated JSON document paths relative to the manifest file.
Use repeated `--schema-filter <id>` values with `--dir` or `--files-from` to
validate only matching embedded `schema_version` families from mixed document
sets. `--schema-filter` cannot be combined with `--schema`; it validates matched
documents against their embedded schema IDs and reports `skipped_count` for
non-matching documents.
Use `covenant schema validate --stdin` to validate a single JSON document from
standard input. Use `--sarif` to
emit SARIF 2.1.0 findings for invalid documents in code-scanning workflows, or
`--junit` to emit JUnit XML test reports for CI systems. `--json`, `--sarif`,
and `--junit` are mutually exclusive. Use `--sarif-baseline <path>` with
`--sarif` to mark accepted recurring schema validation findings with external
SARIF suppressions. Invalid validation reports include a JSON Pointer-like
`location` for the failing instance path when the schema validator can identify
one. JSON validation reports include
`schema_version: covenant.schema-validation-report.v1` and are covered by the
embedded public report schema exported by `covenant schema export`. They also
include deterministic `metadata.command`, `metadata.input_mode`, and
`metadata.source` fields, plus any selected `metadata.explicit_schema_id`,
`metadata.schema_filters`, `metadata.ignore_patterns`, or `metadata.fail_fast`.
Use `--fail-fast` with
`--dir` to stop after the first invalid document
while still emitting the selected text, JSON, SARIF, or JUnit report for
attempted files. Add `--out <path>` with `--json`, `--sarif`, or `--junit` to
write the structured validation report to a file while stdout prints
`schema_validation_report=<path>`. Pass `--schema <id>` to validate against an
explicit schema instead. The command exits non-zero with a schema error when any
attempted document does not conform:

`covenant version --json` emits structured release metadata with
`schema_version: covenant.version-result.v1`, covered by the embedded public
schema exported by `covenant schema export`.

```sh
go run ./cmd/covenant schema catalog
go run ./cmd/covenant schema catalog --json \
  >/tmp/ao-covenant-schema-catalog.json
go run ./cmd/covenant schema export --out /tmp/ao-covenant-schemas
go run ./cmd/covenant schema export --out /tmp/ao-covenant-schemas --json \
  >/tmp/ao-covenant-schema-export.json
go run ./cmd/covenant schema validate \
  --file /tmp/ao-covenant-contract.json
cat /tmp/ao-covenant-contract.json | go run ./cmd/covenant schema validate --stdin
go run ./cmd/covenant schema validate \
	--dir /tmp/ao-covenant-documents \
	--json \
	--out /tmp/ao-covenant-schema-validation.json
go run ./cmd/covenant schema validate \
  --dir /tmp/ao-covenant-documents \
  --ignore generated \
  --ignore vendor/schemas
go run ./cmd/covenant schema validate \
  --dir /tmp/ao-covenant-documents \
  --schema-filter covenant.contract.v1 \
  --schema-filter covenant.evidence-bundle.v1
go run ./cmd/covenant schema validate \
  --dir /tmp/ao-covenant-documents \
  --fail-fast
go run ./cmd/covenant schema validate \
  --files-from /tmp/ao-covenant-schema-files.txt \
  --json \
  --out /tmp/ao-covenant-schema-validation.json
go run ./cmd/covenant schema validate \
	--dir /tmp/ao-covenant-documents \
	--sarif \
	--out /tmp/ao-covenant-schema-validation.sarif
go run ./cmd/covenant schema validate \
  --dir /tmp/ao-covenant-documents \
  --sarif \
  --sarif-baseline /tmp/ao-covenant-schema-validation-baseline.json
go run ./cmd/covenant schema validate \
	--dir /tmp/ao-covenant-documents \
	--junit \
	--out /tmp/ao-covenant-schema-validation.xml
go run ./cmd/covenant schema validate \
  --schema covenant.contract.v1 \
  --file /tmp/ao-covenant-contract.json
go run ./cmd/covenant schema validate \
	--schema covenant.contract.v1 \
	--file /tmp/ao-covenant-contract.json \
	--json \
	--out /tmp/ao-covenant-schema-validation.json
```

`covenant compile` accepts a brief inside the current workspace and records that
workspace-relative source path in the emitted contract. The emitted contract is
validated against the embedded `covenant.contract.v1` schema before it is
written. By default the demo contract writes `demo-output/report.txt`; pass
repeated `--write <workspace-path>` flags to author explicit write targets.
Use `--json` to emit `schema_version: covenant.compile-result.v1` with the
contract path, contract digest, and digest file path. `compile --out <path>`
also writes `<path>.sha256`; the contract and digest sidecar are treated as one
output pair. The result schema is embedded and exported by `covenant schema
export`. `--summary` prints reads, writes, tasks, and obligations as text, while
`--summary-json` emits the same compile summary as structured JSON with
`schema_version: covenant.compile-summary.v1`, covered by the embedded public
schema exported by `covenant schema export`.

`covenant run` writes the event ledger and evidence pack for a contract run.
Use `--json` to emit `schema_version: covenant.run-result.v1` with the run ID,
run directory, ledger path, and evidence pack path. The result schema is
embedded and exported by `covenant schema export`.

Commands that write a primary artifact plus a digest sidecar, currently
`compile --out` and `approval attach --out`, use the same output-sidecar
guarantees. the `--out` parent directory must already exist. The parent path must be a
directory, not a file. The `--out` target must point to a file path rather than
a directory. The parent directory must already exist. Failed path validation must leave stdout empty and must not create
output artifacts. The digest is written to `<out>.sha256`. If primary output
validation or writing fails, the digest sidecar must not be created. If the
sidecar write fails after the primary artifact is written, AO Covenant rolls the
primary artifact back. If the primary artifact is written but the digest sidecar
write fails, the writer must rollback the primary artifact. New primary artifacts are removed; pre-existing primary
artifacts are restored with their previous contents and permission bits on POSIX
filesystems. On Windows, rollback preserves contents and leaves access-control
semantics to the platform. Existing sidecar artifacts are
left in their previous state when a write fails. If rollback itself fails, the
command reports both the sidecar write failure and the rollback failure.
Developers maintaining file-output behavior should use the
[CLI Output Writer Contract](docs/output-writer-contract.md) for the full
command-writer matrix and error taxonomy.

`covenant lint` preflights briefs and compiled contracts without writing output
files or executing tasks. Linting a brief uses the same structured authoring
parser as `compile`; linting a contract validates the JSON schema and semantic
contract rules used by `run`. Where the input can still be analyzed, lint
aggregates multiple semantic diagnostics in one run instead of stopping at the
first issue. Diagnostics include actionable remediation hints when AO Covenant
can infer a specific next edit. Text output is stable key-value lines, and
`--json` emits `valid` plus `diagnostics[]` with stable code, severity, optional
line/field, message, and optional hint. JSON output includes `schema_version:
covenant.lint-result.v1`, covered by the embedded public schema exported by
`covenant schema export`. Use `--sarif` instead of `--json` to emit SARIF 2.1.0
for code-scanning workflows:

```sh
go run ./cmd/covenant lint --brief examples/structured-release/brief.md
go run ./cmd/covenant lint --json \
  --brief examples/structured-release/brief.md \
  >/tmp/ao-covenant-lint-brief.json
go run ./cmd/covenant lint --sarif \
  --brief examples/structured-release/brief.md \
  >/tmp/ao-covenant-lint-brief.sarif
go run ./cmd/covenant lint --sarif \
  --sarif-baseline /tmp/ao-covenant-lint-baseline.json \
  --brief examples/structured-release/brief.md \
  >/tmp/ao-covenant-lint-brief.sarif
go run ./cmd/covenant lint --contract /tmp/ao-covenant-contract.json
```

SARIF baseline mode keeps accepted recurring diagnostics visible while marking
them with SARIF external suppression metadata. When every diagnostic is matched
by the baseline, `covenant lint --sarif --sarif-baseline <file>` exits 0. The
baseline file shape is:

```json
{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "STRUCTURED_TASK_FIELD_UNKNOWN",
      "source_uri": "examples/structured-release/brief.md",
      "line": 8,
      "field": "tasks.writes",
      "justification": "accepted until the source brief is migrated"
    }
  ]
}
```

`source_uri`, `line`, and `field` narrow the match when present; omit `field`
for diagnostics that do not carry one. The public baseline schema is published
at `schemas/covenant.lint-sarif-baseline.v1.schema.json` and embedded into the
runtime, so baseline files are schema-validated before suppression matching.
Schema validation SARIF baseline mode reuses the same baseline file shape with
`rule_id` set to `SCHEMA_VALIDATION_FAILED`, `source_uri` set to the schema
validation report file path, and optional `field` set to the reported validation
`location`.

Unstructured briefs still compile to the built-in three-task demo chain:
`scripted_change`, `verify_change`, and `review_change`. A structured markdown
brief that contains at least one `## Task:` block authors a real task DAG using
the existing contract schema:

```markdown
# Objective
Create a release report.

# Reads
- docs/source.md

# Writes
- reports/release.md

# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

## Obligation: obl_verify_passes
required: true
text: Verification passes.

# Tasks
## Task: draft_release_report
kind: scripted
writes:
- reports/release.md
reads:
- docs/source.md
obligations:
- obl_release_report
timeout_seconds: 45

## Task: verify_release_report
kind: verify
depends_on:
- draft_release_report
obligations:
- obl_verify_passes
```

Supported task fields are `kind`, `adapter`, `depends_on`, `obligations`,
`writes`, `reads`, and `timeout_seconds`. Task-level `writes` become
`file.write` side effects; task-level `reads` become `file.read` side effects.
Each compiled task is also validated against the embedded public
`covenant.task.v1` schema during contract validation, so required task arrays
and declared side-effect shapes are enforced consistently whether tasks come
from structured briefs or direct contract JSON.
The source brief path is always retained as the first `workspace.reads` entry.
Top-level `# Writes` declares the workspace write scope; if omitted, the compiler
uses the union of task-level `writes`. CLI `--write` flags override top-level
`# Writes`.

Structured authoring errors include a stable diagnostic code and source line in
the form `CODE line N: message`. Common diagnostics include
`STRUCTURED_TASK_FIELD_UNKNOWN` for unsupported task fields,
`STRUCTURED_TASK_DEP_UNKNOWN` for unresolved dependencies,
`STRUCTURED_TASK_OBLIGATION_UNKNOWN` for unresolved obligation references,
`STRUCTURED_TASK_ID_DUPLICATE` for duplicate task IDs, and
`STRUCTURED_TASK_WRITE_UNDECLARED` when a task write is outside the effective
workspace write scope. A task write must be present under `# Writes` or supplied
with `--write`; otherwise strict policy would deny the compiled side effect.

`covenant run` executes a contract inside the selected workspace and writes a run
directory containing `events.ndjson`, `evidence-pack.json`, and
`input-snapshots/`. Before task execution, every declared `workspace.reads` file
is copied into `input-snapshots/<source-path>` under the run directory and
recorded in the evidence pack as `input_snapshots` with source path, snapshot
path, media type, and SHA-256 digest. Contract input, ledger events, and the
evidence pack are all validated against the embedded public schemas during the
run.

Each event in `events.ndjson` carries `previous_event_hash` and `event_hash`,
forming a hash chain from a fixed genesis value. The evidence pack records the
SHA-256 digest of the final ledger file as `ledger_digest`, binding the
human-readable evidence summary to the immutable event stream.

Strict policy mode allows declared `file.write` effects only when the resource is
listed in `workspace.writes`, allows declared `file.read` effects only when the
resource is listed in `workspace.reads`, and denies `network.request` or
`process.spawn` unless the contract includes a matching approved ticket. Every
decision is emitted as a `policy_decided` event and recorded in the evidence
pack under `policy_decisions`.

`covenant policy explain` reads an existing evidence pack, validates its schema,
and prints every recorded allow/deny decision with a human-readable summary. For
denied decisions it also prints the operator action required to make the request
valid, such as attaching a matching approval ticket or declaring the workspace
scope. Use `--json` to emit `policy_explanations` for automation. JSON output
includes `schema_version: covenant.policy-explain-result.v1`, covered by the
embedded public schema exported by `covenant schema export`:

```sh
go run ./cmd/covenant policy explain \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json
go run ./cmd/covenant policy explain --json \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  >/tmp/ao-covenant-policy-explain.json
```

`covenant policy index` filters recorded decisions from an evidence pack or
bundle by task, effect, resource, allow/deny decision, and approval-ticket
state. Provide exactly one of `--evidence` or `--bundle`; pass `--public-key`
with signed bundles when signature verification is required. Use `--approval
with-ticket` to find decisions allowed by explicit approval and `--approval
without-ticket` to find decisions that did not reference an approval ticket.
Text output prints the matching count plus the same human-readable policy lines
as `policy explain`; `--json` emits `policy_decisions` and
`policy_explanations`. JSON output includes `schema_version:
covenant.policy-index-result.v1`, covered by the embedded public schema
exported by `covenant schema export`:

```sh
go run ./cmd/covenant policy index \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --task scripted_change \
  --effect file.write \
  --decision allow
go run ./cmd/covenant policy index --json \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --approval with-ticket \
  >/tmp/ao-covenant-policy-index.json
go run ./cmd/covenant policy index \
  --bundle /tmp/ao-covenant-demo-bundle.zip \
  --effect file.write \
  --decision allow
```

`covenant approval` manages approval tickets for declared side effects that
strict policy would otherwise deny. Given a contract that declares the same task,
effect, and resource, operators can create a ticket, inspect it, validate it
against that contract, and attach it to produce a new contract plus digest.
Tickets may include optional `operator_id` and `expires_at` fields. `expires_at`
must be RFC3339; policy evaluation denies an otherwise matching ticket after its
expiration time:

```sh
go run ./cmd/covenant approval create \
  --task scripted_change \
  --effect process.spawn \
  --resource make-test \
  --reason "operator approved local test command" \
  --operator operator_alice \
  --expires-at 2099-01-02T03:04:05Z \
  --out /tmp/ao-covenant-approval.json
go run ./cmd/covenant approval inspect \
  --ticket /tmp/ao-covenant-approval.json
go run ./cmd/covenant approval validate \
  --contract /tmp/ao-covenant-contract.json \
  --ticket /tmp/ao-covenant-approval.json
go run ./cmd/covenant approval attach \
  --contract /tmp/ao-covenant-contract.json \
  --ticket /tmp/ao-covenant-approval.json \
  --out /tmp/ao-covenant-approved-contract.json
```

`approval attach --out <path>` writes the approved contract and `<path>.sha256`
with the shared output-sidecar guarantees described above.

Add `--json` to approval commands for schema-backed automation output.
`approval create --json`, `approval validate --json`, and
`approval attach --json` emit `schema_version:
covenant.approval-create-result.v1`, `schema_version:
covenant.approval-validate-result.v1`, and `schema_version:
covenant.approval-attach-result.v1`. `approval inspect --json` emits the
approval ticket itself with `schema_version: covenant.approval-ticket.v1`.
These schemas are embedded and exported by `covenant schema export`.

Local approval revocation lists can invalidate previously attached tickets at
run or verification time. A revocation list is a JSON file with
`schema_version: covenant.approval-revocations.v1` and `revoked_tickets[]`
entries containing `ticket_id` and `reason`. The public schema is published at
`schemas/covenant.approval-revocations.v1.schema.json` and embedded into the
runtime, so revocation lists are schema-validated before semantic duplicate
checks. Use `approval revoke` to create a revocation list, add `--append` to add
another ticket to an existing list, and use `approval revocations inspect` to
inspect the list:

```sh
go run ./cmd/covenant approval revoke \
  --ticket-id approval-scripted_change-process_spawn-make-test \
  --reason "operator revoked local process approval" \
  --out /tmp/ao-covenant-revocations.json
go run ./cmd/covenant approval revocations inspect \
  --file /tmp/ao-covenant-revocations.json
```

`approval revoke --json` emits `schema_version:
covenant.approval-revoke-result.v1`, and `approval revocations inspect --json`
emits `schema_version: covenant.approval-revocations-inspect-result.v1`. Both
result documents include the revocation-list path, revoked-ticket count, and a
nested `revocations` document with `schema_version:
covenant.approval-revocations.v1`. These result schemas are embedded and
exported by `covenant schema export`. Pass one or more revocation lists with
repeated `--revocations` flags:

```json
{
  "schema_version": "covenant.approval-revocations.v1",
  "revoked_tickets": [
    {
      "ticket_id": "approval-scripted_change-process_spawn-make-test",
      "reason": "operator revoked local process approval"
    }
  ]
}
```

```sh
go run ./cmd/covenant run \
  --contract /tmp/ao-covenant-approved-contract.json \
  --revocations /tmp/ao-covenant-revocations.json
go run ./cmd/covenant verify \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --revocations /tmp/ao-covenant-revocations.json
```

After policy allows a declared side effect, the runner sends the action through
a typed action adapter. The default local adapter implements `file.write` for
demo artifacts, `file.read` for digest-bound workspace input evidence, and a
sandboxed `process.spawn` path. `file.read` actions are allowed only when the
resource is declared in `workspace.reads`; the evidence pack records the source
workspace path and SHA-256 digest as an artifact. Process resources must be
approved by ticket and exact-match allowlisted at run time via
`--allow-process`; they are executed without a shell, from the workspace root,
with a minimal environment and the task timeout. Stdout and stderr are captured
as evidence artifacts under `.covenant/process/`. `network.request` still fails
closed until an explicit adapter is provided.

Every evidence pack also includes `closure_matrix`, which links each contract
obligation to claiming tasks, artifact IDs, policy decision IDs, and final run
status. A run is accepted only when every required obligation is closed.

Failed runs include structured `failures` records in the evidence pack. Each
failure has a stable failure ID, phase, reason, task ID when available, and the
failed ledger event ID so policy denials and adapter errors can be audited from
the evidence summary back to the event stream. Successful runs emit an empty
`failures` array.

`covenant verify` replays the event hash chain, recomputes the ledger file
digest, validates ledger and evidence schema conformance, checks that the
evidence pack references the same run and digest, validates every input snapshot
relative to the evidence pack directory, and recomputes every artifact manifest
digest from the workspace. Use `--workspace <dir>` to select the workspace root
for artifact paths; it defaults to `.`. Declared source files may change after a
run without invalidating verification, because `input_snapshots` are checked
against the copied run-bundle files. Verification output includes
`artifact_count`, `input_snapshot_count`, and `failure_count` for quick
inspection. Failed runs also print one `failure=` line per failure with the
failure ID, ledger event ID, 1-based ledger line, task ID, phase, and reason, so
operators can jump directly from the summary to the relevant `events.ndjson`
record. Use `covenant verify --json` to emit the same verification result,
including `artifact_count`, `input_snapshot_count`, and
`failures[].event_line`, as structured JSON for automation with
`schema_version: covenant.verify-result.v1`, covered by the embedded public
schema exported by `covenant schema export`. Verification output also includes
`policy_explanations` derived from recorded policy decisions, so operators can
see the allow/deny summary and remediation action without running a separate
`covenant policy explain` command.
When `--revocations` is supplied, verification also rejects any evidence whose
policy decisions reference a revoked approval ticket, including bundle
verification through `covenant verify --bundle`.

Verification also checks provenance links across the evidence pack and ledger.
Every artifact manifest entry must point at an `artifact_recorded` producer event
that includes the artifact ID. Every closure row artifact ID must exist in the
manifest and must be produced by one of the row's claimed tasks. Every closure
row policy decision ID must exist in `policy_decisions` and belong to one of the
row's claimed tasks. Missing row artifacts or policy decisions for claimed tasks
are rejected, so a closure matrix cannot silently drift away from the ledger and
manifest. Every evidence policy decision must also be backed by a matching
ledger `policy_decided` event with the same task, status, and reason, so bundle
verification rejects policy evidence that cannot be traced to the event stream.
New `policy_decided` events also carry structured `decision_id`, `decision`,
`effect_type`, `resource`, and optional `approval_ticket_id` fields. The public
event schema requires those policy fields on `policy_decided` events and rejects
policy-only fields on other ledger event types. Verification prefers the stable
`decision_id` link when present while still accepting older ledgers that only
recorded task, status, and reason.

`covenant bundle export` packages a verified run into a portable zip archive.
Export runs `covenant verify` semantics first; if the ledger, evidence pack,
input snapshots, artifact digests, or provenance links fail verification, no
bundle is written. A successful bundle contains `contract.json`, `events.ndjson`,
`evidence-pack.json`, `input-snapshots/`, `artifacts/`, `bundle-manifest.json`,
and `SHA256SUMS`. When `--revocations` is supplied, the validated revocation
lists are attached under `revocations/`, included in the manifest and checksums,
and enforced automatically by `covenant verify --bundle`. Signed bundles also
include `bundle-signature.json`:

`bundle-manifest.json` uses the public
`schemas/covenant.evidence-bundle.v1.schema.json` schema. AO Covenant validates
generated manifests before writing bundles and validates in-bundle manifests
before offline inspect/report decoding, after checksum verification has proven
the manifest bytes are bundle-local. Use `bundle export --json` to emit a
schema-backed `covenant.bundle-export-result.v1` result with the bundle path,
entry count, optional public key fingerprint for signed exports, and the nested
manifest. The result schema is embedded and exported by `covenant schema export`.

```sh
go run ./cmd/covenant bundle export \
  --contract /tmp/ao-covenant-contract.json \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --revocations /tmp/ao-covenant-revocations.json \
  --workspace . \
  --out /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant bundle inspect --bundle /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant bundle report --bundle /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant verify --bundle /tmp/ao-covenant-demo-bundle.zip
```

`covenant bundle inspect` reads bundle metadata directly from the zip without
extracting files. It validates `SHA256SUMS`, reports manifest counts, signature
status, artifact and input snapshot summaries, policy explanations, and artifact
producer provenance from the in-bundle ledger and evidence pack. Bundles that
carry `revocations/*.json` also report revocation-list and revoked-ticket counts
plus ticket IDs and reasons. Use `--json` for automation; JSON output includes
`schema_version: covenant.bundle-inspect-result.v1`, covered by the embedded
public schema exported by `covenant schema export`. Inspect accepts the same
`--audience`, `--redact`, `--redaction-policy`, and `--redaction-profile`
controls as reports; external/path/digest redaction masks bundle paths,
manifest paths, artifact and snapshot paths, public-key fingerprints, bundled
revocation file paths, and revoked approval ticket IDs before text or JSON is
printed.

`covenant bundle report` is the deeper offline provenance view. It validates the
same checksums and optional signature without extracting files, then links
manifest entries, ledger events with line numbers, artifacts, input snapshots,
policy explanations, failures, closure rows, and bundled revocation details.
Use `--json` for a complete machine-readable report with `schema_version:
covenant.bundle-report-result.v1`, covered by the embedded public schema
exported by `covenant schema export`; use `--markdown` for a portable audit
report, or
`--public-key` to verify signed bundle manifests. Use `--redact paths,digests`
to mask path/resource and digest/fingerprint fields while preserving IDs,
counts, decisions, and closure structure. `--audience external` applies the same
path and digest redactions for reports shared outside the operating team,
including bundled revocation file paths and revoked approval ticket IDs.
For repeatable exports, store named profiles in a redaction policy file and pass
`--redaction-policy <file> --redaction-profile <name>`:

```json
{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths"]
    },
    "external": {
      "redact": ["paths", "digests"]
    }
  }
}
```

Policy profile redactions are merged with `--audience` and inline `--redact`
values, so a command can select a standard profile and add stricter one-off
redactions when needed. The public policy schema is published at
`schemas/covenant.report-redaction-policy.v1.schema.json` and embedded into the
runtime, so policy files are schema-validated before profile selection.
Stable release redaction policy examples live in
`internal/cli/testdata/redaction-policies/release-redaction-policy.json`; the
test suite applies that same `partner` profile to release inspect, release
report, and release diff JSON output.

Use local Ed25519 key files when a bundle needs offline operator
authentication. `bundle keygen` writes a private key JSON file and a public key
JSON file, then prints `public_key_sha256` for operator comparison. Generated
private keys use `schema_version: covenant.bundle-private-key.v1`; generated
public keys use `schema_version: covenant.bundle-public-key.v1`. Use
`bundle keygen --json` to emit a machine-readable
`schema_version: covenant.bundle-keygen-result.v1` result containing the private
key path, public key path, and public key fingerprint. `bundle export --sign-key`
signs the exact `bundle-manifest.json` bytes, writes `bundle-signature.json` with
`schema_version: covenant.bundle-signature.v1`, and prints the same public key
fingerprint. These key file, signature, and keygen result schemas are embedded,
validated at runtime, and exported by `covenant schema export`. `bundle export
--json --sign-key` includes the same fingerprint in its
`covenant.bundle-export-result.v1` output. `bundle inspect --public-key` and
`verify --bundle --public-key` also expose
`public_key_sha256`, so key identity can be checked consistently before trusting
offline evidence:

```sh
go run ./cmd/covenant bundle keygen \
  --private /tmp/ao-covenant-bundle-private-key.json \
  --public /tmp/ao-covenant-bundle-public-key.json \
  --json
go run ./cmd/covenant bundle export \
  --contract /tmp/ao-covenant-contract.json \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --workspace . \
  --out /tmp/ao-covenant-demo-signed-bundle.zip \
  --sign-key /tmp/ao-covenant-bundle-private-key.json
go run ./cmd/covenant bundle inspect \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json
go run ./cmd/covenant verify \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json
```

`covenant verify --bundle` validates `SHA256SUMS`, checks the bundled contract
digest against `bundle-manifest.json`, extracts the source entries to a
temporary directory, then runs the normal ledger, evidence, input snapshot,
artifact digest, and provenance verification against the bundled contents. When
`--public-key` is provided, it also verifies `bundle-signature.json` against the
manifest. Use `covenant verify --json --bundle <zip>` for machine-readable
bundle verification.

`covenant self-run` dogfoods the local repository without a shell script. It
reads `examples/self-run/brief.md`, writes `.covenant/self-run/contract.json`
and `.sha256`, runs the contract with evidence under `.covenant/self-run/runs`,
then verifies the generated ledger and evidence pack before printing the paths:

```sh
go run ./cmd/covenant self-run
```

Use `--json` to emit `schema_version: covenant.self-run-result.v1` with
contract paths, the contract digest, run evidence paths, verification status,
and failure count. The result schema is embedded and exported by `covenant
schema export`.

`covenant version` prints embedded build metadata. Release builds can inject
`version`, `commit`, and `date` via ldflags; `covenant release package` applies
those ldflags while building target binaries, then writes `manifest.json` and
`SHA256SUMS`. The release manifest includes `schema_version:
covenant.release-manifest.v1` and is covered by the embedded public schema
exported by `covenant schema export`. Use `--json` to emit `schema_version:
covenant.release-package-result.v1` with the manifest path, checksums path,
artifact paths, and embedded release manifest; the result schema is also
exported by `covenant schema export`. The CLI test suite includes a
release-readiness workflow that exercises compile, run, verify, signed bundles,
schema validation, and release package output together. Without explicit
`--target` flags, release packaging builds `linux/amd64`, `linux/arm64`,
`darwin/amd64`, `darwin/arm64`, and `windows/amd64` artifacts. The test suite
also builds the compiled `covenant` binary and runs a release-readiness smoke
workflow through that executable. Use `covenant release verify --dir <dist>` to
validate the release manifest schema, recompute artifact digests and sizes, and
check `SHA256SUMS` against manifest artifact entries. For artifacts matching the
current host OS and architecture, verification also runs the binary's `version
--json` command and compares embedded version, commit, date, OS, and arch
metadata against `manifest.json`. To sign a release manifest, pass
`--sign-key <private-key.json>` to `release package`; this writes
`release-signature.json` with `schema_version: covenant.release-signature.v1`.
To attach generator-agnostic SBOM or provenance files, pass repeated
`--sbom <file>` or `--provenance <file>` flags. AO Covenant copies those files
into the release directory, records them in `manifest.json` as
`supplemental_artifacts`, and includes them in `SHA256SUMS`; release
verify/inspect then validates their digest, size, and checksum entries without
requiring a specific SBOM or provenance generator. To attach per-binary
attestation files, pass repeated `--attestation <selector>=<file>` values.
Supported selectors are `name:<artifact-name>`, `target:<os>/<arch>`, and
`path:<artifact-path>`; legacy bare artifact names and bare targets such as
`linux/amd64` still work. To label an attestation kind, prefix the selector with
`kind:<label>,`, for example
`--attestation kind:slsa,target:linux/amd64=linux-amd64.intoto.json`. If a
selector does not match, the error lists the available `name:`, `target:`, and
`path:` choices for that release. Attestations are copied into the release
directory, recorded under the matching manifest artifact, included in
`SHA256SUMS`, and reported by release verify/inspect with per-attestation
verification status and kind labels when present.
Then pass `--public-key <public-key.json>` to `release verify` to require and
verify that signature over the exact `manifest.json` bytes. Use `--json` to emit
`schema_version: covenant.release-verify-result.v1` with verification status,
artifact count, release metadata paths, signature fingerprint, per-artifact
digest/size/checksum/metadata status, supplemental artifact
digest/size/checksum status, provenance linking release metadata, signature
verification, artifact targets, binary metadata, artifact attestation
provenance links, and supplemental artifact provenance links, and any
verification problems; the result schema is exported
by `covenant schema export`.
Use `covenant release inspect --dir <dist> --public-key <public-key.json>
--json` for a lightweight `schema_version:
covenant.release-inspect-result.v1` manifest, checksum, and signature status
report that does not execute release binaries. Use `covenant release report
--dir <dist> --public-key <public-key.json>` for the same offline release
inspection as a human-readable summary with manifest, checksum, signature,
artifact, attestation, supplemental artifact, compact provenance summary, and
problem sections; the command
exits non-zero when the inspected release is invalid. The default report format
is `--format text`; use `--format markdown` for a publishable Markdown summary
with tables for release metadata and artifact status, `--format json` to emit a
`schema_version: covenant.release-report-result.v1` automation report exported
by `covenant schema export`, including a compact `provenance_summary` with
signature status, attestation, SBOM, supplemental provenance, and invalid
evidence counts, or `--format sarif` for SARIF 2.1.0 findings consumable by
CI/code-scanning systems. Add `--out <path>` to write any release report format
to a CI artifact file; stdout then prints `release_report=<path>`. JSON and
SARIF reports, including `--out` files, are still emitted for invalid releases
before the command exits non-zero. The `--out` parent directory must already
exist, and `--out` must point to a file path rather than a directory. Add
`--sarif-baseline <baseline.json>` to reuse the
`covenant.lint-sarif-baseline.v1` baseline format for accepted release
findings; matched findings are emitted with SARIF external suppressions, and an
otherwise invalid release exits `0` only when every emitted finding is accepted.
Use `--format sarif-baseline` to generate a baseline template from current
release SARIF findings; generated justifications are review placeholders and
must be replaced before the baseline is treated as accepted risk.
Text/JSON `release inspect` and text/Markdown/JSON `release report` output
supports the same `--audience external`, `--redact paths,digests`,
`--redaction-policy`, and `--redaction-profile` controls as bundle reports.
Inspect JSON redaction preserves `covenant.release-inspect-result.v1` with
placeholder paths and SHA256-shaped digest fields. Release report JSON also
records the applied redactions and policy profile while preserving the published
report schema. The same policy file and profile can be reused with `covenant
release diff --json`; diff JSON records the selected profile and redaction list.
SARIF release reports remain unredacted so code-scanning systems can keep stable
paths, fingerprints, and baselines. Use `covenant release diff
--from <old-dist> --to <new-dist>` to compare two offline release directories;
it reports metadata, artifact, supplemental artifact, signature, and inspection
problem drift, exits `0` when releases match, and exits `1` when drift is
found. Add `--json` to emit a `schema_version:
covenant.release-diff-result.v1` machine-readable diff; diff JSON supports
`--audience external`, `--redact paths,digests`, `--redaction-policy`, and
`--redaction-profile` for shared release outside the operating team. Use
`--sarif` to emit SARIF 2.1.0 release drift findings for CI/code-scanning
review; SARIF diff output remains unredacted so baselines and fingerprints stay
stable. Use
`--sarif-baseline <baseline.json>` with `--sarif` to mark accepted drift with
SARIF external suppressions; when every drift finding is accepted, the command
exits `0` while still emitting the suppressed SARIF findings. Add `--out
<path>` to write text, JSON, or SARIF release diff output to a CI artifact file;
stdout then prints `release_diff=<path>`, and changed releases still return the
same drift status after writing the file. The `--out` parent directory must
already exist, and `--out` must point to a file path rather than a directory:

```sh
go run ./cmd/covenant version
go run ./cmd/covenant release package \
  --source . \
  --out dist \
  --version v0.1.0 \
  --commit "$(git rev-parse --short HEAD)" \
  --date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --sbom sbom.spdx.json \
  --provenance provenance.intoto.json \
  --attestation kind:slsa,target:linux/amd64=linux-amd64.intoto.json \
  --sign-key covenant-private-key.json
go run ./cmd/covenant release verify --dir dist --public-key covenant-public-key.json
go run ./cmd/covenant release verify --dir dist --public-key covenant-public-key.json --json
go run ./cmd/covenant release inspect --dir dist --public-key covenant-public-key.json --json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format markdown
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format json --out release-report.json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format sarif
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format sarif --out release-report.sarif
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format sarif-baseline
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format sarif-baseline --out release-sarif-baseline.json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --format sarif --sarif-baseline release-sarif-baseline.json
go run ./cmd/covenant release report --dir dist --public-key covenant-public-key.json --audience external
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --json
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --json --out release-diff.json
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --json --audience external
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --json --out release-diff-redacted.json --redaction-policy release-redaction-policy.json --redaction-profile partner
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --sarif
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --sarif --out release-diff.sarif
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --sarif --sarif-baseline release-diff-sarif-baseline.json
go run ./cmd/covenant release diff --from dist-v0.1.0 --to dist-v0.2.0 --sarif --out release-diff.sarif --sarif-baseline release-diff-sarif-baseline.json
```

For the full local release gate, run:

```sh
./scripts/release-readiness.sh
```

The script writes its generated workspace to `.covenant/release-readiness` by
default and can be redirected with `COVENANT_RELEASE_READINESS_DIR`. It also
accepts `COVENANT_RELEASE_VERSION`, `COVENANT_RELEASE_COMMIT`,
`COVENANT_RELEASE_DATE`, and `COVENANT_RELEASE_TARGET`.

See `docs/install.md` for Ubuntu, macOS, and Windows install and checksum
verification steps.

Run local verification:

```sh
go test ./...
go run ./cmd/covenant version
go run ./cmd/covenant version --json >/tmp/ao-covenant-version.json
go run ./cmd/covenant compile \
  --brief examples/risky-change/brief.md \
  --out /tmp/ao-covenant-contract.json
go run ./cmd/covenant compile \
  --brief examples/risky-change/brief.md \
  --out /tmp/ao-covenant-contract-json-result.json \
  --json >/tmp/ao-covenant-compile-result.json
go run ./cmd/covenant compile \
  --brief examples/structured-release/brief.md \
  --out /tmp/ao-covenant-structured-contract.json \
  --summary
go run ./cmd/covenant compile \
  --brief examples/risky-change/brief.md \
  --out /tmp/ao-covenant-authoring-contract.json \
  --write reports/summary.txt \
  --write reports/audit.txt \
  --summary
go run ./cmd/covenant compile \
  --brief examples/risky-change/brief.md \
  --out /tmp/ao-covenant-authoring-contract-json.json \
  --write reports/summary.txt \
  --summary-json >/tmp/ao-covenant-authoring-summary.json
go run ./cmd/covenant run \
  --contract /tmp/ao-covenant-contract.json \
  --workspace . \
  --out /tmp/ao-covenant-runs \
  --run-id demo
go run ./cmd/covenant run \
  --contract /tmp/ao-covenant-contract.json \
  --workspace . \
  --out /tmp/ao-covenant-runs \
  --run-id demo-json \
  --json >/tmp/ao-covenant-run.json
go run ./cmd/covenant verify \
  --workspace . \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json
go run ./cmd/covenant verify --json \
  --workspace . \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  >/tmp/ao-covenant-verify.json
go run ./cmd/covenant bundle export \
  --contract /tmp/ao-covenant-contract.json \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --workspace . \
  --out /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant bundle inspect --bundle /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant bundle report --json \
  --bundle /tmp/ao-covenant-demo-bundle.zip \
  >/tmp/ao-covenant-bundle-report.json
go run ./cmd/covenant bundle report --markdown \
  --bundle /tmp/ao-covenant-demo-bundle.zip \
  >/tmp/ao-covenant-bundle-report.md
go run ./cmd/covenant verify --bundle /tmp/ao-covenant-demo-bundle.zip
go run ./cmd/covenant verify --json --bundle /tmp/ao-covenant-demo-bundle.zip \
  >/tmp/ao-covenant-bundle-verify.json
go run ./cmd/covenant bundle keygen \
  --private /tmp/ao-covenant-bundle-private-key.json \
  --public /tmp/ao-covenant-bundle-public-key.json
go run ./cmd/covenant bundle export \
  --contract /tmp/ao-covenant-contract.json \
  --ledger /tmp/ao-covenant-runs/demo/events.ndjson \
  --evidence /tmp/ao-covenant-runs/demo/evidence-pack.json \
  --workspace . \
  --out /tmp/ao-covenant-demo-signed-bundle.zip \
  --sign-key /tmp/ao-covenant-bundle-private-key.json
go run ./cmd/covenant bundle inspect \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json
go run ./cmd/covenant bundle inspect --json \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json \
  >/tmp/ao-covenant-bundle-inspect.json
go run ./cmd/covenant bundle report --json \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json \
  >/tmp/ao-covenant-signed-bundle-report.json
go run ./cmd/covenant bundle report --markdown \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json \
  >/tmp/ao-covenant-signed-bundle-report.md
go run ./cmd/covenant verify \
  --bundle /tmp/ao-covenant-demo-signed-bundle.zip \
  --public-key /tmp/ao-covenant-bundle-public-key.json
go run ./cmd/covenant self-run \
  --workspace . \
  --out /tmp/ao-covenant-self-run \
  --run-id self-run-demo \
  --json >/tmp/ao-covenant-self-run.json
go run ./cmd/covenant release package \
  --source . \
  --out /tmp/ao-covenant-dist \
  --version v0.1.0 \
  --commit dev \
  --date 2026-06-11T00:00:00Z \
  --target linux/amd64 \
  --json >/tmp/ao-covenant-release-package.json
python3 -m json.tool /tmp/ao-covenant-version.json >/tmp/ao-covenant-version.pretty.json
python3 -m json.tool /tmp/ao-covenant-compile-result.json >/tmp/ao-covenant-compile-result.pretty.json
python3 -m json.tool /tmp/ao-covenant-contract.json >/tmp/ao-covenant-contract.pretty.json
python3 -m json.tool /tmp/ao-covenant-structured-contract.json >/tmp/ao-covenant-structured-contract.pretty.json
python3 -m json.tool /tmp/ao-covenant-authoring-contract.json >/tmp/ao-covenant-authoring-contract.pretty.json
python3 -m json.tool /tmp/ao-covenant-authoring-summary.json >/tmp/ao-covenant-authoring-summary.pretty.json
python3 -m json.tool /tmp/ao-covenant-runs/demo/evidence-pack.json >/tmp/ao-covenant-evidence.pretty.json
python3 -m json.tool /tmp/ao-covenant-verify.json >/tmp/ao-covenant-verify.pretty.json
python3 -m json.tool /tmp/ao-covenant-bundle-verify.json >/tmp/ao-covenant-bundle-verify.pretty.json
python3 -m json.tool /tmp/ao-covenant-bundle-inspect.json >/tmp/ao-covenant-bundle-inspect.pretty.json
python3 -m json.tool /tmp/ao-covenant-bundle-report.json >/tmp/ao-covenant-bundle-report.pretty.json
python3 -m json.tool /tmp/ao-covenant-self-run.json >/tmp/ao-covenant-self-run.pretty.json
python3 -m json.tool /tmp/ao-covenant-self-run/contract.json >/tmp/ao-covenant-self-run-contract.pretty.json
python3 -m json.tool /tmp/ao-covenant-self-run/runs/self-run-demo/evidence-pack.json >/tmp/ao-covenant-self-run-evidence.pretty.json
python3 -m json.tool /tmp/ao-covenant-release-package.json >/tmp/ao-covenant-release-package.pretty.json
python3 -m json.tool /tmp/ao-covenant-dist/manifest.json >/tmp/ao-covenant-release-manifest.pretty.json
python3 -m zipfile -l /tmp/ao-covenant-demo-bundle.zip
test -s /tmp/ao-covenant-contract.json.sha256
test -s /tmp/ao-covenant-authoring-contract.json.sha256
test -s /tmp/ao-covenant-self-run/contract.json.sha256
test -s /tmp/ao-covenant-dist/SHA256SUMS
CGO_ENABLED=0 go build -o bin/covenant ./cmd/covenant
```
