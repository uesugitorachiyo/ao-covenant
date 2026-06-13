# CLI Output Writer Contract

This document is the developer-facing contract for CLI commands that write files through `--out`.

## Shared Helpers

- `writeOutputFileBytes` is the lowest-level file writer. It validates the output path, writes one complete file, and returns command-scoped diagnostics.
- `writeNamedOutputFile` wraps `writeOutputFileBytes` for commands that write one primary artifact and then print a marker such as `release_report=<path>` or `schema_validation_report=<path>`.
- `writeOutputPairWithRollback` writes an output pair: one primary artifact plus one companion checksum file. User-facing text calls the companion checksum a digest sidecar.
- `outputPairErrorStage` lets command handlers choose whether an output pair failure should be reported as a primary artifact failure or a digest sidecar failure.

Do not call os.WriteFile directly from command handlers. Command handlers should use the shared writer helpers so path validation, diagnostics, and rollback behavior stay consistent.

## Command Writer Matrix

The source of truth for this table is `internal/cli/testdata/output-command-writer-matrix.json` with schema version `ao-covenant.output-command-writer-matrix.v1`.

<!-- output-command-writer-matrix:start -->
| Command | CLI function | Shared writer | Output contract |
| --- | --- | --- | --- |
| `compile --out` | `runCompile` | `writeOutputPairWithRollback` | output pair with digest sidecar rollback |
| `schema validate --out` | `writeSchemaValidationOutput` | `writeNamedOutputFile` | named output marker schema_validation_report |
| `release report --out` | `writeReleaseReportOutput` | `writeNamedOutputFile` | named output marker release_report |
| `release diff --out` | `writeReleaseDiffOutput` | `writeNamedOutputFile` | named output marker release_diff |
| `approval create --out` | `runApprovalCreate` | `writeOutputFileBytes` | single artifact full-file write |
| `approval attach --out` | `runApprovalAttach` | `writeOutputPairWithRollback` | output pair with digest sidecar rollback |
| `approval revoke --out` | `runApprovalRevoke` | `writeOutputFileBytes` | single artifact full-file write; append mode validates before rewrite |
<!-- output-command-writer-matrix:end -->

## Path Contract

Every file-style `--out` path follows the same path rules:

- The parent directory must already exist.
- The parent path must be a directory, not a file.
- The `--out` target must point to a file path rather than a directory.
- Inspection errors and write errors must include the command name and path.
- Failed path validation must leave stdout empty and must not create output artifacts.

These rules apply to single-artifact writers, named-output writers, and output pairs.

### Error Taxonomy

Output writer diagnostics use these stable categories and wording stems:

- `missing-parent`: `<command> --out parent directory does not exist: <parent>`
- `parent-inspect`: `<command> --out parent path cannot be inspected: <parent>: <error>`
- `parent-not-directory`: `<command> --out parent path is not a directory: <parent>`
- `target-directory`: `<command> --out points to a directory: <path>`
- `target-inspect`: `<command> --out path cannot be inspected: <path>: <error>`
- `write-failed`: `<command> --out write failed: <path>: <error>`

## Output Pairs

`compile --out` and `approval attach --out` write an output pair. The primary artifact and digest sidecar should behave as one logical result.

If primary output validation or writing fails, the digest sidecar must not be created. If the primary artifact is written but the digest sidecar write fails, the writer must rollback the primary artifact:

- New primary artifacts are removed.
- Existing primary artifacts are restored with previous contents.
- Existing digest sidecar artifacts are left in their previous state when a write fails.
- On POSIX filesystems, rollback also restores previous permission bits.
- On Windows, rollback preserves contents and leaves access-control semantics to the platform.
- If rollback fails, diagnostics must include both the digest sidecar failure and the rollback failure.

### Output Pair Failure Fixture Index

The source of truth for this table is `internal/cli/testdata/output-pair-failure-fixture-index.json` with schema version `ao-covenant.output-pair-failure-fixture-index.v1`.

<!-- output-pair-failure-fixture-index:start -->
| Guarantee | Helper fixture | Compile fixture | Approval attach fixture |
| --- | --- | --- | --- |
| primary failure does not create sidecar | `TestWriteOutputPairWithRollbackDoesNotWriteSidecarWhenOutputWriteFails` | `TestCompileCommandRejectsOutputFileWithParentFile` | `TestApprovalAttachRejectsOutputPathWithParentFile` |
| sidecar failure removes new primary | `TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure` | `TestCompileCommandRemovesNewContractWhenDigestSidecarFails` | `TestApprovalAttachRemovesNewContractWhenDigestSidecarFails` |
| sidecar failure restores existing primary | `TestWriteOutputPairWithRollbackRestoresExistingOutputContentOnSidecarFailure` | `TestCompileCommandPreservesExistingContractWhenDigestSidecarFails` | `TestApprovalAttachPreservesExistingContractWhenDigestSidecarFails` |
| rollback failure reports both failures | `TestWriteOutputPairWithRollbackReportsRollbackFailure` | `TestCompileCommandReportsRollbackFailureWhenDigestSidecarFails` | `TestApprovalAttachReportsRollbackFailureWhenDigestSidecarFails` |
<!-- output-pair-failure-fixture-index:end -->

## Named Outputs

Named output commands write the artifact first and print the marker only after the file write succeeds. If writing fails, stdout must remain empty.

Current named-output commands include:

- `schema validate --out`, marker `schema_validation_report`
- `release report --out`, marker `release_report`
- `release diff --out`, marker `release_diff`

## Append And Merge Modes

append or merge modes must validate existing input before writing. They are still full-file writes: the command computes the complete next artifact, validates it, and then writes it through the shared output writer.

If existing input cannot be read, decoded, or validated, the command must fail before writing and leave the existing output bytes unchanged. `approval revoke --append` follows this rule for revocation lists.

## Test Expectations

Every file-style CLI `--out` command should have fixtures for:

- missing parent directory
- parent path is a file
- target path is a directory

Every output format that supports `--out` should have at least one output-file fixture. Output pair commands must also cover digest sidecar failure and rollback behavior.

### Failure Fixture Index

The source of truth for this table is `internal/cli/testdata/output-failure-fixture-index.json` with schema version `ao-covenant.output-failure-fixture-index.v1`.

<!-- output-failure-fixture-index:start -->
| Command | Missing parent fixture | Parent file fixture | Directory target fixture |
| --- | --- | --- | --- |
| `compile --out` | `TestCompileCommandRejectsOutputFileWithMissingParent` | `TestCompileCommandRejectsOutputFileWithParentFile` | `TestCompileCommandRejectsOutputFileDirectoryTarget` |
| `schema validate --out` | `TestSchemaValidateCommandJSONRejectsOutputFileWithMissingParent` | `TestSchemaValidateCommandJSONRejectsOutputFileWithParentFile` | `TestSchemaValidateCommandJSONRejectsOutputFileDirectoryTarget` |
| `release report --out` | `TestReleaseReportCommandRejectsOutputFileWithMissingParent` | `TestReleaseReportCommandRejectsOutputFileWithParentFile` | `TestReleaseReportCommandRejectsOutputFileDirectoryTarget` |
| `release diff --out` | `TestReleaseDiffCommandRejectsOutputFileWithMissingParent` | `TestReleaseDiffCommandRejectsOutputFileWithParentFile` | `TestReleaseDiffCommandRejectsOutputFileDirectoryTarget` |
| `approval create --out` | `TestApprovalCreateRejectsOutputPathWithMissingParent` | `TestApprovalCreateRejectsOutputPathWithParentFile` | `TestApprovalCreateRejectsOutputPathDirectoryTarget` |
| `approval attach --out` | `TestApprovalAttachRejectsOutputPathWithMissingParent` | `TestApprovalAttachRejectsOutputPathWithParentFile` | `TestApprovalAttachRejectsOutputPathDirectoryTarget` |
| `approval revoke --out` | `TestApprovalRevokeRejectsOutputPathWithMissingParent` | `TestApprovalRevokeRejectsOutputPathWithParentFile` | `TestApprovalRevokeRejectsOutputPathDirectoryTarget` |
<!-- output-failure-fixture-index:end -->

Source-level guard tests in `internal/cli/cli_test.go` keep this contract aligned with the helper names, command matrix, and documentation phrases.
