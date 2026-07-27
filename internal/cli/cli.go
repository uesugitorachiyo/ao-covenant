package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	runner "github.com/uesugitorachiyo/ao-covenant/internal/run"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
	"github.com/uesugitorachiyo/ao-covenant/internal/selfrun"
	"github.com/uesugitorachiyo/ao-covenant/internal/verify"
)

func runVersion(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	info := buildinfo.Current()
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.VersionResultSchemaID, info); err != nil {
			fmt.Fprintf(stderr, "write version: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "version=%s\n", info.Version)
	fmt.Fprintf(stdout, "commit=%s\n", info.Commit)
	fmt.Fprintf(stdout, "date=%s\n", info.Date)
	fmt.Fprintf(stdout, "go_version=%s\n", info.GoVersion)
	fmt.Fprintf(stdout, "os=%s\n", info.OS)
	fmt.Fprintf(stdout, "arch=%s\n", info.Arch)
	return 0
}

func runCompile(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("compile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	briefPath := flags.String("brief", "", "path to brief markdown")
	outPath := flags.String("out", "", "path to write contract JSON")
	summary := flags.Bool("summary", false, "print contract authoring summary")
	summaryJSON := flags.Bool("summary-json", false, "emit contract authoring summary as JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var workspaceWrites repeatedStringFlag
	flags.Var(&workspaceWrites, "write", "workspace path the contract may write")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *jsonOutput && *summaryJSON {
		fmt.Fprintln(stderr, "--json cannot be combined with --summary-json")
		return 2
	}
	if *briefPath == "" {
		fmt.Fprintln(stderr, "--brief is required")
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "--out is required")
		return 2
	}

	brief, err := os.ReadFile(*briefPath)
	if err != nil {
		fmt.Fprintf(stderr, "read brief: %v\n", err)
		return 1
	}
	sourcePath, err := workspaceRelativePath(*briefPath)
	if err != nil {
		fmt.Fprintf(stderr, "brief path: %v\n", err)
		return 1
	}
	c, err := contract.CompileBriefWithOptions(string(brief), contract.CompileOptions{
		SourcePath:      sourcePath,
		WorkspaceWrites: workspaceWrites.Values(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "compile brief: %v\n", err)
		return 1
	}
	if err := schema.ValidateValue(schema.ContractSchemaID, c); err != nil {
		fmt.Fprintf(stderr, "validate contract schema: %v\n", err)
		return 1
	}
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode contract: %v\n", err)
		return 1
	}
	digest, err := contract.Digest(c)
	if err != nil {
		fmt.Fprintf(stderr, "digest contract: %v\n", err)
		return 1
	}
	bytes = append(bytes, '\n')
	if err := writeOutputPairWithRollback("compile", *outPath, bytes, *outPath+".sha256", []byte(digest+"\n")); err != nil {
		if outputPairErrorStage(err) == outputPairStageSidecar {
			fmt.Fprintf(stderr, "write digest: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "write contract: %v\n", err)
		return 1
	}
	compileSummary := contract.NewSummary(c, *outPath, digest)
	if *jsonOutput {
		jsonResult := compileResult{
			SchemaVersion:      schema.CompileResultSchemaID,
			ContractPath:       *outPath,
			ContractDigest:     digest,
			ContractDigestFile: *outPath + ".sha256",
		}
		if err := writeSchemaJSON(stdout, schema.CompileResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write compile result: %v\n", err)
			return 1
		}
		return 0
	}
	if *summaryJSON {
		if err := writeSchemaJSON(stdout, schema.CompileSummarySchemaID, compileSummary); err != nil {
			fmt.Fprintf(stderr, "write summary: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "contract=%s\n", *outPath)
	fmt.Fprintf(stdout, "contract_digest=%s\n", digest)
	if *summary {
		printCompileSummary(stdout, compileSummary)
	}
	return 0
}

func runLint(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("lint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	briefPath := flags.String("brief", "", "path to brief markdown")
	contractPath := flags.String("contract", "", "path to contract JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	sarifOutput := flags.Bool("sarif", false, "emit SARIF")
	sarifBaselinePath := flags.String("sarif-baseline", "", "path to lint SARIF baseline JSON")
	var workspaceWrites repeatedStringFlag
	flags.Var(&workspaceWrites, "write", "workspace path the brief contract may write")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if (*briefPath == "" && *contractPath == "") || (*briefPath != "" && *contractPath != "") {
		fmt.Fprintln(stderr, "provide exactly one of --brief or --contract")
		return 2
	}
	if *jsonOutput && *sarifOutput {
		fmt.Fprintln(stderr, "--json cannot be combined with --sarif")
		return 2
	}
	if strings.TrimSpace(*sarifBaselinePath) != "" && !*sarifOutput {
		fmt.Fprintln(stderr, "--sarif-baseline requires --sarif")
		return 2
	}
	var result contract.LintResult
	sourceURI := ""
	if *briefPath != "" {
		brief, err := os.ReadFile(*briefPath)
		if err != nil {
			fmt.Fprintf(stderr, "read brief: %v\n", err)
			return 1
		}
		sourcePath, err := workspaceRelativePath(*briefPath)
		if err != nil {
			fmt.Fprintf(stderr, "brief path: %v\n", err)
			return 1
		}
		sourceURI = sourcePath
		result = contract.LintBrief(string(brief), contract.CompileOptions{
			SourcePath:      sourcePath,
			WorkspaceWrites: workspaceWrites.Values(),
		})
	} else {
		sourceURI = *contractPath
		c, err := readContractForLint(*contractPath)
		if err != nil {
			result = contract.LintResult{
				Valid: false,
				Diagnostics: []contract.LintDiagnostic{
					{
						Code:     "CONTRACT_SCHEMA_INVALID",
						Severity: "error",
						Field:    "contract",
						Message:  err.Error(),
					},
				},
			}
		} else {
			result = contract.LintContract(c)
		}
	}
	if *sarifOutput {
		baseline, err := readLintSARIFBaseline(*sarifBaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
			return 1
		}
		sarifOptions := contract.LintSARIFOptions{SourceURI: sourceURI, Baseline: baseline}
		bytes, err := json.MarshalIndent(contract.LintSARIF(result, sarifOptions), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode lint sarif: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(append(bytes, '\n')); err != nil {
			fmt.Fprintf(stderr, "write lint sarif: %v\n", err)
			return 1
		}
		if !result.Valid && contract.LintDiagnosticsAllSuppressed(result, sarifOptions) {
			return 0
		}
	} else if *jsonOutput {
		result.SchemaVersion = schema.LintResultSchemaID
		if err := writeSchemaJSON(stdout, schema.LintResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write lint result: %v\n", err)
			return 1
		}
	} else {
		printLintResult(stdout, result)
	}
	if !result.Valid {
		return 1
	}
	return 0
}

func readLintSARIFBaseline(path string) (contract.LintSARIFBaseline, error) {
	if strings.TrimSpace(path) == "" {
		return contract.LintSARIFBaseline{}, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return contract.LintSARIFBaseline{}, err
	}
	if err := schema.ValidateBytes(schema.LintSARIFBaselineSchemaID, bytes); err != nil {
		return contract.LintSARIFBaseline{}, err
	}
	var baseline contract.LintSARIFBaseline
	if err := json.Unmarshal(bytes, &baseline); err != nil {
		return contract.LintSARIFBaseline{}, err
	}
	if baseline.SchemaVersion != contract.LintSARIFBaselineSchemaVersion {
		return contract.LintSARIFBaseline{}, fmt.Errorf("schema_version must be %q", contract.LintSARIFBaselineSchemaVersion)
	}
	return baseline, nil
}

func readSchemaValidationSARIFBaseline(path string) (schema.SARIFBaseline, error) {
	if strings.TrimSpace(path) == "" {
		return schema.SARIFBaseline{}, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return schema.SARIFBaseline{}, err
	}
	if err := schema.ValidateBytes(schema.LintSARIFBaselineSchemaID, bytes); err != nil {
		return schema.SARIFBaseline{}, err
	}
	var baseline contract.LintSARIFBaseline
	if err := json.Unmarshal(bytes, &baseline); err != nil {
		return schema.SARIFBaseline{}, err
	}
	if baseline.SchemaVersion != contract.LintSARIFBaselineSchemaVersion {
		return schema.SARIFBaseline{}, fmt.Errorf("schema_version must be %q", contract.LintSARIFBaselineSchemaVersion)
	}
	accepted := make([]schema.SARIFBaselineEntry, 0, len(baseline.Accepted))
	for _, entry := range baseline.Accepted {
		accepted = append(accepted, schema.SARIFBaselineEntry{
			RuleID:        entry.RuleID,
			SourceURI:     entry.SourceURI,
			Field:         entry.Field,
			Justification: entry.Justification,
		})
	}
	return schema.SARIFBaseline{Accepted: accepted}, nil
}

func releaseSARIFBaselineTemplate(sarif schema.SARIFLog) contract.LintSARIFBaseline {
	baseline := contract.LintSARIFBaseline{
		SchemaVersion: contract.LintSARIFBaselineSchemaVersion,
		Accepted:      []contract.LintSARIFBaselineEntry{},
	}
	seen := map[string]bool{}
	for _, run := range sarif.Runs {
		for _, result := range run.Results {
			sourceURI := releaseSARIFResultSourceURI(result)
			field := result.Properties.Location
			key := result.RuleID + "\x00" + sourceURI + "\x00" + field
			if seen[key] {
				continue
			}
			seen[key] = true
			baseline.Accepted = append(baseline.Accepted, contract.LintSARIFBaselineEntry{
				RuleID:        result.RuleID,
				SourceURI:     sourceURI,
				Field:         field,
				Justification: "REVIEW: explain why this release finding is accepted",
			})
		}
	}
	return baseline
}

func releaseSARIFResultSourceURI(result schema.SARIFResult) string {
	if len(result.Locations) == 0 {
		return ""
	}
	return result.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

func runContract(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to contract JSON")
	workspaceDir := flags.String("workspace", ".", "workspace root for contract execution")
	outDir := flags.String("out", ".covenant/runs", "directory to write run evidence")
	runID := flags.String("run-id", "", "stable run id")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var processAllowlist repeatedStringFlag
	var revocationPaths repeatedStringFlag
	flags.Var(&processAllowlist, "allow-process", "exact process.spawn resource to allow")
	flags.Var(&revocationPaths, "revocations", "path to approval revocation list JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *contractPath == "" {
		fmt.Fprintln(stderr, "--contract is required")
		return 2
	}
	revokedIDs, err := readRevokedApprovalIDs(revocationPaths.Values())
	if err != nil {
		fmt.Fprintf(stderr, "read revocations: %v\n", err)
		return 1
	}

	bytes, err := os.ReadFile(*contractPath)
	if err != nil {
		fmt.Fprintf(stderr, "read contract: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.ContractSchemaID, bytes); err != nil {
		fmt.Fprintf(stderr, "validate contract schema: %v\n", err)
		return 1
	}
	var c contract.Contract
	if err := json.Unmarshal(bytes, &c); err != nil {
		fmt.Fprintf(stderr, "decode contract: %v\n", err)
		return 1
	}
	result, err := runner.Execute(context.Background(), c, runner.Options{
		WorkspaceDir:             *workspaceDir,
		OutDir:                   *outDir,
		RunID:                    *runID,
		ProcessAllowlist:         processAllowlist.Values(),
		RevokedApprovalTicketIDs: revokedIDs,
	})
	if err != nil {
		fmt.Fprintf(stderr, "run contract: %v\n", err)
		return 1
	}
	if *jsonOutput {
		jsonResult := runCommandResult{
			SchemaVersion:    schema.RunResultSchemaID,
			RunID:            result.EvidencePack.RunID,
			RunDir:           displayPath(result.RunDir),
			LedgerPath:       displayPath(result.LedgerPath),
			EvidencePackPath: displayPath(result.EvidencePackPath),
		}
		if err := writeSchemaJSON(stdout, schema.RunResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write run result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "run_dir=%s\n", displayPath(result.RunDir))
	fmt.Fprintf(stdout, "ledger=%s\n", displayPath(result.LedgerPath))
	fmt.Fprintf(stdout, "evidence_pack=%s\n", displayPath(result.EvidencePackPath))
	return 0
}

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ledgerPath := flags.String("ledger", "", "path to events.ndjson")
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	bundlePath := flags.String("bundle", "", "path to evidence bundle zip")
	publicKeyPath := flags.String("public-key", "", "path to bundle public key JSON")
	workspaceDir := flags.String("workspace", ".", "workspace root for artifact verification")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var revocationPaths repeatedStringFlag
	flags.Var(&revocationPaths, "revocations", "path to approval revocation list JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *bundlePath != "" && (*ledgerPath != "" || *evidencePath != "") {
		fmt.Fprintln(stderr, "provide either --bundle or --ledger/--evidence")
		return 2
	}
	if *bundlePath == "" && *ledgerPath == "" {
		fmt.Fprintln(stderr, "--ledger is required")
		return 2
	}
	if *bundlePath == "" && *evidencePath == "" {
		fmt.Fprintln(stderr, "--evidence is required")
		return 2
	}
	revokedIDs, err := readRevokedApprovalIDs(revocationPaths.Values())
	if err != nil {
		fmt.Fprintf(stderr, "read revocations: %v\n", err)
		return 1
	}
	var result verify.Result
	if *bundlePath != "" {
		result, err = bundlepkg.Verify(bundlepkg.VerifyOptions{
			BundlePath:               *bundlePath,
			PublicKeyPath:            *publicKeyPath,
			RevokedApprovalTicketIDs: revokedIDs,
		})
	} else {
		result, err = verify.Verify(verify.Options{
			LedgerPath:               *ledgerPath,
			EvidencePath:             *evidencePath,
			WorkspaceDir:             *workspaceDir,
			RevokedApprovalTicketIDs: revokedIDs,
		})
	}
	if err != nil {
		fmt.Fprintf(stderr, "verify run: %v\n", err)
		return 1
	}
	return printVerifyResult(stdout, stderr, result, *jsonOutput)
}

func printVerifyResult(stdout io.Writer, stderr io.Writer, result verify.Result, jsonOutput bool) int {
	if jsonOutput {
		if err := writeSchemaJSON(stdout, schema.VerifyResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write verify result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "verified=%t\n", result.Verified)
	fmt.Fprintf(stdout, "run_id=%s\n", result.RunID)
	fmt.Fprintf(stdout, "event_count=%d\n", result.EventCount)
	fmt.Fprintf(stdout, "artifact_count=%d\n", result.ArtifactCount)
	fmt.Fprintf(stdout, "input_snapshot_count=%d\n", result.InputSnapshotCount)
	fmt.Fprintf(stdout, "failure_count=%d\n", result.FailureCount)
	if result.PublicKeySHA256 != "" {
		fmt.Fprintf(stdout, "public_key_sha256=%s\n", result.PublicKeySHA256)
	}
	fmt.Fprintf(stdout, "ledger_digest=%s\n", result.LedgerDigest)
	fmt.Fprintf(stdout, "last_event_hash=%s\n", result.LastEventHash)
	for _, failure := range result.Failures {
		fmt.Fprintf(stdout, "failure=%s event=%s line=%d", failure.FailureID, failure.EventID, failure.EventLine)
		if failure.TaskID != "" {
			fmt.Fprintf(stdout, " task=%s", failure.TaskID)
		}
		fmt.Fprintf(stdout, " phase=%s reason=%s\n", failure.Phase, failure.Reason)
	}
	printPolicyExplanations(stdout, result.PolicyExplanations)
	return 0
}

func runSelfRun(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("self-run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	workspaceDir := flags.String("workspace", ".", "workspace root for self-run execution")
	outDir := flags.String("out", filepath.Join(".covenant", "self-run"), "directory to write self-run artifacts")
	runID := flags.String("run-id", "self-run", "stable run id")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	result, err := selfrun.Execute(context.Background(), selfrun.Options{
		WorkspaceDir: *workspaceDir,
		OutDir:       *outDir,
		RunID:        *runID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "self-run: %v\n", err)
		return 1
	}
	if *jsonOutput {
		jsonResult := selfRunCommandResult{
			SchemaVersion:      schema.SelfRunResultSchemaID,
			ContractPath:       displayPath(result.ContractPath),
			ContractDigest:     result.ContractDigest,
			ContractDigestFile: displayPath(result.ContractDigestPath),
			RunID:              result.Verification.RunID,
			RunDir:             displayPath(result.RunDir),
			LedgerPath:         displayPath(result.LedgerPath),
			EvidencePackPath:   displayPath(result.EvidencePackPath),
			Verified:           result.Verification.Verified,
			FailureCount:       result.Verification.FailureCount,
		}
		if err := writeSchemaJSON(stdout, schema.SelfRunResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write self-run result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "contract=%s\n", displayPath(result.ContractPath))
	fmt.Fprintf(stdout, "contract_digest=%s\n", result.ContractDigest)
	fmt.Fprintf(stdout, "contract_digest_file=%s\n", displayPath(result.ContractDigestPath))
	fmt.Fprintf(stdout, "run_dir=%s\n", displayPath(result.RunDir))
	fmt.Fprintf(stdout, "ledger=%s\n", displayPath(result.LedgerPath))
	fmt.Fprintf(stdout, "evidence_pack=%s\n", displayPath(result.EvidencePackPath))
	fmt.Fprintf(stdout, "verified=%t\n", result.Verification.Verified)
	fmt.Fprintf(stdout, "failure_count=%d\n", result.Verification.FailureCount)
	return 0
}

func runBundle(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printBundleUsage(stderr)
		return 2
	}
	switch args[0] {
	case "export":
		return runBundleExport(args[1:], stdout, stderr)
	case "inspect":
		return runBundleInspect(args[1:], stdout, stderr)
	case "report":
		return runBundleReport(args[1:], stdout, stderr)
	case "keygen":
		return runBundleKeygen(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown bundle command %q\n", args[0])
		printBundleUsage(stderr)
		return 2
	}
}

func runBundleExport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("bundle export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to contract JSON")
	ledgerPath := flags.String("ledger", "", "path to events.ndjson")
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	workspaceDir := flags.String("workspace", ".", "workspace root for artifact verification")
	outPath := flags.String("out", "", "path to write bundle zip")
	signKeyPath := flags.String("sign-key", "", "path to bundle private key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	var revocationPaths repeatedStringFlag
	flags.Var(&revocationPaths, "revocations", "path to approval revocation list JSON to attach and enforce")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *contractPath == "" {
		fmt.Fprintln(stderr, "--contract is required")
		return 2
	}
	if *ledgerPath == "" {
		fmt.Fprintln(stderr, "--ledger is required")
		return 2
	}
	if *evidencePath == "" {
		fmt.Fprintln(stderr, "--evidence is required")
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "--out is required")
		return 2
	}
	result, err := bundlepkg.Export(bundlepkg.Options{
		ContractPath:    *contractPath,
		LedgerPath:      *ledgerPath,
		EvidencePath:    *evidencePath,
		WorkspaceDir:    *workspaceDir,
		OutPath:         *outPath,
		SignKeyPath:     *signKeyPath,
		RevocationPaths: revocationPaths.Values(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "bundle export: %v\n", err)
		return 1
	}
	if *jsonOutput {
		jsonResult := bundleExportResult{
			SchemaVersion:   schema.BundleExportResultSchemaID,
			BundlePath:      result.BundlePath,
			EntryCount:      len(result.Manifest.Entries),
			PublicKeySHA256: result.PublicKeySHA256,
			Manifest:        result.Manifest,
		}
		if err := writeSchemaJSON(stdout, schema.BundleExportResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write bundle export result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "bundle=%s\n", result.BundlePath)
	fmt.Fprintf(stdout, "entry_count=%d\n", len(result.Manifest.Entries))
	if result.PublicKeySHA256 != "" {
		fmt.Fprintf(stdout, "public_key_sha256=%s\n", result.PublicKeySHA256)
	}
	return 0
}

func runBundleInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("bundle inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundlePath := flags.String("bundle", "", "path to evidence bundle zip")
	publicKeyPath := flags.String("public-key", "", "path to bundle public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	redact := flags.String("redact", "", "comma-separated redactions: paths,digests")
	audience := flags.String("audience", "internal", "inspection audience: internal or external")
	redactionPolicyPath := flags.String("redaction-policy", "", "path to bundle inspect redaction policy JSON")
	redactionProfile := flags.String("redaction-profile", "", "redaction policy profile name")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "--bundle is required")
		return 2
	}
	redaction, err := bundleReportRedactionOptions(*audience, *redact, *redactionPolicyPath, *redactionProfile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	result, err := bundlepkg.Inspect(bundlepkg.InspectOptions{
		BundlePath:    *bundlePath,
		PublicKeyPath: *publicKeyPath,
	})
	if err != nil {
		fmt.Fprintf(stderr, "bundle inspect: %v\n", err)
		return 1
	}
	result = bundlepkg.RedactInspect(result, redaction)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.BundleInspectResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write bundle inspection: %v\n", err)
			return 1
		}
		return 0
	}
	printBundleInspection(stdout, result)
	return 0
}

func runBundleReport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("bundle report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundlePath := flags.String("bundle", "", "path to evidence bundle zip")
	publicKeyPath := flags.String("public-key", "", "path to bundle public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	markdownOutput := flags.Bool("markdown", false, "emit Markdown")
	redact := flags.String("redact", "", "comma-separated redactions: paths,digests")
	audience := flags.String("audience", "internal", "report audience: internal or external")
	redactionPolicyPath := flags.String("redaction-policy", "", "path to bundle report redaction policy JSON")
	redactionProfile := flags.String("redaction-profile", "", "redaction policy profile name")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" {
		fmt.Fprintln(stderr, "--bundle is required")
		return 2
	}
	if *jsonOutput && *markdownOutput {
		fmt.Fprintln(stderr, "--json cannot be combined with --markdown")
		return 2
	}
	redaction, err := bundleReportRedactionOptions(*audience, *redact, *redactionPolicyPath, *redactionProfile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	result, err := bundlepkg.Report(bundlepkg.ReportOptions{
		BundlePath:    *bundlePath,
		PublicKeyPath: *publicKeyPath,
	})
	if err != nil {
		fmt.Fprintf(stderr, "bundle report: %v\n", err)
		return 1
	}
	result = bundlepkg.RedactReport(result, redaction)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.BundleReportResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write bundle report: %v\n", err)
			return 1
		}
		return 0
	}
	if *markdownOutput {
		if _, err := stdout.Write([]byte(bundlepkg.MarkdownReport(result))); err != nil {
			fmt.Fprintf(stderr, "write bundle markdown report: %v\n", err)
			return 1
		}
		return 0
	}
	printBundleReport(stdout, result)
	return 0
}

func bundleReportRedactionOptions(audience string, rawRedactions string, policyPath string, profile string) (bundlepkg.RedactionOptions, error) {
	var opts bundlepkg.RedactionOptions
	switch audience {
	case "", "internal":
	case "external":
		opts.Paths = true
		opts.Digests = true
	default:
		return bundlepkg.RedactionOptions{}, fmt.Errorf("--audience must be %q or %q", "internal", "external")
	}
	if strings.TrimSpace(policyPath) != "" || strings.TrimSpace(profile) != "" {
		releaseOpts, err := releaseRedactionOptions(audience, rawRedactions, policyPath, profile)
		if err != nil {
			return bundlepkg.RedactionOptions{}, err
		}
		return bundlepkg.RedactionOptions{Paths: releaseOpts.Paths, Digests: releaseOpts.Digests}, nil
	}
	if strings.TrimSpace(rawRedactions) == "" {
		return opts, nil
	}
	for _, raw := range strings.Split(rawRedactions, ",") {
		value := strings.TrimSpace(raw)
		switch value {
		case "":
			continue
		case "paths":
			opts.Paths = true
		case "digests":
			opts.Digests = true
		default:
			return bundlepkg.RedactionOptions{}, fmt.Errorf("--redact values must be %q or %q", "paths", "digests")
		}
	}
	return opts, nil
}

const reportRedactionPolicySchemaVersion = schema.ReportRedactionPolicySchemaID

type reportRedactionPolicyFile struct {
	SchemaVersion string                            `json:"schema_version"`
	Profiles      map[string]reportRedactionProfile `json:"profiles"`
}

type reportRedactionProfile struct {
	Redact []string `json:"redact"`
}

func runBundleKeygen(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("bundle keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private", "", "path to write private key JSON")
	publicPath := flags.String("public", "", "path to write public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *privatePath == "" {
		fmt.Fprintln(stderr, "--private is required")
		return 2
	}
	if *publicPath == "" {
		fmt.Fprintln(stderr, "--public is required")
		return 2
	}
	result, err := bundlepkg.GenerateKeyPairWithResult(*privatePath, *publicPath)
	if err != nil {
		fmt.Fprintf(stderr, "bundle keygen: %v\n", err)
		return 1
	}
	if *jsonOutput {
		jsonResult := bundleKeygenResult{
			SchemaVersion:   schema.BundleKeygenResultSchemaID,
			PrivateKeyPath:  result.PrivateKeyPath,
			PublicKeyPath:   result.PublicKeyPath,
			PublicKeySHA256: result.PublicKeySHA256,
		}
		if err := writeSchemaJSON(stdout, schema.BundleKeygenResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write bundle keygen result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "private_key=%s\n", result.PrivateKeyPath)
	fmt.Fprintf(stdout, "public_key=%s\n", result.PublicKeyPath)
	fmt.Fprintf(stdout, "public_key_sha256=%s\n", result.PublicKeySHA256)
	return 0
}

type policyExplainReport struct {
	SchemaVersion      string               `json:"schema_version"`
	PolicyExplanations []policy.Explanation `json:"policy_explanations"`
}

type policyIndexReport struct {
	SchemaVersion      string               `json:"schema_version"`
	PolicyCount        int                  `json:"policy_count"`
	PolicyDecisions    []policy.Decision    `json:"policy_decisions"`
	PolicyExplanations []policy.Explanation `json:"policy_explanations"`
}

type approvalCreateResult struct {
	SchemaVersion string                `json:"schema_version"`
	TicketPath    string                `json:"ticket_path"`
	Ticket        policy.ApprovalTicket `json:"ticket"`
}

type approvalValidateResult struct {
	SchemaVersion string `json:"schema_version"`
	Valid         bool   `json:"valid"`
	TicketID      string `json:"ticket_id"`
	ContractPath  string `json:"contract_path,omitempty"`
}

type liveDocsApprovalValidateResult struct {
	SchemaVersion string `json:"schema_version"`
	Valid         bool   `json:"valid"`
	TicketID      string `json:"ticket_id"`
	RequestID     string `json:"request_id"`
	ApprovalState string `json:"approval_state"`
	SafeToExecute bool   `json:"safe_to_execute"`
}

type mutationClassAuthorityValidateResult struct {
	SchemaVersion string `json:"schema_version"`
	Valid         bool   `json:"valid"`
	TicketID      string `json:"ticket_id"`
	RequestID     string `json:"request_id"`
	MutationClass string `json:"mutation_class"`
	SafeToRequest bool   `json:"safe_to_request"`
	SafeToExecute bool   `json:"safe_to_execute"`
}

type lowRiskCodeLivePolicyValidateResult struct {
	SchemaVersion     string   `json:"schema_version"`
	Valid             bool     `json:"valid"`
	PolicyID          string   `json:"policy_id"`
	MutationClass     string   `json:"mutation_class"`
	CandidateRepo     string   `json:"candidate_repo"`
	BaseBranch        string   `json:"base_branch"`
	ProposedBranch    string   `json:"proposed_branch"`
	FileAllowlist     []string `json:"file_allowlist"`
	CommandAllowlist  []string `json:"command_allowlist"`
	SafeToRequest     bool     `json:"safe_to_request"`
	SafeToExecute     bool     `json:"safe_to_execute"`
	LiveMutationGrant bool     `json:"live_mutation_grant"`
}

type approvalAttachResult struct {
	SchemaVersion  string `json:"schema_version"`
	ContractPath   string `json:"contract_path"`
	ContractDigest string `json:"contract_digest"`
	ApprovalCount  int    `json:"approval_count"`
	TicketID       string `json:"ticket_id"`
}

type approvalRevokeResult struct {
	SchemaVersion      string                  `json:"schema_version"`
	RevocationsPath    string                  `json:"revocations_path"`
	RevokedTicketCount int                     `json:"revoked_ticket_count"`
	TicketID           string                  `json:"ticket_id"`
	Revocations        approval.RevocationList `json:"revocations"`
}

type approvalRevocationsInspectResult struct {
	SchemaVersion      string                  `json:"schema_version"`
	RevocationsPath    string                  `json:"revocations_path"`
	RevokedTicketCount int                     `json:"revoked_ticket_count"`
	Revocations        approval.RevocationList `json:"revocations"`
}

type schemaCatalogReport struct {
	SchemaVersion string                `json:"schema_version"`
	Schemas       []schema.CatalogEntry `json:"schemas"`
}

type schemaExportReport struct {
	SchemaVersion string                  `json:"schema_version"`
	Schemas       []schema.ExportedSchema `json:"schemas"`
}

type compileResult struct {
	SchemaVersion      string `json:"schema_version"`
	ContractPath       string `json:"contract_path"`
	ContractDigest     string `json:"contract_digest"`
	ContractDigestFile string `json:"contract_digest_file"`
}

type runResult struct {
	SchemaVersion    string `json:"schema_version"`
	RunID            string `json:"run_id"`
	RunDir           string `json:"run_dir"`
	LedgerPath       string `json:"ledger_path"`
	EvidencePackPath string `json:"evidence_pack_path"`
}

type bundleExportResult struct {
	SchemaVersion   string             `json:"schema_version"`
	BundlePath      string             `json:"bundle_path"`
	EntryCount      int                `json:"entry_count"`
	PublicKeySHA256 string             `json:"public_key_sha256,omitempty"`
	Manifest        bundlepkg.Manifest `json:"manifest"`
}

type bundleKeygenResult struct {
	SchemaVersion   string `json:"schema_version"`
	PrivateKeyPath  string `json:"private_key_path"`
	PublicKeyPath   string `json:"public_key_path"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type schemaValidationReportMetadata struct {
	Command          string   `json:"command"`
	InputMode        string   `json:"input_mode"`
	Source           string   `json:"source"`
	ExplicitSchemaID string   `json:"explicit_schema_id,omitempty"`
	SchemaFilters    []string `json:"schema_filters,omitempty"`
	IgnorePatterns   []string `json:"ignore_patterns,omitempty"`
	FailFast         bool     `json:"fail_fast,omitempty"`
}

type schemaValidationReport struct {
	SchemaVersion string                          `json:"schema_version,omitempty"`
	Metadata      *schemaValidationReportMetadata `json:"metadata,omitempty"`
	SchemaID      string                          `json:"schema_id"`
	File          string                          `json:"file"`
	Valid         bool                            `json:"valid"`
	Error         string                          `json:"error,omitempty"`
	Location      string                          `json:"location,omitempty"`
}

type schemaValidationSetReport struct {
	SchemaVersion string                            `json:"schema_version"`
	Metadata      *schemaValidationReportMetadata   `json:"metadata,omitempty"`
	Valid         bool                              `json:"valid"`
	Total         int                               `json:"total"`
	ValidCount    int                               `json:"valid_count"`
	InvalidCount  int                               `json:"invalid_count"`
	SkippedCount  int                               `json:"skipped_count,omitempty"`
	IgnoredCount  int                               `json:"ignored_count,omitempty"`
	Schemas       []schemaValidationSchemaSummary   `json:"schemas,omitempty"`
	Validations   []schemaValidationReport          `json:"validations"`
	Ignored       []schemaValidationIgnoredDocument `json:"ignored,omitempty"`
}

type schemaValidationSchemaSummary struct {
	SchemaID     string `json:"schema_id"`
	Total        int    `json:"total,omitempty"`
	ValidCount   int    `json:"valid_count,omitempty"`
	InvalidCount int    `json:"invalid_count,omitempty"`
	SkippedCount int    `json:"skipped_count,omitempty"`
}

type schemaValidationInputDocument struct {
	Path        string
	DisplayPath string
}

type schemaValidationIgnoredDocument struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
}

type runCommandResult struct {
	SchemaVersion    string `json:"schema_version"`
	RunID            string `json:"run_id"`
	RunDir           string `json:"run_dir"`
	LedgerPath       string `json:"ledger_path"`
	EvidencePackPath string `json:"evidence_pack_path"`
}

type selfRunCommandResult struct {
	SchemaVersion      string `json:"schema_version"`
	ContractPath       string `json:"contract_path"`
	ContractDigest     string `json:"contract_digest"`
	ContractDigestFile string `json:"contract_digest_file"`
	RunID              string `json:"run_id"`
	RunDir             string `json:"run_dir"`
	LedgerPath         string `json:"ledger_path"`
	EvidencePackPath   string `json:"evidence_pack_path"`
	Verified           bool   `json:"verified"`
	FailureCount       int    `json:"failure_count"`
}

type releasePackageResult struct {
	SchemaVersion   string              `json:"schema_version"`
	ManifestPath    string              `json:"manifest_path"`
	ChecksumsPath   string              `json:"checksums_path"`
	SignaturePath   string              `json:"signature_path,omitempty"`
	PublicKeySHA256 string              `json:"public_key_sha256,omitempty"`
	ArtifactPaths   []string            `json:"artifact_paths"`
	Manifest        releasepkg.Manifest `json:"manifest"`
}

type releaseProvenanceSummaryFields = releasepkg.ProvenanceSummary

const (
	maxSchemaValidationDirectoryFiles      = 4096
	maxSchemaValidationDirectoryFileBytes  = 8 * 1024 * 1024
	maxSchemaValidationDirectoryTotalBytes = 64 * 1024 * 1024
)

type schemaValidationDirectoryScanBudget struct {
	files      int
	totalBytes int64
}

func ensureSchemaValidationDirectoryRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("schema validation directory root is a symlink: %s", root)
	}
	if !info.IsDir() {
		return fmt.Errorf("schema validation directory root is not a directory: %s", root)
	}
	return nil
}

func workspaceRelativePath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("path is required")
	}
	candidate := raw
	if filepath.IsAbs(raw) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		relative, err := filepath.Rel(cwd, raw)
		if err != nil {
			return "", err
		}
		candidate = relative
	}
	normalized := filepath.ToSlash(filepath.Clean(candidate))
	if normalized == "." {
		return "", fmt.Errorf("path must name a file")
	}
	if normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("%q is outside workspace", raw)
	}
	return normalized, nil
}

func readContractFile(path string) (contract.Contract, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return contract.Contract{}, err
	}
	if err := schema.ValidateBytes(schema.ContractSchemaID, bytes); err != nil {
		return contract.Contract{}, err
	}
	var c contract.Contract
	if err := json.Unmarshal(bytes, &c); err != nil {
		return contract.Contract{}, err
	}
	if err := contract.Validate(c); err != nil {
		return contract.Contract{}, err
	}
	return c, nil
}

func readContractForLint(path string) (contract.Contract, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return contract.Contract{}, err
	}
	if err := schema.ValidateBytes(schema.ContractSchemaID, bytes); err != nil {
		return contract.Contract{}, err
	}
	var c contract.Contract
	if err := json.Unmarshal(bytes, &c); err != nil {
		return contract.Contract{}, err
	}
	return c, nil
}

func readEvidencePackFile(path string) (runner.EvidencePack, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return runner.EvidencePack{}, err
	}
	if err := schema.ValidateBytes(schema.EvidencePackSchemaID, bytes); err != nil {
		return runner.EvidencePack{}, err
	}
	var evidence runner.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		return runner.EvidencePack{}, err
	}
	return evidence, nil
}

func readRevokedApprovalIDs(paths []string) (map[string]bool, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	lists := make([]approval.RevocationList, 0, len(paths))
	for _, path := range paths {
		list, err := approval.ReadRevocationList(path)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}
	return approval.RevokedTicketIDs(lists), nil
}

func writeSchemaJSON(stdout io.Writer, schemaID string, value any) error {
	if err := schema.WriteJSON(stdout, schemaID, value); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

func displayPath(path string) string {
	return filepath.ToSlash(path)
}

func marshalSchemaJSONBytes(schemaID string, value any) ([]byte, error) {
	if err := schema.ValidateValue(schemaID, value); err != nil {
		return nil, err
	}
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(bytes, '\n'), nil
}

func printTicket(stdout io.Writer, ticket policy.ApprovalTicket) {
	fmt.Fprintf(stdout, "ticket_id=%s\n", ticket.TicketID)
	fmt.Fprintf(stdout, "task_id=%s\n", ticket.TaskID)
	fmt.Fprintf(stdout, "effect_type=%s\n", ticket.EffectType)
	fmt.Fprintf(stdout, "resource=%s\n", ticket.Resource)
	fmt.Fprintf(stdout, "approved=%t\n", ticket.Approved)
	fmt.Fprintf(stdout, "reason=%s\n", ticket.Reason)
	if ticket.OperatorID != "" {
		fmt.Fprintf(stdout, "operator_id=%s\n", ticket.OperatorID)
	}
	if ticket.ExpiresAt != "" {
		fmt.Fprintf(stdout, "expires_at=%s\n", ticket.ExpiresAt)
	}
}

func printCompileSummary(stdout io.Writer, summary contract.Summary) {
	for _, readPath := range summary.Reads {
		fmt.Fprintf(stdout, "read=%s\n", readPath)
	}
	for _, writePath := range summary.Writes {
		fmt.Fprintf(stdout, "write=%s\n", writePath)
	}
	for _, task := range summary.Tasks {
		fmt.Fprintf(stdout, "task=%s kind=%s\n", task.ID, task.Kind)
	}
	for _, obligation := range summary.Obligations {
		fmt.Fprintf(stdout, "obligation=%s required=%t\n", obligation.ID, obligation.Required)
	}
}

func printLintResult(stdout io.Writer, result contract.LintResult) {
	fmt.Fprintf(stdout, "valid=%t\n", result.Valid)
	fmt.Fprintf(stdout, "diagnostic_count=%d\n", len(result.Diagnostics))
	for _, diagnostic := range result.Diagnostics {
		fmt.Fprintf(stdout, "diagnostic=%s severity=%s", diagnostic.Code, diagnostic.Severity)
		if diagnostic.Line > 0 {
			fmt.Fprintf(stdout, " line=%d", diagnostic.Line)
		}
		if diagnostic.Field != "" {
			fmt.Fprintf(stdout, " field=%s", diagnostic.Field)
		}
		fmt.Fprintf(stdout, " message=%s", diagnostic.Message)
		if diagnostic.Hint != "" {
			fmt.Fprintf(stdout, " hint=%s", diagnostic.Hint)
		}
		fmt.Fprintln(stdout)
	}
}

func printBundleInspection(stdout io.Writer, result bundlepkg.InspectResult) {
	fmt.Fprintf(stdout, "bundle=%s\n", result.BundlePath)
	fmt.Fprintf(stdout, "run_id=%s\n", result.RunID)
	fmt.Fprintf(stdout, "schema_version=%s\n", result.SchemaVersion)
	fmt.Fprintf(stdout, "entry_count=%d\n", result.EntryCount)
	fmt.Fprintf(stdout, "checksums=%s\n", result.ChecksumStatus)
	fmt.Fprintf(stdout, "signature=%s\n", result.Signature.Status)
	if result.Signature.SignedEntry != "" {
		fmt.Fprintf(stdout, "signature_entry=%s\n", result.Signature.SignedEntry)
	}
	if result.Signature.PublicKeySHA256 != "" {
		fmt.Fprintf(stdout, "public_key_sha256=%s\n", result.Signature.PublicKeySHA256)
		fmt.Fprintf(stdout, "signature_public_key_sha256=%s\n", result.Signature.PublicKeySHA256)
	}
	fmt.Fprintf(stdout, "event_count=%d\n", result.EventCount)
	fmt.Fprintf(stdout, "artifact_count=%d\n", result.ArtifactCount)
	fmt.Fprintf(stdout, "input_snapshot_count=%d\n", result.InputSnapshotCount)
	fmt.Fprintf(stdout, "policy_decision_count=%d\n", result.PolicyDecisionCount)
	fmt.Fprintf(stdout, "closure_row_count=%d\n", result.ClosureRowCount)
	fmt.Fprintf(stdout, "failure_count=%d\n", result.FailureCount)
	fmt.Fprintf(stdout, "revocation_list_count=%d\n", result.RevocationListCount)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", result.RevokedTicketCount)
	fmt.Fprintf(stdout, "contract_digest=%s\n", result.ContractDigest)
	fmt.Fprintf(stdout, "ledger_digest=%s\n", result.LedgerDigest)
	for _, artifact := range result.Artifacts {
		fmt.Fprintf(stdout, "artifact=%s path=%s digest=%s producer_event=%s", artifact.ArtifactID, artifact.Path, artifact.Digest, artifact.ProducerEventID)
		if artifact.ProducerTaskID != "" {
			fmt.Fprintf(stdout, " producer_task=%s", artifact.ProducerTaskID)
		}
		fmt.Fprintf(stdout, " producer_found=%t\n", artifact.ProducerFound)
	}
	for _, snapshot := range result.InputSnapshots {
		fmt.Fprintf(stdout, "snapshot=%s source=%s path=%s digest=%s\n", snapshot.SnapshotID, snapshot.SourcePath, snapshot.SnapshotPath, snapshot.Digest)
	}
	printPolicyExplanations(stdout, result.PolicyExplanations)
	printRevocations(stdout, result.Revocations)
}

func printBundleReport(stdout io.Writer, result bundlepkg.ReportResult) {
	fmt.Fprintf(stdout, "bundle=%s\n", result.BundlePath)
	fmt.Fprintf(stdout, "run_id=%s\n", result.RunID)
	fmt.Fprintf(stdout, "schema_version=%s\n", result.SchemaVersion)
	fmt.Fprintf(stdout, "entry_count=%d\n", result.EntryCount)
	fmt.Fprintf(stdout, "event_count=%d\n", result.EventCount)
	fmt.Fprintf(stdout, "artifact_count=%d\n", result.ArtifactCount)
	fmt.Fprintf(stdout, "input_snapshot_count=%d\n", result.InputSnapshotCount)
	fmt.Fprintf(stdout, "policy_decision_count=%d\n", result.PolicyDecisionCount)
	fmt.Fprintf(stdout, "closure_row_count=%d\n", result.ClosureRowCount)
	fmt.Fprintf(stdout, "failure_count=%d\n", result.FailureCount)
	fmt.Fprintf(stdout, "revocation_list_count=%d\n", result.RevocationListCount)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", result.RevokedTicketCount)
	fmt.Fprintf(stdout, "checksums=%s\n", result.ChecksumStatus)
	fmt.Fprintf(stdout, "signature=%s\n", result.Signature.Status)
	if result.Signature.SignedEntry != "" {
		fmt.Fprintf(stdout, "signature_entry=%s\n", result.Signature.SignedEntry)
	}
	if result.Signature.PublicKeySHA256 != "" {
		fmt.Fprintf(stdout, "public_key_sha256=%s\n", result.Signature.PublicKeySHA256)
		fmt.Fprintf(stdout, "signature_public_key_sha256=%s\n", result.Signature.PublicKeySHA256)
	}
	fmt.Fprintf(stdout, "contract_digest=%s\n", result.ContractDigest)
	fmt.Fprintf(stdout, "ledger_digest=%s\n", result.LedgerDigest)
	for _, entry := range result.Entries {
		fmt.Fprintf(stdout, "entry=%s source=%s sha256=%s size=%d\n", entry.Path, entry.Source, entry.SHA256, entry.SizeBytes)
	}
	for _, event := range result.Events {
		fmt.Fprintf(stdout, "event=%s line=%d sequence=%d type=%s status=%s", event.EventID, event.Line, event.Sequence, event.Type, event.Status)
		if event.TaskID != "" {
			fmt.Fprintf(stdout, " task=%s", event.TaskID)
		}
		if len(event.ArtifactIDs) > 0 {
			fmt.Fprintf(stdout, " artifacts=%s", strings.Join(event.ArtifactIDs, ","))
		}
		if event.Message != "" {
			fmt.Fprintf(stdout, " message=%s", event.Message)
		}
		fmt.Fprintln(stdout)
	}
	for _, artifact := range result.Artifacts {
		fmt.Fprintf(stdout, "artifact=%s path=%s digest=%s producer_event=%s", artifact.ArtifactID, artifact.Path, artifact.Digest, artifact.ProducerEventID)
		if artifact.ProducerTaskID != "" {
			fmt.Fprintf(stdout, " producer_task=%s", artifact.ProducerTaskID)
		}
		fmt.Fprintf(stdout, " producer_found=%t\n", artifact.ProducerFound)
	}
	for _, snapshot := range result.InputSnapshots {
		fmt.Fprintf(stdout, "snapshot=%s source=%s path=%s digest=%s\n", snapshot.SnapshotID, snapshot.SourcePath, snapshot.SnapshotPath, snapshot.Digest)
	}
	printPolicyExplanations(stdout, result.PolicyExplanations)
	for _, failure := range result.Failures {
		fmt.Fprintf(stdout, "failure=%s event=%s event_found=%t line=%d", failure.FailureID, failure.EventID, failure.EventFound, failure.EventLine)
		if failure.TaskID != "" {
			fmt.Fprintf(stdout, " task=%s", failure.TaskID)
		}
		fmt.Fprintf(stdout, " phase=%s reason=%s\n", failure.Phase, failure.Reason)
	}
	for _, row := range result.ClosureRows {
		fmt.Fprintf(stdout, "closure=%s status=%s required=%t tasks=%s artifacts=%s policy_decisions=%s reason=%s\n",
			row.ObligationID,
			row.Status,
			row.Required,
			strings.Join(row.TaskIDs, ","),
			strings.Join(row.ArtifactIDs, ","),
			strings.Join(row.PolicyDecisionIDs, ","),
			row.Reason,
		)
		if len(row.MissingArtifactIDs) > 0 || len(row.MissingPolicyDecisionIDs) > 0 {
			fmt.Fprintf(stdout, "closure_missing=%s artifacts=%s policy_decisions=%s\n", row.ObligationID, strings.Join(row.MissingArtifactIDs, ","), strings.Join(row.MissingPolicyDecisionIDs, ","))
		}
	}
	printRevocations(stdout, result.Revocations)
}

func printRevocations(stdout io.Writer, revocations []bundlepkg.RevocationInspection) {
	for _, revocation := range revocations {
		for _, ticket := range revocation.RevokedTickets {
			fmt.Fprintf(stdout, "revocation=%s ticket=%s reason=%s\n", revocation.Path, ticket.TicketID, ticket.Reason)
		}
	}
}

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (f *repeatedStringFlag) Values() []string {
	return append([]string(nil), (*f)...)
}
