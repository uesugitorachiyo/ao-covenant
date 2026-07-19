package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	return RunWithInput(args, os.Stdin, stdout, stderr)
}

func RunWithInput(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 2 {
		printUsage(stderr)
		return 2
	}

	switch args[1] {
	case "version":
		return runVersion(args[2:], stdout, stderr)
	case "compile":
		return runCompile(args[2:], stdout, stderr)
	case "lint":
		return runLint(args[2:], stdout, stderr)
	case "run":
		return runContract(args[2:], stdout, stderr)
	case "verify":
		return runVerify(args[2:], stdout, stderr)
	case "self-run":
		return runSelfRun(args[2:], stdout, stderr)
	case "release":
		return runRelease(args[2:], stdout, stderr)
	case "bundle":
		return runBundle(args[2:], stdout, stderr)
	case "approval":
		return runApproval(args[2:], stdout, stderr)
	case "policy":
		return runPolicy(args[2:], stdout, stderr)
	case "schema":
		return runSchema(args[2:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[1])
		printUsage(stderr)
		return 2
	}
}

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

func runRelease(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printReleaseUsage(stderr)
		return 2
	}
	switch args[0] {
	case "package":
		return runReleasePackage(args[1:], stdout, stderr)
	case "verify":
		return runReleaseVerify(args[1:], stdout, stderr)
	case "inspect":
		return runReleaseInspect(args[1:], stdout, stderr)
	case "report":
		return runReleaseReport(args[1:], stdout, stderr)
	case "diff":
		return runReleaseDiff(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown release command %q\n", args[0])
		printReleaseUsage(stderr)
		return 2
	}
}

func runReleasePackage(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("release package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourceDir := flags.String("source", ".", "source repository root")
	outDir := flags.String("out", "dist", "directory to write release artifacts")
	version := flags.String("version", "", "release version")
	commit := flags.String("commit", "", "release commit")
	date := flags.String("date", "", "release build date")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	signKeyPath := flags.String("sign-key", "", "path to release signing private key JSON")
	var targetFlags repeatedStringFlag
	var sbomPaths repeatedStringFlag
	var provenancePaths repeatedStringFlag
	var attestationPaths repeatedStringFlag
	flags.Var(&targetFlags, "target", "release target as os/arch")
	flags.Var(&sbomPaths, "sbom", "path to supplemental SBOM artifact")
	flags.Var(&provenancePaths, "provenance", "path to supplemental provenance artifact")
	flags.Var(&attestationPaths, "attestation", "artifact attestation selector and path")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	targets := make([]releasepkg.Target, 0, len(targetFlags))
	for _, raw := range targetFlags {
		target, err := releasepkg.ParseTarget(raw)
		if err != nil {
			fmt.Fprintf(stderr, "target %q: %v\n", raw, err)
			return 2
		}
		targets = append(targets, target)
	}
	result, err := releasepkg.Package(context.Background(), releasepkg.Options{
		SourceDir:        *sourceDir,
		OutDir:           *outDir,
		Version:          *version,
		Commit:           *commit,
		Date:             *date,
		Targets:          targets,
		SignKeyPath:      *signKeyPath,
		SBOMPaths:        sbomPaths.Values(),
		ProvenancePaths:  provenancePaths.Values(),
		AttestationPaths: attestationPaths.Values(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "release package: %v\n", err)
		return 1
	}
	if *jsonOutput {
		artifactPaths := make([]string, 0, len(result.Artifacts))
		for _, artifact := range result.Artifacts {
			artifactPaths = append(artifactPaths, filepath.Join(*outDir, artifact.Path))
		}
		jsonResult := releasePackageResult{
			SchemaVersion:   schema.ReleasePackageResultSchemaID,
			ManifestPath:    result.ManifestPath,
			ChecksumsPath:   result.ChecksumsPath,
			SignaturePath:   result.SignaturePath,
			PublicKeySHA256: result.PublicKeySHA256,
			ArtifactPaths:   artifactPaths,
			Manifest:        result.Manifest,
		}
		if err := writeSchemaJSON(stdout, schema.ReleasePackageResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write release package result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "manifest=%s\n", result.ManifestPath)
	fmt.Fprintf(stdout, "checksums=%s\n", result.ChecksumsPath)
	for _, artifact := range result.Artifacts {
		fmt.Fprintf(stdout, "artifact=%s\n", filepath.Join(*outDir, artifact.Path))
	}
	return 0
}

func runReleaseVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("release verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "dist", "release directory")
	publicKeyPath := flags.String("public-key", "", "release public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	result, err := releasepkg.Verify(releasepkg.VerifyOptions{Dir: *dir, PublicKeyPath: *publicKeyPath, HostMetadata: releasepkg.ReadBinaryMetadata})
	if err != nil {
		fmt.Fprintf(stderr, "release verify: %v\n", err)
		return 1
	}
	if *jsonOutput {
		jsonResult := struct {
			SchemaVersion string `json:"schema_version"`
			releasepkg.VerifyReport
		}{SchemaVersion: schema.ReleaseVerifyResultSchemaID, VerifyReport: result}
		if err := writeSchemaJSON(stdout, schema.ReleaseVerifyResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write release verify result: %v\n", err)
			return 1
		}
		if !result.Verified {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "verified=%t\n", result.Verified)
	fmt.Fprintf(stdout, "manifest=%s\n", result.ManifestPath)
	fmt.Fprintf(stdout, "checksums=%s\n", result.ChecksumsPath)
	fmt.Fprintf(stdout, "artifact_count=%d\n", result.ArtifactCount)
	if result.SignaturePath != "" {
		fmt.Fprintf(stdout, "signature=%s\n", result.SignaturePath)
	}
	for _, problem := range result.Problems {
		fmt.Fprintf(stdout, "problem=%s\n", problem)
	}
	if !result.Verified {
		return 1
	}
	return 0
}

func runReleaseInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("release inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "dist", "release directory")
	publicKeyPath := flags.String("public-key", "", "release public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	audience := flags.String("audience", "internal", "audience")
	redact := flags.String("redact", "", "comma-separated redactions")
	policyPath := flags.String("redaction-policy", "", "redaction policy JSON")
	profile := flags.String("redaction-profile", "", "redaction profile")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	redaction, err := releaseRedactionOptions(*audience, *redact, *policyPath, *profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	result, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: *dir, PublicKeyPath: *publicKeyPath})
	if err != nil {
		fmt.Fprintf(stderr, "release inspect: %v\n", err)
		return 1
	}
	if redaction.Paths || redaction.Digests {
		result = releasepkg.RedactInspect(result, redaction)
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.ReleaseInspectResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write release inspect result: %v\n", err)
			return 1
		}
		return 0
	}
	writeReleaseReport(stdout, result, bundlepkg.RedactionOptions{})
	return 0
}

func runReleaseReport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("release report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "dist", "release directory")
	publicKeyPath := flags.String("public-key", "", "release public key JSON")
	format := flags.String("format", "text", "text, markdown, json, sarif, or sarif-baseline")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	markdownOutput := flags.Bool("markdown", false, "emit Markdown")
	outPath := flags.String("out", "", "output file")
	audience := flags.String("audience", "internal", "audience")
	redact := flags.String("redact", "", "comma-separated redactions")
	policyPath := flags.String("redaction-policy", "", "redaction policy JSON")
	profile := flags.String("redaction-profile", "", "redaction profile")
	sarifBaselinePath := flags.String("sarif-baseline", "", "SARIF baseline")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	selectedFormat := *format
	if *jsonOutput {
		selectedFormat = "json"
	}
	if *markdownOutput {
		selectedFormat = "markdown"
	}
	switch selectedFormat {
	case "text", "markdown", "json", "sarif", "sarif-baseline":
	default:
		fmt.Fprintf(stderr, "unsupported release report format %q\n", selectedFormat)
		return 2
	}
	redaction, err := releaseRedactionOptions(*audience, *redact, *policyPath, *profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if selectedFormat == "sarif" && (redaction.Paths || redaction.Digests) {
		fmt.Fprintln(stderr, "release report redaction is only supported for text, markdown, and JSON output")
		return 2
	}
	if *sarifBaselinePath != "" && selectedFormat != "sarif" {
		fmt.Fprintln(stderr, "--sarif-baseline requires --format sarif")
		return 2
	}
	inspection, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: *dir, PublicKeyPath: *publicKeyPath})
	if err != nil {
		fmt.Fprintf(stderr, "release report: %v\n", err)
		return 1
	}
	valid := inspection.ChecksumStatus == "verified" && len(inspection.Problems) == 0 && inspection.Signature.Status != "invalid"
	var output []byte
	allSuppressed := false
	switch selectedFormat {
	case "text":
		var buf bytes.Buffer
		writeReleaseReport(&buf, inspection, bundlepkg.RedactionOptions{Paths: redaction.Paths, Digests: redaction.Digests})
		output = buf.Bytes()
	case "markdown":
		var buf bytes.Buffer
		writeReleaseReportMarkdown(&buf, inspection, bundlepkg.RedactionOptions{Paths: redaction.Paths, Digests: redaction.Digests})
		output = buf.Bytes()
	case "json":
		report := releasepkg.ReportResult{
			SchemaVersion:     schema.ReleaseReportResultSchemaID,
			Valid:             valid,
			Format:            "json",
			Audience:          defaultAudience(*audience),
			Redacted:          redaction.Paths || redaction.Digests,
			Redactions:        releaseRedactionNames(redaction),
			RedactionProfile:  redaction.RedactionProfile,
			ProvenanceSummary: releasepkg.SummarizeProvenance(inspection),
			Inspection:        inspection,
		}
		if redaction.Paths || redaction.Digests {
			report = releasepkg.RedactReport(report, redaction)
		}
		output, err = marshalSchemaJSONBytes(schema.ReleaseReportResultSchemaID, report)
		if err != nil {
			fmt.Fprintf(stderr, "encode release report: %v\n", err)
			return 1
		}
	case "sarif":
		baseline, err := readSchemaValidationSARIFBaseline(*sarifBaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
			return 1
		}
		sarif := releasepkg.InspectSARIFWithOptions(inspection, releasepkg.InspectSARIFOptions{Baseline: baseline})
		allSuppressed = sarifResultsAllSuppressed(sarif)
		output, err = json.MarshalIndent(sarif, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode release report sarif: %v\n", err)
			return 1
		}
		output = append(output, '\n')
	case "sarif-baseline":
		sarif := releasepkg.InspectSARIF(inspection)
		baseline := releaseSARIFBaselineTemplate(sarif)
		output, err = marshalSchemaJSONBytes(schema.LintSARIFBaselineSchemaID, baseline)
		if err != nil {
			fmt.Fprintf(stderr, "encode release report sarif baseline: %v\n", err)
			return 1
		}
	}
	if err := writeNamedOutputFile(stdout, "release report", "release_report", *outPath, output); err != nil {
		fmt.Fprintf(stderr, "write release report: %v\n", err)
		return 1
	}
	if !valid && !allSuppressed {
		return 1
	}
	return 0
}

func runReleaseDiff(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("release diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fromDir := flags.String("from", "", "from release directory")
	toDir := flags.String("to", "", "to release directory")
	publicKeyPath := flags.String("public-key", "", "release public key JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	sarifOutput := flags.Bool("sarif", false, "emit SARIF")
	outPath := flags.String("out", "", "output file")
	audience := flags.String("audience", "internal", "audience")
	redact := flags.String("redact", "", "comma-separated redactions")
	policyPath := flags.String("redaction-policy", "", "redaction policy JSON")
	profile := flags.String("redaction-profile", "", "redaction profile")
	sarifBaselinePath := flags.String("sarif-baseline", "", "SARIF baseline")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *fromDir == "" {
		fmt.Fprintln(stderr, "--from is required")
		return 2
	}
	if *toDir == "" {
		fmt.Fprintln(stderr, "--to is required")
		return 2
	}
	if *jsonOutput && *sarifOutput {
		fmt.Fprintln(stderr, "--json and --sarif are mutually exclusive")
		return 2
	}
	if *sarifBaselinePath != "" && !*sarifOutput {
		fmt.Fprintln(stderr, "--sarif-baseline requires --sarif")
		return 2
	}
	redaction, err := releaseRedactionOptions(*audience, *redact, *policyPath, *profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	report, err := releasepkg.Diff(releasepkg.DiffOptions{FromDir: *fromDir, ToDir: *toDir, Redaction: redaction, FromPublicKeyPath: *publicKeyPath, ToPublicKeyPath: *publicKeyPath})
	if err != nil {
		fmt.Fprintf(stderr, "release diff: %v\n", err)
		return 1
	}
	var output []byte
	allSuppressed := false
	if *sarifOutput {
		baseline, err := readSchemaValidationSARIFBaseline(*sarifBaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
			return 1
		}
		sarif := releasepkg.DiffSARIFWithOptions(report, releasepkg.DiffSARIFOptions{Baseline: baseline})
		allSuppressed = sarifResultsAllSuppressed(sarif)
		output, err = json.MarshalIndent(sarif, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode release diff sarif: %v\n", err)
			return 1
		}
		output = append(output, '\n')
	} else if *jsonOutput {
		output, err = marshalSchemaJSONBytes(schema.ReleaseDiffResultSchemaID, report)
		if err != nil {
			fmt.Fprintf(stderr, "encode release diff: %v\n", err)
			return 1
		}
	} else {
		var buf bytes.Buffer
		fmt.Fprintln(&buf, "AO Covenant Release Diff")
		fmt.Fprintf(&buf, "from: %s\n", report.FromDir)
		fmt.Fprintf(&buf, "to: %s\n", report.ToDir)
		fmt.Fprintf(&buf, "changed: %t\n", report.Changed)
		if report.Changed {
			fmt.Fprintln(&buf, "status: changed")
		} else {
			fmt.Fprintln(&buf, "status: unchanged")
		}
		if !report.Changed {
			fmt.Fprintln(&buf, "changes: none")
		}
		lastCategory := ""
		for _, entry := range report.Entries {
			if entry.Category != lastCategory {
				fmt.Fprintf(&buf, "%s:\n", entry.Category)
				lastCategory = entry.Category
			}
			if entry.Category == "artifacts" || entry.Category == "supplemental_artifacts" {
				fmt.Fprintf(&buf, "- %s %s (%s)\n", entry.Action, entry.Name, entry.Detail)
			} else {
				fmt.Fprintf(&buf, "- %s %s: %s\n", entry.Action, entry.Name, entry.Detail)
			}
		}
		output = buf.Bytes()
	}
	if err := writeReleaseDiffOutput(stdout, *outPath, output); err != nil {
		fmt.Fprintf(stderr, "write release diff: %v\n", err)
		return 1
	}
	if report.Changed && !allSuppressed {
		return 1
	}
	return 0
}

func sarifResultsAllSuppressed(log schema.SARIFLog) bool {
	resultCount := 0
	for _, run := range log.Runs {
		for _, result := range run.Results {
			resultCount++
			if len(result.Suppressions) == 0 {
				return false
			}
		}
	}
	return resultCount > 0
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

func releaseRedactionOptions(audience string, rawRedactions string, policyPath string, profile string) (releasepkg.RedactionOptions, error) {
	var opts releasepkg.RedactionOptions
	switch audience {
	case "", "internal":
	case "external":
		opts.Paths = true
		opts.Digests = true
	default:
		return releasepkg.RedactionOptions{}, fmt.Errorf("--audience must be %q or %q", "internal", "external")
	}
	if strings.TrimSpace(policyPath) != "" {
		policy, err := readReportRedactionPolicy(policyPath)
		if err != nil {
			return releasepkg.RedactionOptions{}, err
		}
		profileName := strings.TrimSpace(profile)
		if profileName == "" {
			profileName = "partner"
		}
		selected, ok := policy.Profiles[profileName]
		if !ok {
			return releasepkg.RedactionOptions{}, fmt.Errorf("redaction profile %q not found", profileName)
		}
		opts = releasepkg.RedactionOptions{RedactionProfile: profileName}
		for _, value := range selected.Redact {
			if err := applyReleaseRedactionValue(&opts, value); err != nil {
				return releasepkg.RedactionOptions{}, err
			}
		}
	}
	if strings.TrimSpace(rawRedactions) != "" {
		for _, raw := range strings.Split(rawRedactions, ",") {
			if err := applyReleaseRedactionValue(&opts, strings.TrimSpace(raw)); err != nil {
				return releasepkg.RedactionOptions{}, err
			}
		}
	}
	return opts, nil
}

func readReportRedactionPolicy(path string) (reportRedactionPolicyFile, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return reportRedactionPolicyFile{}, err
	}
	if err := schema.ValidateBytes(schema.ReportRedactionPolicySchemaID, bytes); err != nil {
		return reportRedactionPolicyFile{}, err
	}
	var policy reportRedactionPolicyFile
	if err := json.Unmarshal(bytes, &policy); err != nil {
		return reportRedactionPolicyFile{}, err
	}
	if policy.SchemaVersion != reportRedactionPolicySchemaVersion {
		return reportRedactionPolicyFile{}, fmt.Errorf("schema_version must be %q", reportRedactionPolicySchemaVersion)
	}
	return policy, nil
}

func applyReleaseRedactionValue(opts *releasepkg.RedactionOptions, value string) error {
	switch value {
	case "":
		return nil
	case "paths":
		opts.Paths = true
	case "digests":
		opts.Digests = true
	default:
		return fmt.Errorf("--redact values must be %q or %q", "paths", "digests")
	}
	return nil
}

func releaseRedactionNames(opts releasepkg.RedactionOptions) []string {
	names := []string{}
	if opts.Paths {
		names = append(names, "paths")
	}
	if opts.Digests {
		names = append(names, "digests")
	}
	return names
}

func defaultAudience(audience string) string {
	if strings.TrimSpace(audience) == "" {
		return "internal"
	}
	return audience
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

func runApproval(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalUsage(stderr)
		return 2
	}
	switch args[0] {
	case "create":
		return runApprovalCreate(args[1:], stdout, stderr)
	case "inspect":
		return runApprovalInspect(args[1:], stdout, stderr)
	case "live-docs":
		return runApprovalLiveDocs(args[1:], stdout, stderr)
	case "mutation-class":
		return runApprovalMutationClass(args[1:], stdout, stderr)
	case "low-risk-code-live":
		return runApprovalLowRiskCodeLive(args[1:], stdout, stderr)
	case "validate":
		return runApprovalValidate(args[1:], stdout, stderr)
	case "attach":
		return runApprovalAttach(args[1:], stdout, stderr)
	case "revoke":
		return runApprovalRevoke(args[1:], stdout, stderr)
	case "revocations":
		return runApprovalRevocations(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval command %q\n", args[0])
		printApprovalUsage(stderr)
		return 2
	}
}

func runPolicy(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printPolicyUsage(stderr)
		return 2
	}
	switch args[0] {
	case "explain":
		return runPolicyExplain(args[1:], stdout, stderr)
	case "index":
		return runPolicyIndex(args[1:], stdout, stderr)
	case "spine":
		return runPolicySpine(args[1:], stdout, stderr)
	case "credential-checklist":
		return runPolicyCredentialChecklist(args[1:], stdout, stderr)
	case "claim-publish-gate":
		return runPolicyClaimPublishGate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown policy command %q\n", args[0])
		printPolicyUsage(stderr)
		return 2
	}
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

func runSchema(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printSchemaUsage(stderr)
		return 2
	}
	switch args[0] {
	case "catalog":
		return runSchemaCatalog(args[1:], stdout, stderr)
	case "export":
		return runSchemaExport(args[1:], stdout, stderr)
	case "validate":
		return runSchemaValidate(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown schema command %q\n", args[0])
		printSchemaUsage(stderr)
		return 2
	}
}

func runSchemaCatalog(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema catalog", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := schemaCatalogReport{
		SchemaVersion: schema.SchemaCatalogResultSchemaID,
		Schemas:       schema.Catalog(),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.SchemaCatalogResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write schema catalog: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range report.Schemas {
		fmt.Fprintf(stdout, "schema=%s file=%s path=%s\n", entry.ID, entry.FileName, entry.SchemaPath)
	}
	return 0
}

func runSchemaExport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outDir := flags.String("out", "", "directory to write public JSON schemas")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*outDir) == "" {
		fmt.Fprintln(stderr, "--out is required")
		return 2
	}
	exported, err := schema.Export(*outDir)
	if err != nil {
		fmt.Fprintf(stderr, "export schemas: %v\n", err)
		return 1
	}
	report := schemaExportReport{
		SchemaVersion: schema.SchemaExportResultSchemaID,
		Schemas:       exported,
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.SchemaExportResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write schema export: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range report.Schemas {
		fmt.Fprintf(stdout, "schema=%s file=%s written=%s\n", entry.ID, entry.FileName, entry.WrittenPath)
	}
	return 0
}

func runSchemaValidate(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	schemaID := flags.String("schema", "", "schema ID to validate against")
	filePath := flags.String("file", "", "JSON document to validate")
	dirPath := flags.String("dir", "", "directory tree of JSON documents to validate")
	stdinInput := flags.Bool("stdin", false, "read JSON document from stdin")
	filesFromPath := flags.String("files-from", "", "newline-delimited list of JSON documents to validate")
	var ignorePatterns repeatedStringFlag
	flags.Var(&ignorePatterns, "ignore", "slash-separated file or directory path to skip during --dir validation")
	var schemaFilterIDs repeatedStringFlag
	flags.Var(&schemaFilterIDs, "schema-filter", "schema ID to include during --dir or --files-from validation")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	sarifOutput := flags.Bool("sarif", false, "emit SARIF")
	junitOutput := flags.Bool("junit", false, "emit JUnit XML")
	sarifBaselinePath := flags.String("sarif-baseline", "", "path to SARIF baseline JSON")
	outPath := flags.String("out", "", "path to write structured validation report")
	failFast := flags.Bool("fail-fast", false, "stop directory validation after the first invalid document")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if countEnabled(*jsonOutput, *sarifOutput, *junitOutput) > 1 {
		fmt.Fprintln(stderr, "--json, --sarif, and --junit are mutually exclusive")
		return 2
	}
	if strings.TrimSpace(*sarifBaselinePath) != "" && !*sarifOutput {
		fmt.Fprintln(stderr, "--sarif-baseline requires --sarif")
		return 2
	}
	selectedOutPath := strings.TrimSpace(*outPath)
	if selectedOutPath != "" && countEnabled(*jsonOutput, *sarifOutput, *junitOutput) == 0 {
		fmt.Fprintln(stderr, "--out requires --json, --sarif, or --junit")
		return 2
	}
	selectedFilePath := strings.TrimSpace(*filePath)
	selectedDirPath := strings.TrimSpace(*dirPath)
	selectedFilesFromPath := strings.TrimSpace(*filesFromPath)
	if countEnabled(selectedFilePath != "", selectedDirPath != "", *stdinInput, selectedFilesFromPath != "") != 1 {
		fmt.Fprintln(stderr, "provide exactly one of --file, --dir, --stdin, or --files-from")
		return 2
	}
	selectedSchemaFilters, schemaFilterErr := normalizeSchemaValidationSchemaFilters(schemaFilterIDs.Values())
	if schemaFilterErr != nil {
		fmt.Fprintln(stderr, schemaFilterErr)
		return 2
	}
	if len(selectedSchemaFilters) > 0 {
		if selectedDirPath == "" && selectedFilesFromPath == "" {
			fmt.Fprintln(stderr, "--schema-filter can only be used with --dir or --files-from")
			return 2
		}
		if strings.TrimSpace(*schemaID) != "" {
			fmt.Fprintln(stderr, "--schema-filter cannot be combined with --schema")
			return 2
		}
	}
	selectedIgnorePatterns, ignoreErr := normalizeSchemaValidationIgnorePatterns(ignorePatterns.Values())
	if ignoreErr != nil {
		fmt.Fprintf(stderr, "%v\n", ignoreErr)
		return 2
	}
	if len(selectedIgnorePatterns) > 0 && selectedDirPath == "" {
		fmt.Fprintln(stderr, "--ignore can only be used with --dir")
		return 2
	}

	if selectedDirPath != "" || selectedFilesFromPath != "" {
		var documents []schemaValidationInputDocument
		var ignoredDocuments []schemaValidationIgnoredDocument
		if selectedDirPath != "" {
			paths, ignored, err := collectSchemaValidationDirectory(selectedDirPath, selectedIgnorePatterns)
			if err != nil {
				fmt.Fprintf(stderr, "collect schema documents: %v\n", err)
				return 1
			}
			ignoredDocuments = ignored
			if len(paths) == 0 {
				fmt.Fprintf(stderr, "no JSON documents found under %s\n", selectedDirPath)
				return 1
			}
			documents = make([]schemaValidationInputDocument, 0, len(paths))
			for _, path := range paths {
				displayPath, err := schemaValidationDisplayPath(selectedDirPath, path)
				if err != nil {
					fmt.Fprintf(stderr, "%s: %v\n", path, err)
					return 1
				}
				documents = append(documents, schemaValidationInputDocument{
					Path:        path,
					DisplayPath: displayPath,
				})
			}
		} else {
			var err error
			documents, err = readSchemaValidationManifest(selectedFilesFromPath)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		report := validateSchemaInputDocuments(documents, *schemaID, selectedSchemaFilters, *failFast, stderr)
		inputMode := "files-from"
		source := selectedFilesFromPath
		if selectedDirPath != "" {
			inputMode = "dir"
			source = selectedDirPath
		}
		report.Metadata = schemaValidationMetadata(inputMode, source, *schemaID, selectedSchemaFilters, selectedIgnorePatterns, *failFast)
		report.Ignored = ignoredDocuments
		report.IgnoredCount = len(ignoredDocuments)
		if *sarifOutput {
			baseline, err := readSchemaValidationSARIFBaseline(*sarifBaselinePath)
			if err != nil {
				fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
				return 1
			}
			sarifReports := schemaValidationSARIFReports(report.Validations)
			sarifOptions := schema.ValidationSARIFOptions{Baseline: baseline}
			bytes, err := json.MarshalIndent(schema.ValidationSARIFWithOptions(sarifReports, sarifOptions), "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "encode schema validation sarif: %v\n", err)
				return 1
			}
			if err := writeSchemaValidationOutput(stdout, selectedOutPath, bytes); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
			if !report.Valid && schema.ValidationSARIFReportsAllSuppressed(sarifReports, sarifOptions) {
				return 0
			}
		} else if *junitOutput {
			bytes, err := xml.MarshalIndent(schema.ValidationJUnit(schemaValidationJUnitReports(report.Validations), ""), "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "encode schema validation junit: %v\n", err)
				return 1
			}
			if err := writeSchemaValidationOutput(stdout, selectedOutPath, bytes); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
		} else if *jsonOutput {
			if err := writeSchemaValidationJSON(stdout, selectedOutPath, report); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
		} else {
			for _, validation := range report.Validations {
				printSchemaValidationLine(stdout, validation)
			}
			for _, ignored := range report.Ignored {
				fmt.Fprintf(stdout, "ignored=%s pattern=%s\n", ignored.File, ignored.Pattern)
			}
			for _, summary := range report.Schemas {
				fmt.Fprintf(stdout, "schema_summary=%s", summary.SchemaID)
				if summary.Total > 0 {
					fmt.Fprintf(stdout, " total=%d valid_count=%d invalid_count=%d", summary.Total, summary.ValidCount, summary.InvalidCount)
				}
				if summary.SkippedCount > 0 {
					fmt.Fprintf(stdout, " skipped_count=%d", summary.SkippedCount)
				}
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "valid=%t total=%d valid_count=%d invalid_count=%d", report.Valid, report.Total, report.ValidCount, report.InvalidCount)
			if report.SkippedCount > 0 {
				fmt.Fprintf(stdout, " skipped_count=%d", report.SkippedCount)
			}
			if report.IgnoredCount > 0 {
				fmt.Fprintf(stdout, " ignored_count=%d", report.IgnoredCount)
			}
			fmt.Fprintln(stdout)
		}
		if len(selectedSchemaFilters) > 0 && report.Total == 0 {
			fmt.Fprintln(stderr, "no schema documents matched --schema-filter")
			return 1
		}
		if !report.Valid {
			return 1
		}
		return 0
	}

	var report schemaValidationReport
	var err error
	if *stdinInput {
		var bytes []byte
		bytes, err = io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return 1
		}
		report, err = validateSchemaDocumentBytes("-", bytes, *schemaID)
	} else {
		report, err = validateSchemaDocument(selectedFilePath, *schemaID)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	inputMode := "file"
	source := selectedFilePath
	if *stdinInput {
		inputMode = "stdin"
		source = "-"
	}
	report.Metadata = schemaValidationMetadata(inputMode, source, *schemaID, nil, nil, false)
	return printSingleSchemaValidationReport(report, *sarifOutput, *junitOutput, *jsonOutput, selectedOutPath, *sarifBaselinePath, stdout, stderr)
}

func schemaValidationMetadata(inputMode string, source string, schemaID string, schemaFilters []string, ignorePatterns []string, failFast bool) *schemaValidationReportMetadata {
	metadata := &schemaValidationReportMetadata{
		Command:   "schema validate",
		InputMode: inputMode,
		Source:    source,
	}
	if value := strings.TrimSpace(schemaID); value != "" {
		metadata.ExplicitSchemaID = value
	}
	if len(schemaFilters) > 0 {
		metadata.SchemaFilters = append([]string(nil), schemaFilters...)
	}
	if len(ignorePatterns) > 0 {
		metadata.IgnorePatterns = append([]string(nil), ignorePatterns...)
	}
	if failFast {
		metadata.FailFast = true
	}
	return metadata
}

func printSingleSchemaValidationReport(report schemaValidationReport, sarifOutput bool, junitOutput bool, jsonOutput bool, outPath string, sarifBaselinePath string, stdout io.Writer, stderr io.Writer) int {
	if sarifOutput {
		baseline, err := readSchemaValidationSARIFBaseline(sarifBaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
			return 1
		}
		sarifReports := schemaValidationSARIFReports([]schemaValidationReport{report})
		sarifOptions := schema.ValidationSARIFOptions{Baseline: baseline}
		bytes, err := json.MarshalIndent(schema.ValidationSARIFWithOptions(sarifReports, sarifOptions), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode schema validation sarif: %v\n", err)
			return 1
		}
		if err := writeSchemaValidationOutput(stdout, outPath, bytes); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
		if !report.Valid && schema.ValidationSARIFReportsAllSuppressed(sarifReports, sarifOptions) {
			return 0
		}
	} else if junitOutput {
		bytes, err := xml.MarshalIndent(schema.ValidationJUnit(schemaValidationJUnitReports([]schemaValidationReport{report}), ""), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode schema validation junit: %v\n", err)
			return 1
		}
		if err := writeSchemaValidationOutput(stdout, outPath, bytes); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
	} else if jsonOutput {
		if err := writeSchemaValidationJSON(stdout, outPath, report); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
	} else {
		printSchemaValidationLine(stdout, report)
	}
	if !report.Valid {
		if report.Error != "" {
			fmt.Fprintln(stderr, schemaValidationErrorMessage(report))
		}
		return 1
	}
	return 0
}

func writeSchemaValidationJSON(stdout io.Writer, outPath string, report any) error {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if err := schema.ValidateBytes(schema.SchemaValidationReportSchemaID, bytes); err != nil {
		return err
	}
	return writeSchemaValidationOutput(stdout, outPath, bytes)
}

func writeSchemaValidationOutput(stdout io.Writer, outPath string, bytes []byte) error {
	bytes = append(bytes, '\n')
	return writeNamedOutputFile(stdout, "schema validate", "schema_validation_report", outPath, bytes)
}

func writeReleaseReportOutput(stdout io.Writer, outPath string, bytes []byte) error {
	return writeNamedOutputFile(stdout, "release report", "release_report", outPath, bytes)
}

func writeReleaseDiffOutput(stdout io.Writer, outPath string, bytes []byte) error {
	return writeNamedOutputFile(stdout, "release diff", "release_diff", outPath, bytes)
}

type outputFileSnapshot struct {
	Exists bool
	Bytes  []byte
	Mode   os.FileMode
}

type rollbackOutputFileFunc func(string, outputFileSnapshot) error

var rollbackOutputFileForWrite rollbackOutputFileFunc = rollbackOutputFile

func replaceRollbackOutputFileForWrite(rollback rollbackOutputFileFunc) rollbackOutputFileFunc {
	previous := rollbackOutputFileForWrite
	rollbackOutputFileForWrite = rollback
	return previous
}

const (
	outputPairStageMain    = "main"
	outputPairStageSidecar = "sidecar"
)

const (
	maxSchemaValidationDirectoryFiles      = 4096
	maxSchemaValidationDirectoryFileBytes  = 8 * 1024 * 1024
	maxSchemaValidationDirectoryTotalBytes = 64 * 1024 * 1024
)

type outputPairError struct {
	stage string
	err   error
}

func (err outputPairError) Error() string {
	return err.err.Error()
}

func (err outputPairError) Unwrap() error {
	return err.err
}

func outputPairErrorStage(err error) string {
	var staged outputPairError
	if errors.As(err, &staged) {
		return staged.stage
	}
	return outputPairStageMain
}

func writeNamedOutputFile(stdout io.Writer, commandName string, markerName string, outPath string, bytes []byte) error {
	if strings.TrimSpace(outPath) == "" {
		_, err := stdout.Write(bytes)
		return err
	}
	if err := writeOutputFileBytes(commandName, outPath, bytes); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "%s=%s\n", markerName, outPath)
	return err
}

func writeOutputFileBytes(commandName string, outPath string, bytes []byte) error {
	if err := validateOutputFileTarget(commandName, outPath); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, bytes, 0o644); err != nil {
		return fmt.Errorf("%s --out write failed: %w", commandName, err)
	}
	return nil
}

func validateOutputFileTarget(commandName string, outPath string) error {
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("%s --out is required", commandName)
	}
	parentDir := filepath.Dir(outPath)
	if info, err := os.Stat(parentDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s --out parent directory does not exist: %s", commandName, parentDir)
		}
		if strings.Contains(err.Error(), "not a directory") {
			return fmt.Errorf("%s --out parent path is not a directory: %s", commandName, parentDir)
		}
		return fmt.Errorf("%s --out parent path cannot be inspected: %w", commandName, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s --out parent path is not a directory: %s", commandName, parentDir)
	}
	if info, err := os.Stat(outPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s --out points to a directory: %s", commandName, outPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s --out path cannot be inspected: %w", commandName, err)
	}
	return nil
}

// Internal code calls this an output pair. User-facing diagnostics and README text call the second artifact a digest sidecar.
// writeOutputPairWithRollback writes a primary artifact and sidecar as one output pair.
func writeOutputPairWithRollback(commandName string, outPath string, bytes []byte, sidecarPath string, sidecarBytes []byte) error {
	if err := validateOutputFileTarget(commandName, outPath); err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	outputSnapshot, err := snapshotOutputFile(outPath)
	if err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	if err := writeOutputFileBytes(commandName, outPath, bytes); err != nil {
		return outputPairError{stage: outputPairStageMain, err: err}
	}
	if err := writeOutputFileBytes(commandName, sidecarPath, sidecarBytes); err != nil {
		if rollbackErr := rollbackOutputFileForWrite(outPath, outputSnapshot); rollbackErr != nil {
			err = fmt.Errorf("%w; rollback output: %v", err, rollbackErr)
		}
		return outputPairError{stage: outputPairStageSidecar, err: err}
	}
	return nil
}

func snapshotOutputFile(path string) (outputFileSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return outputFileSnapshot{}, nil
		}
		return outputFileSnapshot{}, fmt.Errorf("snapshot output: %w", err)
	}
	if info.IsDir() {
		return outputFileSnapshot{Exists: true, Mode: info.Mode().Perm()}, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return outputFileSnapshot{}, fmt.Errorf("snapshot output: %w", err)
	}
	return outputFileSnapshot{Exists: true, Bytes: bytes, Mode: info.Mode().Perm()}, nil
}

func rollbackOutputFile(path string, snapshot outputFileSnapshot) error {
	if snapshot.Exists {
		if err := os.WriteFile(path, snapshot.Bytes, snapshot.Mode); err != nil {
			return fmt.Errorf("restore output: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove output: %w", err)
	}
	return nil
}

func printSchemaValidationLine(stdout io.Writer, validation schemaValidationReport) {
	if validation.Location != "" {
		fmt.Fprintf(stdout, "schema=%s file=%s valid=%t location=%s\n", validation.SchemaID, validation.File, validation.Valid, validation.Location)
		return
	}
	fmt.Fprintf(stdout, "schema=%s file=%s valid=%t\n", validation.SchemaID, validation.File, validation.Valid)
}

func schemaValidationErrorMessage(validation schemaValidationReport) string {
	message := validation.Error
	if validation.Location != "" {
		message += " location=" + validation.Location
	}
	return message
}

func schemaValidationDisplayPath(root string, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	normalized := filepath.ToSlash(filepath.Clean(relative))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("schema document %q is outside %q", path, root)
	}
	return normalized, nil
}

func countEnabled(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func schemaValidationSARIFReports(validations []schemaValidationReport) []schema.ValidationSARIFReport {
	reports := make([]schema.ValidationSARIFReport, 0, len(validations))
	for _, validation := range validations {
		reports = append(reports, schema.ValidationSARIFReport{
			SchemaID: validation.SchemaID,
			File:     validation.File,
			Valid:    validation.Valid,
			Error:    validation.Error,
			Location: validation.Location,
		})
	}
	return reports
}

func schemaValidationJUnitReports(validations []schemaValidationReport) []schema.ValidationJUnitReport {
	reports := make([]schema.ValidationJUnitReport, 0, len(validations))
	for _, validation := range validations {
		reports = append(reports, schema.ValidationJUnitReport{
			SchemaID: validation.SchemaID,
			File:     validation.File,
			Valid:    validation.Valid,
			Error:    validation.Error,
			Location: validation.Location,
		})
	}
	return reports
}

func validateSchemaDocument(path string, schemaID string) (schemaValidationReport, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: displayPath(path), Valid: false, Error: err.Error()}, fmt.Errorf("read schema document: %w", err)
	}
	return validateSchemaDocumentBytes(displayPath(path), bytes, schemaID)
}

func validateSchemaDocumentBytes(displayPath string, bytes []byte, schemaID string) (schemaValidationReport, error) {
	selectedSchemaID := strings.TrimSpace(schemaID)
	var err error
	if selectedSchemaID == "" {
		selectedSchemaID, err = schema.InferSchemaIDBytes(bytes)
		if err != nil {
			return schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: displayPath, Valid: false, Error: err.Error()}, fmt.Errorf("infer schema: %w when --schema is omitted", err)
		}
	}
	validation := schema.ValidateDocumentBytes(selectedSchemaID, bytes)
	return schemaValidationReport{
		SchemaVersion: schema.SchemaValidationReportSchemaID,
		SchemaID:      validation.SchemaID,
		File:          displayPath,
		Valid:         validation.Valid,
		Error:         validation.Error,
		Location:      validation.Location,
	}, nil
}

func validateSchemaInputDocuments(documents []schemaValidationInputDocument, schemaID string, schemaFilters []string, failFast bool, stderr io.Writer) schemaValidationSetReport {
	report := schemaValidationSetReport{
		SchemaVersion: schema.SchemaValidationReportSchemaID,
		Valid:         true,
		Validations:   make([]schemaValidationReport, 0, len(documents)),
	}
	filterSet := schemaValidationFilterSet(schemaFilters)
	schemaSummaries := map[string]*schemaValidationSchemaSummary{}
	recordSchemaSummary := func(schemaID string, valid bool, skipped bool) {
		value := strings.TrimSpace(schemaID)
		if value == "" {
			value = "unknown"
		}
		summary, ok := schemaSummaries[value]
		if !ok {
			summary = &schemaValidationSchemaSummary{SchemaID: value}
			schemaSummaries[value] = summary
		}
		if skipped {
			summary.SkippedCount++
			return
		}
		summary.Total++
		if valid {
			summary.ValidCount++
		} else {
			summary.InvalidCount++
		}
	}
	for _, document := range documents {
		bytes, readErr := os.ReadFile(document.Path)
		if readErr != nil {
			validation := schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: document.DisplayPath, Valid: false, Error: readErr.Error()}
			report.Valid = false
			report.Total++
			report.InvalidCount++
			report.Validations = append(report.Validations, validation)
			recordSchemaSummary(validation.SchemaID, validation.Valid, false)
			fmt.Fprintf(stderr, "%s: read schema document: %v\n", validation.File, readErr)
			if failFast {
				break
			}
			continue
		}
		if len(filterSet) > 0 {
			documentSchemaID, matches, err := schemaValidationFilterMatch(bytes, filterSet)
			if err != nil {
				validation := schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: document.DisplayPath, Valid: false, Error: err.Error()}
				report.Valid = false
				report.Total++
				report.InvalidCount++
				report.Validations = append(report.Validations, validation)
				recordSchemaSummary(validation.SchemaID, validation.Valid, false)
				fmt.Fprintf(stderr, "%s: %v\n", validation.File, err)
				if failFast {
					break
				}
				continue
			}
			if !matches {
				report.SkippedCount++
				recordSchemaSummary(documentSchemaID, false, true)
				continue
			}
			validation := schema.ValidateDocumentBytes(documentSchemaID, bytes)
			validationReport := schemaValidationReport{
				SchemaVersion: schema.SchemaValidationReportSchemaID,
				SchemaID:      validation.SchemaID,
				File:          document.DisplayPath,
				Valid:         validation.Valid,
				Error:         validation.Error,
				Location:      validation.Location,
			}
			if !validationReport.Valid {
				report.Valid = false
				fmt.Fprintf(stderr, "%s: %s\n", validationReport.File, schemaValidationErrorMessage(validationReport))
			}
			report.Total++
			if validationReport.Valid {
				report.ValidCount++
			} else {
				report.InvalidCount++
			}
			report.Validations = append(report.Validations, validationReport)
			recordSchemaSummary(validationReport.SchemaID, validationReport.Valid, false)
			if failFast && !validationReport.Valid {
				break
			}
			continue
		}
		validation, err := validateSchemaDocumentBytes(document.DisplayPath, bytes, schemaID)
		if err != nil {
			report.Valid = false
			fmt.Fprintf(stderr, "%s: %v\n", validation.File, err)
		}
		if !validation.Valid {
			report.Valid = false
			if validation.Error != "" && err == nil {
				fmt.Fprintf(stderr, "%s: %s\n", validation.File, schemaValidationErrorMessage(validation))
			}
		}
		report.Total++
		if validation.Valid {
			report.ValidCount++
		} else {
			report.InvalidCount++
		}
		report.Validations = append(report.Validations, validation)
		recordSchemaSummary(validation.SchemaID, validation.Valid, false)
		if failFast && !validation.Valid {
			break
		}
	}
	report.Schemas = sortedSchemaValidationSummaries(schemaSummaries)
	return report
}

func sortedSchemaValidationSummaries(values map[string]*schemaValidationSchemaSummary) []schemaValidationSchemaSummary {
	summaries := make([]schemaValidationSchemaSummary, 0, len(values))
	for _, summary := range values {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].SchemaID < summaries[j].SchemaID
	})
	return summaries
}

func schemaValidationFilterSet(filters []string) map[string]bool {
	if len(filters) == 0 {
		return nil
	}
	set := make(map[string]bool, len(filters))
	for _, filter := range filters {
		value := strings.TrimSpace(filter)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func schemaValidationFilterMatch(bytes []byte, filters map[string]bool) (string, bool, error) {
	var document map[string]any
	if err := json.Unmarshal(bytes, &document); err != nil {
		return "", false, fmt.Errorf("decode JSON for schema filter: %w", err)
	}
	rawSchemaID, ok := document["schema_version"]
	if !ok {
		return "", false, nil
	}
	schemaID, ok := rawSchemaID.(string)
	if !ok {
		return "", false, nil
	}
	schemaID = strings.TrimSpace(schemaID)
	if schemaID == "" || !schema.KnownSchemaID(schemaID) {
		return "", false, nil
	}
	return schemaID, filters[schemaID], nil
}

func collectSchemaValidationDirectory(root string, ignored []string) ([]string, []schemaValidationIgnoredDocument, error) {
	if err := ensureSchemaValidationDirectoryRoot(root); err != nil {
		return nil, nil, err
	}
	var paths []string
	var ignoredDocuments []schemaValidationIgnoredDocument
	budget := schemaValidationDirectoryScanBudget{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("schema validation directory symlink is not allowed: %s", filepath.ToSlash(path))
		}
		if path != root {
			displayPath, err := schemaValidationDisplayPath(root, path)
			if err != nil {
				return err
			}
			if pattern, ok := schemaValidationIgnoredByPattern(displayPath, ignored); ok {
				if entry.IsDir() {
					nestedIgnored, err := collectIgnoredSchemaValidationJSON(root, path, pattern, &budget)
					if err != nil {
						return err
					}
					ignoredDocuments = append(ignoredDocuments, nestedIgnored...)
					return filepath.SkipDir
				}
				if strings.EqualFold(filepath.Ext(path), ".json") {
					if err := budget.accept(path, entry); err != nil {
						return err
					}
					ignoredDocuments = append(ignoredDocuments, schemaValidationIgnoredDocument{File: displayPath, Pattern: pattern})
				}
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			if err := budget.accept(path, entry); err != nil {
				return err
			}
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return paths, ignoredDocuments, nil
}

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

func (budget *schemaValidationDirectoryScanBudget) accept(path string, entry os.DirEntry) error {
	budget.files++
	if budget.files > maxSchemaValidationDirectoryFiles {
		return fmt.Errorf("schema validation directory file count limit exceeded: max %d", maxSchemaValidationDirectoryFiles)
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	size := info.Size()
	if size > maxSchemaValidationDirectoryFileBytes {
		return fmt.Errorf("schema validation directory file size limit exceeded for %s: max %d bytes", filepath.ToSlash(path), maxSchemaValidationDirectoryFileBytes)
	}
	budget.totalBytes += size
	if budget.totalBytes > maxSchemaValidationDirectoryTotalBytes {
		return fmt.Errorf("schema validation directory total byte limit exceeded: max %d bytes", maxSchemaValidationDirectoryTotalBytes)
	}
	return nil
}

func collectIgnoredSchemaValidationJSON(root string, ignoredRoot string, pattern string, budget *schemaValidationDirectoryScanBudget) ([]schemaValidationIgnoredDocument, error) {
	var documents []schemaValidationIgnoredDocument
	if err := filepath.WalkDir(ignoredRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("schema validation directory symlink is not allowed: %s", filepath.ToSlash(path))
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		if err := budget.accept(path, entry); err != nil {
			return err
		}
		displayPath, err := schemaValidationDisplayPath(root, path)
		if err != nil {
			return err
		}
		documents = append(documents, schemaValidationIgnoredDocument{File: displayPath, Pattern: pattern})
		return nil
	}); err != nil {
		return nil, err
	}
	return documents, nil
}

func normalizeSchemaValidationIgnorePatterns(patterns []string) ([]string, error) {
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		value := strings.TrimSpace(pattern)
		displayPath := filepath.ToSlash(filepath.Clean(value))
		if value == "" || displayPath == "." || displayPath == ".." || strings.HasPrefix(displayPath, "../") || strings.HasPrefix(displayPath, "/") || strings.Contains(value, "\\") || filepath.IsAbs(value) {
			return nil, fmt.Errorf("invalid ignore pattern %q", pattern)
		}
		normalized = append(normalized, displayPath)
	}
	return normalized, nil
}

func normalizeSchemaValidationSchemaFilters(values []string) ([]string, error) {
	filters := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("invalid schema filter %q", raw)
		}
		if !schema.KnownSchemaID(value) {
			return nil, fmt.Errorf("unknown schema filter %q", value)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		filters = append(filters, value)
	}
	return filters, nil
}

func schemaValidationPathIgnored(displayPath string, ignored []string) bool {
	_, ok := schemaValidationIgnoredByPattern(displayPath, ignored)
	return ok
}

func schemaValidationIgnoredByPattern(displayPath string, ignored []string) (string, bool) {
	for _, pattern := range ignored {
		if displayPath == pattern || strings.HasPrefix(displayPath, pattern+"/") {
			return pattern, true
		}
	}
	return "", false
}

func readSchemaValidationManifest(manifestPath string) ([]schemaValidationInputDocument, error) {
	bytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read schema validation manifest: %w", err)
	}
	baseDir := filepath.Dir(manifestPath)
	lines := strings.Split(string(bytes), "\n")
	documents := make([]schemaValidationInputDocument, 0, len(lines))
	for index, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		displayPath := filepath.ToSlash(filepath.Clean(entry))
		if displayPath == "." || displayPath == ".." || strings.HasPrefix(displayPath, "../") || strings.Contains(entry, "\\") || filepath.IsAbs(entry) {
			return nil, fmt.Errorf("invalid manifest entry on line %d: %q", index+1, entry)
		}
		documents = append(documents, schemaValidationInputDocument{
			Path:        filepath.Join(baseDir, filepath.FromSlash(displayPath)),
			DisplayPath: displayPath,
		})
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("no schema documents listed in %s", manifestPath)
	}
	return documents, nil
}

func runPolicyExplain(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *evidencePath == "" {
		fmt.Fprintln(stderr, "--evidence is required")
		return 2
	}
	evidence, err := readEvidencePackFile(*evidencePath)
	if err != nil {
		fmt.Fprintf(stderr, "read evidence: %v\n", err)
		return 1
	}
	report := policyExplainReport{
		SchemaVersion:      schema.PolicyExplainResultSchemaID,
		PolicyExplanations: policy.ExplainDecisions(evidence.PolicyDecisions),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicyExplainResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy explanations: %v\n", err)
			return 1
		}
		return 0
	}
	printPolicyExplanations(stdout, report.PolicyExplanations)
	return 0
}

func runPolicyIndex(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy index", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	bundlePath := flags.String("bundle", "", "path to evidence bundle zip")
	publicKeyPath := flags.String("public-key", "", "path to public key for signed bundles")
	taskID := flags.String("task", "", "filter by task id")
	effectType := flags.String("effect", "", "filter by side effect type")
	resource := flags.String("resource", "", "filter by side effect resource")
	decision := flags.String("decision", "", "filter by decision allow or deny")
	approvalState := flags.String("approval", "", "filter by approval state: with-ticket or without-ticket")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if (*evidencePath == "" && *bundlePath == "") || (*evidencePath != "" && *bundlePath != "") {
		fmt.Fprintln(stderr, "provide exactly one of --evidence or --bundle")
		return 2
	}
	if *approvalState != "" && *approvalState != policy.ApprovalStateWithTicket && *approvalState != policy.ApprovalStateWithoutTicket {
		fmt.Fprintf(stderr, "--approval must be %q or %q\n", policy.ApprovalStateWithTicket, policy.ApprovalStateWithoutTicket)
		return 2
	}
	decisions, err := readPolicyIndexDecisions(*evidencePath, *bundlePath, *publicKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read policy source: %v\n", err)
		return 1
	}
	decisions = policy.FilterDecisions(decisions, policy.DecisionFilters{
		TaskID:        *taskID,
		EffectType:    *effectType,
		Resource:      *resource,
		Decision:      *decision,
		ApprovalState: *approvalState,
	})
	report := policyIndexReport{
		SchemaVersion:      schema.PolicyIndexResultSchemaID,
		PolicyCount:        len(decisions),
		PolicyDecisions:    decisions,
		PolicyExplanations: policy.ExplainDecisions(decisions),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicyIndexResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy index: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "policy_count=%d\n", report.PolicyCount)
	printPolicyExplanations(stdout, report.PolicyExplanations)
	return 0
}

func readPolicyIndexDecisions(evidencePath string, bundlePath string, publicKeyPath string) ([]policy.Decision, error) {
	if evidencePath != "" {
		evidence, err := readEvidencePackFile(evidencePath)
		if err != nil {
			return nil, fmt.Errorf("read evidence: %w", err)
		}
		return evidence.PolicyDecisions, nil
	}
	report, err := bundlepkg.Report(bundlepkg.ReportOptions{
		BundlePath:    bundlePath,
		PublicKeyPath: publicKeyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return report.PolicyDecisions, nil
}

func runPolicySpine(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy spine", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := policy.AO2FirstSpine(schema.PolicySpineResultSchemaID)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicySpineResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy spine: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "stack=%s\n", report.Stack)
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "active_repositories=%s\n", strings.Join(report.Scope.ActiveRepositories, ","))
	for _, responsibility := range report.Responsibilities {
		fmt.Fprintf(stdout, "responsibility=%s owner=%s gates=%s\n", responsibility.Name, responsibility.Owner, strings.Join(responsibility.Gates, ";"))
	}
	for _, boundary := range report.OutOfBounds {
		fmt.Fprintf(stdout, "out_of_bounds=%s\n", boundary)
	}
	return 0
}

func runPolicyCredentialChecklist(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy credential-checklist", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := policy.ScopedCredentialPolicyChecklist(schema.ScopedCredentialPolicyChecklistSchemaID)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.ScopedCredentialPolicyChecklistSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write credential checklist: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "scope=%s\n", report.Scope)
	fmt.Fprintf(stdout, "credential_values_inspected=%t\n", report.CredentialValuesInspected)
	fmt.Fprintf(stdout, "requires_credential_material=%t\n", report.RequiresCredentialMaterial)
	for _, check := range report.Checks {
		fmt.Fprintf(stdout, "check=%s status=%s requires_credential_value=%t\n", check.ID, check.Status, check.RequiresCredentialValue)
	}
	return 0
}

func runPolicyClaimPublishGate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy claim-publish-gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	claimReadinessPath := flags.String("claim-readiness", "", "path to AO2 RSI claim-readiness summary JSON")
	readbackIndexPath := flags.String("readback-index", "", "path to AO2 live self-change readback index summary JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *claimReadinessPath == "" {
		fmt.Fprintln(stderr, "--claim-readiness is required")
		return 2
	}
	if *readbackIndexPath == "" {
		fmt.Fprintln(stderr, "--readback-index is required")
		return 2
	}
	claimReadiness, err := readJSONObjectFile(*claimReadinessPath)
	if err != nil {
		fmt.Fprintf(stderr, "read claim readiness: %v\n", err)
		return 1
	}
	readbackIndex, err := readJSONObjectFile(*readbackIndexPath)
	if err != nil {
		fmt.Fprintf(stderr, "read readback index: %v\n", err)
		return 1
	}
	report := policy.EvaluateRSIClaimPublishGate(policy.ClaimPublishGateInput{
		ClaimReadiness: claimReadiness,
		ReadbackIndex:  readbackIndex,
	})
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.RSIClaimPublishGateSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy claim-publish gate: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "decision=%s\n", report.Decision)
	fmt.Fprintf(stdout, "publish_authority=%t\n", report.PublishAuthority)
	fmt.Fprintf(stdout, "claim_level=%s\n", report.ClaimLevel)
	fmt.Fprintf(stdout, "claim_publish_resource=%s\n", report.ClaimPublishResource)
	for _, blocker := range report.Blockers {
		fmt.Fprintf(stdout, "blocker=%s evidence_state=%s required_evidence=%s\n", blocker.ID, blocker.EvidenceState, blocker.RequiredEvidence)
	}
	return 0
}

func readJSONObjectFile(path string) (map[string]any, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func runApprovalCreate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	taskID := flags.String("task", "", "task id")
	effectType := flags.String("effect", "", "side effect type")
	resource := flags.String("resource", "", "side effect resource")
	reason := flags.String("reason", "", "approval reason")
	outPath := flags.String("out", "", "path to write approval ticket JSON")
	ticketID := flags.String("ticket-id", "", "approval ticket id")
	approved := flags.Bool("approved", true, "whether the ticket approves the effect")
	operatorID := flags.String("operator", "", "operator identity approving the ticket")
	expiresAt := flags.String("expires-at", "", "RFC3339 timestamp when the approval expires")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *taskID == "" || *effectType == "" || *resource == "" || *reason == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--task, --effect, --resource, --reason, and --out are required")
		return 2
	}
	ticket, err := approval.Create(approval.CreateInput{
		TicketID:   *ticketID,
		TaskID:     *taskID,
		EffectType: *effectType,
		Resource:   *resource,
		Approved:   *approved,
		Reason:     *reason,
		OperatorID: *operatorID,
		ExpiresAt:  *expiresAt,
	})
	if err != nil {
		fmt.Fprintf(stderr, "create approval ticket: %v\n", err)
		return 1
	}
	ticketBytes, err := marshalSchemaJSONBytes(schema.ApprovalTicketSchemaID, ticket)
	if err != nil {
		fmt.Fprintf(stderr, "encode approval ticket: %v\n", err)
		return 1
	}
	if err := writeOutputFileBytes("approval create", *outPath, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "write approval ticket: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalCreateResult{
			SchemaVersion: schema.ApprovalCreateResultSchemaID,
			TicketPath:    *outPath,
			Ticket:        ticket,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalCreateResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval create result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "ticket=%s\n", *outPath)
	fmt.Fprintf(stdout, "ticket_id=%s\n", ticket.TicketID)
	if ticket.OperatorID != "" {
		fmt.Fprintf(stdout, "operator_id=%s\n", ticket.OperatorID)
	}
	if ticket.ExpiresAt != "" {
		fmt.Fprintf(stdout, "expires_at=%s\n", ticket.ExpiresAt)
	}
	return 0
}

func runApprovalInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.ApprovalTicketSchemaID, ticket); err != nil {
			fmt.Fprintf(stderr, "write approval ticket: %v\n", err)
			return 1
		}
		return 0
	}
	printTicket(stdout, ticket)
	return 0
}

func runApprovalValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	contractPath := flags.String("contract", "", "path to contract JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if *contractPath != "" {
		c, err := readContractFile(*contractPath)
		if err != nil {
			fmt.Fprintf(stderr, "read contract: %v\n", err)
			return 1
		}
		if err := approval.ValidateAgainstContract(c, ticket); err != nil {
			fmt.Fprintf(stderr, "validate approval ticket: %v\n", err)
			return 1
		}
	}
	if *jsonOutput {
		result := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      ticket.TicketID,
			ContractPath:  *contractPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", ticket.TicketID)
	return 0
}

func runApprovalLiveDocs(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalLiveDocsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalLiveDocsValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval live-docs command %q\n", args[0])
		printApprovalLiveDocsUsage(stderr)
		return 2
	}
}

func runApprovalLowRiskCodeLive(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalLowRiskCodeLiveUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalLowRiskCodeLiveValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval low-risk-code-live command %q\n", args[0])
		printApprovalLowRiskCodeLiveUsage(stderr)
		return 2
	}
}

func runApprovalMutationClass(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalMutationClassUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalMutationClassValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval mutation-class command %q\n", args[0])
		printApprovalMutationClassUsage(stderr)
		return 2
	}
}

func runApprovalMutationClassValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval mutation-class validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "path to Foundry mutation-class authority request JSON")
	ticketPath := flags.String("ticket", "", "path to Covenant mutation-class authority ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *requestPath == "" {
		fmt.Fprintln(stderr, "--request is required")
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	request, err := readJSONObjectFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "read mutation-class authority request: %v\n", err)
		return 1
	}
	ticketBytes, err := os.ReadFile(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read mutation-class authority ticket: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.MutationClassAuthorityTicketSchemaID, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "validate mutation-class authority ticket schema: %v\n", err)
		return 1
	}
	var ticket map[string]any
	if err := json.Unmarshal(ticketBytes, &ticket); err != nil {
		fmt.Fprintf(stderr, "decode mutation-class authority ticket: %v\n", err)
		return 1
	}
	if err := validateMutationClassAuthorityTicket(request, ticket, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate mutation-class authority ticket: %v\n", err)
		return 1
	}
	result := mutationClassAuthorityValidateResult{
		SchemaVersion: schema.ApprovalValidateResultSchemaID,
		Valid:         true,
		TicketID:      stringField(ticket, "ticket_id"),
		RequestID:     stringField(ticket, "request_id"),
		MutationClass: stringField(ticket, "mutation_class"),
		SafeToRequest: boolField(request, "safe_to_request"),
		SafeToExecute: false,
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.TicketID,
			ContractPath:  *requestPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write mutation-class authority validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", result.TicketID)
	fmt.Fprintf(stdout, "request_id=%s\n", result.RequestID)
	fmt.Fprintf(stdout, "mutation_class=%s\n", result.MutationClass)
	fmt.Fprintf(stdout, "safe_to_request=%t\n", result.SafeToRequest)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	return 0
}

func runApprovalLowRiskCodeLiveValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval low-risk-code-live validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "path to Covenant low_risk_code live policy evidence JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "--policy is required")
		return 2
	}
	policyBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read low_risk_code live policy: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.LowRiskCodeLivePolicySchemaID, policyBytes); err != nil {
		fmt.Fprintf(stderr, "validate low_risk_code live policy schema: %v\n", err)
		return 1
	}
	var policy map[string]any
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		fmt.Fprintf(stderr, "decode low_risk_code live policy: %v\n", err)
		return 1
	}
	if err := validateLowRiskCodeLivePolicy(policy, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate low_risk_code live policy: %v\n", err)
		return 1
	}
	candidateScope, _ := policy["candidate_scope"].(map[string]any)
	repo, _ := candidateScope["repo"].(map[string]any)
	fileAllowlist, _ := stringSliceField(candidateScope["file_allowlist"])
	commandAllowlist, _ := stringSliceField(candidateScope["command_allowlist"])
	boundaries, _ := policy["authority_boundaries"].(map[string]any)
	result := lowRiskCodeLivePolicyValidateResult{
		SchemaVersion:     schema.ApprovalValidateResultSchemaID,
		Valid:             true,
		PolicyID:          stringField(policy, "policy_id"),
		MutationClass:     stringField(policy, "mutation_class"),
		CandidateRepo:     stringField(repo, "id"),
		BaseBranch:        stringField(candidateScope, "base_branch"),
		ProposedBranch:    stringField(candidateScope, "proposed_branch"),
		FileAllowlist:     fileAllowlist,
		CommandAllowlist:  commandAllowlist,
		SafeToRequest:     boolField(policy, "safe_to_request"),
		SafeToExecute:     boolField(policy, "safe_to_execute"),
		LiveMutationGrant: boolField(boundaries, "live_mutation_grant"),
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.PolicyID,
			ContractPath:  *policyPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write low_risk_code live policy validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "policy_id=%s\n", result.PolicyID)
	fmt.Fprintf(stdout, "mutation_class=%s\n", result.MutationClass)
	fmt.Fprintf(stdout, "candidate_repo=%s\n", result.CandidateRepo)
	fmt.Fprintf(stdout, "base_branch=%s\n", result.BaseBranch)
	fmt.Fprintf(stdout, "proposed_branch=%s\n", result.ProposedBranch)
	for _, path := range result.FileAllowlist {
		fmt.Fprintf(stdout, "file_allowlist=%s\n", path)
	}
	for _, command := range result.CommandAllowlist {
		fmt.Fprintf(stdout, "command_allowlist=%s\n", command)
	}
	fmt.Fprintf(stdout, "safe_to_request=%t\n", result.SafeToRequest)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	fmt.Fprintf(stdout, "live_mutation_grant=%t\n", result.LiveMutationGrant)
	return 0
}

func runApprovalLiveDocsValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval live-docs validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "path to Foundry live docs approval request JSON")
	ticketPath := flags.String("ticket", "", "path to Covenant live docs approval ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *requestPath == "" {
		fmt.Fprintln(stderr, "--request is required")
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	request, err := readJSONObjectFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval request: %v\n", err)
		return 1
	}
	ticketBytes, err := os.ReadFile(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.LiveDocsApprovalTicketSchemaID, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "validate approval ticket schema: %v\n", err)
		return 1
	}
	var ticket map[string]any
	if err := json.Unmarshal(ticketBytes, &ticket); err != nil {
		fmt.Fprintf(stderr, "decode approval ticket: %v\n", err)
		return 1
	}
	if err := validateLiveDocsApprovalTicket(request, ticket, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate live docs approval ticket: %v\n", err)
		return 1
	}
	result := liveDocsApprovalValidateResult{
		SchemaVersion: schema.ApprovalValidateResultSchemaID,
		Valid:         true,
		TicketID:      stringField(ticket, "ticket_id"),
		RequestID:     stringField(ticket, "request_id"),
		ApprovalState: stringField(ticket, "approval_state"),
		SafeToExecute: true,
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.TicketID,
			ContractPath:  *requestPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write approval validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", result.TicketID)
	fmt.Fprintf(stdout, "request_id=%s\n", result.RequestID)
	fmt.Fprintf(stdout, "approval_state=%s\n", result.ApprovalState)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	return 0
}

func validateLiveDocsApprovalTicket(request map[string]any, ticket map[string]any, now time.Time) error {
	if stringField(request, "schema_version") != "ao.foundry.live-mutation-approval-request.v0.1" {
		return fmt.Errorf("request schema_version must be ao.foundry.live-mutation-approval-request.v0.1")
	}
	if stringField(request, "status") != "pending_operator_approval" {
		return fmt.Errorf("request status must be pending_operator_approval")
	}
	if stringField(request, "first_live_class") != "docs_only" || boolField(request, "safe_to_request") != true || boolField(request, "safe_to_execute") != false {
		return fmt.Errorf("request must be safe_to_request=true, safe_to_execute=false, first_live_class=docs_only")
	}
	if stringField(ticket, "request_id") != stringField(request, "request_id") {
		return fmt.Errorf("ticket request_id does not match request")
	}
	if stringField(ticket, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(ticket, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(ticket, "consumed") {
		return fmt.Errorf("approval ticket has already been consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339, stringField(ticket, "expires_at"))
	if err != nil {
		return fmt.Errorf("approval ticket expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("approval ticket expired")
	}
	if stringField(ticket, "foundry_required_ticket_schema") != "ao.covenant.live-docs-approval-ticket.v0.1" {
		return fmt.Errorf("foundry_required_ticket_schema does not match request expectation")
	}
	ticketScope, ok := ticket["approved_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("approved_scope is required")
	}
	for _, field := range []string{"repo", "branch_policy", "docs_only_path_allowlist", "forbidden_paths", "max_changed_files"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match request")
		}
	}
	return nil
}

func validateMutationClassAuthorityTicket(request map[string]any, ticket map[string]any, now time.Time) error {
	if stringField(request, "schema_version") != "ao.foundry.mutation-class-authority-request.v0.1" {
		return fmt.Errorf("request schema_version must be ao.foundry.mutation-class-authority-request.v0.1")
	}
	if stringField(request, "status") != "pending_covenant_authority" {
		return fmt.Errorf("request status must be pending_covenant_authority")
	}
	requestClass := stringField(request, "mutation_class")
	if !validMutationClass(requestClass) {
		return fmt.Errorf("request mutation_class is not supported")
	}
	if boolField(request, "safe_to_request") != true || boolField(request, "safe_to_execute") != false {
		return fmt.Errorf("request must be safe_to_request=true and safe_to_execute=false")
	}
	if stringField(ticket, "request_id") != stringField(request, "request_id") {
		return fmt.Errorf("ticket request_id does not match request")
	}
	if stringField(ticket, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(ticket, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(ticket, "consumed") {
		return fmt.Errorf("authority ticket has already been consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339, stringField(ticket, "expires_at"))
	if err != nil {
		return fmt.Errorf("authority ticket expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("authority ticket expired")
	}
	if stringField(ticket, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	ticketScope, ok := ticket["approved_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("approved_scope is required")
	}
	if stringField(ticketScope, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	if !jsonEquivalent(ticketScope["allowed_paths"], request["allowed_paths"]) {
		return fmt.Errorf("ticket path scope is broader than request")
	}
	if !jsonEquivalent(ticketScope["max_changed_files"], request["max_changed_files"]) {
		return fmt.Errorf("ticket diff limit does not exactly match request")
	}
	for _, field := range []string{"repo", "branch_policy", "forbidden_paths", "required_gates", "authority_boundary"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match request")
		}
	}
	if boolField(request, "rollback_required") != true || boolField(ticketScope, "rollback_required") != true {
		return fmt.Errorf("rollback is required for mutation-class authority tickets")
	}
	for _, field := range []string{"rollback_scope", "rollback_evidence"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket rollback scope does not exactly match request")
		}
	}
	if requestClass == "multi_repo_low_risk" {
		if err := validateMultiRepoLowRiskAuthorityScope(request, ticketScope, now); err != nil {
			return err
		}
	}
	digest, ok := ticket["scope_digest"].(map[string]any)
	if !ok {
		return fmt.Errorf("scope_digest is required")
	}
	if stringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "approved_scope") {
		return fmt.Errorf("scope_digest must cover approved_scope")
	}
	expected, err := digestApprovedScope(ticketScope)
	if err != nil {
		return err
	}
	if stringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match approved_scope")
	}
	boundaries, ok := ticket["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use"} {
		if !boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "provider_calls_allowed", "release_or_publish_allowed"} {
		if boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be false", field)
		}
	}
	return nil
}

func validateLowRiskCodeLivePolicy(policy map[string]any, now time.Time) error {
	if stringField(policy, "schema_version") != schema.LowRiskCodeLivePolicySchemaID {
		return fmt.Errorf("schema_version must be %s", schema.LowRiskCodeLivePolicySchemaID)
	}
	if stringField(policy, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(policy, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(policy, "consumed") {
		return fmt.Errorf("low_risk_code live policy has already been consumed")
	}
	if stringField(policy, "mutation_class") != "low_risk_code" {
		return fmt.Errorf("mutation_class must be low_risk_code")
	}
	if boolField(policy, "safe_to_request") != true || boolField(policy, "safe_to_execute") != false {
		return fmt.Errorf("policy must be safe_to_request=true and safe_to_execute=false")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, stringField(policy, "issued_at"))
	expiresAt, expiresErr := time.Parse(time.RFC3339, stringField(policy, "expires_at"))
	if issuedErr != nil || expiresErr != nil {
		return fmt.Errorf("policy issued_at and expires_at must be RFC3339")
	}
	if issuedAt.After(now) || !expiresAt.After(now) {
		return fmt.Errorf("low_risk_code live policy is stale or not yet valid")
	}
	candidateScope, ok := policy["candidate_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("candidate_scope is required")
	}
	if err := validateLowRiskCodeLiveCandidateScope(candidateScope); err != nil {
		return err
	}
	digest, ok := policy["scope_digest"].(map[string]any)
	if !ok {
		return fmt.Errorf("scope_digest is required")
	}
	if stringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "candidate_scope") {
		return fmt.Errorf("scope_digest must cover candidate_scope")
	}
	expected, err := digestApprovedScope(candidateScope)
	if err != nil {
		return err
	}
	if stringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match candidate_scope")
	}
	boundaries, ok := policy["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use", "single_repo", "single_branch"} {
		if !boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "multi_repo_mutation_allowed", "complex_repo_mutation_allowed", "fully_unsupervised_complex_mutation_allowed", "provider_calls_allowed", "release_or_publish_allowed"} {
		if boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be false", field)
		}
	}
	return nil
}

func validateLowRiskCodeLiveCandidateScope(scope map[string]any) error {
	chain, ok := scope["dry_run_chain"].(map[string]any)
	if !ok {
		return fmt.Errorf("dry_run_chain is required")
	}
	if stringField(chain, "path") != "tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json" {
		return fmt.Errorf("dry_run_chain path must be tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json")
	}
	if stringField(chain, "sha256") != "046dcdc9a17fcfd60877c8e61d1a15c722f7c34cacdeeb139651f153c6e1196e" {
		return fmt.Errorf("dry_run_chain sha256 must match current held rehearsal chain")
	}
	repo, ok := scope["repo"].(map[string]any)
	if !ok {
		return fmt.Errorf("repo is required")
	}
	if stringField(repo, "id") != "ao-atlas" {
		return fmt.Errorf("repo id must be ao-atlas")
	}
	if stringField(repo, "remote") != "uesugitorachiyo/ao-atlas" {
		return fmt.Errorf("repo remote must be uesugitorachiyo/ao-atlas")
	}
	if stringField(scope, "base_branch") != "main" {
		return fmt.Errorf("base_branch must be main")
	}
	if stringField(scope, "proposed_branch") != "codex/low-risk-code-rehearsal-one" {
		return fmt.Errorf("proposed_branch must be codex/low-risk-code-rehearsal-one")
	}
	if stringField(scope, "intent") != "behavior-preserving cleanup in internal uniqueStrings helper" {
		return fmt.Errorf("intent must match selected held candidate")
	}
	if err := requireExactStringSlice(scope["file_allowlist"], []string{"internal/atlas/validate.go"}, "file_allowlist"); err != nil {
		return err
	}
	if err := requireExactStringSlice(scope["command_allowlist"], []string{"git diff --check", "go test ./..."}, "command_allowlist"); err != nil {
		return err
	}
	rollbackPlan, ok := scope["rollback_plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("rollback_plan is required")
	}
	if !boolField(rollbackPlan, "required") {
		return fmt.Errorf("rollback_plan required must be true")
	}
	if stringField(rollbackPlan, "strategy") == "" {
		return fmt.Errorf("rollback_plan strategy is required")
	}
	if err := requireExactStringSlice(rollbackPlan["scope"], []string{"internal/atlas/validate.go"}, "rollback_plan scope"); err != nil {
		return err
	}
	return nil
}

func validateMultiRepoLowRiskAuthorityScope(request map[string]any, ticketScope map[string]any, now time.Time) error {
	for _, field := range []string{"multi_repo_plan", "per_repo_rollback", "ci_by_repo", "repo_state_evidence", "kill_switch"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match multi_repo_low_risk request")
		}
	}
	plan, ok := ticketScope["multi_repo_plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("multi_repo_low_risk ordered merge plan is required")
	}
	if stringField(plan, "status") != "ready" {
		return fmt.Errorf("multi_repo_low_risk ordered merge plan is not ready")
	}
	plannedRepos, err := validateOrderedMultiRepoPlan(plan)
	if err != nil {
		return err
	}
	if err := validatePerRepoRollback(plannedRepos, ticketScope["per_repo_rollback"]); err != nil {
		return err
	}
	if err := validatePerRepoCI(plannedRepos, ticketScope["ci_by_repo"]); err != nil {
		return err
	}
	if err := validateFreshRepoState(plannedRepos, ticketScope["repo_state_evidence"], now); err != nil {
		return err
	}
	killSwitch, ok := ticketScope["kill_switch"].(map[string]any)
	if !ok || !boolField(killSwitch, "required") || stringField(killSwitch, "status") != "armed" {
		return fmt.Errorf("operator kill-switch must be armed for multi_repo_low_risk")
	}
	return nil
}

func validateOrderedMultiRepoPlan(plan map[string]any) ([]string, error) {
	order, ok := stringSliceField(plan["order"])
	if !ok || len(order) == 0 {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	entries, ok := mapSliceField(plan["ordered_merge_plan"])
	if !ok || len(entries) != len(order) {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	seen := map[string]bool{}
	repos := make([]string, 0, len(entries))
	for index, entry := range entries {
		repo := stringField(entry, "repo")
		if repo == "" || repo != order[index] || intField(entry, "order") != index+1 || stringField(entry, "planned_pr") == "" {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		dependencies, ok := stringSliceField(entry["depends_on"])
		if !ok {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		mergeAfter, ok := stringSliceField(entry["merge_after"])
		if !ok || !jsonEquivalent(entry["depends_on"], entry["merge_after"]) {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		for _, dependency := range dependencies {
			if !seen[dependency] {
				return nil, fmt.Errorf("ordered dependency is missing or not earlier")
			}
		}
		for _, dependency := range mergeAfter {
			if !seen[dependency] {
				return nil, fmt.Errorf("ordered dependency is missing or not earlier")
			}
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	return repos, nil
}

func validatePerRepoRollback(repos []string, value any) error {
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("per-repo rollback is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		scope, _ := stringSliceField(entry["rollback_scope"])
		if entry == nil || stringField(entry, "status") != "ready" || len(scope) == 0 {
			return fmt.Errorf("per-repo rollback is incomplete")
		}
	}
	return nil
}

func validatePerRepoCI(repos []string, value any) error {
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("per-repo CI is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		status := stringField(entry, "status")
		if entry == nil || !boolField(entry, "required") || (status != "passed" && status != "success") {
			return fmt.Errorf("per-repo CI is incomplete")
		}
	}
	return nil
}

func validateFreshRepoState(repos []string, value any, now time.Time) error {
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("repo state evidence is stale")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		if entry == nil || stringField(entry, "status") != "clean_synced" || stringField(entry, "branch") != "main" {
			return fmt.Errorf("repo state evidence is stale")
		}
		observedAt, observedErr := time.Parse(time.RFC3339, stringField(entry, "observed_at_utc"))
		expiresAt, expiresErr := time.Parse(time.RFC3339, stringField(entry, "expires_at_utc"))
		if observedErr != nil || expiresErr != nil || observedAt.After(now) || !expiresAt.After(now) {
			return fmt.Errorf("repo state evidence is stale")
		}
	}
	return nil
}

func validMutationClass(value string) bool {
	switch value {
	case "docs_only_single_file",
		"docs_only_multi_file",
		"docs_config_only",
		"test_only",
		"low_risk_code",
		"multi_repo_low_risk",
		"complex_repo_mutation":
		return true
	default:
		return false
	}
}

func digestApprovedScope(scope map[string]any) (string, error) {
	bytes, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("encode approved_scope for digest: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func stringArrayContains(value any, want string) bool {
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, raw := range values {
		if raw == want {
			return true
		}
	}
	return false
}

func requireExactStringSlice(value any, want []string, label string) error {
	got, ok := stringSliceField(value)
	if !ok {
		return fmt.Errorf("%s must be a string array", label)
	}
	if len(got) != len(want) {
		return fmt.Errorf("%s must exactly match selected held candidate", label)
	}
	for index := range want {
		if got[index] != want[index] {
			return fmt.Errorf("%s must exactly match selected held candidate", label)
		}
	}
	return nil
}

func stringField(document map[string]any, key string) string {
	value, _ := document[key].(string)
	return value
}

func boolField(document map[string]any, key string) bool {
	value, _ := document[key].(bool)
	return value
}

func intField(document map[string]any, key string) int {
	switch value := document[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func stringSliceField(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

func mapSliceField(value any) ([]map[string]any, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	values := make([]map[string]any, 0, len(items))
	for _, item := range items {
		document, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		values = append(values, document)
	}
	return values, true
}

func jsonEquivalent(left any, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func runApprovalAttach(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval attach", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to contract JSON")
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	outPath := flags.String("out", "", "path to write approved contract JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *contractPath == "" || *ticketPath == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--contract, --ticket, and --out are required")
		return 2
	}
	c, err := readContractFile(*contractPath)
	if err != nil {
		fmt.Fprintf(stderr, "read contract: %v\n", err)
		return 1
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	approvedContract, err := approval.Attach(c, ticket)
	if err != nil {
		fmt.Fprintf(stderr, "attach approval ticket: %v\n", err)
		return 1
	}
	contractBytes, err := marshalSchemaJSONBytes(schema.ContractSchemaID, approvedContract)
	if err != nil {
		fmt.Fprintf(stderr, "encode contract: %v\n", err)
		return 1
	}
	digest, err := contract.Digest(approvedContract)
	if err != nil {
		fmt.Fprintf(stderr, "digest contract: %v\n", err)
		return 1
	}
	if err := writeOutputPairWithRollback("approval attach", *outPath, contractBytes, *outPath+".sha256", []byte(digest+"\n")); err != nil {
		if outputPairErrorStage(err) == outputPairStageSidecar {
			fmt.Fprintf(stderr, "write digest: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "write contract: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalAttachResult{
			SchemaVersion:  schema.ApprovalAttachResultSchemaID,
			ContractPath:   *outPath,
			ContractDigest: digest,
			ApprovalCount:  len(approvedContract.Approvals),
			TicketID:       ticket.TicketID,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalAttachResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval attach result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "contract=%s\n", *outPath)
	fmt.Fprintf(stdout, "contract_digest=%s\n", digest)
	fmt.Fprintf(stdout, "approvals=%d\n", len(approvedContract.Approvals))
	return 0
}

func runApprovalRevoke(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketID := flags.String("ticket-id", "", "approval ticket id to revoke")
	reason := flags.String("reason", "", "revocation reason")
	outPath := flags.String("out", "", "path to write approval revocation list JSON")
	appendToExisting := flags.Bool("append", false, "append to an existing revocation list")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketID == "" || *reason == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--ticket-id, --reason, and --out are required")
		return 2
	}

	list := approval.RevocationList{
		SchemaVersion: schema.ApprovalRevocationsSchemaID,
		RevokedTickets: []approval.RevokedTicket{
			{
				TicketID: *ticketID,
				Reason:   *reason,
			},
		},
	}
	if *appendToExisting {
		existing, err := approval.ReadRevocationList(*outPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "read approval revocation list: %v\n", err)
			return 1
		}
		if err == nil {
			list = existing
			list.RevokedTickets = append(list.RevokedTickets, approval.RevokedTicket{
				TicketID: *ticketID,
				Reason:   *reason,
			})
		}
	}
	if err := approval.ValidateRevocationList(list); err != nil {
		fmt.Fprintf(stderr, "validate approval revocation list: %v\n", err)
		return 1
	}
	revocationBytes, err := marshalSchemaJSONBytes(schema.ApprovalRevocationsSchemaID, list)
	if err != nil {
		fmt.Fprintf(stderr, "encode approval revocation list: %v\n", err)
		return 1
	}
	if err := writeOutputFileBytes("approval revoke", *outPath, revocationBytes); err != nil {
		fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalRevokeResult{
			SchemaVersion:      schema.ApprovalRevokeResultSchemaID,
			RevocationsPath:    *outPath,
			RevokedTicketCount: len(list.RevokedTickets),
			TicketID:           *ticketID,
			Revocations:        list,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalRevokeResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "revocations=%s\n", *outPath)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", len(list.RevokedTickets))
	fmt.Fprintf(stdout, "ticket_id=%s\n", *ticketID)
	return 0
}

func runApprovalRevocations(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalRevocationsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "inspect":
		return runApprovalRevocationsInspect(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval revocations command %q\n", args[0])
		printApprovalRevocationsUsage(stderr)
		return 2
	}
}

func runApprovalRevocationsInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval revocations inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "path to approval revocation list JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(stderr, "--file is required")
		return 2
	}
	list, err := approval.ReadRevocationList(*filePath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval revocation list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalRevocationsInspectResult{
			SchemaVersion:      schema.ApprovalRevocationsInspectResultSchemaID,
			RevocationsPath:    *filePath,
			RevokedTicketCount: len(list.RevokedTickets),
			Revocations:        list,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalRevocationsInspectResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
			return 1
		}
		return 0
	}
	printRevocationListSummary(stdout, list)
	return 0
}

func printRevocationListSummary(stdout io.Writer, list approval.RevocationList) {
	fmt.Fprintf(stdout, "schema_version=%s\n", list.SchemaVersion)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", len(list.RevokedTickets))
	for _, revoked := range list.RevokedTickets {
		fmt.Fprintf(stdout, "ticket_id=%s reason=%s\n", revoked.TicketID, revoked.Reason)
	}
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

func writeReleaseReport(stdout io.Writer, result releasepkg.InspectResult, redaction bundlepkg.RedactionOptions) {
	redacted := result
	if redaction.Paths || redaction.Digests {
		redacted = releasepkg.RedactInspect(result, releasepkg.RedactionOptions{Paths: redaction.Paths, Digests: redaction.Digests})
	}
	summary := releasepkg.SummarizeProvenance(redacted)
	fmt.Fprintln(stdout, "AO Covenant Release Report")
	fmt.Fprintf(stdout, "release_dir: %s\n", redacted.ReleaseDir)
	fmt.Fprintf(stdout, "manifest_valid=%t\n", redacted.ManifestValid)
	manifestStatus := "invalid"
	if redacted.ManifestValid {
		manifestStatus = "valid"
	}
	fmt.Fprintf(stdout, "manifest: %s (%s)\n", redacted.ManifestPath, manifestStatus)
	fmt.Fprintf(stdout, "manifest=%s\n", redacted.ManifestPath)
	fmt.Fprintf(stdout, "checksums: %s (%s)\n", redacted.ChecksumsPath, redacted.ChecksumStatus)
	fmt.Fprintf(stdout, "checksums=%s\n", redacted.ChecksumsPath)
	fmt.Fprintf(stdout, "checksum_status=%s\n", redacted.ChecksumStatus)
	fmt.Fprintf(stdout, "signature: %s\n", defaultReleaseStatus(redacted.Signature.Status, "unsigned"))
	fmt.Fprintf(stdout, "signature=%s\n", defaultReleaseStatus(redacted.Signature.Status, "unsigned"))
	if redacted.SignaturePath != "" {
		fmt.Fprintf(stdout, "signature_file: %s\n", redacted.SignaturePath)
	}
	if redacted.Signature.PublicKeySHA256 != "" {
		key := redacted.Signature.PublicKeySHA256
		if redaction.Digests || key == strings.Repeat("0", 64) {
			key = "[REDACTED_DIGEST]"
		}
		fmt.Fprintf(stdout, "public_key_sha256: %s\n", key)
		fmt.Fprintf(stdout, "public_key_sha256=%s\n", key)
		fmt.Fprintf(stdout, "signature_public_key_sha256=%s\n", key)
	}
	fmt.Fprintf(stdout, "artifacts: %d\n", redacted.ArtifactCount)
	fmt.Fprintf(stdout, "artifact_count=%d\n", redacted.ArtifactCount)
	for _, artifact := range redacted.Artifacts {
		fmt.Fprintf(stdout, "- %s (%s/%s): %s\n", artifact.Name, artifact.Target.OS, artifact.Target.Arch, verifiedLabel(artifact.Verified))
		fmt.Fprintf(stdout, "  path: %s\n", artifact.Path)
		fmt.Fprintf(stdout, "  digest: %s\n", verifiedLabel(artifact.DigestVerified))
		fmt.Fprintf(stdout, "  size: %s\n", verifiedLabel(artifact.SizeVerified))
		fmt.Fprintf(stdout, "  checksum: %s\n", verifiedLabel(artifact.ChecksumVerified))
		fmt.Fprintf(stdout, "  metadata: %s\n", metadataLabel(artifact))
		for _, attestation := range artifact.Attestations {
			kind := attestation.Kind
			if kind == "" {
				kind = "unknown"
			}
			fmt.Fprintf(stdout, "  attestation_kind: %s\n", kind)
			fmt.Fprintf(stdout, "  attestation: %s [%s] (%s)\n", attestation.Name, kind, verifiedLabel(attestation.Verified))
		}
	}
	for _, supplemental := range redacted.SupplementalArtifacts {
		fmt.Fprintf(stdout, "supplemental_%s: %s (%s)\n", supplemental.Kind, supplemental.Name, verifiedLabel(supplemental.Verified))
	}
	fmt.Fprintln(stdout, "provenance_summary:")
	fmt.Fprintf(stdout, "  signature: %s\n", summary.SignatureStatus)
	fmt.Fprintf(stdout, "  attestations: %d verified, %d invalid\n", summary.AttestationVerifiedCount, summary.AttestationInvalidCount)
	fmt.Fprintf(stdout, "  supplemental_sbom: %d verified, %d invalid\n", summary.SBOMVerifiedCount, summary.SBOMInvalidCount)
	fmt.Fprintf(stdout, "  supplemental_provenance: %d verified, %d invalid\n", summary.SupplementalProvenanceVerifiedCount, summary.SupplementalProvenanceInvalidCount)
	fmt.Fprintf(stdout, "  invalid_evidence: %d\n", summary.InvalidEvidenceCount)
	if len(redacted.Problems) == 0 {
		fmt.Fprintln(stdout, "problems: none")
		return
	}
	fmt.Fprintln(stdout, "problems:")
	for _, problem := range redacted.Problems {
		fmt.Fprintf(stdout, "- %s\n", problem)
		fmt.Fprintf(stdout, "problem: %s\n", problem)
	}
}

func writeReleaseReportMarkdown(stdout io.Writer, result releasepkg.InspectResult, redaction bundlepkg.RedactionOptions) {
	redacted := result
	if redaction.Paths || redaction.Digests {
		redacted = releasepkg.RedactInspect(result, releasepkg.RedactionOptions{Paths: redaction.Paths, Digests: redaction.Digests})
	}
	summary := releasepkg.SummarizeProvenance(redacted)
	fmt.Fprintln(stdout, "# AO Covenant Release Report")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "## Summary")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "| Field | Value |")
	fmt.Fprintln(stdout, "| --- | --- |")
	manifestStatus := "invalid"
	if redacted.ManifestValid {
		manifestStatus = "valid"
	}
	fmt.Fprintf(stdout, "| Release directory | %s |\n", redacted.ReleaseDir)
	fmt.Fprintf(stdout, "| Manifest | %s (%s) |\n", redacted.ManifestPath, manifestStatus)
	fmt.Fprintf(stdout, "| Checksums | %s (%s) |\n", redacted.ChecksumsPath, redacted.ChecksumStatus)
	fmt.Fprintf(stdout, "| Signature | %s |\n", defaultReleaseStatus(redacted.Signature.Status, "unsigned"))
	fmt.Fprintf(stdout, "| Public key SHA256 | %s |\n", redacted.Signature.PublicKeySHA256)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "## Artifacts")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "| Name | Target | Status | Digest | Size | Checksum | Metadata | Path |")
	fmt.Fprintln(stdout, "| --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, artifact := range redacted.Artifacts {
		fmt.Fprintf(stdout, "| %s | %s/%s | %s | %s | %s | %s | %s | %s |\n", artifact.Name, artifact.Target.OS, artifact.Target.Arch, verifiedLabel(artifact.Verified), verifiedLabel(artifact.DigestVerified), verifiedLabel(artifact.SizeVerified), verifiedLabel(artifact.ChecksumVerified), metadataLabel(artifact), artifact.Path)
		for _, attestation := range artifact.Attestations {
			kind := attestation.Kind
			if kind == "" {
				kind = "unknown"
			}
			fmt.Fprintln(stdout)
			fmt.Fprintln(stdout, "| Artifact | Kind | Name | Status | Digest | Size | Checksum | Path |")
			fmt.Fprintln(stdout, "| --- | --- | --- | --- | --- | --- | --- | --- |")
			fmt.Fprintf(stdout, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", artifact.Name, kind, attestation.Name, verifiedLabel(attestation.Verified), verifiedLabel(attestation.DigestVerified), verifiedLabel(attestation.SizeVerified), verifiedLabel(attestation.ChecksumVerified), attestation.Path)
		}
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "## Provenance Summary")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "| Field | Value |")
	fmt.Fprintln(stdout, "| --- | --- |")
	fmt.Fprintf(stdout, "| Signature | %s |\n", summary.SignatureStatus)
	fmt.Fprintf(stdout, "| Artifact attestations | %d verified, %d invalid |\n", summary.AttestationVerifiedCount, summary.AttestationInvalidCount)
	fmt.Fprintf(stdout, "| Supplemental SBOMs | %d verified, %d invalid |\n", summary.SBOMVerifiedCount, summary.SBOMInvalidCount)
	fmt.Fprintf(stdout, "| Supplemental provenance | %d verified, %d invalid |\n", summary.SupplementalProvenanceVerifiedCount, summary.SupplementalProvenanceInvalidCount)
	fmt.Fprintf(stdout, "| Invalid provenance evidence | %d |\n", summary.InvalidEvidenceCount)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "## Problems")
	fmt.Fprintln(stdout)
	if len(redacted.Problems) == 0 {
		fmt.Fprintln(stdout, "No problems.")
		return
	}
	for _, problem := range redacted.Problems {
		fmt.Fprintf(stdout, "- %s\n", problem)
	}
}

func verifiedLabel(ok bool) string {
	if ok {
		return "verified"
	}
	return "invalid"
}

func metadataLabel(artifact releasepkg.ArtifactVerifyReport) string {
	if !artifact.HostMetadataChecked {
		return "not_checked"
	}
	return verifiedLabel(artifact.MetadataVerified)
}

func defaultReleaseStatus(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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

func printPolicyExplanations(stdout io.Writer, explanations []policy.Explanation) {
	for _, explanation := range explanations {
		fmt.Fprintf(stdout, "policy=%s task=%s decision=%s effect=%s resource=%s summary=%s\n", explanation.DecisionID, explanation.TaskID, explanation.Decision, explanation.EffectType, explanation.Resource, explanation.Summary)
		if explanation.OperatorAction != "" {
			fmt.Fprintf(stdout, "policy_action=%s action=%s\n", explanation.DecisionID, explanation.OperatorAction)
		}
	}
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant <command>")
	fmt.Fprintln(stderr, "commands: version, compile, lint, run, verify, self-run, release, bundle, approval, policy, schema")
}

func printApprovalUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval <command>")
	fmt.Fprintln(stderr, "commands: create, inspect, live-docs, mutation-class, low-risk-code-live, validate, attach, revoke, revocations")
}

func printApprovalLiveDocsUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval live-docs <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalMutationClassUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval mutation-class <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalLowRiskCodeLiveUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval low-risk-code-live <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalRevocationsUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval revocations <command>")
	fmt.Fprintln(stderr, "commands: inspect")
}

func printPolicyUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant policy <command>")
	fmt.Fprintln(stderr, "commands: explain, index, spine, credential-checklist, claim-publish-gate")
}

func printSchemaUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant schema <command>")
	fmt.Fprintln(stderr, "commands: catalog, export, validate")
}

func printReleaseUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant release <command>")
	fmt.Fprintln(stderr, "commands: package, verify")
}

func printBundleUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant bundle <command>")
	fmt.Fprintln(stderr, "commands: export, inspect, report, keygen")
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
