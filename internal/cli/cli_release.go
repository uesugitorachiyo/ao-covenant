package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

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
	var prebuiltFlags repeatedStringFlag
	var sbomPaths repeatedStringFlag
	var provenancePaths repeatedStringFlag
	var attestationPaths repeatedStringFlag
	flags.Var(&targetFlags, "target", "release target as os/arch")
	flags.Var(&prebuiltFlags, "prebuilt", "prebuilt native candidate as target=path")
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
	prebuilt := make(map[string]string, len(prebuiltFlags))
	for _, raw := range prebuiltFlags {
		targetValue, path, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(path) == "" {
			fmt.Fprintf(stderr, "prebuilt %q must use target=path\n", raw)
			return 2
		}
		target, err := releasepkg.ParseTarget(targetValue)
		if err != nil {
			fmt.Fprintf(stderr, "prebuilt target %q: %v\n", targetValue, err)
			return 2
		}
		key := target.OS + "/" + target.Arch
		if _, exists := prebuilt[key]; exists {
			fmt.Fprintf(stderr, "duplicate prebuilt target %q\n", key)
			return 2
		}
		prebuilt[key] = path
	}
	result, err := releasepkg.Package(context.Background(), releasepkg.Options{
		SourceDir:        *sourceDir,
		OutDir:           *outDir,
		Version:          *version,
		Commit:           *commit,
		Date:             *date,
		Targets:          targets,
		Prebuilt:         prebuilt,
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

func writeReleaseReportOutput(stdout io.Writer, outPath string, bytes []byte) error {
	return writeNamedOutputFile(stdout, "release report", "release_report", outPath, bytes)
}

func writeReleaseDiffOutput(stdout io.Writer, outPath string, bytes []byte) error {
	return writeNamedOutputFile(stdout, "release diff", "release_diff", outPath, bytes)
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
