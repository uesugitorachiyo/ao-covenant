package release

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func Inspect(opts InspectOptions) (InspectResult, error) {
	dir := defaultString(opts.Dir, "dist")
	verifyReport, err := Verify(VerifyOptions{
		Dir:           dir,
		PublicKeyPath: opts.PublicKeyPath,
		Metadata:      opts.Metadata,
	})
	if err != nil {
		return InspectResult{}, err
	}
	signature := inspectReleaseSignature(verifyReport.SignaturePath, opts.PublicKeyPath, verifyReport.PublicKeySHA256)
	return InspectResult{
		SchemaVersion:         schema.ReleaseInspectResultSchemaID,
		ReleaseDir:            dir,
		ManifestPath:          verifyReport.ManifestPath,
		ChecksumsPath:         verifyReport.ChecksumsPath,
		SignaturePath:         nonEmptyFilePath(verifyReport.SignaturePath),
		ManifestValid:         true,
		ChecksumStatus:        checksumStatus(verifyReport.Verified),
		Signature:             signature,
		ArtifactCount:         verifyReport.ArtifactCount,
		Artifacts:             verifyReport.Artifacts,
		SupplementalArtifacts: verifyReport.SupplementalArtifacts,
		Problems:              verifyReport.Problems,
	}, nil
}

func Report(opts ReportOptions) (ReportResult, error) {
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		audience = "internal"
	}
	inspection, err := Inspect(InspectOptions{Dir: opts.Dir, PublicKeyPath: opts.PublicKeyPath})
	if err != nil {
		return ReportResult{}, err
	}
	if opts.Redaction.Paths || opts.Redaction.Digests {
		inspection = RedactInspect(inspection, opts.Redaction)
	}
	result := ReportResult{
		SchemaVersion:     schema.ReleaseReportResultSchemaID,
		Valid:             inspection.ChecksumStatus == "verified" && inspection.Signature.Status != "invalid" && len(inspection.Problems) == 0,
		Format:            "json",
		Audience:          audience,
		Redacted:          opts.Redaction.Paths || opts.Redaction.Digests,
		Redactions:        redactionNames(opts.Redaction),
		RedactionProfile:  opts.Redaction.RedactionProfile,
		ProvenanceSummary: SummarizeProvenance(inspection),
		Inspection:        inspection,
	}
	return result, nil
}

func SummarizeProvenance(inspection InspectResult) ProvenanceSummary {
	summary := ProvenanceSummary{SignatureStatus: inspection.Signature.Status}
	if summary.SignatureStatus == "" {
		summary.SignatureStatus = "unsigned"
	}
	for _, artifact := range inspection.Artifacts {
		for _, attestation := range artifact.Attestations {
			if attestation.Verified {
				summary.AttestationVerifiedCount++
			} else {
				summary.AttestationInvalidCount++
				summary.InvalidEvidenceCount++
			}
		}
	}
	for _, supplemental := range inspection.SupplementalArtifacts {
		switch supplemental.Kind {
		case "sbom":
			if supplemental.Verified {
				summary.SBOMVerifiedCount++
			} else {
				summary.SBOMInvalidCount++
				summary.InvalidEvidenceCount++
			}
		case "provenance":
			if supplemental.Verified {
				summary.SupplementalProvenanceVerifiedCount++
			} else {
				summary.SupplementalProvenanceInvalidCount++
				summary.InvalidEvidenceCount++
			}
		}
	}
	if inspection.Signature.Status == "invalid" {
		summary.InvalidEvidenceCount++
	}
	return summary
}

func RedactInspect(result InspectResult, opts RedactionOptions) InspectResult {
	if opts.Paths {
		result.ReleaseDir = redactedPath
		result.ManifestPath = redactedPath
		result.ChecksumsPath = redactedPath
		if result.SignaturePath != "" {
			result.SignaturePath = redactedPath
		}
	}
	if opts.Digests {
		result.Signature.PublicKeySHA256 = redactedDigest
	}
	for i := range result.Artifacts {
		if opts.Paths {
			result.Artifacts[i].Path = redactedPath
		}
		if opts.Digests {
			result.Artifacts[i].SHA256 = redactedDigest
			result.Artifacts[i].ActualSHA256 = redactedDigest
		}
		for j := range result.Artifacts[i].Attestations {
			if opts.Paths {
				result.Artifacts[i].Attestations[j].Path = redactedPath
			}
			if opts.Digests {
				result.Artifacts[i].Attestations[j].SHA256 = redactedDigest
				result.Artifacts[i].Attestations[j].ActualSHA256 = redactedDigest
			}
		}
	}
	for i := range result.SupplementalArtifacts {
		if opts.Paths {
			result.SupplementalArtifacts[i].Path = redactedPath
		}
		if opts.Digests {
			result.SupplementalArtifacts[i].SHA256 = redactedDigest
			result.SupplementalArtifacts[i].ActualSHA256 = redactedDigest
		}
	}
	if opts.Digests {
		result.Problems = redactProblemDigests(result.Problems)
	}
	if opts.Paths {
		result.Problems = redactProblemPaths(result.Problems)
	}
	return result
}

func RedactReport(result ReportResult, opts RedactionOptions) ReportResult {
	result.Redacted = opts.Paths || opts.Digests
	result.Redactions = redactionNames(opts)
	result.RedactionProfile = opts.RedactionProfile
	result.Inspection = RedactInspect(result.Inspection, opts)
	return result
}

func Diff(opts DiffOptions) (DiffReport, error) {
	fromInspection, err := Inspect(InspectOptions{Dir: opts.FromDir, PublicKeyPath: opts.FromPublicKeyPath})
	if err != nil {
		return DiffReport{}, fmt.Errorf("inspect from release: %w", err)
	}
	toInspection, err := Inspect(InspectOptions{Dir: opts.ToDir, PublicKeyPath: opts.ToPublicKeyPath})
	if err != nil {
		return DiffReport{}, fmt.Errorf("inspect to release: %w", err)
	}
	report := DiffReport{
		SchemaVersion:    schema.ReleaseDiffResultSchemaID,
		FromDir:          opts.FromDir,
		ToDir:            opts.ToDir,
		Entries:          []DiffEntry{},
		Redacted:         opts.Redaction.Paths || opts.Redaction.Digests,
		Redactions:       redactionNames(opts.Redaction),
		RedactionProfile: opts.Redaction.RedactionProfile,
	}
	fromManifest, err := readManifestFile(fromInspection.ManifestPath)
	if err != nil {
		return DiffReport{}, err
	}
	toManifest, err := readManifestFile(toInspection.ManifestPath)
	if err != nil {
		return DiffReport{}, err
	}
	if fromManifest.Version != toManifest.Version {
		report.Entries = append(report.Entries, DiffEntry{Category: "metadata", Action: "changed", Name: "version", Detail: fromManifest.Version + " -> " + toManifest.Version})
	}
	if fromManifest.Commit != toManifest.Commit {
		report.Entries = append(report.Entries, DiffEntry{Category: "metadata", Action: "changed", Name: "commit", Detail: redactDigestPair(fromManifest.Commit, toManifest.Commit, opts.Redaction)})
	}
	diffArtifacts(&report, fromManifest.Artifacts, toManifest.Artifacts, opts.Redaction)
	diffSupplementalArtifacts(&report, fromManifest.SupplementalArtifacts, toManifest.SupplementalArtifacts, opts.Redaction)
	if fromInspection.Signature.PublicKeySHA256 != toInspection.Signature.PublicKeySHA256 {
		report.Entries = append(report.Entries, DiffEntry{
			Category: "signatures",
			Action:   "changed",
			Name:     "public_key_sha256",
			Detail:   redactDigestPair(fromInspection.Signature.PublicKeySHA256, toInspection.Signature.PublicKeySHA256, opts.Redaction),
		})
	}
	for _, problem := range fromInspection.Problems {
		report.Entries = append(report.Entries, DiffEntry{Category: "problems", Action: "present", Name: "from", Detail: redactProblem(problem, opts.Redaction)})
	}
	for _, problem := range toInspection.Problems {
		report.Entries = append(report.Entries, DiffEntry{Category: "problems", Action: "present", Name: "to", Detail: redactProblem(problem, opts.Redaction)})
	}
	if opts.Redaction.Paths {
		report.FromDir = redactedPath
		report.ToDir = redactedPath
	}
	report.Changed = len(report.Entries) > 0
	return report, nil
}

func InspectSARIF(result InspectResult) schema.SARIFLog {
	return InspectSARIFWithOptions(result, InspectSARIFOptions{})
}

func InspectSARIFWithOptions(result InspectResult, opts InspectSARIFOptions) schema.SARIFLog {
	rules := []schema.SARIFRule{
		sarifRule("RELEASE_ARTIFACT_PROBLEM", "Release artifact problem"),
		sarifRule("RELEASE_ATTESTATION_PROBLEM", "Release attestation problem"),
		sarifRule("RELEASE_SUPPLEMENTAL_PROBLEM", "Release supplemental artifact problem"),
		sarifRule("RELEASE_PROBLEM", "Release problem"),
	}
	results := []schema.SARIFResult{}
	for _, artifact := range result.Artifacts {
		for _, message := range artifact.Problems {
			field := "artifact:" + artifact.Name
			results = append(results, releaseSARIFResult("RELEASE_ARTIFACT_PROBLEM", message, artifact.Path, schema.SARIFResultProperties{Component: "artifact", Name: artifact.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
		}
		for _, attestation := range artifact.Attestations {
			for _, message := range attestation.Problems {
				field := "attestation:" + artifact.Name + "/" + attestation.Name
				results = append(results, releaseSARIFResult("RELEASE_ATTESTATION_PROBLEM", message, attestation.Path, schema.SARIFResultProperties{Component: "attestation", Name: attestation.Name, ArtifactName: artifact.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
			}
		}
	}
	for _, supplemental := range result.SupplementalArtifacts {
		for _, message := range supplemental.Problems {
			field := "supplemental:" + supplemental.Kind + "/" + supplemental.Name
			results = append(results, releaseSARIFResult("RELEASE_SUPPLEMENTAL_PROBLEM", message, supplemental.Path, schema.SARIFResultProperties{Component: "supplemental_artifact", Kind: supplemental.Kind, Name: supplemental.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
		}
	}
	for _, message := range result.Problems {
		if problemCoveredByComponent(result, message) {
			continue
		}
		results = append(results, releaseSARIFResult("RELEASE_PROBLEM", message, result.ChecksumsPath, schema.SARIFResultProperties{Component: "release", Location: "release", ReleaseDir: result.ReleaseDir}, opts.Baseline, "release"))
	}
	return schema.SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []schema.SARIFRun{{
			Tool:    schema.SARIFTool{Driver: schema.SARIFDriver{Name: "AO Covenant Release Inspector", InformationURI: "https://github.com/uesugitorachiyo/ao-covenant", Rules: rules}},
			Results: results,
		}},
	}
}

func DiffSARIF(result DiffReport) schema.SARIFLog {
	return DiffSARIFWithOptions(result, DiffSARIFOptions{})
}

func DiffSARIFWithOptions(result DiffReport, opts DiffSARIFOptions) schema.SARIFLog {
	rules := []schema.SARIFRule{
		sarifRule("RELEASE_DIFF_METADATA", "Release metadata changed"),
		sarifRule("RELEASE_DIFF_ARTIFACT", "Release artifact changed"),
		sarifRule("RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT", "Release supplemental artifact changed"),
		sarifRule("RELEASE_DIFF_SIGNATURE", "Release signature changed"),
		sarifRule("RELEASE_DIFF_PROBLEM", "Release problem changed"),
	}
	results := []schema.SARIFResult{}
	for _, entry := range result.Entries {
		ruleID := diffRuleID(entry.Category)
		field := entry.Category + ":" + entry.Name
		uri := filepath.ToSlash(filepath.Join(result.ToDir, "manifest.json"))
		if entry.Category == "problems" && entry.Name == "from" {
			uri = filepath.ToSlash(filepath.Join(result.FromDir, "manifest.json"))
		}
		sarifResult := releaseSARIFResult(ruleID, entry.Detail, uri, schema.SARIFResultProperties{
			Component:  entry.Category,
			Kind:       entry.Action,
			Name:       entry.Name,
			Location:   field,
			ReleaseDir: result.ToDir,
		}, opts.Baseline, field)
		sarifResult.Level = "warning"
		results = append(results, sarifResult)
	}
	return schema.SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []schema.SARIFRun{{
			Tool:    schema.SARIFTool{Driver: schema.SARIFDriver{Name: "AO Covenant Release Diff", InformationURI: "https://github.com/uesugitorachiyo/ao-covenant", Rules: rules}},
			Results: results,
		}},
	}
}

func inspectReleaseSignature(signaturePath string, publicKeyPath string, verifiedFingerprint string) SignatureInspection {
	bytes, err := os.ReadFile(signaturePath)
	if err != nil {
		if strings.TrimSpace(publicKeyPath) == "" {
			return SignatureInspection{Status: "unsigned"}
		}
		return SignatureInspection{Status: "invalid", Problem: err.Error()}
	}
	var signature SignatureFile
	if err := json.Unmarshal(bytes, &signature); err != nil {
		return SignatureInspection{Status: "invalid", Problem: err.Error()}
	}
	status := "present_unverified"
	if strings.TrimSpace(publicKeyPath) != "" {
		if verifiedFingerprint != "" {
			status = "verified"
		} else {
			status = "invalid"
		}
	}
	return SignatureInspection{
		Status:          status,
		Algorithm:       signature.Algorithm,
		SignedEntry:     signature.SignedEntry,
		PublicKeySHA256: signature.PublicKeySHA256,
	}
}

func nonEmptyFilePath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func checksumStatus(verified bool) string {
	if verified {
		return "verified"
	}
	return "invalid"
}

func redactionNames(opts RedactionOptions) []string {
	names := []string{}
	if opts.Paths {
		names = append(names, "paths")
	}
	if opts.Digests {
		names = append(names, "digests")
	}
	return names
}

func redactProblem(problem string, opts RedactionOptions) string {
	if opts.Digests {
		problem = redactProblemDigests([]string{problem})[0]
	}
	if opts.Paths {
		problem = redactProblemPaths([]string{problem})[0]
	}
	return problem
}

func redactProblemDigests(problems []string) []string {
	redacted := append([]string{}, problems...)
	for i, problem := range redacted {
		fields := strings.Fields(problem)
		for _, field := range fields {
			candidate := strings.Trim(field, `"'.,:;()[]`)
			if len(candidate) == 64 && isLowerHex(candidate) {
				problem = strings.ReplaceAll(problem, candidate, "[REDACTED_DIGEST]")
			}
		}
		redacted[i] = problem
	}
	return redacted
}

func redactProblemPaths(problems []string) []string {
	redacted := append([]string{}, problems...)
	for i := range redacted {
		redacted[i] = strings.ReplaceAll(redacted[i], "\\", "/")
	}
	return redacted
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func redactDigestPair(from string, to string, opts RedactionOptions) string {
	if opts.Digests {
		return "[REDACTED_DIGEST] -> [REDACTED_DIGEST]"
	}
	return from + " -> " + to
}

func readManifestFile(path string) (Manifest, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func diffArtifacts(report *DiffReport, from []Artifact, to []Artifact, redaction RedactionOptions) {
	fromByName := map[string]Artifact{}
	toByName := map[string]Artifact{}
	for _, artifact := range from {
		fromByName[artifact.Name] = artifact
	}
	for _, artifact := range to {
		toByName[artifact.Name] = artifact
	}
	for name, artifact := range fromByName {
		next, ok := toByName[name]
		if !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "removed", Name: name, Detail: artifact.Target.OS + "/" + artifact.Target.Arch})
			continue
		}
		if artifact.SHA256 != next.SHA256 {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "changed", Name: name, Detail: redactDigestPair(artifact.SHA256, next.SHA256, redaction)})
		}
	}
	for name, artifact := range toByName {
		if _, ok := fromByName[name]; !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "added", Name: name, Detail: artifact.Target.OS + "/" + artifact.Target.Arch})
		}
	}
}

func diffSupplementalArtifacts(report *DiffReport, from []SupplementalArtifact, to []SupplementalArtifact, redaction RedactionOptions) {
	fromByName := map[string]SupplementalArtifact{}
	toByName := map[string]SupplementalArtifact{}
	for _, artifact := range from {
		fromByName[artifact.Name] = artifact
	}
	for _, artifact := range to {
		toByName[artifact.Name] = artifact
	}
	for name, artifact := range fromByName {
		next, ok := toByName[name]
		if !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "removed", Name: name, Detail: artifact.Kind})
			continue
		}
		if artifact.SHA256 != next.SHA256 {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "changed", Name: name, Detail: redactDigestPair(artifact.SHA256, next.SHA256, redaction)})
		}
	}
	for name, artifact := range toByName {
		if _, ok := fromByName[name]; !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "added", Name: name, Detail: artifact.Kind})
		}
	}
}

func sarifRule(id string, text string) schema.SARIFRule {
	return schema.SARIFRule{
		ID:               id,
		ShortDescription: schema.SARIFMessage{Text: text},
	}
}

func releaseSARIFResult(ruleID string, message string, uri string, properties schema.SARIFResultProperties, baseline schema.SARIFBaseline, field string) schema.SARIFResult {
	result := schema.SARIFResult{
		RuleID:     ruleID,
		Level:      "error",
		Message:    schema.SARIFMessage{Text: message},
		Properties: properties,
	}
	if uri != "" {
		result.Locations = []schema.SARIFLocation{{
			PhysicalLocation: schema.SARIFPhysicalLocation{
				ArtifactLocation: schema.SARIFArtifactLocation{URI: filepath.ToSlash(uri)},
			},
		}}
	}
	if suppression, ok := matchingReleaseBaseline(ruleID, filepath.ToSlash(uri), field, baseline); ok {
		result.Suppressions = []schema.SARIFSuppression{{Kind: "external", Justification: suppression.Justification}}
	}
	return result
}

func matchingReleaseBaseline(ruleID string, uri string, field string, baseline schema.SARIFBaseline) (schema.SARIFBaselineEntry, bool) {
	for _, entry := range baseline.Accepted {
		if entry.RuleID != ruleID {
			continue
		}
		if entry.SourceURI != "" && entry.SourceURI != uri {
			continue
		}
		if entry.Field != "" && entry.Field != field {
			continue
		}
		return entry, true
	}
	return schema.SARIFBaselineEntry{}, false
}

func problemCoveredByComponent(result InspectResult, message string) bool {
	for _, artifact := range result.Artifacts {
		for _, problem := range artifact.Problems {
			if problem == message {
				return true
			}
		}
		for _, attestation := range artifact.Attestations {
			for _, problem := range attestation.Problems {
				if problem == message {
					return true
				}
			}
		}
	}
	for _, supplemental := range result.SupplementalArtifacts {
		for _, problem := range supplemental.Problems {
			if problem == message {
				return true
			}
		}
	}
	return false
}

func diffRuleID(category string) string {
	switch category {
	case "metadata":
		return "RELEASE_DIFF_METADATA"
	case "artifacts":
		return "RELEASE_DIFF_ARTIFACT"
	case "supplemental_artifacts":
		return "RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT"
	case "signatures":
		return "RELEASE_DIFF_SIGNATURE"
	default:
		return "RELEASE_DIFF_PROBLEM"
	}
}
