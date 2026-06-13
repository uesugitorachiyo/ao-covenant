package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseReportTextFixturesMatchGeneratedGoldenFiles(t *testing.T) {
	for _, fixture := range releaseReportTextFixtureGoldenFiles(t) {
		fixture.assertFresh(t)
	}
}

func TestReleaseReportSARIFFixturesMatchGeneratedGoldenFiles(t *testing.T) {
	for _, fixture := range releaseReportSARIFFixtureGoldenFiles(t) {
		fixture.assertFresh(t)
	}
}

func TestReleaseReportDisplaysAttestationKind(t *testing.T) {
	result := releaseReportFixtureResultWithAttestationKind()

	text := string(renderReleaseReportFixture(result, bundlepkg.RedactionOptions{}))
	if !strings.Contains(text, "attestation: attestation.intoto.json [slsa] (verified)") {
		t.Fatalf("text report = %q, want attestation kind", text)
	}

	markdown := string(renderReleaseReportMarkdownFixture(result, bundlepkg.RedactionOptions{}))
	if !strings.Contains(markdown, "| Artifact | Kind | Name | Status | Digest | Size | Checksum | Path |") ||
		!strings.Contains(markdown, "| covenant-linux-amd64 | slsa | attestation.intoto.json | verified | verified | verified | verified | covenant-linux-amd64.attestation.intoto.json |") {
		t.Fatalf("markdown report = %q, want attestation kind column and value", markdown)
	}
}

type releaseReportTextFixtureGoldenFile struct {
	FileName string
	Text     []byte
}

type releaseReportSARIFFixtureGoldenFile struct {
	FileName string
	JSON     []byte
}

func releaseReportFixtureResultWithAttestationKind() releasepkg.InspectResult {
	const (
		releaseDir        = "dist/release"
		manifestPath      = "dist/release/manifest.json"
		checksumsPath     = "dist/release/SHA256SUMS"
		signaturePath     = "dist/release/release-signature.json"
		artifactName      = "covenant-linux-amd64"
		artifactPath      = "covenant-linux-amd64"
		artifactSHA256    = "1111111111111111111111111111111111111111111111111111111111111111"
		artifactSize      = int64(1048576)
		publicKeySHA256   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		attestationName   = "attestation.intoto.json"
		attestationPath   = "covenant-linux-amd64.attestation.intoto.json"
		attestationSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
		attestationSize   = int64(4096)
	)
	target := releasepkg.Target{OS: "linux", Arch: "amd64"}
	return releasepkg.InspectResult{
		SchemaVersion:  schema.ReleaseInspectResultSchemaID,
		ReleaseDir:     releaseDir,
		ManifestPath:   manifestPath,
		ChecksumsPath:  checksumsPath,
		SignaturePath:  signaturePath,
		ManifestValid:  true,
		ChecksumStatus: "verified",
		Signature: releasepkg.SignatureInspection{
			Status:          "verified",
			Algorithm:       "ed25519",
			SignedEntry:     "manifest.json",
			PublicKeySHA256: publicKeySHA256,
		},
		ArtifactCount: 1,
		Artifacts: []releasepkg.ArtifactVerifyReport{{
			Name:                artifactName,
			Target:              target,
			Path:                artifactPath,
			Verified:            true,
			PathValid:           true,
			DigestVerified:      true,
			SizeVerified:        true,
			ChecksumVerified:    true,
			MetadataVerified:    true,
			HostMetadataChecked: true,
			SHA256:              artifactSHA256,
			SizeBytes:           artifactSize,
			ActualSHA256:        artifactSHA256,
			ActualSizeBytes:     artifactSize,
			Problems:            []string{},
			Attestations: []releasepkg.AttestationVerifyReport{{
				Name:             attestationName,
				Kind:             "slsa",
				Path:             attestationPath,
				Verified:         true,
				PathValid:        true,
				DigestVerified:   true,
				SizeVerified:     true,
				ChecksumVerified: true,
				SHA256:           attestationSHA256,
				SizeBytes:        attestationSize,
				ActualSHA256:     attestationSHA256,
				ActualSizeBytes:  attestationSize,
				Problems:         []string{},
			}},
		}},
		Problems: []string{},
	}
}

func releaseReportTextFixtureGoldenFiles(t *testing.T) []releaseReportTextFixtureGoldenFile {
	t.Helper()

	const (
		releaseDir        = "dist/release"
		manifestPath      = "dist/release/manifest.json"
		checksumsPath     = "dist/release/SHA256SUMS"
		signaturePath     = "dist/release/release-signature.json"
		artifactName      = "covenant-linux-amd64"
		artifactPath      = "covenant-linux-amd64"
		artifactSHA256    = "1111111111111111111111111111111111111111111111111111111111111111"
		artifactSize      = int64(1048576)
		actualSHA256      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		publicKeySHA256   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		attestationName   = "attestation.intoto.json"
		attestationPath   = "covenant-linux-amd64.attestation.intoto.json"
		attestationSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
		attestationSize   = int64(4096)
		sbomName          = "sbom.spdx.json"
		sbomSHA256        = "2222222222222222222222222222222222222222222222222222222222222222"
		sbomSize          = int64(2048)
	)

	target := releasepkg.Target{OS: "linux", Arch: "amd64"}
	signature := releasepkg.SignatureInspection{
		Status:          "verified",
		Algorithm:       "ed25519",
		SignedEntry:     "manifest.json",
		PublicKeySHA256: publicKeySHA256,
	}
	validArtifact := releasepkg.ArtifactVerifyReport{
		Name:                artifactName,
		Target:              target,
		Path:                artifactPath,
		Verified:            true,
		PathValid:           true,
		DigestVerified:      true,
		SizeVerified:        true,
		ChecksumVerified:    true,
		MetadataVerified:    true,
		HostMetadataChecked: true,
		SHA256:              artifactSHA256,
		SizeBytes:           artifactSize,
		ActualSHA256:        artifactSHA256,
		ActualSizeBytes:     artifactSize,
		Problems:            []string{},
	}
	baseResult := func() releasepkg.InspectResult {
		return releasepkg.InspectResult{
			SchemaVersion:  schema.ReleaseInspectResultSchemaID,
			ReleaseDir:     releaseDir,
			ManifestPath:   manifestPath,
			ChecksumsPath:  checksumsPath,
			SignaturePath:  signaturePath,
			ManifestValid:  true,
			ChecksumStatus: "verified",
			Signature:      signature,
			ArtifactCount:  1,
			Artifacts:      []releasepkg.ArtifactVerifyReport{validArtifact},
			Problems:       []string{},
		}
	}

	valid := baseResult()

	invalid := baseResult()
	invalid.ChecksumStatus = "invalid"
	invalid.Artifacts[0].Verified = false
	invalid.Artifacts[0].DigestVerified = false
	invalid.Artifacts[0].ActualSHA256 = actualSHA256
	invalid.Artifacts[0].Problems = []string{"artifact \"covenant-linux-amd64\" sha256 mismatch: got " + actualSHA256 + " want " + artifactSHA256}
	invalid.Problems = append([]string{}, invalid.Artifacts[0].Problems...)

	redacted := invalid
	redacted.Signature.Problem = "release signature read dist/release/release-signature.json with key " + publicKeySHA256
	redacted.Problems = append(redacted.Problems, "release used dist/release/covenant-linux-amd64 digest "+artifactSHA256)

	attested := baseResult()
	attested.Artifacts[0].Attestations = []releasepkg.AttestationVerifyReport{{
		Name:             attestationName,
		Kind:             "slsa",
		Path:             attestationPath,
		Verified:         true,
		PathValid:        true,
		DigestVerified:   true,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           attestationSHA256,
		SizeBytes:        attestationSize,
		ActualSHA256:     attestationSHA256,
		ActualSizeBytes:  attestationSize,
		Problems:         []string{},
	}}

	supplemental := baseResult()
	supplemental.SupplementalArtifacts = []releasepkg.SupplementalVerifyReport{{
		Kind:             "sbom",
		Name:             sbomName,
		Path:             sbomName,
		Verified:         true,
		PathValid:        true,
		DigestVerified:   true,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           sbomSHA256,
		SizeBytes:        sbomSize,
		ActualSHA256:     sbomSHA256,
		ActualSizeBytes:  sbomSize,
		Problems:         []string{},
	}}

	return []releaseReportTextFixtureGoldenFile{
		{FileName: "valid.txt", Text: renderReleaseReportFixture(valid, bundlepkg.RedactionOptions{})},
		{FileName: "invalid.txt", Text: renderReleaseReportFixture(invalid, bundlepkg.RedactionOptions{})},
		{FileName: "redacted.txt", Text: renderReleaseReportFixture(redacted, bundlepkg.RedactionOptions{Paths: true, Digests: true})},
		{FileName: "attested.txt", Text: renderReleaseReportFixture(attested, bundlepkg.RedactionOptions{})},
		{FileName: "supplemental.txt", Text: renderReleaseReportFixture(supplemental, bundlepkg.RedactionOptions{})},
		{FileName: "markdown-valid.md", Text: renderReleaseReportMarkdownFixture(valid, bundlepkg.RedactionOptions{})},
		{FileName: "markdown-invalid-redacted.md", Text: renderReleaseReportMarkdownFixture(redacted, bundlepkg.RedactionOptions{Paths: true, Digests: true})},
	}
}

func renderReleaseReportFixture(result releasepkg.InspectResult, redaction bundlepkg.RedactionOptions) []byte {
	var stdout bytes.Buffer
	writeReleaseReport(&stdout, result, redaction)
	return stdout.Bytes()
}

func renderReleaseReportMarkdownFixture(result releasepkg.InspectResult, redaction bundlepkg.RedactionOptions) []byte {
	var stdout bytes.Buffer
	writeReleaseReportMarkdown(&stdout, result, redaction)
	return stdout.Bytes()
}

func releaseReportSARIFFixtureGoldenFiles(t *testing.T) []releaseReportSARIFFixtureGoldenFile {
	t.Helper()

	valid := releaseReportSARIFValidFixtureResult()
	invalid := releaseReportSARIFInvalidFixtureResult()
	suppressed := releasepkg.InspectSARIFWithOptions(invalid, releasepkg.InspectSARIFOptions{
		Baseline: schema.SARIFBaseline{Accepted: []schema.SARIFBaselineEntry{
			{
				RuleID:        "RELEASE_ARTIFACT_PROBLEM",
				SourceURI:     "covenant-linux-amd64",
				Field:         "artifact:covenant-linux-amd64",
				Justification: "accepted fixture artifact drift",
			},
			{
				RuleID:        "RELEASE_ATTESTATION_PROBLEM",
				SourceURI:     "covenant-linux-amd64.attestation.intoto.json",
				Field:         "attestation:covenant-linux-amd64/attestation.intoto.json",
				Justification: "accepted fixture attestation drift",
			},
			{
				RuleID:        "RELEASE_SUPPLEMENTAL_PROBLEM",
				SourceURI:     "sbom.spdx.json",
				Field:         "supplemental:sbom/sbom.spdx.json",
				Justification: "accepted fixture sbom drift",
			},
			{
				RuleID:        "RELEASE_PROBLEM",
				SourceURI:     "dist/release/SHA256SUMS",
				Field:         "release",
				Justification: "accepted fixture release drift",
			},
		}},
	})

	return []releaseReportSARIFFixtureGoldenFile{
		{FileName: "sarif-valid.json", JSON: marshalReleaseReportSARIFFixture(t, releasepkg.InspectSARIF(valid))},
		{FileName: "sarif-invalid.json", JSON: marshalReleaseReportSARIFFixture(t, releasepkg.InspectSARIF(invalid))},
		{FileName: "sarif-baseline-suppressed.json", JSON: marshalReleaseReportSARIFFixture(t, suppressed)},
	}
}

func releaseReportSARIFValidFixtureResult() releasepkg.InspectResult {
	const (
		releaseDir      = "dist/release"
		manifestPath    = "dist/release/manifest.json"
		checksumsPath   = "dist/release/SHA256SUMS"
		signaturePath   = "dist/release/release-signature.json"
		artifactName    = "covenant-linux-amd64"
		artifactPath    = "covenant-linux-amd64"
		artifactSHA256  = "1111111111111111111111111111111111111111111111111111111111111111"
		artifactSize    = int64(1048576)
		publicKeySHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	return releasepkg.InspectResult{
		SchemaVersion:  schema.ReleaseInspectResultSchemaID,
		ReleaseDir:     releaseDir,
		ManifestPath:   manifestPath,
		ChecksumsPath:  checksumsPath,
		SignaturePath:  signaturePath,
		ManifestValid:  true,
		ChecksumStatus: "verified",
		Signature: releasepkg.SignatureInspection{
			Status:          "verified",
			Algorithm:       "ed25519",
			SignedEntry:     "manifest.json",
			PublicKeySHA256: publicKeySHA256,
		},
		ArtifactCount: 1,
		Artifacts: []releasepkg.ArtifactVerifyReport{{
			Name:                artifactName,
			Target:              releasepkg.Target{OS: "linux", Arch: "amd64"},
			Path:                artifactPath,
			Verified:            true,
			PathValid:           true,
			DigestVerified:      true,
			SizeVerified:        true,
			ChecksumVerified:    true,
			MetadataVerified:    true,
			HostMetadataChecked: true,
			SHA256:              artifactSHA256,
			SizeBytes:           artifactSize,
			ActualSHA256:        artifactSHA256,
			ActualSizeBytes:     artifactSize,
			Problems:            []string{},
		}},
		Problems: []string{},
	}
}

func releaseReportSARIFInvalidFixtureResult() releasepkg.InspectResult {
	const (
		actualArtifactSHA256    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		artifactProblem         = `artifact "covenant-linux-amd64" sha256 mismatch: got aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa want 1111111111111111111111111111111111111111111111111111111111111111`
		attestationProblem      = `attestation "attestation.intoto.json" sha256 mismatch: got cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc want 3333333333333333333333333333333333333333333333333333333333333333`
		supplementalProblem     = `supplemental "sbom.spdx.json" sha256 mismatch: got dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd want 2222222222222222222222222222222222222222222222222222222222222222`
		unmanifestedFileProblem = `SHA256SUMS contains unmanifested artifact "extra.bin"`
	)
	invalid := releaseReportSARIFValidFixtureResult()
	invalid.ChecksumStatus = "invalid"
	invalid.Artifacts[0].Verified = false
	invalid.Artifacts[0].DigestVerified = false
	invalid.Artifacts[0].ActualSHA256 = actualArtifactSHA256
	invalid.Artifacts[0].Problems = []string{artifactProblem}
	invalid.Artifacts[0].Attestations = []releasepkg.AttestationVerifyReport{{
		Name:             "attestation.intoto.json",
		Kind:             "slsa",
		Path:             "covenant-linux-amd64.attestation.intoto.json",
		Verified:         false,
		PathValid:        true,
		DigestVerified:   false,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           "3333333333333333333333333333333333333333333333333333333333333333",
		SizeBytes:        4096,
		ActualSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ActualSizeBytes:  4096,
		Problems:         []string{attestationProblem},
	}}
	invalid.SupplementalArtifacts = []releasepkg.SupplementalVerifyReport{{
		Kind:             "sbom",
		Name:             "sbom.spdx.json",
		Path:             "sbom.spdx.json",
		Verified:         false,
		PathValid:        true,
		DigestVerified:   false,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           "2222222222222222222222222222222222222222222222222222222222222222",
		SizeBytes:        2048,
		ActualSHA256:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ActualSizeBytes:  2048,
		Problems:         []string{supplementalProblem},
	}}
	invalid.Problems = []string{artifactProblem, attestationProblem, supplementalProblem, unmanifestedFileProblem}
	return invalid
}

func marshalReleaseReportSARIFFixture(t *testing.T, value schema.SARIFLog) []byte {
	t.Helper()
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal release report SARIF fixture: %v", err)
	}
	return append(bytes, '\n')
}

func (fixture releaseReportSARIFFixtureGoldenFile) assertFresh(t *testing.T) {
	t.Helper()

	var sarif schema.SARIFLog
	if err := json.Unmarshal(fixture.JSON, &sarif); err != nil {
		t.Fatalf("generated %s is not SARIF JSON: %v\njson:\n%s", fixture.FileName, err, string(fixture.JSON))
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Fatalf("generated %s = %+v, want one SARIF 2.1.0 run", fixture.FileName, sarif)
	}
	switch fixture.FileName {
	case "sarif-valid.json":
		if len(sarif.Runs[0].Results) != 0 {
			t.Fatalf("%s results = %+v, want none", fixture.FileName, sarif.Runs[0].Results)
		}
	case "sarif-invalid.json":
		requireReleaseReportSARIFFixtureRules(t, fixture.FileName, sarif, map[string]bool{
			"RELEASE_ARTIFACT_PROBLEM":     true,
			"RELEASE_ATTESTATION_PROBLEM":  true,
			"RELEASE_SUPPLEMENTAL_PROBLEM": true,
			"RELEASE_PROBLEM":              true,
		})
	case "sarif-baseline-suppressed.json":
		if len(sarif.Runs[0].Results) == 0 {
			t.Fatalf("%s results = none, want suppressed findings", fixture.FileName)
		}
		for _, result := range sarif.Runs[0].Results {
			if len(result.Suppressions) != 1 || result.Suppressions[0].Kind != "external" {
				t.Fatalf("%s result = %+v, want one external suppression", fixture.FileName, result)
			}
		}
	default:
		t.Fatalf("unexpected SARIF fixture %s", fixture.FileName)
	}

	path := filepath.Join("testdata", "release-report-sarif-fixtures", fixture.FileName)
	if os.Getenv("COVENANT_UPDATE_RELEASE_REPORT_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, fixture.JSON, 0o644); err != nil {
			t.Fatalf("update %s: %v", path, err)
		}
	}

	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(normalizeGoldenFixtureBytes(golden), normalizeGoldenFixtureBytes(fixture.JSON)) {
		t.Fatalf("%s is stale; regenerate with COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1 go test ./internal/cli -run 'ReleaseReportSARIFFixtures' -count=1", path)
	}
}

func requireReleaseReportSARIFFixtureRules(t *testing.T, fileName string, sarif schema.SARIFLog, want map[string]bool) {
	t.Helper()
	got := map[string]bool{}
	for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
		got[rule.ID] = true
	}
	for ruleID := range want {
		if !got[ruleID] {
			t.Fatalf("%s rules = %+v, want %s", fileName, sarif.Runs[0].Tool.Driver.Rules, ruleID)
		}
	}
}

func (fixture releaseReportTextFixtureGoldenFile) assertFresh(t *testing.T) {
	t.Helper()

	path := filepath.Join("testdata", "release-report-fixtures", fixture.FileName)
	if os.Getenv("COVENANT_UPDATE_RELEASE_REPORT_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir: %v", err)
		}
		if err := os.WriteFile(path, fixture.Text, 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if !bytes.Equal(normalizeGoldenFixtureBytes(got), normalizeGoldenFixtureBytes(fixture.Text)) {
		t.Fatalf("%s is stale; refresh with COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1 go test ./internal/cli -run 'ReleaseReportTextFixtures' -count=1", path)
	}
}
