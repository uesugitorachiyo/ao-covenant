package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseRedactionPolicyFixtureValidatesPublishedSchema(t *testing.T) {
	bytes := readReleaseRedactionPolicyFixture(t)
	if err := schema.ValidateBytes(schema.ReportRedactionPolicySchemaID, bytes); err != nil {
		t.Fatalf("policy fixture did not validate against %s: %v\njson:\n%s", schema.ReportRedactionPolicySchemaID, err, string(bytes))
	}

	var decoded reportRedactionPolicyFile
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode policy fixture: %v", err)
	}
	if decoded.SchemaVersion != reportRedactionPolicySchemaVersion {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, reportRedactionPolicySchemaVersion)
	}
	if !reflect.DeepEqual(decoded.Profiles["partner"].Redact, []string{"paths", "digests"}) {
		t.Fatalf("partner profile = %+v, want paths+digests", decoded.Profiles["partner"])
	}
	if !reflect.DeepEqual(decoded.Profiles["partner-paths"].Redact, []string{"paths"}) {
		t.Fatalf("partner-paths profile = %+v, want paths", decoded.Profiles["partner-paths"])
	}
}

func TestReleaseRedactionPolicyFixtureAppliesToInspectReportAndDiff(t *testing.T) {
	policyPath := releaseRedactionPolicyFixturePath()
	outDir, publicKeyPath := packageReleaseForProvenanceSummaryTest(t, "policy-fixture-redaction")
	unredacted, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("inspect unredacted release: %v", err)
	}
	if len(unredacted.Artifacts) != 1 || unredacted.Signature.PublicKeySHA256 == "" {
		t.Fatalf("unredacted inspection = %+v, want signed release with one artifact", unredacted)
	}

	var inspectStdout bytes.Buffer
	var inspectStderr bytes.Buffer
	inspectCode := Run([]string{
		"covenant",
		"release",
		"inspect",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &inspectStdout, &inspectStderr)
	if inspectCode != 0 {
		t.Fatalf("inspect exit code = %d, stdout = %q stderr = %q", inspectCode, inspectStdout.String(), inspectStderr.String())
	}
	var inspectResult releasepkg.InspectResult
	if err := json.Unmarshal(inspectStdout.Bytes(), &inspectResult); err != nil {
		t.Fatalf("decode inspect JSON: %v; stdout = %q", err, inspectStdout.String())
	}
	zeroSHA256 := strings.Repeat("0", 64)
	if inspectResult.ReleaseDir != "[REDACTED_PATH]" ||
		inspectResult.ManifestPath != "[REDACTED_PATH]" ||
		inspectResult.Signature.PublicKeySHA256 != zeroSHA256 ||
		inspectResult.Artifacts[0].SHA256 != zeroSHA256 {
		t.Fatalf("inspect result = %+v, want partner profile redaction", inspectResult)
	}
	assertReleasePolicyFixtureRedacted(t, "inspect", inspectStdout.String(), outDir, unredacted.Signature.PublicKeySHA256, unredacted.Artifacts[0].SHA256)
	if inspectStderr.Len() != 0 {
		t.Fatalf("inspect stderr = %q, want empty", inspectStderr.String())
	}

	var reportStdout bytes.Buffer
	var reportStderr bytes.Buffer
	reportCode := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--format", "json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &reportStdout, &reportStderr)
	if reportCode != 0 {
		t.Fatalf("report exit code = %d, stdout = %q stderr = %q", reportCode, reportStdout.String(), reportStderr.String())
	}
	var reportResult struct {
		SchemaVersion    string                   `json:"schema_version"`
		Redacted         bool                     `json:"redacted"`
		Redactions       []string                 `json:"redactions"`
		RedactionProfile string                   `json:"redaction_profile"`
		Inspection       releasepkg.InspectResult `json:"inspection"`
	}
	if err := json.Unmarshal(reportStdout.Bytes(), &reportResult); err != nil {
		t.Fatalf("decode report JSON: %v; stdout = %q", err, reportStdout.String())
	}
	if reportResult.SchemaVersion != schema.ReleaseReportResultSchemaID ||
		!reportResult.Redacted ||
		!reflect.DeepEqual(reportResult.Redactions, []string{"paths", "digests"}) ||
		reportResult.RedactionProfile != "partner" ||
		reportResult.Inspection.ReleaseDir != "[REDACTED_PATH]" ||
		reportResult.Inspection.Artifacts[0].SHA256 != zeroSHA256 {
		t.Fatalf("report result = %+v, want partner profile redaction metadata and inspection redaction", reportResult)
	}
	assertReleasePolicyFixtureRedacted(t, "report", reportStdout.String(), outDir, unredacted.Signature.PublicKeySHA256, unredacted.Artifacts[0].SHA256)
	if reportStderr.Len() != 0 {
		t.Fatalf("report stderr = %q, want empty", reportStderr.String())
	}

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	diffRoot := t.TempDir()
	fromDir := filepath.Join(diffRoot, "from")
	toDir := filepath.Join(diffRoot, "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "policy-fixture-diff-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "policy-fixture-diff-to")

	var diffStdout bytes.Buffer
	var diffStderr bytes.Buffer
	diffCode := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &diffStdout, &diffStderr)
	if diffCode != 1 {
		t.Fatalf("diff exit code = %d, want 1; stdout = %q stderr = %q", diffCode, diffStdout.String(), diffStderr.String())
	}
	var diffResult struct {
		SchemaVersion    string                 `json:"schema_version"`
		FromDir          string                 `json:"from_dir"`
		ToDir            string                 `json:"to_dir"`
		Changed          bool                   `json:"changed"`
		Redacted         bool                   `json:"redacted"`
		Redactions       []string               `json:"redactions"`
		RedactionProfile string                 `json:"redaction_profile"`
		Entries          []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(diffStdout.Bytes(), &diffResult); err != nil {
		t.Fatalf("decode diff JSON: %v; stdout = %q", err, diffStdout.String())
	}
	if diffResult.SchemaVersion != schema.ReleaseDiffResultSchemaID ||
		diffResult.FromDir != "[REDACTED_PATH]" ||
		diffResult.ToDir != "[REDACTED_PATH]" ||
		!diffResult.Changed ||
		!diffResult.Redacted ||
		!reflect.DeepEqual(diffResult.Redactions, []string{"paths", "digests"}) ||
		diffResult.RedactionProfile != "partner" ||
		len(diffResult.Entries) == 0 {
		t.Fatalf("diff result = %+v, want partner profile redacted diff", diffResult)
	}
	for _, forbidden := range []string{fromDir, toDir} {
		if strings.Contains(diffStdout.String(), forbidden) {
			t.Fatalf("diff stdout = %q, want %q redacted", diffStdout.String(), forbidden)
		}
	}
	if diffStderr.Len() != 0 {
		t.Fatalf("diff stderr = %q, want empty", diffStderr.String())
	}
}

func releaseRedactionPolicyFixturePath() string {
	return filepath.Join("testdata", "redaction-policies", "release-redaction-policy.json")
}

func readReleaseRedactionPolicyFixture(t *testing.T) []byte {
	t.Helper()
	bytes, err := os.ReadFile(releaseRedactionPolicyFixturePath())
	if err != nil {
		t.Fatalf("read release redaction policy fixture: %v", err)
	}
	return bytes
}

func assertReleasePolicyFixtureRedacted(t *testing.T, name string, output string, forbidden ...string) {
	t.Helper()
	if !strings.Contains(output, "[REDACTED_PATH]") {
		t.Fatalf("%s output = %q, want [REDACTED_PATH]", name, output)
	}
	for _, value := range forbidden {
		if strings.TrimSpace(value) != "" && strings.Contains(output, value) {
			t.Fatalf("%s output = %q, want %q redacted", name, output, value)
		}
	}
}
