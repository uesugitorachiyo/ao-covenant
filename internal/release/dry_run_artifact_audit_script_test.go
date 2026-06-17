package release

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseDryRunArtifactAuditScriptProducesSchemaValidReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash dry-run artifact audit smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	auditPath := filepath.Join(distDir, "release-dry-run-artifact-audit.json")

	for name, contents := range map[string]string{
		"manifest.json":                        `{"schema_version":"covenant.release-manifest.v1"}`,
		"SHA256SUMS":                           "checksum fixture\n",
		"release-signature.json":               `{"schema_version":"covenant.release-signature.v1"}`,
		"covenant-release-public-key.json":     `{"schema_version":"covenant.bundle-public-key.v1"}`,
		"release-package.json":                 `{"schema_version":"covenant.release-package-result.v1"}`,
		"release-verify.json":                  `{"schema_version":"covenant.release-verify-result.v1"}`,
		"release-report.json":                  `{"schema_version":"covenant.release-report-result.v1"}`,
		"ao-covenant_v0.1.0_linux_amd64":       "binary fixture\n",
		"ao-covenant_v0.1.0_windows_amd64.exe": "binary fixture\n",
	} {
		if err := os.WriteFile(filepath.Join(distDir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("write dist artifact %s: %v", name, err)
		}
	}

	cmd := exec.Command("bash", "./scripts/release-dry-run-artifact-audit.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"DRY_RUN=true",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=2",
		"COVENANT_RELEASE_DRY_RUN_ARTIFACT_AUDIT_JSON="+auditPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run artifact audit failed: %v\n%s", err, string(output))
	}
	if !strings.Contains(string(output), "release_dry_run_artifact_audit=passed") {
		t.Fatalf("audit output missing passed marker:\n%s", string(output))
	}

	bytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit report: %v", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseDryRunArtifactAuditSchemaID, bytes); err != nil {
		t.Fatalf("audit report failed schema validation: %v\n%s", err, string(bytes))
	}
	if _, err := os.Stat(auditPath + ".validation.json"); !os.IsNotExist(err) {
		t.Fatalf("audit script wrote an uncounted validation artifact: %v", err)
	}
	var report struct {
		SchemaVersion  string `json:"schema_version"`
		Status         string `json:"status"`
		Version        string `json:"version"`
		DryRun         bool   `json:"dry_run"`
		ArtifactCounts struct {
			TotalFiles           int `json:"total_files"`
			RequiredFilesPresent int `json:"required_files_present"`
			PlatformAssets       int `json:"platform_assets"`
			ForbiddenFiles       int `json:"forbidden_files"`
		} `json:"artifact_counts"`
		TrustBoundary struct {
			PublishesGitHubRelease      bool `json:"publishes_github_release"`
			MutatesGitHubReleases       bool `json:"mutates_github_releases"`
			GeneratesGitHubAttestations bool `json:"generates_github_attestations"`
			StoresCredentials           bool `json:"stores_credentials"`
			ContainsPrivateKeyMaterial  bool `json:"contains_private_key_material"`
		} `json:"trust_boundary"`
	}
	if err := json.Unmarshal(bytes, &report); err != nil {
		t.Fatalf("decode audit report: %v\n%s", err, string(bytes))
	}
	if report.SchemaVersion != schema.ReleaseDryRunArtifactAuditSchemaID {
		t.Fatalf("schema_version = %q", report.SchemaVersion)
	}
	if report.Status != "passed" || report.Version != "v0.1.0" || !report.DryRun {
		t.Fatalf("unexpected audit metadata: %+v", report)
	}
	if report.ArtifactCounts.RequiredFilesPresent != 7 || report.ArtifactCounts.PlatformAssets != 2 || report.ArtifactCounts.ForbiddenFiles != 0 {
		t.Fatalf("unexpected artifact counts: %+v", report.ArtifactCounts)
	}
	if report.TrustBoundary.PublishesGitHubRelease || report.TrustBoundary.MutatesGitHubReleases || report.TrustBoundary.GeneratesGitHubAttestations || report.TrustBoundary.StoresCredentials || report.TrustBoundary.ContainsPrivateKeyMaterial {
		t.Fatalf("dry-run trust boundary was not read-only: %+v", report.TrustBoundary)
	}
	if strings.Contains(string(bytes), distDir) {
		t.Fatalf("audit report leaked local dist path %q:\n%s", distDir, string(bytes))
	}
}

func TestReleaseDryRunArtifactAuditScriptFailsClosedForMissingRequiredFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash dry-run artifact audit smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	auditPath := filepath.Join(distDir, "release-dry-run-artifact-audit.json")

	for name, contents := range map[string]string{
		"SHA256SUMS":                       "checksum fixture\n",
		"release-signature.json":           `{"schema_version":"covenant.release-signature.v1"}`,
		"covenant-release-public-key.json": `{"schema_version":"covenant.bundle-public-key.v1"}`,
		"release-package.json":             `{"schema_version":"covenant.release-package-result.v1"}`,
		"release-verify.json":              `{"schema_version":"covenant.release-verify-result.v1"}`,
		"release-report.json":              `{"schema_version":"covenant.release-report-result.v1"}`,
	} {
		if err := os.WriteFile(filepath.Join(distDir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("write dist artifact %s: %v", name, err)
		}
	}

	cmd := exec.Command("bash", "./scripts/release-dry-run-artifact-audit.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"DRY_RUN=true",
		"COVENANT_RELEASE_DRY_RUN_ARTIFACT_AUDIT_JSON="+auditPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("dry-run artifact audit unexpectedly passed:\n%s", string(output))
	}
	if !strings.Contains(string(output), "release_dry_run_artifact_audit=failed") {
		t.Fatalf("audit output missing failed marker:\n%s", string(output))
	}
	bytes, readErr := os.ReadFile(auditPath)
	if readErr != nil {
		t.Fatalf("read failed audit report: %v\noutput:\n%s", readErr, string(output))
	}
	if err := schema.ValidateBytes(schema.ReleaseDryRunArtifactAuditSchemaID, bytes); err != nil {
		t.Fatalf("failed audit report did not validate: %v\n%s", err, string(bytes))
	}
	if !strings.Contains(string(bytes), "missing required artifact: manifest.json") {
		t.Fatalf("failed audit missing manifest finding:\n%s", string(bytes))
	}
}
