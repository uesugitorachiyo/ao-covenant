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

func TestReleaseReplacementPreflightScriptSimulatesPolicyGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash replacement preflight smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	existingAssets := filepath.Join(t.TempDir(), "existing-assets.txt")

	for _, name := range []string{
		"manifest.json",
		"SHA256SUMS",
		"release-signature.json",
		"covenant-release-public-key.json",
		"ao-covenant_v0.1.0_linux_amd64",
	} {
		if err := os.WriteFile(filepath.Join(distDir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatalf("write dist asset %s: %v", name, err)
		}
	}
	if err := os.WriteFile(existingAssets, []byte(strings.Join([]string{
		"manifest.json",
		"ao-covenant_v0.1.0_linux_amd64",
	}, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write existing assets: %v", err)
	}

	cmd := exec.Command("bash", "./scripts/release-replacement-preflight.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"REPLACE_EXISTING_ASSETS=true",
		"REPLACEMENT_REASON=public release correction",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=2",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE="+existingAssets,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("preflight failed: %v\n%s", err, string(output))
	}

	policyPath := filepath.Join(distDir, "release-replacement-policy.json")
	bytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read replacement policy: %v\noutput:\n%s", err, string(output))
	}
	var policy struct {
		SchemaVersion  string   `json:"schema_version"`
		Version        string   `json:"version"`
		Reason         string   `json:"reason"`
		ReplacedAssets []string `json:"replaced_assets"`
		GitHub         struct {
			Repository string `json:"repository"`
			RunID      string `json:"run_id"`
			RunAttempt string `json:"run_attempt"`
		} `json:"github"`
	}
	if err := json.Unmarshal(bytes, &policy); err != nil {
		t.Fatalf("decode replacement policy: %v\n%s", err, string(bytes))
	}
	if policy.SchemaVersion != "covenant.release-replacement-policy.v1" {
		t.Fatalf("schema_version = %q", policy.SchemaVersion)
	}
	if policy.Version != "v0.1.0" || policy.Reason != "public release correction" {
		t.Fatalf("policy metadata = %+v", policy)
	}
	if got, want := strings.Join(policy.ReplacedAssets, ","), "ao-covenant_v0.1.0_linux_amd64,manifest.json"; got != want {
		t.Fatalf("replaced_assets = %q, want %q", got, want)
	}
	if policy.GitHub.Repository != "uesugitorachiyo/ao-covenant" || policy.GitHub.RunID != "12345" || policy.GitHub.RunAttempt != "2" {
		t.Fatalf("github metadata = %+v", policy.GitHub)
	}
}

func TestReleaseReplacementPreflightScriptFailsClosedWithoutReplacementOptIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell exit-code assertion is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	existingAssets := filepath.Join(t.TempDir(), "existing-assets.txt")

	if err := os.WriteFile(filepath.Join(distDir, "manifest.json"), []byte("manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(existingAssets, []byte("manifest.json\n"), 0o644); err != nil {
		t.Fatalf("write existing assets: %v", err)
	}

	cmd := exec.Command("bash", "./scripts/release-replacement-preflight.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"REPLACE_EXISTING_ASSETS=false",
		"REPLACEMENT_REASON=public release correction",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=2",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE="+existingAssets,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("preflight succeeded, want fail-closed conflict\n%s", string(output))
	}
	if !strings.Contains(string(output), "release asset replacement requires workflow_dispatch input replace_existing_assets=true") {
		t.Fatalf("output = %q, want replacement opt-in diagnostic", string(output))
	}
	if _, err := os.Stat(filepath.Join(distDir, "release-replacement-policy.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement policy should not exist after fail-closed preflight: %v", err)
	}
}

func TestReleaseReplacementPreflightScriptWritesReportForReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash replacement preflight report smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	existingAssets := filepath.Join(t.TempDir(), "existing-assets.txt")
	reportPath := filepath.Join(t.TempDir(), "release-replacement-preflight-report.json")

	for _, name := range []string{
		"manifest.json",
		"SHA256SUMS",
		"release-signature.json",
		"covenant-release-public-key.json",
		"ao-covenant_v0.1.0_linux_amd64",
	} {
		if err := os.WriteFile(filepath.Join(distDir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatalf("write dist asset %s: %v", name, err)
		}
	}
	if err := os.WriteFile(existingAssets, []byte("manifest.json\nao-covenant_v0.1.0_linux_amd64\n"), 0o644); err != nil {
		t.Fatalf("write existing assets: %v", err)
	}

	cmd := exec.Command("bash", "./scripts/release-replacement-preflight.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"REPLACE_EXISTING_ASSETS=true",
		"REPLACEMENT_REASON=public release correction",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=2",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE="+existingAssets,
		"COVENANT_RELEASE_REPLACEMENT_CREATED_AT=2026-06-16T00:00:00Z",
		"COVENANT_RELEASE_REPLACEMENT_REPORT_JSON="+reportPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("preflight failed: %v\n%s", err, string(output))
	}

	report := readReplacementPreflightReport(t, reportPath)
	if report.SchemaVersion != "covenant.release-replacement-preflight-report.v1" {
		t.Fatalf("schema_version = %q", report.SchemaVersion)
	}
	if report.Status != "replacement_policy_written" || !report.ReplaceExistingAssets || !report.ReleaseExists {
		t.Fatalf("report status fields = %+v", report)
	}
	if report.PolicyPath != "release-replacement-policy.json" {
		t.Fatalf("policy_path = %q", report.PolicyPath)
	}
	if got, want := strings.Join(report.Assets.Conflicting, ","), "ao-covenant_v0.1.0_linux_amd64,manifest.json"; got != want {
		t.Fatalf("conflicting assets = %q, want %q", got, want)
	}
	if got := strings.Join(report.Assets.New, ","); !strings.Contains(got, "release-replacement-policy.json") {
		t.Fatalf("new assets = %q, want release-replacement-policy.json included", got)
	}
}

func TestReleaseReplacementPreflightScriptWritesReportBeforeFailClosedExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash replacement preflight report smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	repoRoot := filepath.Join("..", "..")
	distDir := t.TempDir()
	existingAssets := filepath.Join(t.TempDir(), "existing-assets.txt")
	reportPath := filepath.Join(t.TempDir(), "release-replacement-preflight-report.json")

	if err := os.WriteFile(filepath.Join(distDir, "manifest.json"), []byte("manifest\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(existingAssets, []byte("manifest.json\n"), 0o644); err != nil {
		t.Fatalf("write existing assets: %v", err)
	}

	cmd := exec.Command("bash", "./scripts/release-replacement-preflight.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"REPLACE_EXISTING_ASSETS=false",
		"REPLACEMENT_REASON=public release correction",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=2",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE="+existingAssets,
		"COVENANT_RELEASE_REPLACEMENT_CREATED_AT=2026-06-16T00:00:00Z",
		"COVENANT_RELEASE_REPLACEMENT_REPORT_JSON="+reportPath,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("preflight succeeded, want fail-closed conflict\n%s", string(output))
	}

	report := readReplacementPreflightReport(t, reportPath)
	if report.Status != "blocked_existing_assets" || report.ReplaceExistingAssets || !report.ReleaseExists {
		t.Fatalf("report status fields = %+v", report)
	}
	if report.Error != "release asset replacement requires workflow_dispatch input replace_existing_assets=true" {
		t.Fatalf("error = %q", report.Error)
	}
	if got, want := strings.Join(report.Assets.Conflicting, ","), "manifest.json"; got != want {
		t.Fatalf("conflicting assets = %q, want %q", got, want)
	}
}

type replacementPreflightReport struct {
	SchemaVersion         string `json:"schema_version"`
	Version               string `json:"version"`
	Status                string `json:"status"`
	ReplaceExistingAssets bool   `json:"replace_existing_assets"`
	ReleaseExists         bool   `json:"release_exists"`
	PolicyPath            string `json:"policy_path,omitempty"`
	Error                 string `json:"error,omitempty"`
	Assets                struct {
		New         []string `json:"new"`
		Existing    []string `json:"existing"`
		Conflicting []string `json:"conflicting"`
	} `json:"assets"`
}

func readReplacementPreflightReport(t *testing.T, path string) replacementPreflightReport {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preflight report: %v", err)
	}
	if err := schema.ValidateBytes("covenant.release-replacement-preflight-report.v1", bytes); err != nil {
		t.Fatalf("preflight report did not validate against schema: %v\n%s", err, string(bytes))
	}
	var report replacementPreflightReport
	if err := json.Unmarshal(bytes, &report); err != nil {
		t.Fatalf("decode preflight report: %v\n%s", err, string(bytes))
	}
	return report
}
