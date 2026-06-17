package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

type releaseConsumerSmokeFixture struct {
	repoRoot    string
	releaseDir  string
	outDir      string
	covenantBin string
}

func TestReleaseConsumerSmokeShellScriptRunsGeneratedFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell consumer smoke fixture runs on Unix-like CI")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}
	fixture := prepareReleaseConsumerSmokeFixture(t)
	scriptPath := filepath.Join(fixture.repoRoot, "scripts", "release-consumer-smoke.sh")
	cmd := exec.Command("bash", scriptPath, fixture.releaseDir, "--out", fixture.outDir, "--skip-attestation")
	cmd.Dir = fixture.repoRoot
	cmd.Env = append(os.Environ(), "COVENANT_BIN="+fixture.covenantBin)

	output := runReleaseConsumerSmokeCommand(t, cmd)

	if !strings.Contains(output, "release_consumer_smoke=passed") {
		t.Fatalf("shell smoke output missing passed marker:\n%s", output)
	}
	assertReleaseConsumerSmokeOutputs(t, fixture.releaseDir, fixture.outDir, true)
}

func TestReleaseConsumerSmokePowerShellScriptRunsGeneratedFixtureOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell consumer smoke fixture runs on Windows CI")
	}
	powershell, err := exec.LookPath("powershell")
	if err != nil {
		t.Skipf("powershell not available: %v", err)
	}
	fixture := prepareReleaseConsumerSmokeFixture(t)
	scriptPath := filepath.Join(fixture.repoRoot, "scripts", "release-consumer-smoke.ps1")
	cmd := exec.Command(powershell,
		"-NoProfile",
		"-ExecutionPolicy",
		"Bypass",
		"-File",
		scriptPath,
		fixture.releaseDir,
		"-Out",
		fixture.outDir,
		"-SkipAttestation",
		"-CovenantBin",
		fixture.covenantBin,
	)
	cmd.Dir = fixture.repoRoot

	output := runReleaseConsumerSmokeCommand(t, cmd)

	if !strings.Contains(output, "release_consumer_smoke=passed") {
		t.Fatalf("PowerShell smoke output missing passed marker:\n%s", output)
	}
	assertReleaseConsumerSmokeOutputs(t, fixture.releaseDir, fixture.outDir, true)
}

func prepareReleaseConsumerSmokeFixture(t *testing.T) releaseConsumerSmokeFixture {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	workDir := t.TempDir()
	binName := "covenant"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	covenantBin := filepath.Join(workDir, binName)
	build := exec.Command("go", "build", "-o", covenantBin, "./cmd/covenant")
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build covenant test binary: %v\n%s", err, string(output))
	}

	keysDir := filepath.Join(workDir, "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}
	privateKeyPath := filepath.Join(keysDir, "private.json")
	publicKeyPath := filepath.Join(keysDir, "public.json")
	keygen := exec.Command(covenantBin, "bundle", "keygen", "--private", privateKeyPath, "--public", publicKeyPath)
	keygen.Dir = repoRoot
	if output, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("generate release smoke keys: %v\n%s", err, string(output))
	}

	releaseDir := filepath.Join(workDir, "release")
	packageCmd := exec.Command(covenantBin,
		"release",
		"package",
		"--source", repoRoot,
		"--out", releaseDir,
		"--version", "v0.1.0",
		"--commit", "consumer-smoke-fixture",
		"--date", "2026-06-17T00:00:00Z",
		"--target", runtime.GOOS+"/"+runtime.GOARCH,
		"--sign-key", privateKeyPath,
		"--json",
	)
	packageCmd.Dir = repoRoot
	if output, err := packageCmd.CombinedOutput(); err != nil {
		t.Fatalf("package release smoke fixture: %v\n%s", err, string(output))
	}
	copyFile(t, publicKeyPath, filepath.Join(releaseDir, "covenant-release-public-key.json"))

	outDir := filepath.Join(workDir, "smoke-output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("create smoke output dir: %v", err)
	}
	return releaseConsumerSmokeFixture{
		repoRoot:    repoRoot,
		releaseDir:  releaseDir,
		outDir:      outDir,
		covenantBin: covenantBin,
	}
}

func runReleaseConsumerSmokeCommand(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("release consumer smoke command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("release consumer smoke stderr = %q, want empty", stderr.String())
	}
	return stdout.String()
}

func assertReleaseConsumerSmokeOutputs(t *testing.T, releaseDir, outDir string, attestationSkipped bool) {
	t.Helper()
	outputSchemas := map[string]string{
		"release-verify.json":         schema.ReleaseVerifyResultSchemaID,
		"release-report.json":         schema.ReleaseReportResultSchemaID,
		"release-inspect.json":        schema.ReleaseInspectResultSchemaID,
		"release-consumer-smoke.json": schema.ReleaseConsumerSmokeResultSchemaID,
	}
	for name, schemaID := range outputSchemas {
		path := filepath.Join(outDir, name)
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read smoke output %s: %v", name, err)
		}
		if err := schema.ValidateBytes(schemaID, bytes); err != nil {
			t.Fatalf("smoke output %s failed schema %s: %v\n%s", name, schemaID, err, string(bytes))
		}
	}

	var summary struct {
		SchemaVersion            string   `json:"schema_version"`
		Status                   string   `json:"status"`
		AttestationSkipped       bool     `json:"attestation_skipped"`
		AttestationChecked       bool     `json:"attestation_checked"`
		ReplacementPolicyPresent bool     `json:"replacement_policy_present"`
		ReleaseFiles             []string `json:"release_files"`
		ReportFiles              []string `json:"report_files"`
		Checks                   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	summaryBytes, err := os.ReadFile(filepath.Join(outDir, "release-consumer-smoke.json"))
	if err != nil {
		t.Fatalf("read consumer smoke summary: %v", err)
	}
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode consumer smoke summary: %v\n%s", err, string(summaryBytes))
	}
	if summary.SchemaVersion != schema.ReleaseConsumerSmokeResultSchemaID || summary.Status != "passed" {
		t.Fatalf("summary metadata = %+v", summary)
	}
	if summary.AttestationSkipped != attestationSkipped || summary.AttestationChecked == attestationSkipped {
		t.Fatalf("summary attestation flags = %+v", summary)
	}
	requireStringSet(t, "release files", summary.ReleaseFiles, []string{
		"manifest.json",
		"SHA256SUMS",
		"release-signature.json",
		"covenant-release-public-key.json",
	})
	requireStringSet(t, "report files", summary.ReportFiles, []string{
		"release-verify.json",
		"release-report.json",
		"release-inspect.json",
	})
	checks := make(map[string]string, len(summary.Checks))
	for _, check := range summary.Checks {
		checks[check.Name] = check.Status
	}
	for _, name := range []string{"required-files", "checksums", "release-verify", "release-report", "release-inspect", "schema-validation"} {
		if checks[name] != "passed" {
			t.Fatalf("summary check %s = %q, want passed; checks=%+v", name, checks[name], checks)
		}
	}
	if checks["attestation"] != "skipped" {
		t.Fatalf("summary attestation check = %q, want skipped; checks=%+v", checks["attestation"], checks)
	}
	if strings.Contains(string(summaryBytes), outDir) {
		t.Fatalf("consumer smoke summary leaked local output path %q:\n%s", outDir, string(summaryBytes))
	}
	if strings.Contains(string(summaryBytes), releaseDir) {
		t.Fatalf("consumer smoke summary leaked local release path %q:\n%s", releaseDir, string(summaryBytes))
	}
}

func copyFile(t *testing.T, fromPath, toPath string) {
	t.Helper()
	bytes, err := os.ReadFile(fromPath)
	if err != nil {
		t.Fatalf("read %s: %v", fromPath, err)
	}
	if err := os.WriteFile(toPath, bytes, 0o644); err != nil {
		t.Fatalf("write %s: %v", toPath, err)
	}
}

func requireStringSet(t *testing.T, name string, got []string, want []string) {
	t.Helper()
	values := make(map[string]bool, len(got))
	for _, value := range got {
		values[value] = true
	}
	for _, value := range want {
		if !values[value] {
			t.Fatalf("%s = %+v, missing %q", name, got, value)
		}
	}
}
