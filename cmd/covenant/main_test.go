package main

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

func TestInstalledBinaryRunsReleaseReadinessSmoke(t *testing.T) {
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	binaryPath := filepath.Join(t.TempDir(), "covenant")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = packageDir
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build covenant binary: %v: %s", err, strings.TrimSpace(string(output)))
	}

	workspace := t.TempDir()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create demo-output/report.txt")
	if err := os.MkdirAll(filepath.Join(workspace, "artifacts"), 0o755); err != nil {
		t.Fatalf("create artifacts directory: %v", err)
	}

	runJSON := func(name string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(binaryPath, args...)
		cmd.Dir = workspace
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s failed: %v\nstdout:\n%s\nstderr:\n%s", name, err, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s stderr = %q, want empty", name, stderr.String())
		}
		path := filepath.Join(workspace, "artifacts", name+".json")
		if err := os.WriteFile(path, stdout.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return stdout.Bytes()
	}

	runJSON("version", "version", "--json")
	runJSON("compile",
		"compile",
		"--brief", "examples/risky-change/brief.md",
		"--out", "contract.json",
		"--json",
	)
	runJSON("lint-contract",
		"lint",
		"--contract", "contract.json",
		"--json",
	)

	runResultJSON := runJSON("run",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "binary-smoke",
		"--json",
	)
	var runResult struct {
		LedgerPath       string `json:"ledger_path"`
		EvidencePackPath string `json:"evidence_pack_path"`
	}
	if err := json.Unmarshal(runResultJSON, &runResult); err != nil {
		t.Fatalf("decode run json: %v; json = %q", err, string(runResultJSON))
	}
	if runResult.LedgerPath == "" || runResult.EvidencePackPath == "" {
		t.Fatalf("run result paths = %+v", runResult)
	}

	runJSON("verify",
		"verify",
		"--ledger", runResult.LedgerPath,
		"--evidence", runResult.EvidencePackPath,
		"--json",
	)
	keygenJSON := runJSON("bundle-keygen",
		"bundle", "keygen",
		"--private", "private.json",
		"--public", "public.json",
		"--json",
	)
	var keygenResult struct {
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(keygenJSON, &keygenResult); err != nil {
		t.Fatalf("decode keygen json: %v; json = %q", err, string(keygenJSON))
	}
	if len(keygenResult.PublicKeySHA256) != 64 {
		t.Fatalf("public key fingerprint = %q, want 64 hex chars", keygenResult.PublicKeySHA256)
	}

	runJSON("bundle-export",
		"bundle", "export",
		"--contract", "contract.json",
		"--ledger", runResult.LedgerPath,
		"--evidence", runResult.EvidencePackPath,
		"--workspace", ".",
		"--out", "bundle.zip",
		"--sign-key", "private.json",
		"--json",
	)
	runJSON("bundle-verify",
		"verify",
		"--bundle", "bundle.zip",
		"--public-key", "public.json",
		"--json",
	)
	releaseJSON := runJSON("release-package",
		"release", "package",
		"--source", repoRoot,
		"--out", "release",
		"--version", "v0.1.0-binary-smoke",
		"--commit", "binary-smoke",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--json",
	)
	var releaseResult struct {
		ManifestPath string `json:"manifest_path"`
	}
	if err := json.Unmarshal(releaseJSON, &releaseResult); err != nil {
		t.Fatalf("decode release package json: %v; json = %q", err, string(releaseJSON))
	}
	if releaseResult.ManifestPath != filepath.Join("release", "manifest.json") {
		t.Fatalf("release manifest path = %q, want release/manifest.json", releaseResult.ManifestPath)
	}

	manifestEntry := func(path string) string {
		t.Helper()
		if filepath.IsAbs(path) {
			relative, err := filepath.Rel(workspace, path)
			if err != nil {
				t.Fatalf("make %s relative to %s: %v", path, workspace, err)
			}
			path = relative
		}
		return filepath.ToSlash(filepath.Clean(path))
	}
	manifest := strings.Join([]string{
		"contract.json",
		manifestEntry(runResult.EvidencePackPath),
		"private.json",
		"public.json",
		manifestEntry(releaseResult.ManifestPath),
		"artifacts/version.json",
		"artifacts/compile.json",
		"artifacts/lint-contract.json",
		"artifacts/run.json",
		"artifacts/verify.json",
		"artifacts/bundle-keygen.json",
		"artifacts/bundle-export.json",
		"artifacts/bundle-verify.json",
		"artifacts/release-package.json",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(workspace, "schema-files.txt"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write schema-files.txt: %v", err)
	}

	var validationStdout bytes.Buffer
	var validationStderr bytes.Buffer
	validation := exec.Command(binaryPath,
		"schema", "validate",
		"--files-from", "schema-files.txt",
		"--json",
		"--out", "artifacts/schema-validation.json",
	)
	validation.Dir = workspace
	validation.Stdout = &validationStdout
	validation.Stderr = &validationStderr
	if err := validation.Run(); err != nil {
		t.Fatalf("schema validation failed: %v\nstdout:\n%s\nstderr:\n%s", err, validationStdout.String(), validationStderr.String())
	}
	if validationStdout.String() != "schema_validation_report=artifacts/schema-validation.json\n" {
		t.Fatalf("schema validation stdout = %q", validationStdout.String())
	}
	if validationStderr.Len() != 0 {
		t.Fatalf("schema validation stderr = %q, want empty", validationStderr.String())
	}
}

func TestReleaseReadinessScriptRunsSmokeGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-readiness.sh requires a Unix shell")
	}
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	workDir := t.TempDir()
	scriptPath := filepath.Join(repoRoot, "scripts", "release-readiness.sh")
	scriptInfo, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("stat release-readiness.sh: %v", err)
	}
	if scriptInfo.Mode()&0o111 == 0 {
		t.Fatalf("release-readiness.sh mode = %v, want executable bit", scriptInfo.Mode().Perm())
	}

	cmd := exec.Command(scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"COVENANT_RELEASE_READINESS_DIR="+workDir,
		"COVENANT_RELEASE_VERSION=v0.1.0-script-smoke",
		"COVENANT_RELEASE_COMMIT=script-smoke",
		"COVENANT_RELEASE_DATE=2026-06-12T00:00:00Z",
		"COVENANT_RELEASE_TARGET="+runtime.GOOS+"/"+runtime.GOARCH,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("release-readiness.sh failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "release readiness complete") {
		t.Fatalf("stdout = %q, want completion marker", stdout.String())
	}
	for _, path := range []string{
		filepath.Join(workDir, "artifacts", "release-package.json"),
		filepath.Join(workDir, "artifacts", "policy-spine.json"),
		filepath.Join(workDir, "artifacts", "release-verify.json"),
		filepath.Join(workDir, "artifacts", "schema-validation.json"),
		filepath.Join(workDir, "artifacts", "release-readiness-summary-validation.json"),
		filepath.Join(workDir, "artifacts", "binary-release-verify.json"),
		filepath.Join(workDir, "release-readiness-summary.json"),
		filepath.Join(workDir, "release", "manifest.json"),
		filepath.Join(workDir, "release", "release-signature.json"),
		filepath.Join(workDir, "release", "covenant-release-public-key.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected readiness artifact %s: %v\nstdout:\n%s\nstderr:\n%s", path, err, stdout.String(), stderr.String())
		}
	}
	summaryBytes, err := os.ReadFile(filepath.Join(workDir, "release-readiness-summary.json"))
	if err != nil {
		t.Fatalf("read release readiness summary: %v", err)
	}
	var summary map[string]any
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("release readiness summary is not JSON: %v\n%s", err, string(summaryBytes))
	}
	for key, want := range map[string]string{
		"schema_version": schema.ReleaseReadinessSummarySchemaID,
		"status":         "passed",
		"version":        "v0.1.0-script-smoke",
		"commit":         "script-smoke",
		"date":           "2026-06-12T00:00:00Z",
		"target":         runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if got, ok := summary[key].(string); !ok || got != want {
			t.Fatalf("summary[%q] = %v, want %q\njson:\n%s", key, summary[key], want, string(summaryBytes))
		}
	}
	for _, forbidden := range []string{
		workDir,
		"covenant-private-key.json",
		"covenant-public-key.json",
		"release-ready-bundle.zip",
		"SHA256SUMS",
		"manifest.json",
		"release-signature.json",
	} {
		if strings.Contains(string(summaryBytes), forbidden) {
			t.Fatalf("release readiness summary contains sensitive or generated detail %q:\n%s", forbidden, string(summaryBytes))
		}
	}
	validateSchemaFile(t, schema.ReleasePackageResultSchemaID, filepath.Join(workDir, "artifacts", "release-package.json"))
	validateSchemaFile(t, schema.PolicySpineResultSchemaID, filepath.Join(workDir, "artifacts", "policy-spine.json"))
	validateSchemaFile(t, schema.ReleaseVerifyResultSchemaID, filepath.Join(workDir, "artifacts", "release-verify.json"))
	validateSchemaFile(t, schema.SchemaValidationReportSchemaID, filepath.Join(workDir, "artifacts", "schema-validation.json"))
	validateSchemaFile(t, schema.SchemaValidationReportSchemaID, filepath.Join(workDir, "artifacts", "release-readiness-summary-validation.json"))
	validateSchemaFile(t, schema.ReleaseVerifyResultSchemaID, filepath.Join(workDir, "artifacts", "binary-release-verify.json"))
	validateSchemaFile(t, schema.ReleaseReadinessSummarySchemaID, filepath.Join(workDir, "release-readiness-summary.json"))
	validateSchemaFile(t, schema.ReleaseManifestSchemaID, filepath.Join(workDir, "release", "manifest.json"))
	validateSchemaFile(t, schema.ReleaseSignatureSchemaID, filepath.Join(workDir, "release", "release-signature.json"))
	validateSchemaFile(t, schema.BundlePublicKeySchemaID, filepath.Join(workDir, "release", "covenant-release-public-key.json"))
}

func TestReleaseReadinessScriptAcceptsRelativeReadinessDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-readiness.sh requires a Unix shell")
	}
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	relativeWorkDir := filepath.Join("tmp", "release-readiness-relative-test")
	workDir := filepath.Join(repoRoot, relativeWorkDir)
	t.Cleanup(func() {
		_ = os.RemoveAll(workDir)
	})

	cmd := exec.Command(filepath.Join(repoRoot, "scripts", "release-readiness.sh"))
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"COVENANT_RELEASE_READINESS_DIR="+relativeWorkDir,
		"COVENANT_RELEASE_VERSION=v0.1.0-relative-dir-smoke",
		"COVENANT_RELEASE_COMMIT=relative-dir-smoke",
		"COVENANT_RELEASE_DATE=2026-06-23T00:00:00Z",
		"COVENANT_RELEASE_TARGET="+runtime.GOOS+"/"+runtime.GOARCH,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("release-readiness.sh failed with relative readiness dir: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "release-readiness-summary.json")); err != nil {
		t.Fatalf("relative readiness dir summary missing: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "release readiness complete") {
		t.Fatalf("stdout = %q, want completion marker", stdout.String())
	}
}

func validateSchemaFile(t *testing.T, schemaID string, path string) {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := schema.ValidateBytes(schemaID, bytes); err != nil {
		t.Fatalf("%s did not match %s: %v\njson:\n%s", path, schemaID, err, string(bytes))
	}
}

func mustWriteFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
