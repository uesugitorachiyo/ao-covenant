package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseReplacementPreflightFixturesAreStableAndIndexed(t *testing.T) {
	const fixtureDir = "internal/cli/testdata/release-replacement-preflight-fixtures"
	indexBytes, err := os.ReadFile(filepath.Join("testdata", "release-fixture-index.json"))
	if err != nil {
		t.Fatalf("read release fixture index: %v", err)
	}
	if !strings.Contains(string(indexBytes), `"name": "release-replacement-preflight"`) {
		t.Fatalf("release fixture index missing release-replacement-preflight entry")
	}
	if !strings.Contains(string(indexBytes), `"directory": "`+fixtureDir+`"`) {
		t.Fatalf("release fixture index missing %s", fixtureDir)
	}

	for _, name := range []string{
		"dist-assets.txt",
		"existing-assets.txt",
		"fail-closed-diagnostic.txt",
		"generated-policy.json",
	} {
		if !strings.Contains(string(indexBytes), `"`+name+`"`) {
			t.Fatalf("release fixture index missing %s", name)
		}
		if _, err := os.Stat(filepath.Join("testdata", "release-replacement-preflight-fixtures", name)); err != nil {
			t.Fatalf("fixture %s is not readable: %v", name, err)
		}
	}

	generatedPolicy := readReplacementPreflightFixture(t, "generated-policy.json")
	if err := schema.ValidateBytes(schema.ReleaseReplacementPolicySchemaID, generatedPolicy); err != nil {
		t.Fatalf("generated replacement policy fixture did not validate: %v\n%s", err, string(generatedPolicy))
	}
	requireNoSensitiveReleaseFixtureText(t, "generated-policy.json", string(generatedPolicy))
}

func TestReleaseReplacementPreflightFixturesMatchScriptOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash replacement preflight fixture smoke is covered on Unix-like platforms")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available: %v", err)
	}

	policyDist := replacementPreflightDistFromFixture(t)
	runReplacementPreflightFixture(t, policyDist, "true")
	policyPath := filepath.Join(policyDist, "release-replacement-policy.json")
	gotPolicy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read generated replacement policy: %v", err)
	}
	wantPolicy := readReplacementPreflightFixture(t, "generated-policy.json")
	if !bytes.Equal(bytes.TrimSpace(gotPolicy), bytes.TrimSpace(wantPolicy)) {
		t.Fatalf("generated policy mismatch\n--- got ---\n%s\n--- want ---\n%s", gotPolicy, wantPolicy)
	}

	failClosedDist := replacementPreflightDistFromFixture(t)
	output, err := runReplacementPreflightFixture(t, failClosedDist, "false")
	if err == nil {
		t.Fatalf("preflight succeeded, want fail-closed conflict\n%s", output)
	}
	wantDiagnostic := readReplacementPreflightFixture(t, "fail-closed-diagnostic.txt")
	if strings.TrimSpace(string(output)) != strings.TrimSpace(string(wantDiagnostic)) {
		t.Fatalf("fail-closed diagnostic mismatch\n--- got ---\n%s\n--- want ---\n%s", output, wantDiagnostic)
	}
	if _, err := os.Stat(filepath.Join(failClosedDist, "release-replacement-policy.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement policy should not exist after fail-closed preflight: %v", err)
	}
	requireNoSensitiveReleaseFixtureText(t, "fail-closed-diagnostic.txt", string(output))
}

func replacementPreflightDistFromFixture(t *testing.T) string {
	t.Helper()
	distDir := t.TempDir()
	for _, name := range strings.Fields(string(readReplacementPreflightFixture(t, "dist-assets.txt"))) {
		if err := os.WriteFile(filepath.Join(distDir, name), []byte(name+"\n"), 0o644); err != nil {
			t.Fatalf("write dist asset %s: %v", name, err)
		}
	}
	return distDir
}

func runReplacementPreflightFixture(t *testing.T, distDir string, replace string) ([]byte, error) {
	t.Helper()
	repoRoot := filepath.Join("..", "..")
	existingAssets, err := filepath.Abs(filepath.Join("testdata", "release-replacement-preflight-fixtures", "existing-assets.txt"))
	if err != nil {
		t.Fatalf("resolve existing assets fixture path: %v", err)
	}
	cmd := exec.Command("bash", "./scripts/release-replacement-preflight.sh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"DIST_DIR="+distDir,
		"VERSION=v0.1.0",
		"REPLACE_EXISTING_ASSETS="+replace,
		"REPLACEMENT_REASON=public release correction",
		"GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"GITHUB_RUN_ID=12345",
		"GITHUB_RUN_ATTEMPT=1",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE="+existingAssets,
		"COVENANT_RELEASE_REPLACEMENT_CREATED_AT=2026-06-16T00:00:00Z",
	)
	return cmd.CombinedOutput()
}

func readReplacementPreflightFixture(t *testing.T, name string) []byte {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "release-replacement-preflight-fixtures", name))
	if err != nil {
		t.Fatalf("read release replacement preflight fixture %s: %v", name, err)
	}
	return bytes
}
