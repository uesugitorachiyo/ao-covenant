package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIActionsUseNode24CompatibleVersions(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "ci.yml")

	requireWorkflowContains(t, workflow, "uses: actions/checkout@v6")
	requireWorkflowContains(t, workflow, "uses: actions/setup-go@v6")
	requireWorkflowOmits(t, workflow, "uses: actions/checkout@v4")
	requireWorkflowOmits(t, workflow, "uses: actions/setup-go@v5")
}

func TestCIWorkflowRunsRepositoryPolicyScanners(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "ci.yml")

	requireWorkflowContains(t, workflow, "name: License policy")
	requireWorkflowContains(t, workflow, "scripts/check-license-policy.sh")
	requireWorkflowContains(t, workflow, "scripts/check-public-repo-policy.sh")
	requireWorkflowOrder(t, workflow, "scripts/check-license-policy.sh", "scripts/check-public-repo-policy.sh")
}

func TestCIWorkflowPinsMacOSRunner(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "ci.yml")

	requireWorkflowContains(t, workflow, "name: Go ${{ matrix.os }}")
	requireWorkflowContains(t, workflow, "os: [ubuntu-latest, macos-26, windows-latest]")
	requireWorkflowOmits(t, workflow, "macos-latest")
}

func TestReleaseDocsExplainSigningAndProvenanceAutomation(t *testing.T) {
	doc := readRepoFile(t, "docs", "release.md")

	for _, want := range []string{
		"COVENANT_RELEASE_SIGNING_KEY",
		"covenant.bundle-private-key.v1",
		"gh secret set COVENANT_RELEASE_SIGNING_KEY",
		"< covenant-release-private-key.json",
		"covenant-release-public-key.json",
		"gh release download",
		"chmod +x ao-covenant_*",
		"covenant release verify",
		"--public-key covenant-release-public-key.json",
		"post-release smoke verification",
		"workflow_dispatch",
		"approved_manifest_sha256",
		"ao-covenant-release",
	} {
		requireWorkflowContains(t, doc, want)
	}
	requireWorkflowOmits(t, doc, "private_key\":")
	requireWorkflowOmits(t, doc, "--body-file")
}

func TestReleaseReadinessWorkflowRunsSmokeGateWithoutPublishing(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release-readiness.yml")

	for _, want := range []string{
		"name: Release Readiness",
		"workflow_dispatch:",
		"schedule:",
		"cron:",
		"contents: read",
		"strategy:",
		"fail-fast: false",
		"matrix:",
		"os: [ubuntu-latest, macos-26, windows-latest]",
		"runs-on: ${{ matrix.os }}",
		"uses: actions/checkout@v6",
		"uses: actions/setup-go@v6",
		"go-version-file: go.mod",
		"cache: true",
		"if: runner.os != 'Windows'",
		"shell: bash",
		"COVENANT_RELEASE_READINESS_DIR",
		"$RUNNER_TEMP/covenant-release-readiness",
		"./scripts/release-readiness.sh",
		"if: runner.os == 'Windows'",
		"shell: pwsh",
		"./scripts/release-readiness.ps1",
		"uses: actions/upload-artifact@v7.0.1",
		"name: ao-covenant-release-readiness-summary-${{ matrix.os }}",
		"path: ${{ runner.temp }}/covenant-release-readiness/release-readiness-summary.json",
		"if-no-files-found: error",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	for _, forbidden := range []string{
		"contents: write",
		"id-token: write",
		"attestations: write",
		"gh release",
		"release package",
		"release upload",
		"path: ${{ runner.temp }}/covenant-release-readiness/**",
		"path: ${{ runner.temp }}/covenant-release-readiness/artifacts/",
		"path: ${{ runner.temp }}/covenant-release-readiness/release/",
		"macos-latest",
		"actions/upload-artifact@v7\n",
	} {
		requireWorkflowOmits(t, workflow, forbidden)
	}
}

func TestProductionReadinessOpsWorkflowVerifiesBranchProtectionDrift(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "production-readiness-ops.yml")
	readme := readRepoFile(t, "README.md")
	runbook := readRepoFile(t, "docs", "branch-protection.md")

	for _, want := range []string{
		"name: Production Readiness Ops",
		"workflow_dispatch:",
		"schedule:",
		"cron:",
		"contents: read",
		"name: Branch protection drift",
		"runs-on: ubuntu-latest",
		"uses: actions/checkout@v6",
		"GH_TOKEN: ${{ github.token }}",
		"AO_COVENANT_BRANCH_PROTECTION_MODE: limited",
		"scripts/verify-branch-protection.sh",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	for _, forbidden := range []string{
		"contents: write",
		"id-token: write",
		"attestations: write",
		"gh release",
	} {
		requireWorkflowOmits(t, workflow, forbidden)
	}

	for _, want := range []string{
		"Production Readiness Ops",
		"production-readiness-ops.yml",
		"scripts/verify-branch-protection.sh",
	} {
		requireWorkflowContains(t, readme, want)
		requireWorkflowContains(t, runbook, want)
	}
}

func TestBranchProtectionVerifierSupportsLimitedWorkflowTokenMode(t *testing.T) {
	script := readRepoFile(t, "scripts", "verify-branch-protection.sh")
	runbook := readRepoFile(t, "docs", "branch-protection.md")

	for _, want := range []string{
		`mode="${AO_COVENANT_BRANCH_PROTECTION_MODE:-full}"`,
		`if [[ "$mode" == "full" ]]; then`,
		`gh api "repos/${repository}/branches/${branch}/protection"`,
		`elif [[ "$mode" == "limited" ]]; then`,
		`gh api "repos/${repository}/branches/${branch}"`,
		`unsupported AO_COVENANT_BRANCH_PROTECTION_MODE`,
		`"mode": mode`,
		`"branch_metadata_api_available": True`,
		`"branch_protected": branch_info.get("protected") is True`,
		`required_status_checks.get("enforcement_level") == "everyone"`,
	} {
		requireWorkflowContains(t, script, want)
	}

	for _, want := range []string{
		"AO_COVENANT_BRANCH_PROTECTION_MODE=limited",
		"branch metadata API",
		"workflow `GH_TOKEN`",
		"full mode",
	} {
		requireWorkflowContains(t, runbook, want)
	}
}

func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(bytes)
}

func requireWorkflowContains(t *testing.T, workflow string, want string) {
	t.Helper()
	if !strings.Contains(workflow, want) {
		t.Fatalf("workflow missing %q", want)
	}
}

func requireWorkflowOmits(t *testing.T, workflow string, forbidden string) {
	t.Helper()
	if strings.Contains(workflow, forbidden) {
		t.Fatalf("workflow contains forbidden %q", forbidden)
	}
}

func requireWorkflowContainsNormalized(t *testing.T, workflow string, want string) {
	t.Helper()
	normalized := strings.Join(strings.Fields(workflow), " ")
	if !strings.Contains(normalized, want) {
		t.Fatalf("workflow missing %q", want)
	}
}

func requireWorkflowOrder(t *testing.T, workflow string, wants ...string) {
	t.Helper()
	last := -1
	for _, want := range wants {
		index := strings.Index(workflow, want)
		if index == -1 {
			t.Fatalf("workflow missing %q", want)
		}
		if index <= last {
			t.Fatalf("workflow has %q out of order", want)
		}
		last = index
	}
}
