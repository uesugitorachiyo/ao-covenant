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

func TestReleaseWorkflowRequiresSignedProvenanceAutomation(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"tags:",
		"v*",
		"contents: write",
		"id-token: write",
		"attestations: write",
		"uses: actions/checkout@v6",
		"ref: ${{ github.event_name == 'workflow_dispatch' && inputs.version || github.ref }}",
		"uses: actions/setup-go@v6",
		"uses: actions/upload-artifact@v7",
		"uses: actions/attest-build-provenance@v4",
		"COVENANT_RELEASE_SIGNING_KEY",
		"covenant-release-private-key.json",
		"covenant-release-public-key.json",
		"chmod 600",
		"covenant.bundle-public-key.v1",
		"cp \"$COVENANT_RELEASE_PUBLIC_KEY\" dist/covenant-release-public-key.json",
		"go run ./cmd/covenant release package",
		"--sign-key",
		"--target linux/amd64",
		"--target linux/arm64",
		"--target darwin/amd64",
		"--target darwin/arm64",
		"--target windows/amd64",
		"go run ./cmd/covenant release verify",
		"go run ./cmd/covenant release report",
		"gh release create",
		"gh release upload",
		"$RUNNER_TEMP/release-notes.md",
		"subject-path:",
		"dist/*",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	for _, forbidden := range []string{
		"BEGIN PRIVATE KEY",
		"private_key\":",
		"bundle keygen",
	} {
		requireWorkflowOmits(t, workflow, forbidden)
	}
}

func TestReleaseDocsExplainSigningAndProvenanceAutomation(t *testing.T) {
	doc := readRepoFile(t, "docs", "release.md")

	for _, want := range []string{
		"COVENANT_RELEASE_SIGNING_KEY",
		"covenant.bundle-private-key.v1",
		"gh secret set COVENANT_RELEASE_SIGNING_KEY",
		"< covenant-release-private-key.json",
		"covenant-release-public-key.json",
		"GitHub artifact attestations",
		"gh release download",
		"chmod +x ao-covenant_*",
		"covenant release verify",
		"--public-key covenant-release-public-key.json",
		"post-release smoke verification",
		"gh attestation verify",
		"workflow_dispatch",
		"v*",
	} {
		requireWorkflowContains(t, doc, want)
	}
	requireWorkflowOmits(t, doc, "private_key\":")
	requireWorkflowOmits(t, doc, "--body-file")
}

func TestReleaseWorkflowRunsPostPublishSmokeVerification(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"outputs:",
		"version: ${{ steps.meta.outputs.version }}",
		"post-release-smoke",
		"name: Post-release smoke verification",
		"needs: release",
		"ref: ${{ needs.release.outputs.version }}",
		"gh release download \"$VERSION\"",
		"chmod +x smoke/ao-covenant_*",
		"go run ./cmd/covenant release verify",
		"--dir smoke",
		"--public-key smoke/covenant-release-public-key.json",
		"gh attestation verify smoke/manifest.json",
	} {
		requireWorkflowContains(t, workflow, want)
	}
}

func TestReleaseWorkflowSupportsDryRunDispatchWithoutPublishing(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"dry_run:",
		"description: \"Package, verify, preflight, and upload workflow artifacts without publishing\"",
		"default: true",
		"type: boolean",
		"dry_run: ${{ steps.meta.outputs.dry_run }}",
		"dry_run=\"false\"",
		"if [[ \"${{ github.event_name }}\" == \"workflow_dispatch\" && \"${{ inputs.dry_run }}\" == \"true\" ]]; then",
		"dry_run=\"true\"",
		"echo \"dry_run=$dry_run\"",
		"name: Generate GitHub artifact attestations",
		"if: steps.meta.outputs.dry_run != 'true'",
		"name: Publish GitHub release",
		"name: Post-release smoke verification",
		"if: needs.release.outputs.dry_run != 'true'",
		"name: Upload workflow artifact",
		"path: dist/*",
		"name: Upload replacement preflight report",
		"name: Audit dry-run workflow artifact",
		"if: steps.meta.outputs.dry_run == 'true'",
		"COVENANT_RELEASE_DRY_RUN_ARTIFACT_AUDIT_JSON: dist/release-dry-run-artifact-audit.json",
		"./scripts/release-dry-run-artifact-audit.sh",
	} {
		requireWorkflowContains(t, workflow, want)
	}
	for _, unwanted := range []string{
		"release-dry-run-artifact-audit.validation.json",
		"release-dry-run-artifact-audit.json.validation.json",
	} {
		requireWorkflowOmits(t, workflow, unwanted)
	}

	requireWorkflowOrder(t, workflow,
		"name: Upload replacement preflight report",
		"name: Generate GitHub artifact attestations",
		"name: Audit dry-run workflow artifact",
		"name: Upload workflow artifact",
		"name: Publish GitHub release",
	)
	requireWorkflowOmits(t, workflow, "if: steps.meta.outputs.dry_run == 'true'\n        uses: actions/attest-build-provenance")
	requireWorkflowOmits(t, workflow, "if: steps.meta.outputs.dry_run == 'true'\n        run: |\n          set -euo pipefail\n          notes=")
}

func TestReleaseWorkflowMatchesAttestationCoverageMap(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	replacementPreflight := readRepoFile(t, "scripts", "release-replacement-preflight.sh")
	coverage := readRepoFile(t, "docs", "release-attestation-coverage.md")

	for _, want := range []string{
		"attestations: write",
		"actions/attest-build-provenance@v4",
		"subject-path: \"dist/*\"",
		"gh attestation verify smoke/manifest.json",
		"covenant-release-public-key.json",
	} {
		requireWorkflowContains(t, workflow, want)
		requireWorkflowContains(t, coverage, want)
	}

	for _, want := range []string{
		"release-replacement-policy.json",
		"./scripts/release-replacement-preflight.sh",
	} {
		requireWorkflowContains(t, workflow+replacementPreflight, want)
	}
	requireWorkflowContains(t, coverage, "release-replacement-policy.json")

	for _, want := range []string{
		"post-release smoke verification",
		"direct GitHub attestation from `dist/*` when replacement metadata is generated",
		"manifest.json",
		"platform binaries",
	} {
		requireWorkflowContains(t, coverage, want)
	}
}

func TestReleaseWorkflowAttestsReplacementPolicyBeforePublish(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"name: Preflight release asset replacement",
		"id: replacement_preflight",
		"./scripts/release-replacement-preflight.sh",
		"DIST_DIR: dist",
		"VERSION: ${{ steps.meta.outputs.version }}",
		"REPLACE_EXISTING_ASSETS: ${{ github.event_name == 'workflow_dispatch' && inputs.replace_existing_assets || false }}",
		"REPLACEMENT_REASON: ${{ github.event_name == 'workflow_dispatch' && inputs.replacement_reason || '' }}",
		"COVENANT_RELEASE_REPLACEMENT_REPORT_JSON: ${{ runner.temp }}/release-replacement-preflight-report.json",
		"name: Upload replacement preflight report",
		"if: always() && steps.replacement_preflight.conclusion != 'skipped'",
		"name: ao-covenant-${{ steps.meta.outputs.version }}-replacement-preflight-report",
		"path: ${{ runner.temp }}/release-replacement-preflight-report.json",
		"name: Generate GitHub artifact attestations",
		"name: Publish GitHub release",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	requireWorkflowOrder(t, workflow,
		"name: Verify signed release",
		"name: Preflight release asset replacement",
		"name: Upload replacement preflight report",
		"name: Generate GitHub artifact attestations",
		"name: Upload workflow artifact",
		"name: Publish GitHub release",
	)
	requireWorkflowOrder(t, workflow,
		"./scripts/release-replacement-preflight.sh",
		"name: Generate GitHub artifact attestations",
	)
}

func TestReleaseWorkflowGuardsExistingReleaseAssets(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	script := readRepoFile(t, "scripts", "release-replacement-preflight.sh")

	for _, want := range []string{
		"replace_existing_assets:",
		"type: boolean",
		"default: false",
		"replacement_reason:",
		"DIST_DIR: dist",
		"REPLACE_EXISTING_ASSETS",
		"REPLACEMENT_REASON",
		"COVENANT_RELEASE_REPLACEMENT_REPORT_JSON",
		"./scripts/release-replacement-preflight.sh",
		"gh release upload \"$VERSION\" dist/* --clobber",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	for _, want := range []string{
		"release asset replacement requires workflow_dispatch input replace_existing_assets=true",
		"gh release view \"$VERSION\" --json assets --jq '.assets[].name'",
		"comm -12 \"$existing_assets\" \"$new_assets\"",
		"release-replacement-policy.json",
		"covenant.release-replacement-policy.v1",
		"\"replaced_assets\":",
		"go run ./cmd/covenant schema validate --schema covenant.release-replacement-policy.v1 --file \"$policy_path\"",
		"COVENANT_RELEASE_EXISTING_ASSETS_FILE",
		"covenant.release-replacement-preflight-report.v1",
		"write_preflight_report",
	} {
		requireWorkflowContains(t, script, want)
	}

	requireWorkflowOmits(t, workflow, "if gh release view \"$VERSION\" >/dev/null 2>&1; then\n            gh release upload \"$VERSION\" dist/* --clobber")
	requireWorkflowOmits(t, workflow, "ao-covenant.release-replacement-policy.v1")
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
		"os: [ubuntu-latest, macos-latest, windows-latest]",
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
		"uses: actions/upload-artifact@v7",
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

func TestReleaseDocsExplainAssetReplacementGuard(t *testing.T) {
	doc := readRepoFile(t, "docs", "release.md")

	for _, want := range []string{
		"replace_existing_assets",
		"replacement_reason",
		"release-replacement-policy.json",
		"`covenant.release-replacement-policy.v1`",
		"covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json",
		"Existing release assets are immutable by default",
	} {
		requireWorkflowContains(t, doc, want)
	}
	requireWorkflowContainsNormalized(t, doc, "AO Covenant fails closed instead of overwriting assets")
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
