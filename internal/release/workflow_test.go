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

func TestReleaseWorkflowGuardsExistingReleaseAssets(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"replace_existing_assets:",
		"type: boolean",
		"default: false",
		"replacement_reason:",
		"REPLACE_EXISTING_ASSETS",
		"REPLACEMENT_REASON",
		"release asset replacement requires workflow_dispatch input replace_existing_assets=true",
		"gh release view \"$VERSION\" --json assets --jq '.assets[].name'",
		"comm -12 \"$existing_assets\" \"$new_assets\"",
		"release-replacement-policy.json",
		"ao-covenant.release-replacement-policy.v1",
		"replaced_assets:",
		"gh release upload \"$VERSION\" dist/* --clobber",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	requireWorkflowOmits(t, workflow, "if gh release view \"$VERSION\" >/dev/null 2>&1; then\n            gh release upload \"$VERSION\" dist/* --clobber")
}

func TestReleaseReadinessWorkflowRunsSmokeGateWithoutPublishing(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release-readiness.yml")

	for _, want := range []string{
		"name: Release Readiness",
		"workflow_dispatch:",
		"schedule:",
		"cron:",
		"contents: read",
		"uses: actions/checkout@v6",
		"uses: actions/setup-go@v6",
		"go-version-file: go.mod",
		"cache: true",
		"COVENANT_RELEASE_READINESS_DIR",
		"$RUNNER_TEMP/covenant-release-readiness",
		"./scripts/release-readiness.sh",
		"uses: actions/upload-artifact@v7",
		"name: ao-covenant-release-readiness-summary",
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

func TestReleaseDocsExplainAssetReplacementGuard(t *testing.T) {
	doc := readRepoFile(t, "docs", "release.md")

	for _, want := range []string{
		"replace_existing_assets",
		"replacement_reason",
		"release-replacement-policy.json",
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
