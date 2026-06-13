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
		"chmod 600",
		"covenant.bundle-public-key.v1",
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
		"GitHub artifact attestations",
		"covenant release verify",
		"workflow_dispatch",
		"v*",
	} {
		requireWorkflowContains(t, doc, want)
	}
	requireWorkflowOmits(t, doc, "private_key\":")
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
