package release

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseWorkflowHasBoundedManualAuthority(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")

	for _, want := range []string{
		"workflow_dispatch:",
		"source_sha:",
		"version:",
		"tag:",
		"approved_manifest_base64:",
		"approved_manifest_sha256:",
		"dry_run:",
		"live_confirmation:",
		"environment: ao-covenant-release",
		"contents: write",
		"id-token: write",
		"attestations: write",
		"actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373",
		"COVENANT_RELEASE_SIGNING_KEY",
		"covenant-release-private-key.json",
		"covenant-release-public-key.json",
		"chmod 600",
		"go test ./... -count=1",
		"go vet ./...",
		"covenant release verify",
		"publication_status",
		"not_attempted",
		"tag_creation_attempted",
		"release_creation_attempted",
		"public_upload_attempted",
	} {
		requireWorkflowContains(t, workflow, want)
	}
	requireWorkflowContainsNormalized(t, workflow, "permissions: contents: read")

	for _, forbidden := range []string{
		"push:",
		"replace_existing_assets",
		"replacement_reason",
		"--clobber",
		"BEGIN PRIVATE KEY",
	} {
		requireWorkflowOmits(t, workflow, forbidden)
	}
}

func TestReleaseWorkflowPinsEveryActionToApprovedImmutableCommit(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	approved := map[string]string{
		"actions/checkout":                "df4cb1c069e1874edd31b4311f1884172cec0e10",
		"actions/setup-go":                "924ae3a1cded613372ab5595356fb5720e22ba16",
		"actions/upload-artifact":         "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
		"actions/download-artifact":       "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
		"actions/attest-build-provenance": "0f67c3f4856b2e3261c31976d6725780e5e4c373",
	}
	usesPattern := regexp.MustCompile(`(?m)^\s*uses:\s+([^@\s]+)@([^\s#]+)`)
	uses := usesPattern.FindAllStringSubmatch(workflow, -1)
	if len(uses) == 0 {
		t.Fatal("release workflow has no action references")
	}
	for _, match := range uses {
		want, ok := approved[match[1]]
		if !ok {
			t.Fatalf("release workflow uses unapproved action %q", match[1])
		}
		if match[2] != want {
			t.Fatalf("action %s ref = %q, want immutable commit %q", match[1], match[2], want)
		}
		if matched, _ := regexp.MatchString(`^[0-9a-f]{40}$`, match[2]); !matched {
			t.Fatalf("action %s ref is mutable: %q", match[1], match[2])
		}
	}
}

func TestReleaseWorkflowBuildsAndChecksNativeCandidates(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	builder := readRepoFile(t, "scripts", "build-release-candidate.py")
	verifier := readRepoFile(t, "scripts", "verify-release-modernization.py")

	for _, want := range []string{
		"runs-on: ${{ matrix.runner }}",
		"runner: ubuntu-latest",
		"runner: macos-15-intel",
		"runner: windows-latest",
		"target: linux-amd64",
		"target: darwin-amd64",
		"target: windows-amd64",
		"scripts/build-release-candidate.py",
		"scripts/verify-release-modernization.py candidates",
		"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
		"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
		"LICENSE",
		"NOTICE",
		"candidate-summary.json",
		"promotion-plan.json",
		"release-signature.json",
		"release-verify.json",
		"release-report.json",
	} {
		requireWorkflowContains(t, workflow+builder+verifier, want)
	}
}

func TestReleaseCandidateUsesSupportedProviderFreeSchemaSmoke(t *testing.T) {
	builder := readRepoFile(t, "scripts", "build-release-candidate.py")
	requireWorkflowContains(t, builder, `[str(binary), "schema", "catalog", "--json"]`)
	requireWorkflowOmits(t, builder, `[str(binary), "schema", "list", "--json"]`)
}

func TestReleaseWorkflowPublisherRequiresEverySuccessfulPrerequisite(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	publisherStart := strings.Index(workflow, "  publisher:")
	publisherEnd := strings.Index(workflow, "  post-publication-verification:")
	if publisherStart < 0 || publisherEnd <= publisherStart {
		t.Fatal("cannot isolate publisher job")
	}
	publisher := workflow[publisherStart:publisherEnd]

	for _, want := range []string{
		"needs: [validate-inputs, native-candidates, assemble-plan]",
		"needs.validate-inputs.result == 'success'",
		"needs.native-candidates.result == 'success'",
		"needs.assemble-plan.result == 'success'",
		"inputs.dry_run == false",
		"gh api --method POST \"repos/${GITHUB_REPOSITORY}/git/refs\"",
		"gh release create \"$TAG\"",
		"--verify-tag",
		"git/refs",
		"refs/tags/${TAG}",
		"--target \"$SOURCE_SHA\"",
		"scripts/verify-release-modernization.py published",
		"scripts/verify-release-modernization.py promotion",
		"go run ./cmd/covenant release verify",
		"--public-key bundle/release/covenant-release-public-key.json",
		"candidates/",
	} {
		requireWorkflowContains(t, workflow, want)
	}

	requireWorkflowOmits(t, workflow, "if: always()")
	requireWorkflowOmits(t, workflow, "gh release upload")
	requireWorkflowOrder(t, publisher,
		"name: Checkout exact publisher verifier source",
		"name: Download exact signed promotion bundle",
		"name: Re-verify complete promotion bundle",
		"scripts/verify-release-modernization.py promotion",
		"name: Fail closed on any existing tag or release",
		"name: Generate GitHub provenance for exact release assets",
		"name: Atomically create exact source tag",
		"name: Publish new immutable GitHub release",
	)
}

func TestReleaseWorkflowVerifiesAttestationsForManifestAndEveryNativeBinary(t *testing.T) {
	workflow := readRepoFile(t, ".github", "workflows", "release.yml")
	for _, want := range []string{
		"attestations: read",
		"gh attestation verify \"downloaded/manifest.json\"",
		"ao-covenant_${VERSION}_linux_amd64",
		"ao-covenant_${VERSION}_darwin_amd64",
		"ao-covenant_${VERSION}_windows_amd64.exe",
		"--repo \"$GITHUB_REPOSITORY\"",
		"--format json",
	} {
		requireWorkflowContains(t, workflow, want)
	}
}

func TestReleaseModernizationVerifierRegressionSuite(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	absoluteRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	testScript := filepath.Join(absoluteRoot, "scripts", "test_release_modernization.py")
	if _, err := os.Stat(testScript); err != nil {
		t.Fatalf("stat release modernization tests: %v", err)
	}

	cmd := exec.Command("python3", testScript)
	cmd.Dir = absoluteRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("release modernization tests failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "OK") {
		t.Fatalf("release modernization tests did not report success:\n%s", output)
	}
}

func TestPackageUsesExactPrebuiltNativeCandidate(t *testing.T) {
	root := t.TempDir()
	prebuilt := filepath.Join(root, "native-covenant")
	if err := os.WriteFile(prebuilt, []byte("native-candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "dist")
	buildCalled := false

	result, err := Package(context.Background(), Options{
		SourceDir: root,
		OutDir:    out,
		Version:   "v0.1.0",
		Commit:    strings.Repeat("a", 40),
		Date:      "2026-07-20T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Prebuilt:  map[string]string{"linux/amd64": prebuilt},
		Build: func(context.Context, BuildRequest) error {
			buildCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("package prebuilt candidate: %v", err)
	}
	if buildCalled {
		t.Fatal("package invoked the build function for a prebuilt candidate")
	}
	output := filepath.Join(out, result.Artifacts[0].Path)
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "native-candidate" {
		t.Fatalf("packaged candidate = %q", got)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(output); err != nil || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("packaged candidate is not executable: info=%v err=%v", info, err)
		}
	}
}
