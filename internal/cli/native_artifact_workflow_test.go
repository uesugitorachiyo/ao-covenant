package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeArtifactWorkflowContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "native-artifacts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, want := range []string{
		"ubuntu-latest",
		"macos-latest",
		"windows-latest",
		"linux-x86_64",
		"macos-aarch64",
		"windows-x86_64",
		"actions/upload-artifact",
		"ao-covenant-native-artifact-${{ matrix.target_label }}-${{ github.sha }}",
		"native-artifact-summary.json",
		"SHA256SUMS",
		"LICENSE",
		"NOTICE",
		"./cmd/covenant",
		"version --json",
		"contents: read",
		"ref: 4c501b4f1e55cb9b926709e19d496edf41984fb1",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("native artifact workflow missing %q", want)
		}
	}
	for _, forbidden := range []string{"contents: write", "gh release", "actions/create-release", "softprops/action-gh-release"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("native artifact workflow must not include %q", forbidden)
		}
	}

	nativeBuild := strings.Index(workflow, "go build -trimpath")
	policyCheckout := strings.Index(workflow, "repository: uesugitorachiyo/ao-architecture")
	metadataReader := strings.Index(workflow, "scripts/read_go_binary_metadata.go")
	builder := strings.Index(workflow, "scripts/build_go_supply_chain_candidate.py")
	verifier := strings.Index(workflow, "scripts/verify_supply_chain_policy.py")
	if nativeBuild < 0 || policyCheckout < 0 || metadataReader < 0 || builder < 0 || verifier < 0 ||
		!(nativeBuild < policyCheckout && policyCheckout < metadataReader && metadataReader < builder && builder < verifier) {
		t.Fatal("native build, policy checkout, metadata reader, builder, and verifier are required in order")
	}
	hasExactLine := func(section, want string) bool {
		for _, line := range strings.Split(section, "\n") {
			if strings.TrimSpace(line) == want {
				return true
			}
		}
		return false
	}
	if !hasExactLine(workflow[builder:verifier], `--workspace-root . \`) ||
		!hasExactLine(workflow[verifier:], `--workspace-root "$supply_chain_dir" \`) {
		t.Fatal("builder must use the repository root and verifier must use the bundle root")
	}
	if !hasExactLine(workflow[metadataReader:builder], `"$artifact_dir/$binary" > "$artifact_dir/go-modules.json"`) {
		t.Fatal("canonical metadata reader must consume the native binary")
	}
}
