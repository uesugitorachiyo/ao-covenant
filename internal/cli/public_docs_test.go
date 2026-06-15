package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicThreatModelDocumentationIsLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	readme := readText("README.md")
	security := readText("SECURITY.md")
	threatModel := readText("docs", "threat-model.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Threat Model](docs/threat-model.md)"},
		{name: "SECURITY link", doc: security, want: "[Threat Model](docs/threat-model.md)"},
		{name: "trust boundaries", doc: threatModel, want: "## Trust Boundaries"},
		{name: "protected assets", doc: threatModel, want: "## Protected Assets"},
		{name: "threats and mitigations", doc: threatModel, want: "## Threats And Mitigations"},
		{name: "non-goals", doc: threatModel, want: "## Non-Goals"},
		{name: "release keys", doc: threatModel, want: "`COVENANT_RELEASE_SIGNING_KEY`"},
		{name: "private keys", doc: threatModel, want: "Private signing keys"},
		{name: "evidence packs", doc: threatModel, want: "evidence packs"},
		{name: "local paths", doc: threatModel, want: "local paths"},
		{name: "release verification", doc: threatModel, want: "[release operations](release.md)"},
		{name: "security reporting", doc: threatModel, want: "[security policy](../SECURITY.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestSecurityPolicyDocumentsPublicDisclosureProcess(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join("..", "..", "SECURITY.md"))
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	security := string(bytes)

	for _, check := range []struct {
		name string
		want string
	}{
		{name: "reporting section", want: "## Reporting"},
		{name: "supported versions section", want: "## Supported Versions"},
		{name: "response expectations section", want: "## Response Expectations"},
		{name: "severity section", want: "## Severity Guidance"},
		{name: "public issue guidance section", want: "## Public Issue Guidance"},
		{name: "secret leakage section", want: "## Secret Leakage"},
		{name: "github security advisories", want: "GitHub Security Advisories"},
		{name: "sensitive report content", want: "minimal reproducer"},
		{name: "no public exploit details", want: "Do not post exploit details"},
		{name: "critical severity", want: "Critical"},
		{name: "high severity", want: "High"},
		{name: "moderate severity", want: "Moderate"},
		{name: "low severity", want: "Low"},
		{name: "revocation response", want: "revoke or rotate"},
		{name: "main branch support", want: "`main` branch"},
	} {
		if !strings.Contains(security, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseVerificationWalkthroughIsLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	readme := readText("README.md")
	releaseDoc := readText("docs", "release.md")
	installDoc := readText("docs", "install.md")
	walkthrough := readText("docs", "release-verification.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Verification](docs/release-verification.md)"},
		{name: "release operations link", doc: releaseDoc, want: "[release verification walkthrough](release-verification.md)"},
		{name: "install guide link", doc: installDoc, want: "[release verification walkthrough](release-verification.md)"},
		{name: "download section", doc: walkthrough, want: "## 1. Download Release Assets"},
		{name: "checksum section", doc: walkthrough, want: "## 2. Verify SHA-256 Checksums"},
		{name: "signature section", doc: walkthrough, want: "## 3. Verify AO Covenant Release Signature"},
		{name: "attestation section", doc: walkthrough, want: "## 4. Verify GitHub Artifact Attestations"},
		{name: "provenance section", doc: walkthrough, want: "## 5. Review Provenance And Reports"},
		{name: "failure handling section", doc: walkthrough, want: "## Failure Handling"},
		{name: "linux checksum command", doc: walkthrough, want: "sha256sum -c SHA256SUMS"},
		{name: "macos checksum command", doc: walkthrough, want: "shasum -a 256 -c SHA256SUMS"},
		{name: "windows checksum command", doc: walkthrough, want: "Get-FileHash"},
		{name: "release verify command", doc: walkthrough, want: "covenant release verify --dir . --public-key covenant-release-public-key.json"},
		{name: "attestation command", doc: walkthrough, want: "gh attestation verify"},
		{name: "report command", doc: walkthrough, want: "covenant release report --dir . --public-key covenant-release-public-key.json"},
		{name: "public key warning", doc: walkthrough, want: "does not contain the release private key"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestPublicReadinessIndexIsLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	readme := readText("README.md")
	index := readText("docs", "public-readiness.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Public Readiness](docs/public-readiness.md)"},
		{name: "install section", doc: index, want: "## Install And Platform Support"},
		{name: "release verification section", doc: index, want: "## Release Verification"},
		{name: "security section", doc: index, want: "## Security And Disclosure"},
		{name: "schemas section", doc: index, want: "## Public Schemas And Automation"},
		{name: "local gate section", doc: index, want: "## Local Release-Readiness Gate"},
		{name: "repository hygiene section", doc: index, want: "## Repository Hygiene"},
		{name: "install link", doc: index, want: "[install guide](install.md)"},
		{name: "release verification link", doc: index, want: "[release verification walkthrough](release-verification.md)"},
		{name: "threat model link", doc: index, want: "[threat model](threat-model.md)"},
		{name: "security policy link", doc: index, want: "[security policy](../SECURITY.md)"},
		{name: "schema command", doc: index, want: "covenant schema catalog"},
		{name: "release readiness command", doc: index, want: "./scripts/release-readiness.sh"},
		{name: "hygiene test command", doc: index, want: "TestTrackedRepositoryFilesDoNotContainLocalSecretsOrMachinePaths"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestContributorGuideIsLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	readme := readText("README.md")
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Contributing](CONTRIBUTING.md)"},
		{name: "readiness link", doc: readiness, want: "[contributor guide](../CONTRIBUTING.md)"},
		{name: "setup section", doc: contributing, want: "## Local Setup"},
		{name: "test section", doc: contributing, want: "## Required Local Checks"},
		{name: "branch section", doc: contributing, want: "## Branch And Pull Request Rules"},
		{name: "release readiness section", doc: contributing, want: "## Release-Readiness Gate"},
		{name: "docs section", doc: contributing, want: "## Documentation Expectations"},
		{name: "security section", doc: contributing, want: "## Security And Repository Hygiene"},
		{name: "schema section", doc: contributing, want: "## Public Schema Expectations"},
		{name: "go version", doc: contributing, want: "Go 1.24"},
		{name: "full tests", doc: contributing, want: "go test -count=1 ./..."},
		{name: "vet", doc: contributing, want: "go vet ./..."},
		{name: "yaml parse", doc: contributing, want: "YAML.load_file"},
		{name: "diff check", doc: contributing, want: "git diff --check"},
		{name: "release readiness command", doc: contributing, want: "./scripts/release-readiness.sh"},
		{name: "protected main", doc: contributing, want: "protected `main`"},
		{name: "public readiness link", doc: contributing, want: "[public readiness index](docs/public-readiness.md)"},
		{name: "security policy link", doc: contributing, want: "[security policy](SECURITY.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}
