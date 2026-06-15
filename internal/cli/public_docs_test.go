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
		{name: "release readiness workflow", doc: index, want: "`Release Readiness` GitHub Actions workflow"},
		{name: "release readiness read-only permissions", doc: index, want: "read-only repository permissions"},
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
		{name: "go version", doc: contributing, want: "Go 1.26"},
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

func TestConductAndGovernanceDocsAreLinkedAndComplete(t *testing.T) {
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
	conduct := readText("CODE_OF_CONDUCT.md")
	governance := readText("GOVERNANCE.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README conduct link", doc: readme, want: "[Code of Conduct](CODE_OF_CONDUCT.md)"},
		{name: "README governance link", doc: readme, want: "[Governance](GOVERNANCE.md)"},
		{name: "readiness conduct link", doc: readiness, want: "[code of conduct](../CODE_OF_CONDUCT.md)"},
		{name: "readiness governance link", doc: readiness, want: "[governance](../GOVERNANCE.md)"},
		{name: "contributing conduct link", doc: contributing, want: "[code of conduct](CODE_OF_CONDUCT.md)"},
		{name: "contributing governance link", doc: contributing, want: "[governance](GOVERNANCE.md)"},
		{name: "conduct expected behavior", doc: conduct, want: "## Expected Behavior"},
		{name: "conduct unacceptable behavior", doc: conduct, want: "## Unacceptable Behavior"},
		{name: "conduct reporting", doc: conduct, want: "## Reporting Conduct Issues"},
		{name: "conduct security policy link", doc: conduct, want: "[security policy](SECURITY.md)"},
		{name: "governance project status", doc: governance, want: "## Project Status"},
		{name: "governance decision scope", doc: governance, want: "## Maintainer Decision Scope"},
		{name: "governance contribution decisions", doc: governance, want: "## Contribution Decisions"},
		{name: "governance release decisions", doc: governance, want: "## Release Decisions"},
		{name: "governance pre-1.0", doc: governance, want: "pre-1.0"},
		{name: "governance protected main", doc: governance, want: "protected `main`"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestPublicAPIStabilityPolicyIsLinkedAndComplete(t *testing.T) {
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
	governance := readText("GOVERNANCE.md")
	stability := readText("docs", "public-api-stability.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Public API Stability](docs/public-api-stability.md)"},
		{name: "readiness link", doc: readiness, want: "[public API stability policy](public-api-stability.md)"},
		{name: "contributing link", doc: contributing, want: "[public API stability policy](docs/public-api-stability.md)"},
		{name: "governance link", doc: governance, want: "[public API stability policy](docs/public-api-stability.md)"},
		{name: "stability levels section", doc: stability, want: "## Stability Levels"},
		{name: "stable surfaces section", doc: stability, want: "## Stable Surfaces"},
		{name: "experimental surfaces section", doc: stability, want: "## Experimental Surfaces"},
		{name: "cli commands section", doc: stability, want: "## CLI Commands"},
		{name: "public schemas section", doc: stability, want: "## Public Schemas"},
		{name: "fixtures and reports section", doc: stability, want: "## Fixtures And Reports"},
		{name: "release artifacts section", doc: stability, want: "## Release Artifacts"},
		{name: "change process section", doc: stability, want: "## Change Process"},
		{name: "pre-1.0 compatibility section", doc: stability, want: "## Pre-1.0 Compatibility"},
		{name: "stable term", doc: stability, want: "stable"},
		{name: "experimental term", doc: stability, want: "experimental"},
		{name: "schema version term", doc: stability, want: "`schema_version`"},
		{name: "schemas directory", doc: stability, want: "`schemas/`"},
		{name: "release fixtures directory", doc: stability, want: "`internal/schema/testdata/release-fixtures/`"},
		{name: "release verification link", doc: stability, want: "[release verification walkthrough](release-verification.md)"},
		{name: "public readiness link", doc: stability, want: "[public readiness index](public-readiness.md)"},
		{name: "contributing mention", doc: stability, want: "`CONTRIBUTING.md`"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseReadinessWorkflowIsDiscoverable(t *testing.T) {
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
	workflow := readText(".github", "workflows", "release-readiness.yml")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README badge", doc: readme, want: "[![Release Readiness](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml/badge.svg)](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)"},
		{name: "README workflow link", doc: readme, want: "[Release Readiness workflow](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)"},
		{name: "readiness workflow link", doc: readiness, want: "[Release Readiness workflow](https://github.com/uesugitorachiyo/ao-covenant/actions/workflows/release-readiness.yml)"},
		{name: "manual trigger docs", doc: readiness, want: "manual `workflow_dispatch` trigger"},
		{name: "scheduled trigger docs", doc: readiness, want: "weekly scheduled run"},
		{name: "read-only permission docs", doc: readiness, want: "read-only `contents: read` permission"},
		{name: "workflow dispatch trigger", doc: workflow, want: "workflow_dispatch:"},
		{name: "workflow schedule trigger", doc: workflow, want: "schedule:"},
		{name: "workflow cron", doc: workflow, want: "17 9 * * 1"},
		{name: "workflow read-only contents", doc: workflow, want: "contents: read"},
		{name: "workflow release readiness script", doc: workflow, want: "./scripts/release-readiness.sh"},
		{name: "workflow uploads summary artifact", doc: workflow, want: "ao-covenant-release-readiness-summary"},
		{name: "workflow uploads summary only", doc: workflow, want: "release-readiness-summary.json"},
		{name: "readiness summary docs", doc: readiness, want: "non-sensitive `release-readiness-summary.json`"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestGitHubIssueAndPullRequestTemplatesAreComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	config := readText(".github", "ISSUE_TEMPLATE", "config.yml")
	bug := readText(".github", "ISSUE_TEMPLATE", "bug_report.yml")
	releaseVerification := readText(".github", "ISSUE_TEMPLATE", "release_verification_failure.yml")
	securitySensitive := readText(".github", "ISSUE_TEMPLATE", "security_sensitive_report.yml")
	pullRequest := readText(".github", "pull_request_template.md")
	contributing := readText("CONTRIBUTING.md")
	readiness := readText("docs", "public-readiness.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "blank issues disabled", doc: config, want: "blank_issues_enabled: false"},
		{name: "security contact", doc: config, want: "SECURITY.md"},
		{name: "bug template name", doc: bug, want: "name: Bug report"},
		{name: "bug template public safety", doc: bug, want: "Do not include private keys, tokens, production evidence bundles, or local machine paths."},
		{name: "bug version field", doc: bug, want: "AO Covenant version or commit"},
		{name: "bug os field", doc: bug, want: "Operating system"},
		{name: "bug repro field", doc: bug, want: "Minimal synthetic reproducer"},
		{name: "release template name", doc: releaseVerification, want: "name: Release verification failure"},
		{name: "release asset field", doc: releaseVerification, want: "Release tag and asset"},
		{name: "release command field", doc: releaseVerification, want: "Verification command and output"},
		{name: "release walkthrough link", doc: releaseVerification, want: "docs/release-verification.md"},
		{name: "release no secrets", doc: releaseVerification, want: "Do not include private keys, credentials, production evidence, or local machine paths."},
		{name: "security template name", doc: securitySensitive, want: "name: Security-sensitive report"},
		{name: "security private advisory route", doc: securitySensitive, want: "GitHub Security Advisories"},
		{name: "security public minimum", doc: securitySensitive, want: "Do not post exploit details, private keys, tokens, customer data, production evidence bundles, unreleased bundles, or local paths."},
		{name: "security policy link", doc: securitySensitive, want: "SECURITY.md"},
		{name: "pr summary", doc: pullRequest, want: "## Summary"},
		{name: "pr public readiness", doc: pullRequest, want: "## Public Readiness Impact"},
		{name: "pr security", doc: pullRequest, want: "## Security And Sensitive Material"},
		{name: "pr verification", doc: pullRequest, want: "## Verification"},
		{name: "pr tests", doc: pullRequest, want: "- [ ] `go test -count=1 ./...`"},
		{name: "pr vet", doc: pullRequest, want: "- [ ] `go vet ./...`"},
		{name: "pr yaml", doc: pullRequest, want: "YAML.load_file"},
		{name: "pr diff check", doc: pullRequest, want: "- [ ] `git diff --check`"},
		{name: "pr release readiness", doc: pullRequest, want: "./scripts/release-readiness.sh"},
		{name: "pr no sensitive material", doc: pullRequest, want: "private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths"},
		{name: "contributing issue templates", doc: contributing, want: "Use the GitHub issue templates"},
		{name: "contributing pr template", doc: contributing, want: "pull request template"},
		{name: "readiness templates", doc: readiness, want: "GitHub issue and pull request templates"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestDependencyReviewDocumentationIsLinkedAndComplete(t *testing.T) {
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
	pullRequest := readText(".github", "pull_request_template.md")
	dependencyReview := readText("docs", "dependency-review.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Dependency Review](docs/dependency-review.md)"},
		{name: "readiness link", doc: readiness, want: "[dependency review guide](dependency-review.md)"},
		{name: "contributing link", doc: contributing, want: "[dependency review guide](docs/dependency-review.md)"},
		{name: "PR template dependency section", doc: pullRequest, want: "## Dependency And Supply-Chain Review"},
		{name: "PR template dependency guide", doc: pullRequest, want: "docs/dependency-review.md"},
		{name: "go module section", doc: dependencyReview, want: "## Go Module Dependencies"},
		{name: "github actions section", doc: dependencyReview, want: "## GitHub Actions Dependencies"},
		{name: "permissions section", doc: dependencyReview, want: "## Workflow Permissions"},
		{name: "update process section", doc: dependencyReview, want: "## Update Process"},
		{name: "review checklist section", doc: dependencyReview, want: "## Review Checklist"},
		{name: "security response section", doc: dependencyReview, want: "## Security Response"},
		{name: "go mod tidy command", doc: dependencyReview, want: "go mod tidy"},
		{name: "go mod verify command", doc: dependencyReview, want: "go mod verify"},
		{name: "go list modules command", doc: dependencyReview, want: "go list -m all"},
		{name: "go sum", doc: dependencyReview, want: "`go.sum`"},
		{name: "go version file", doc: dependencyReview, want: "`go-version-file: go.mod`"},
		{name: "github action checkout", doc: dependencyReview, want: "`actions/checkout@v6`"},
		{name: "github action setup go", doc: dependencyReview, want: "`actions/setup-go@v6`"},
		{name: "github action attestation", doc: dependencyReview, want: "`actions/attest-build-provenance@v4`"},
		{name: "github action upload artifact", doc: dependencyReview, want: "`actions/upload-artifact@v7`"},
		{name: "permissions contents read", doc: dependencyReview, want: "`contents: read`"},
		{name: "permissions id token", doc: dependencyReview, want: "`id-token: write`"},
		{name: "permissions attestations", doc: dependencyReview, want: "`attestations: write`"},
		{name: "security policy", doc: dependencyReview, want: "[security policy](../SECURITY.md)"},
		{name: "baseline test", doc: dependencyReview, want: "go test -count=1 ./..."},
		{name: "baseline vet", doc: dependencyReview, want: "go vet ./..."},
		{name: "yaml parse", doc: dependencyReview, want: "YAML.load_file"},
		{name: "release readiness", doc: dependencyReview, want: "./scripts/release-readiness.sh"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}
