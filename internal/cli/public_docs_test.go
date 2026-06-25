package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestReleaseThreatModelMatrixIsLinkedAndComplete(t *testing.T) {
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
	threatModel := readText("docs", "threat-model.md")
	readiness := readText("docs", "public-readiness.md")
	releaseOps := readText("docs", "release.md")
	security := readText("SECURITY.md")
	matrix := readText("docs", "release-threat-model-matrix.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Threat Model Matrix](docs/release-threat-model-matrix.md)"},
		{name: "threat model link", doc: threatModel, want: "[release threat model matrix](release-threat-model-matrix.md)"},
		{name: "readiness link", doc: readiness, want: "[release threat model matrix](release-threat-model-matrix.md)"},
		{name: "release operations link", doc: releaseOps, want: "[release threat model matrix](release-threat-model-matrix.md)"},
		{name: "security policy link", doc: security, want: "[release threat model matrix](docs/release-threat-model-matrix.md)"},
		{name: "title", doc: matrix, want: "# AO Covenant Release Threat Model Matrix"},
		{name: "scope section", doc: matrix, want: "## Scope"},
		{name: "matrix section", doc: matrix, want: "## Attack-To-Control Matrix"},
		{name: "evidence section", doc: matrix, want: "## Required Evidence"},
		{name: "operator section", doc: matrix, want: "## Operator Response"},
		{name: "residual risk section", doc: matrix, want: "## Residual Risk"},
		{name: "signing key compromise", doc: matrix, want: "Signing key compromise"},
		{name: "artifact substitution", doc: matrix, want: "Release artifact substitution"},
		{name: "checksum tampering", doc: matrix, want: "Checksum or manifest tampering"},
		{name: "attestation gap", doc: matrix, want: "GitHub attestation gap"},
		{name: "replacement abuse", doc: matrix, want: "Unauthorized asset replacement"},
		{name: "dry-run publish confusion", doc: matrix, want: "Dry-run publish confusion"},
		{name: "consumer verification bypass", doc: matrix, want: "Consumer verification bypass"},
		{name: "sensitive material exposure", doc: matrix, want: "Sensitive material exposure"},
		{name: "private key control", doc: matrix, want: "`COVENANT_RELEASE_SIGNING_KEY`"},
		{name: "release verify control", doc: matrix, want: "`covenant release verify`"},
		{name: "release report control", doc: matrix, want: "`covenant release report`"},
		{name: "consumer smoke control", doc: matrix, want: "`release-consumer-smoke.json`"},
		{name: "dry run audit control", doc: matrix, want: "`release-dry-run-artifact-audit.json`"},
		{name: "replacement preflight control", doc: matrix, want: "`release-replacement-preflight-report.json`"},
		{name: "replacement policy control", doc: matrix, want: "`release-replacement-policy.json`"},
		{name: "rollback runbook link", doc: matrix, want: "[release rollback runbook](release-rollback.md)"},
		{name: "security policy link in matrix", doc: matrix, want: "[security policy](../SECURITY.md)"},
		{name: "dry run checklist link", doc: matrix, want: "[release dry-run checklist](release-dry-run.md)"},
		{name: "attestation map link", doc: matrix, want: "[release attestation coverage map](release-attestation-coverage.md)"},
		{name: "consumer script link", doc: matrix, want: "[release consumer smoke script](../scripts/release-consumer-smoke.sh)"},
		{name: "windows script link", doc: matrix, want: "[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)"},
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
		{name: "replacement attestation command", doc: walkthrough, want: "gh attestation verify release-replacement-policy.json --repo uesugitorachiyo/ao-covenant"},
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
		{name: "policy spine command", doc: index, want: "covenant policy spine --json"},
		{name: "policy spine schema", doc: index, want: "`covenant.policy-spine-result.v1`"},
		{name: "RSI claim policy section", doc: index, want: "## RSI Claim Boundary"},
		{name: "claim publish effect", doc: index, want: "`claim.publish`"},
		{name: "full RSI resource", doc: index, want: "`full-autonomous-self-mutating-rsi`"},
		{name: "mutation authority evidence", doc: index, want: "mutation authority evidence"},
		{name: "rollback evidence", doc: index, want: "rollback evidence"},
		{name: "live self-change evidence", doc: index, want: "live self-change evidence"},
		{name: "release readiness command", doc: index, want: "./scripts/release-readiness.sh"},
		{name: "release readiness workflow", doc: index, want: "`Release Readiness` GitHub Actions workflow"},
		{name: "release readiness read-only permissions", doc: index, want: "read-only repository permissions"},
		{name: "public repo policy script", doc: index, want: "scripts/check-public-repo-policy.sh"},
		{name: "hygiene test command", doc: index, want: "TestTrackedRepositoryFilesDoNotContainLocalSecretsOrMachinePaths"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestBranchProtectionRunbookIsLinkedAndComplete(t *testing.T) {
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
	contributing := readText("CONTRIBUTING.md")
	readiness := readText("docs", "public-readiness.md")
	runbook := readText("docs", "branch-protection.md")
	verifier := readText("scripts", "verify-branch-protection.sh")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Branch Protection](docs/branch-protection.md)"},
		{name: "contributing link", doc: contributing, want: "[branch protection runbook](docs/branch-protection.md)"},
		{name: "public readiness link", doc: readiness, want: "[branch protection runbook](branch-protection.md)"},
		{name: "runbook title", doc: runbook, want: "# AO Covenant Branch Protection"},
		{name: "main branch", doc: runbook, want: "`main`"},
		{name: "require pull request", doc: runbook, want: "Require a pull request before merging"},
		{name: "dismiss stale reviews", doc: runbook, want: "Dismiss stale pull request approvals"},
		{name: "required status checks", doc: runbook, want: "Require status checks to pass before merging"},
		{name: "license policy check", doc: runbook, want: "`License policy`"},
		{name: "public repo policy script", doc: runbook, want: "scripts/check-public-repo-policy.sh"},
		{name: "ubuntu check", doc: runbook, want: "`Go ubuntu-latest`"},
		{name: "macos check", doc: runbook, want: "`Go macos-26`"},
		{name: "windows check", doc: runbook, want: "`Go windows-latest`"},
		{name: "linear history", doc: runbook, want: "Require linear history"},
		{name: "force pushes", doc: runbook, want: "Restrict force pushes"},
		{name: "deletions", doc: runbook, want: "Do not allow deletions"},
		{name: "verifier command", doc: runbook, want: "scripts/verify-branch-protection.sh"},
		{name: "release readiness note", doc: runbook, want: "`Release Readiness` is a scheduled/manual smoke gate"},
		{name: "verifier schema", doc: verifier, want: "ao.covenant.branch-protection-audit.v1"},
		{name: "verifier protection api", doc: verifier, want: "branches/${branch}/protection"},
		{name: "verifier required license policy", doc: verifier, want: "License policy"},
		{name: "verifier required ubuntu", doc: verifier, want: "Go ubuntu-latest"},
		{name: "verifier required macos", doc: verifier, want: "Go macos-26"},
		{name: "verifier required windows", doc: verifier, want: "Go windows-latest"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestBranchProtectionVerifierRunsAgainstFakeGitHubAPI(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	absoluteRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	tempDir := t.TempDir()
	fakeGH := filepath.Join(tempDir, "gh")
	if err := os.WriteFile(fakeGH, []byte(`#!/usr/bin/env bash
set -euo pipefail

if [[ "$1" != "api" ]]; then
  echo "unexpected gh command: $*" >&2
  exit 2
fi

case "$2" in
  repos/*/branches/*/protection)
    cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "License policy",
      "Go ubuntu-latest",
      "Go macos-26",
      "Go windows-latest"
    ]
  },
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true
  },
  "enforce_admins": {
    "enabled": true
  },
  "required_linear_history": {
    "enabled": true
  },
  "allow_force_pushes": {
    "enabled": false
  },
  "allow_deletions": {
    "enabled": false
  }
}
JSON
    ;;
  repos/*/rulesets)
    printf '[]\n'
    ;;
  *)
    echo "unexpected gh api path: $2" >&2
    exit 2
    ;;
esac
`), 0755); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join(absoluteRepoRoot, "scripts", "verify-branch-protection.sh"))
	cmd.Dir = absoluteRepoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AO_COVENANT_GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"AO_COVENANT_BRANCH_PROTECTION_BRANCH=main",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify branch protection failed: %v\n%s", err, out)
	}
	output := string(out)
	for _, want := range []string{
		`"schema_version": "ao.covenant.branch-protection-audit.v1"`,
		`"status": "passed"`,
		`"License policy"`,
		`"Go ubuntu-latest"`,
		`"Go macos-26"`,
		`"Go windows-latest"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("verifier output missing %q\n%s", want, output)
		}
	}
}

func TestBranchProtectionVerifierRejectsRulesetStatusCheckDrift(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	absoluteRepoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	tempDir := t.TempDir()
	fakeGH := filepath.Join(tempDir, "gh")
	if err := os.WriteFile(fakeGH, []byte(`#!/usr/bin/env bash
set -euo pipefail

if [[ "$1" != "api" ]]; then
  echo "unexpected gh command: $*" >&2
  exit 2
fi

case "$2" in
  repos/*/branches/*/protection)
    cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "License policy",
      "Go ubuntu-latest",
      "Go macos-26",
      "Go windows-latest"
    ]
  },
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true
  },
  "enforce_admins": {
    "enabled": true
  },
  "required_linear_history": {
    "enabled": true
  },
  "allow_force_pushes": {
    "enabled": false
  },
  "allow_deletions": {
    "enabled": false
  }
}
JSON
    ;;
  repos/*/rulesets)
    cat <<'JSON'
[
  {
    "name": "main requires CI",
    "enforcement": "active",
    "target": "branch",
    "conditions": {
      "ref_name": {
        "include": ["~DEFAULT_BRANCH"]
      }
    },
    "rules": [
      {
        "type": "required_status_checks",
        "parameters": {
          "required_status_checks": [
            {"context": "Go ubuntu-latest"},
            {"context": "Go macos-latest"},
            {"context": "Go windows-latest"}
          ]
        }
      }
    ]
  }
]
JSON
    ;;
  *)
    echo "unexpected gh api path: $2" >&2
    exit 2
    ;;
esac
`), 0755); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join(absoluteRepoRoot, "scripts", "verify-branch-protection.sh"))
	cmd.Dir = absoluteRepoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AO_COVENANT_GITHUB_REPOSITORY=uesugitorachiyo/ao-covenant",
		"AO_COVENANT_BRANCH_PROTECTION_BRANCH=main",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("verify branch protection passed with stale ruleset check:\n%s", out)
	}
	output := string(out)
	for _, want := range []string{
		`"status": "blocked"`,
		"ruleset_status_checks_current",
		"Go macos-latest",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("verifier output missing %q\n%s", want, output)
		}
	}
}

func TestReleaseAttestationCoverageMapIsLinkedAndComplete(t *testing.T) {
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
	contributing := readText("CONTRIBUTING.md")
	releaseDoc := readText("docs", "release.md")
	readiness := readText("docs", "public-readiness.md")
	knownGood := readText("docs", "public-release-known-good-baseline.md")
	verification := readText("docs", "release-verification.md")
	coverage := readText("docs", "release-attestation-coverage.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Attestation Coverage](docs/release-attestation-coverage.md)"},
		{name: "contributor link", doc: contributing, want: "[release attestation coverage map](docs/release-attestation-coverage.md)"},
		{name: "release operations link", doc: releaseDoc, want: "[release attestation coverage map](release-attestation-coverage.md)"},
		{name: "public readiness link", doc: readiness, want: "[release attestation coverage map](release-attestation-coverage.md)"},
		{name: "known good link", doc: knownGood, want: "[release attestation coverage map](release-attestation-coverage.md)"},
		{name: "verification walkthrough link", doc: verification, want: "[release attestation coverage map](release-attestation-coverage.md)"},
		{name: "title", doc: coverage, want: "# AO Covenant Release Attestation Coverage"},
		{name: "scope section", doc: coverage, want: "## Scope"},
		{name: "required attestations section", doc: coverage, want: "## Required GitHub Attestations"},
		{name: "matrix section", doc: coverage, want: "## Release Asset Coverage Matrix"},
		{name: "consumer section", doc: coverage, want: "## Consumer Verification"},
		{name: "maintainer section", doc: coverage, want: "## Maintainer Checks"},
		{name: "failure section", doc: coverage, want: "## Failure Handling"},
		{name: "non-goals section", doc: coverage, want: "## Non-Goals"},
		{name: "attestation action", doc: coverage, want: "actions/attest-build-provenance@v4"},
		{name: "subject path", doc: coverage, want: "subject-path: \"dist/*\""},
		{name: "permission", doc: coverage, want: "attestations: write"},
		{name: "manifest command", doc: coverage, want: "gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant"},
		{name: "binary command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant"},
		{name: "replacement policy command", doc: coverage, want: "gh attestation verify release-replacement-policy.json --repo uesugitorachiyo/ao-covenant"},
		{name: "shell smoke", doc: coverage, want: "scripts/release-consumer-smoke.sh"},
		{name: "powershell smoke", doc: coverage, want: "scripts/release-consumer-smoke.ps1"},
		{name: "manifest asset", doc: coverage, want: "manifest.json"},
		{name: "checksum asset", doc: coverage, want: "SHA256SUMS"},
		{name: "signature asset", doc: coverage, want: "release-signature.json"},
		{name: "public key asset", doc: coverage, want: "covenant-release-public-key.json"},
		{name: "package report", doc: coverage, want: "release-package.json"},
		{name: "verify report", doc: coverage, want: "release-verify.json"},
		{name: "release report", doc: coverage, want: "release-report.json"},
		{name: "replacement policy", doc: coverage, want: "release-replacement-policy.json"},
		{name: "platform binaries", doc: coverage, want: "platform binaries"},
		{name: "direct coverage phrase", doc: coverage, want: "direct GitHub attestation"},
		{name: "indirect coverage phrase", doc: coverage, want: "covered by manifest signature and checksum verification"},
		{name: "replacement direct coverage", doc: coverage, want: "direct GitHub attestation from `dist/*` when replacement metadata is generated"},
		{name: "sensitive warning", doc: coverage, want: "private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseAttestationConsumerMatrixIsDocumented(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	coverage := readText("docs", "release-attestation-coverage.md")
	verification := readText("docs", "release-verification.md")
	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "coverage matrix section", doc: coverage, want: "## Platform Binary Attestation Matrix"},
		{name: "verification matrix section", doc: verification, want: "## Platform Binary Attestation Matrix"},
		{name: "manifest minimum", doc: coverage, want: "`manifest.json` plus the exact platform binary"},
		{name: "verification manifest minimum", doc: verification, want: "`manifest.json` plus the exact platform binary"},
		{name: "linux amd64 row", doc: coverage, want: "| Ubuntu/Linux amd64 | `linux/amd64` | `ao-covenant_v0.1.0_linux_amd64` |"},
		{name: "linux arm64 row", doc: coverage, want: "| Ubuntu/Linux arm64 | `linux/arm64` | `ao-covenant_v0.1.0_linux_arm64` |"},
		{name: "macos amd64 row", doc: coverage, want: "| macOS Intel | `darwin/amd64` | `ao-covenant_v0.1.0_darwin_amd64` |"},
		{name: "macos arm64 row", doc: coverage, want: "| macOS Apple Silicon | `darwin/arm64` | `ao-covenant_v0.1.0_darwin_arm64` |"},
		{name: "windows amd64 row", doc: coverage, want: "| Windows amd64 | `windows/amd64` | `ao-covenant_v0.1.0_windows_amd64.exe` |"},
		{name: "linux amd64 command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_linux_amd64 --repo uesugitorachiyo/ao-covenant"},
		{name: "linux arm64 command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_linux_arm64 --repo uesugitorachiyo/ao-covenant"},
		{name: "macos amd64 command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_darwin_amd64 --repo uesugitorachiyo/ao-covenant"},
		{name: "macos arm64 command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_darwin_arm64 --repo uesugitorachiyo/ao-covenant"},
		{name: "windows amd64 command", doc: coverage, want: "gh attestation verify ao-covenant_v0.1.0_windows_amd64.exe --repo uesugitorachiyo/ao-covenant"},
		{name: "verification windows command", doc: verification, want: "gh attestation verify ao-covenant_v0.1.0_windows_amd64.exe --repo uesugitorachiyo/ao-covenant"},
		{name: "version substitution", doc: verification, want: "replace `v0.1.0` with the release version you downloaded"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseAttestationFixturesAreLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	coverage := readText("docs", "release-attestation-coverage.md")
	verification := readText("docs", "release-verification.md")
	readiness := readText("docs", "public-readiness.md")
	stability := readText("docs", "public-api-stability.md")
	index := readText("internal", "cli", "testdata", "release-fixture-index.json")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "coverage fixture link", doc: coverage, want: "[release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)"},
		{name: "verification fixture link", doc: verification, want: "[release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)"},
		{name: "readiness fixture link", doc: readiness, want: "[release attestation fixtures](../internal/cli/testdata/release-attestation-fixtures)"},
		{name: "stability fixture directory", doc: stability, want: "`internal/cli/testdata/release-attestation-fixtures/`"},
		{name: "index fixture name", doc: index, want: `"name": "release-attestation"`},
		{name: "index fixture directory", doc: index, want: `"directory": "internal/cli/testdata/release-attestation-fixtures"`},
		{name: "valid fixture", doc: index, want: `"coverage-valid.json"`},
		{name: "missing binary fixture", doc: index, want: `"failure-missing-binary-attestation.json"`},
		{name: "tampered manifest fixture", doc: index, want: `"failure-tampered-manifest-attestation.json"`},
		{name: "fixture check command", doc: index, want: "go test ./internal/cli -run TestReleaseAttestationFixturesAreStableAndIndexed -count=1"},
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

func TestPublicSchemaChangelogIsLinkedAndComplete(t *testing.T) {
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
	stability := readText("docs", "public-api-stability.md")
	contributing := readText("CONTRIBUTING.md")
	changelog := readText("docs", "public-schema-changelog.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Public Schema Changelog](docs/public-schema-changelog.md)"},
		{name: "readiness link", doc: readiness, want: "[public schema changelog](public-schema-changelog.md)"},
		{name: "stability link", doc: stability, want: "[public schema changelog](public-schema-changelog.md)"},
		{name: "contributing link", doc: contributing, want: "[public schema changelog](docs/public-schema-changelog.md)"},
		{name: "title", doc: changelog, want: "# AO Covenant Public Schema Changelog"},
		{name: "scope section", doc: changelog, want: "## Scope"},
		{name: "compatibility rules section", doc: changelog, want: "## Compatibility Rules"},
		{name: "schema history section", doc: changelog, want: "## Schema History"},
		{name: "release readiness summary section", doc: changelog, want: "## Release Readiness Summary"},
		{name: "policy spine result section", doc: changelog, want: "## Policy Spine Result"},
		{name: "release dry-run artifact audit section", doc: changelog, want: "## Release Dry-Run Artifact Audit"},
		{name: "consumer actions section", doc: changelog, want: "## Consumer Actions"},
		{name: "maintainer checklist section", doc: changelog, want: "## Maintainer Checklist"},
		{name: "contract schema", doc: changelog, want: "`covenant.contract.v1`"},
		{name: "release readiness schema", doc: changelog, want: "`covenant.release-readiness-summary.v1`"},
		{name: "policy spine result schema", doc: changelog, want: "`covenant.policy-spine-result.v1`"},
		{name: "release dry-run artifact audit schema", doc: changelog, want: "`covenant.release-dry-run-artifact-audit.v1`"},
		{name: "release replacement policy schema", doc: changelog, want: "`covenant.release-replacement-policy.v1`"},
		{name: "release replacement preflight report schema", doc: changelog, want: "`covenant.release-replacement-preflight-report.v1`"},
		{name: "release attestation fixture schema", doc: changelog, want: "`covenant.release-attestation-fixture.v1`"},
		{name: "schema catalog result schema", doc: changelog, want: "`covenant.schema-catalog-result.v1`"},
		{name: "release fixture index schema", doc: changelog, want: "`covenant.release-fixture-index.v1`"},
		{name: "bundle inspect schema", doc: changelog, want: "`covenant.bundle-inspect-result.v1`"},
		{name: "release report schema", doc: changelog, want: "`covenant.release-report-result.v1`"},
		{name: "release consumer smoke schema", doc: changelog, want: "`covenant.release-consumer-smoke-result.v1`"},
		{name: "additive schemas", doc: changelog, want: "Additive schemas"},
		{name: "breaking schema changes", doc: changelog, want: "Breaking schema changes"},
		{name: "pre 1.0", doc: changelog, want: "pre-1.0"},
		{name: "schema version", doc: changelog, want: "`schema_version`"},
		{name: "catalog command", doc: changelog, want: "covenant schema catalog"},
		{name: "export command", doc: changelog, want: "covenant schema export"},
		{name: "validate command", doc: changelog, want: "covenant schema validate"},
		{name: "schema tests", doc: changelog, want: "go test -count=1 ./internal/schema ./internal/cli"},
		{name: "release readiness command", doc: changelog, want: "./scripts/release-readiness.sh"},
		{name: "release dry-run audit report", doc: changelog, want: "release-dry-run-artifact-audit.json"},
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
		{name: "readiness policy spine artifact docs", doc: readiness, want: "`artifacts/policy-spine.json`"},
		{name: "readiness policy spine schema docs", doc: readiness, want: "`covenant.policy-spine-result.v1`"},
		{name: "readiness summary schema docs", doc: readiness, want: "`covenant.release-readiness-summary.v1`"},
		{name: "readiness summary validation docs", doc: readiness, want: "covenant schema validate --schema covenant.release-readiness-summary.v1 --file release-readiness-summary.json"},
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
		{name: "github action upload artifact", doc: dependencyReview, want: "`actions/upload-artifact@v7.0.1`"},
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

func TestSecurityAdvisoryRoutingDocumentationIsLinkedAndComplete(t *testing.T) {
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
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")
	config := readText(".github", "ISSUE_TEMPLATE", "config.yml")
	securityIssue := readText(".github", "ISSUE_TEMPLATE", "security_sensitive_report.yml")
	routing := readText("docs", "security-advisory-routing.md")
	checklist := readText("docs", "security-advisory-maintainer-checklist.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Security Advisory Routing](docs/security-advisory-routing.md)"},
		{name: "SECURITY link", doc: security, want: "[security advisory routing guide](docs/security-advisory-routing.md)"},
		{name: "SECURITY checklist link", doc: security, want: "[security advisory maintainer checklist](docs/security-advisory-maintainer-checklist.md)"},
		{name: "readiness link", doc: readiness, want: "[security advisory routing guide](security-advisory-routing.md)"},
		{name: "readiness checklist link", doc: readiness, want: "[security advisory maintainer checklist](security-advisory-maintainer-checklist.md)"},
		{name: "contributing link", doc: contributing, want: "[security advisory routing guide](docs/security-advisory-routing.md)"},
		{name: "contributing checklist link", doc: contributing, want: "[security advisory maintainer checklist](docs/security-advisory-maintainer-checklist.md)"},
		{name: "config routing link", doc: config, want: "security-advisory-routing.md"},
		{name: "security issue routing link", doc: securityIssue, want: "docs/security-advisory-routing.md"},
		{name: "routing checklist link", doc: routing, want: "[maintainer checklist](security-advisory-maintainer-checklist.md)"},
		{name: "private first section", doc: routing, want: "## Private-First Rule"},
		{name: "when to use private advisory section", doc: routing, want: "## When To Use A Private Advisory"},
		{name: "minimal public report section", doc: routing, want: "## Minimal Public Report"},
		{name: "what to include section", doc: routing, want: "## What To Include Privately"},
		{name: "what not to post section", doc: routing, want: "## What Not To Post Publicly"},
		{name: "maintainer handling section", doc: routing, want: "## Maintainer Handling"},
		{name: "github security advisories", doc: routing, want: "GitHub Security Advisories"},
		{name: "advisory URL", doc: routing, want: "https://github.com/uesugitorachiyo/ao-covenant/security/advisories/new"},
		{name: "public issue fallback", doc: routing, want: "If GitHub Security Advisories are unavailable"},
		{name: "minimal summary phrase", doc: routing, want: "minimal non-sensitive routing note"},
		{name: "no exploit details", doc: routing, want: "Do not post exploit details"},
		{name: "no private keys", doc: routing, want: "private keys"},
		{name: "no tokens", doc: routing, want: "tokens"},
		{name: "no customer data", doc: routing, want: "customer data"},
		{name: "no production evidence", doc: routing, want: "production evidence bundles"},
		{name: "no unreleased bundles", doc: routing, want: "unreleased bundles"},
		{name: "no local paths", doc: routing, want: "local paths"},
		{name: "synthetic reproducer", doc: routing, want: "synthetic reproducer"},
		{name: "security policy link", doc: routing, want: "[security policy](../SECURITY.md)"},
		{name: "threat model link", doc: routing, want: "[threat model](threat-model.md)"},
		{name: "checklist title", doc: checklist, want: "# AO Covenant Security Advisory Maintainer Checklist"},
		{name: "checklist scope", doc: checklist, want: "## Scope"},
		{name: "checklist intake", doc: checklist, want: "## 1. Intake And Routing"},
		{name: "checklist containment", doc: checklist, want: "## 2. Containment And Evidence Safety"},
		{name: "checklist triage", doc: checklist, want: "## 3. Triage And Severity"},
		{name: "checklist fix", doc: checklist, want: "## 4. Fix And Verification"},
		{name: "checklist disclosure", doc: checklist, want: "## 5. Disclosure And Release Notes"},
		{name: "checklist closure", doc: checklist, want: "## 6. Closure"},
		{name: "checklist private advisory", doc: checklist, want: "GitHub Security Advisories"},
		{name: "checklist synthetic reproduction", doc: checklist, want: "synthetic reproducer"},
		{name: "checklist no secrets", doc: checklist, want: "Do not request or copy private keys, credentials, customer data, production evidence bundles, unreleased bundles, or local machine paths"},
		{name: "checklist release readiness", doc: checklist, want: "./scripts/release-readiness.sh"},
		{name: "checklist ci platforms", doc: checklist, want: "Ubuntu, macOS, and Windows"},
		{name: "checklist public wording", doc: checklist, want: "do not repeat exploit details or secret values"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseDryRunDocumentationIsLinkedAndComplete(t *testing.T) {
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
	releaseOps := readText("docs", "release.md")
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")
	dryRun := readText("docs", "release-dry-run.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Dry Run](docs/release-dry-run.md)"},
		{name: "release operations link", doc: releaseOps, want: "[release dry-run checklist](release-dry-run.md)"},
		{name: "readiness link", doc: readiness, want: "[release dry-run checklist](release-dry-run.md)"},
		{name: "contributing link", doc: contributing, want: "[release dry-run checklist](docs/release-dry-run.md)"},
		{name: "scope section", doc: dryRun, want: "## Scope"},
		{name: "prerequisites section", doc: dryRun, want: "## Prerequisites"},
		{name: "local dry run section", doc: dryRun, want: "## Local Dry Run"},
		{name: "package section", doc: dryRun, want: "## Package Without Publishing"},
		{name: "verify section", doc: dryRun, want: "## Verify Dry-Run Assets"},
		{name: "review section", doc: dryRun, want: "## Review Reports"},
		{name: "cleanup section", doc: dryRun, want: "## Cleanup"},
		{name: "not publishing", doc: dryRun, want: "does not create a tag, GitHub release, attestation, or public release asset"},
		{name: "readiness command", doc: dryRun, want: "./scripts/release-readiness.sh"},
		{name: "tmpdir command", doc: dryRun, want: "tmpdir=\"$(mktemp -d)\""},
		{name: "release package command", doc: dryRun, want: "covenant release package"},
		{name: "readiness public key output", doc: dryRun, want: "`release/covenant-release-public-key.json`"},
		{name: "dry-run public key copy", doc: dryRun, want: "install the public verification key into the release directory before verification"},
		{name: "release verify command", doc: dryRun, want: "covenant release verify"},
		{name: "release report command", doc: dryRun, want: "covenant release report"},
		{name: "release inspect command", doc: dryRun, want: "covenant release inspect"},
		{name: "schema validation command", doc: dryRun, want: "covenant schema validate"},
		{name: "dry-run artifact audit script", doc: dryRun, want: "./scripts/release-dry-run-artifact-audit.sh"},
		{name: "dry-run artifact audit schema", doc: dryRun, want: "`covenant.release-dry-run-artifact-audit.v1`"},
		{name: "dry-run artifact audit report", doc: dryRun, want: "`release-dry-run-artifact-audit.json`"},
		{name: "signing key env", doc: dryRun, want: "`COVENANT_RELEASE_SIGNING_KEY`"},
		{name: "private key warning", doc: dryRun, want: "Do not commit private keys"},
		{name: "generated output warning", doc: dryRun, want: "generated dry-run output"},
		{name: "release verification link", doc: dryRun, want: "[release verification walkthrough](release-verification.md)"},
		{name: "release operations link", doc: dryRun, want: "[release operations](release.md)"},
		{name: "workflow dry run input", doc: dryRun, want: "`dry_run=true`"},
		{name: "workflow dry run no publish", doc: dryRun, want: "does not publish GitHub release assets, create GitHub artifact attestations, or run post-release smoke verification"},
		{name: "workflow dry run artifacts", doc: dryRun, want: "uploads workflow artifacts only"},
		{name: "readiness dry run audit report", doc: readiness, want: "`release-dry-run-artifact-audit.json`"},
		{name: "readiness dry run audit schema", doc: readiness, want: "`covenant.release-dry-run-artifact-audit.v1`"},
		{name: "release operations dry run", doc: releaseOps, want: "`dry_run=true`"},
		{name: "readiness dry run", doc: readiness, want: "`dry_run=true`"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseRollbackRunbookIsLinkedAndComplete(t *testing.T) {
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
	releaseOps := readText("docs", "release.md")
	dryRun := readText("docs", "release-dry-run.md")
	verification := readText("docs", "release-verification.md")
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")
	runbook := readText("docs", "release-rollback.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Rollback](docs/release-rollback.md)"},
		{name: "release operations link", doc: releaseOps, want: "[release rollback runbook](release-rollback.md)"},
		{name: "dry run link", doc: dryRun, want: "[release rollback runbook](release-rollback.md)"},
		{name: "verification link", doc: verification, want: "[release rollback runbook](release-rollback.md)"},
		{name: "readiness link", doc: readiness, want: "[release rollback runbook](release-rollback.md)"},
		{name: "contributing link", doc: contributing, want: "[release rollback runbook](docs/release-rollback.md)"},
		{name: "title", doc: runbook, want: "# AO Covenant Release Rollback And Replacement Runbook"},
		{name: "scope section", doc: runbook, want: "## Scope"},
		{name: "decision section", doc: runbook, want: "## Decision Flow"},
		{name: "replace section", doc: runbook, want: "## Replace Existing Assets"},
		{name: "rollback section", doc: runbook, want: "## Roll Back Or Withdraw A Release"},
		{name: "consumer notice section", doc: runbook, want: "## Consumer Notice Requirements"},
		{name: "post action section", doc: runbook, want: "## Post-Action Verification"},
		{name: "security escalation section", doc: runbook, want: "## Security Escalation"},
		{name: "replacement flag", doc: runbook, want: "replace_existing_assets=true"},
		{name: "replacement reason", doc: runbook, want: "replacement_reason"},
		{name: "replacement policy", doc: runbook, want: "release-replacement-policy.json"},
		{name: "replacement policy schema", doc: runbook, want: "`covenant.release-replacement-policy.v1`"},
		{name: "replacement policy validation", doc: runbook, want: "covenant schema validate --schema covenant.release-replacement-policy.v1 --file release-replacement-policy.json"},
		{name: "release verify command", doc: runbook, want: "covenant release verify"},
		{name: "attestation command", doc: runbook, want: "gh attestation verify"},
		{name: "release report command", doc: runbook, want: "covenant release report"},
		{name: "no silent overwrite", doc: runbook, want: "Do not silently overwrite release assets"},
		{name: "consumer notice", doc: runbook, want: "Consumers must be told what changed, who is affected, what to download, and what to verify"},
		{name: "private key warning", doc: runbook, want: "Do not include private keys, credentials, production evidence, unreleased bundles, or local machine paths"},
		{name: "security policy link", doc: runbook, want: "[security policy](../SECURITY.md)"},
		{name: "release verification link", doc: runbook, want: "[release verification walkthrough](release-verification.md)"},
		{name: "release operations link", doc: runbook, want: "[release operations](release.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseReplacementPreflightScriptIsLinkedAndComplete(t *testing.T) {
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
	releaseOps := readText("docs", "release.md")
	rollback := readText("docs", "release-rollback.md")
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")
	workflow := readText(".github", "workflows", "release.yml")
	script := readText("scripts", "release-replacement-preflight.sh")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Replacement Preflight Script](scripts/release-replacement-preflight.sh)"},
		{name: "release operations link", doc: releaseOps, want: "[release replacement preflight script](../scripts/release-replacement-preflight.sh)"},
		{name: "rollback link", doc: rollback, want: "[release replacement preflight script](../scripts/release-replacement-preflight.sh)"},
		{name: "readiness link", doc: readiness, want: "[release replacement preflight script](../scripts/release-replacement-preflight.sh)"},
		{name: "contributing link", doc: contributing, want: "[release replacement preflight script](scripts/release-replacement-preflight.sh)"},
		{name: "workflow call", doc: workflow, want: "./scripts/release-replacement-preflight.sh"},
		{name: "workflow dist env", doc: workflow, want: "DIST_DIR: dist"},
		{name: "shebang", doc: script, want: "#!/usr/bin/env bash"},
		{name: "strict shell", doc: script, want: "set -euo pipefail"},
		{name: "dist env", doc: script, want: "DIST_DIR"},
		{name: "version env", doc: script, want: "VERSION"},
		{name: "replacement opt in env", doc: script, want: "REPLACE_EXISTING_ASSETS"},
		{name: "replacement reason env", doc: script, want: "REPLACEMENT_REASON"},
		{name: "offline fixture env", doc: script, want: "COVENANT_RELEASE_EXISTING_ASSETS_FILE"},
		{name: "fail closed diagnostic", doc: script, want: "release asset replacement requires workflow_dispatch input replace_existing_assets=true"},
		{name: "existing assets", doc: script, want: "gh release view \"$VERSION\" --json assets --jq '.assets[].name'"},
		{name: "conflict comparison", doc: script, want: "comm -12 \"$existing_assets\" \"$new_assets\""},
		{name: "replacement policy", doc: script, want: "release-replacement-policy.json"},
		{name: "replacement policy schema", doc: script, want: "covenant.release-replacement-policy.v1"},
		{name: "replacement preflight report schema", doc: script, want: "covenant.release-replacement-preflight-report.v1"},
		{name: "replacement preflight report env", doc: script, want: "COVENANT_RELEASE_REPLACEMENT_REPORT_JSON"},
		{name: "schema validation", doc: script, want: "go run ./cmd/covenant schema validate --schema covenant.release-replacement-policy.v1 --file \"$policy_path\""},
		{name: "github metadata repository", doc: script, want: "GITHUB_REPOSITORY"},
		{name: "github metadata run id", doc: script, want: "GITHUB_RUN_ID"},
		{name: "github metadata run attempt", doc: script, want: "GITHUB_RUN_ATTEMPT"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}

	for _, forbidden := range []string{
		"COVENANT_RELEASE_SIGNING_KEY",
		"private_key",
		"/Users/",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script contains sensitive or local-specific content %q", forbidden)
		}
	}
}

func TestReleaseReplacementPreflightFixturesAreLinkedAndComplete(t *testing.T) {
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
	stability := readText("docs", "public-api-stability.md")
	runbook := readText("docs", "release-rollback.md")
	index := readText("internal", "cli", "testdata", "release-fixture-index.json")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README fixture directory", doc: readme, want: "`internal/cli/testdata/release-replacement-preflight-fixtures/`"},
		{name: "readiness fixture link", doc: readiness, want: "[release replacement preflight fixtures](../internal/cli/testdata/release-replacement-preflight-fixtures)"},
		{name: "stability fixture directory", doc: stability, want: "`internal/cli/testdata/release-replacement-preflight-fixtures/`"},
		{name: "runbook fixture link", doc: runbook, want: "[release replacement preflight fixtures](../internal/cli/testdata/release-replacement-preflight-fixtures)"},
		{name: "index fixture name", doc: index, want: `"name": "release-replacement-preflight"`},
		{name: "index fixture directory", doc: index, want: `"directory": "internal/cli/testdata/release-replacement-preflight-fixtures"`},
		{name: "dist assets fixture", doc: index, want: `"dist-assets.txt"`},
		{name: "existing assets fixture", doc: index, want: `"existing-assets.txt"`},
		{name: "diagnostic fixture", doc: index, want: `"fail-closed-diagnostic.txt"`},
		{name: "policy fixture", doc: index, want: `"generated-policy.json"`},
		{name: "fixture check command", doc: index, want: "go test ./internal/cli -run TestReleaseReplacementPreflightFixtures -count=1"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseReplacementPreflightReportIsLinkedAndComplete(t *testing.T) {
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
	releaseOps := readText("docs", "release.md")
	rollback := readText("docs", "release-rollback.md")
	readiness := readText("docs", "public-readiness.md")
	stability := readText("docs", "public-api-stability.md")
	workflow := readText(".github", "workflows", "release.yml")
	script := readText("scripts", "release-replacement-preflight.sh")
	schemaFile := readText("schemas", "covenant.release-replacement-preflight-report.v1.schema.json")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README schema", doc: readme, want: "`covenant.release-replacement-preflight-report.v1`"},
		{name: "release operations report", doc: releaseOps, want: "`release-replacement-preflight-report.json`"},
		{name: "rollback report", doc: rollback, want: "`release-replacement-preflight-report.json`"},
		{name: "readiness report", doc: readiness, want: "`release-replacement-preflight-report.json`"},
		{name: "stability schema", doc: stability, want: "`covenant.release-replacement-preflight-report.v1`"},
		{name: "workflow report env", doc: workflow, want: "COVENANT_RELEASE_REPLACEMENT_REPORT_JSON: ${{ runner.temp }}/release-replacement-preflight-report.json"},
		{name: "workflow upload", doc: workflow, want: "name: Upload replacement preflight report"},
		{name: "workflow artifact", doc: workflow, want: "ao-covenant-${{ steps.meta.outputs.version }}-replacement-preflight-report"},
		{name: "script report env", doc: script, want: "COVENANT_RELEASE_REPLACEMENT_REPORT_JSON"},
		{name: "script schema", doc: script, want: "covenant.release-replacement-preflight-report.v1"},
		{name: "schema id", doc: schemaFile, want: `"$id": "covenant.release-replacement-preflight-report.v1"`},
		{name: "schema status", doc: schemaFile, want: `"status"`},
		{name: "schema assets", doc: schemaFile, want: `"assets"`},
		{name: "blocked status", doc: schemaFile, want: `"blocked_existing_assets"`},
		{name: "written status", doc: schemaFile, want: `"replacement_policy_written"`},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseNoteTemplateIsLinkedAndComplete(t *testing.T) {
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
	releaseOps := readText("docs", "release.md")
	rollback := readText("docs", "release-rollback.md")
	securityChecklist := readText("docs", "security-advisory-maintainer-checklist.md")
	readiness := readText("docs", "public-readiness.md")
	contributing := readText("CONTRIBUTING.md")
	template := readText("docs", "release-note-template.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Note Template](docs/release-note-template.md)"},
		{name: "release operations link", doc: releaseOps, want: "[release note template](release-note-template.md)"},
		{name: "rollback link", doc: rollback, want: "[release note template](release-note-template.md)"},
		{name: "security checklist link", doc: securityChecklist, want: "[release note template](release-note-template.md)"},
		{name: "readiness link", doc: readiness, want: "[release note template](release-note-template.md)"},
		{name: "contributing link", doc: contributing, want: "[release note template](docs/release-note-template.md)"},
		{name: "title", doc: template, want: "# AO Covenant Release Note Template"},
		{name: "scope section", doc: template, want: "## Scope"},
		{name: "normal release section", doc: template, want: "## Normal Release Notes"},
		{name: "replacement section", doc: template, want: "## Replacement Or Withdrawal Notice"},
		{name: "security section", doc: template, want: "## Security-Sensitive Release Notes"},
		{name: "verification section", doc: template, want: "## Verification Block"},
		{name: "safe wording section", doc: template, want: "## Safe Wording Rules"},
		{name: "maintainer checklist section", doc: template, want: "## Maintainer Checklist"},
		{name: "affected version", doc: template, want: "Affected version:"},
		{name: "who is affected", doc: template, want: "Who is affected:"},
		{name: "consumer action", doc: template, want: "Required consumer action:"},
		{name: "download guidance", doc: template, want: "What to download:"},
		{name: "verification command", doc: template, want: "covenant release verify"},
		{name: "report command", doc: template, want: "covenant release report"},
		{name: "attestation command", doc: template, want: "gh attestation verify"},
		{name: "replacement policy", doc: template, want: "release-replacement-policy.json"},
		{name: "private key warning", doc: template, want: "Do not include private keys, credentials, production evidence, unreleased bundles, or local machine paths"},
		{name: "exploit detail warning", doc: template, want: "Do not include exploit payloads or secret values"},
		{name: "security policy link", doc: template, want: "[security policy](../SECURITY.md)"},
		{name: "rollback link", doc: template, want: "[release rollback runbook](release-rollback.md)"},
		{name: "verification link", doc: template, want: "[release verification walkthrough](release-verification.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestPublicReleaseKnownGoodBaselineIsLinkedAndComplete(t *testing.T) {
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
	verification := readText("docs", "release-verification.md")
	readiness := readText("docs", "public-readiness.md")
	template := readText("docs", "release-note-template.md")
	contributing := readText("CONTRIBUTING.md")
	baseline := readText("docs", "public-release-known-good-baseline.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Public Release Known-Good Baseline](docs/public-release-known-good-baseline.md)"},
		{name: "verification link", doc: verification, want: "[public release known-good baseline](public-release-known-good-baseline.md)"},
		{name: "readiness link", doc: readiness, want: "[public release known-good baseline](public-release-known-good-baseline.md)"},
		{name: "template link", doc: template, want: "[public release known-good baseline](public-release-known-good-baseline.md)"},
		{name: "contributing link", doc: contributing, want: "[public release known-good baseline](docs/public-release-known-good-baseline.md)"},
		{name: "title", doc: baseline, want: "# AO Covenant Public Release Known-Good Baseline"},
		{name: "scope section", doc: baseline, want: "## Scope"},
		{name: "required assets section", doc: baseline, want: "## Required Release Assets"},
		{name: "platform assets section", doc: baseline, want: "## Platform Asset Baseline"},
		{name: "verification outputs section", doc: baseline, want: "## Verification Output Baseline"},
		{name: "schema validation section", doc: baseline, want: "## Schema Validation Baseline"},
		{name: "replacement policy section", doc: baseline, want: "## Replacement Policy Baseline"},
		{name: "sensitive material section", doc: baseline, want: "## Sensitive Material Exclusions"},
		{name: "failure handling section", doc: baseline, want: "## Failure Handling"},
		{name: "manifest", doc: baseline, want: "`manifest.json`"},
		{name: "checksums", doc: baseline, want: "`SHA256SUMS`"},
		{name: "release signature", doc: baseline, want: "`release-signature.json`"},
		{name: "public key", doc: baseline, want: "`covenant-release-public-key.json`"},
		{name: "linux target", doc: baseline, want: "`linux/amd64`"},
		{name: "macos target", doc: baseline, want: "`darwin/arm64`"},
		{name: "windows target", doc: baseline, want: "`windows/amd64`"},
		{name: "verify command", doc: baseline, want: "covenant release verify --dir . --public-key covenant-release-public-key.json"},
		{name: "report command", doc: baseline, want: "covenant release report --dir . --public-key covenant-release-public-key.json"},
		{name: "inspect command", doc: baseline, want: "covenant release inspect --dir . --public-key covenant-release-public-key.json"},
		{name: "attestation command", doc: baseline, want: "gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant"},
		{name: "replacement attestation command", doc: baseline, want: "gh attestation verify release-replacement-policy.json --repo uesugitorachiyo/ao-covenant"},
		{name: "verify schema", doc: baseline, want: "covenant.release-verify-result.v1"},
		{name: "report schema", doc: baseline, want: "covenant.release-report-result.v1"},
		{name: "inspect schema", doc: baseline, want: "covenant.release-inspect-result.v1"},
		{name: "replacement schema", doc: baseline, want: "covenant.release-replacement-policy.v1"},
		{name: "schema validate command", doc: baseline, want: "covenant schema validate"},
		{name: "private key warning", doc: baseline, want: "private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths"},
		{name: "security policy link", doc: baseline, want: "[security policy](../SECURITY.md)"},
		{name: "release verification link", doc: baseline, want: "[release verification walkthrough](release-verification.md)"},
		{name: "rollback link", doc: baseline, want: "[release rollback runbook](release-rollback.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}

func TestReleaseConsumerSmokeScriptIsLinkedAndComplete(t *testing.T) {
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
	verification := readText("docs", "release-verification.md")
	readiness := readText("docs", "public-readiness.md")
	baseline := readText("docs", "public-release-known-good-baseline.md")
	contributing := readText("CONTRIBUTING.md")
	script := readText("scripts", "release-consumer-smoke.sh")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Consumer Smoke Script](scripts/release-consumer-smoke.sh)"},
		{name: "verification link", doc: verification, want: "[release consumer smoke script](../scripts/release-consumer-smoke.sh)"},
		{name: "readiness link", doc: readiness, want: "[release consumer smoke script](../scripts/release-consumer-smoke.sh)"},
		{name: "baseline link", doc: baseline, want: "[release consumer smoke script](../scripts/release-consumer-smoke.sh)"},
		{name: "contributing link", doc: contributing, want: "[release consumer smoke script](scripts/release-consumer-smoke.sh)"},
		{name: "shebang", doc: script, want: "#!/usr/bin/env bash"},
		{name: "strict shell", doc: script, want: "set -euo pipefail"},
		{name: "usage", doc: script, want: "Usage:"},
		{name: "custom binary", doc: script, want: "COVENANT_BIN"},
		{name: "repo option", doc: script, want: "--repo"},
		{name: "out option", doc: script, want: "--out"},
		{name: "skip attestation option", doc: script, want: "--skip-attestation"},
		{name: "manifest asset", doc: script, want: "manifest.json"},
		{name: "checksums asset", doc: script, want: "SHA256SUMS"},
		{name: "signature asset", doc: script, want: "release-signature.json"},
		{name: "public key asset", doc: script, want: "covenant-release-public-key.json"},
		{name: "linux checksum", doc: script, want: "sha256sum -c SHA256SUMS"},
		{name: "macos checksum", doc: script, want: "shasum -a 256 -c SHA256SUMS"},
		{name: "release verify", doc: script, want: "covenant release verify --dir \"$RELEASE_DIR\" --public-key \"$PUBLIC_KEY\" --json"},
		{name: "release report", doc: script, want: "covenant release report --dir \"$RELEASE_DIR\" --public-key \"$PUBLIC_KEY\" --format json --out \"$OUT_DIR/release-report.json\""},
		{name: "release inspect", doc: script, want: "covenant release inspect --dir \"$RELEASE_DIR\" --public-key \"$PUBLIC_KEY\" --json"},
		{name: "validate verify", doc: script, want: "covenant schema validate --file \"$OUT_DIR/release-verify.json\""},
		{name: "validate report", doc: script, want: "covenant schema validate --file \"$OUT_DIR/release-report.json\""},
		{name: "validate inspect", doc: script, want: "covenant schema validate --file \"$OUT_DIR/release-inspect.json\""},
		{name: "summary report", doc: script, want: "release-consumer-smoke.json"},
		{name: "summary schema", doc: script, want: "covenant.release-consumer-smoke-result.v1"},
		{name: "replacement policy schema", doc: script, want: "covenant.release-replacement-policy.v1"},
		{name: "attestation", doc: script, want: "gh attestation verify \"$RELEASE_DIR/manifest.json\" --repo \"$REPO\""},
		{name: "replacement policy attestation", doc: script, want: "gh attestation verify \"$RELEASE_DIR/release-replacement-policy.json\" --repo \"$REPO\""},
		{name: "sensitive material warning", doc: script, want: "private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}

	for _, forbidden := range []string{
		"go run ./cmd/covenant",
		"go test",
		"COVENANT_RELEASE_SIGNING_KEY",
		"git -C",
		".covenant/release-readiness",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script contains repo-private command or path %q", forbidden)
		}
	}
}

func TestReleaseConsumerSmokePowerShellScriptIsLinkedAndComplete(t *testing.T) {
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
	verification := readText("docs", "release-verification.md")
	readiness := readText("docs", "public-readiness.md")
	baseline := readText("docs", "public-release-known-good-baseline.md")
	contributing := readText("CONTRIBUTING.md")
	script := readText("scripts", "release-consumer-smoke.ps1")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Windows Release Consumer Smoke Script](scripts/release-consumer-smoke.ps1)"},
		{name: "verification link", doc: verification, want: "[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)"},
		{name: "readiness link", doc: readiness, want: "[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)"},
		{name: "baseline link", doc: baseline, want: "[Windows release consumer smoke script](../scripts/release-consumer-smoke.ps1)"},
		{name: "contributing link", doc: contributing, want: "[Windows release consumer smoke script](scripts/release-consumer-smoke.ps1)"},
		{name: "strict mode", doc: script, want: "Set-StrictMode -Version Latest"},
		{name: "stop on error", doc: script, want: "$ErrorActionPreference = \"Stop\""},
		{name: "usage", doc: script, want: "Usage:"},
		{name: "release dir parameter", doc: script, want: "[Parameter(Mandatory = $true, Position = 0)]"},
		{name: "custom binary", doc: script, want: "COVENANT_BIN"},
		{name: "repo option", doc: script, want: "-Repo"},
		{name: "out option", doc: script, want: "-Out"},
		{name: "skip attestation option", doc: script, want: "-SkipAttestation"},
		{name: "manifest asset", doc: script, want: "manifest.json"},
		{name: "checksums asset", doc: script, want: "SHA256SUMS"},
		{name: "signature asset", doc: script, want: "release-signature.json"},
		{name: "public key asset", doc: script, want: "covenant-release-public-key.json"},
		{name: "windows checksum", doc: script, want: "Get-FileHash -Algorithm SHA256"},
		{name: "release verify", doc: script, want: "covenant release verify --dir $ReleaseDirPath --public-key $PublicKey --json"},
		{name: "release report", doc: script, want: "covenant release report --dir $ReleaseDirPath --public-key $PublicKey --format json --out (Join-Path $OutDir \"release-report.json\")"},
		{name: "release inspect", doc: script, want: "covenant release inspect --dir $ReleaseDirPath --public-key $PublicKey --json"},
		{name: "validate verify", doc: script, want: "covenant schema validate --file (Join-Path $OutDir \"release-verify.json\")"},
		{name: "validate report", doc: script, want: "covenant schema validate --file (Join-Path $OutDir \"release-report.json\")"},
		{name: "validate inspect", doc: script, want: "covenant schema validate --file (Join-Path $OutDir \"release-inspect.json\")"},
		{name: "summary report", doc: script, want: "release-consumer-smoke.json"},
		{name: "summary schema", doc: script, want: "covenant.release-consumer-smoke-result.v1"},
		{name: "replacement policy schema", doc: script, want: "covenant.release-replacement-policy.v1"},
		{name: "attestation", doc: script, want: "gh attestation verify (Join-Path $ReleaseDirPath \"manifest.json\") --repo $Repo"},
		{name: "replacement policy attestation", doc: script, want: "gh attestation verify (Join-Path $ReleaseDirPath \"release-replacement-policy.json\") --repo $Repo"},
		{name: "sensitive material warning", doc: script, want: "private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}

	for _, forbidden := range []string{
		"go run ./cmd/covenant",
		"go test",
		"COVENANT_RELEASE_SIGNING_KEY",
		"git -C",
		".covenant/release-readiness",
		"sha256sum",
		"shasum",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script contains non-Windows, repo-private command, or path %q", forbidden)
		}
	}
}

func TestReleaseConsumerSmokePowerShellScriptParsesOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell parser check runs on Windows CI")
	}
	repoRoot := filepath.Join("..", "..")
	scriptPath, err := filepath.Abs(filepath.Join(repoRoot, "scripts", "release-consumer-smoke.ps1"))
	if err != nil {
		t.Fatalf("resolve PowerShell smoke script path: %v", err)
	}
	escapedScriptPath := strings.ReplaceAll(scriptPath, "'", "''")
	command := `$path = '` + escapedScriptPath + `'; $tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }`
	output, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command).CombinedOutput()
	if err != nil {
		t.Fatalf("parse %s: %v\n%s", scriptPath, err, output)
	}
}

func TestReleaseReadinessPowerShellScriptIsLinkedAndComplete(t *testing.T) {
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
	changelog := readText("docs", "public-schema-changelog.md")
	script := readText("scripts", "release-readiness.ps1")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Windows Release Readiness Script](scripts/release-readiness.ps1)"},
		{name: "readiness link", doc: readiness, want: "[Windows release-readiness script](../scripts/release-readiness.ps1)"},
		{name: "schema changelog platform", doc: changelog, want: "optional `platform` metadata"},
		{name: "strict mode", doc: script, want: "Set-StrictMode -Version Latest"},
		{name: "stop on error", doc: script, want: "$ErrorActionPreference = \"Stop\""},
		{name: "usage", doc: script, want: "Usage: .\\release-readiness.ps1"},
		{name: "readiness dir parameter", doc: script, want: "[string]$ReadinessDir = $env:COVENANT_RELEASE_READINESS_DIR"},
		{name: "version parameter", doc: script, want: "[string]$Version = $env:COVENANT_RELEASE_VERSION"},
		{name: "commit parameter", doc: script, want: "[string]$Commit = $env:COVENANT_RELEASE_COMMIT"},
		{name: "date parameter", doc: script, want: "[string]$Date = $env:COVENANT_RELEASE_DATE"},
		{name: "target parameter", doc: script, want: "[string]$Target = $env:COVENANT_RELEASE_TARGET"},
		{name: "go build", doc: script, want: "go build -o $Bin ./cmd/covenant"},
		{name: "release package", doc: script, want: "release package"},
		{name: "release verify", doc: script, want: "release verify"},
		{name: "release inspect", doc: script, want: "release inspect"},
		{name: "schema validation", doc: script, want: "schema validate"},
		{name: "summary report", doc: script, want: "release-readiness-summary.json"},
		{name: "summary schema", doc: script, want: "covenant.release-readiness-summary.v1"},
		{name: "platform metadata", doc: script, want: "platform"},
		{name: "script metadata", doc: script, want: "scripts/release-readiness.ps1"},
		{name: "sensitive material warning", doc: script, want: "summary-only; does not include workspace paths, signing key paths, bundle paths, checksums, manifest entries, or generated release asset names"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}

	for _, forbidden := range []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"sha256sum",
		"shasum",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("PowerShell release-readiness script contains non-Windows shell dependency %q", forbidden)
		}
	}
}

func TestReleaseReadinessPowerShellScriptParsesOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell parser check runs on Windows CI")
	}
	repoRoot := filepath.Join("..", "..")
	scriptPath, err := filepath.Abs(filepath.Join(repoRoot, "scripts", "release-readiness.ps1"))
	if err != nil {
		t.Fatalf("resolve PowerShell readiness script path: %v", err)
	}
	escapedScriptPath := strings.ReplaceAll(scriptPath, "'", "''")
	command := `$path = '` + escapedScriptPath + `'; $tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }`
	output, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command).CombinedOutput()
	if err != nil {
		t.Fatalf("parse %s: %v\n%s", scriptPath, err, output)
	}
}

func TestReleaseNoteFixturesAreLinkedAndComplete(t *testing.T) {
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
	template := readText("docs", "release-note-template.md")
	baseline := readText("docs", "public-release-known-good-baseline.md")
	contributing := readText("CONTRIBUTING.md")
	index := readText("docs", "release-note-fixtures.md")
	fixtures := map[string]string{
		"normal":             readText("internal", "cli", "testdata", "release-note-fixtures", "normal.md"),
		"replacement":        readText("internal", "cli", "testdata", "release-note-fixtures", "replacement.md"),
		"withdrawal":         readText("internal", "cli", "testdata", "release-note-fixtures", "withdrawal.md"),
		"security-sensitive": readText("internal", "cli", "testdata", "release-note-fixtures", "security-sensitive.md"),
	}

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Release Note Fixtures](docs/release-note-fixtures.md)"},
		{name: "readiness link", doc: readiness, want: "[release note fixtures](release-note-fixtures.md)"},
		{name: "template link", doc: template, want: "[release note fixtures](release-note-fixtures.md)"},
		{name: "baseline link", doc: baseline, want: "[release note fixtures](release-note-fixtures.md)"},
		{name: "contributing link", doc: contributing, want: "[release note fixtures](docs/release-note-fixtures.md)"},
		{name: "title", doc: index, want: "# AO Covenant Release Note Fixtures"},
		{name: "scope section", doc: index, want: "## Scope"},
		{name: "fixture inventory section", doc: index, want: "## Fixture Inventory"},
		{name: "stable content section", doc: index, want: "## Stable Content Requirements"},
		{name: "safety section", doc: index, want: "## Safety Requirements"},
		{name: "maintenance section", doc: index, want: "## Maintenance"},
		{name: "normal fixture link", doc: index, want: "[normal.md](../internal/cli/testdata/release-note-fixtures/normal.md)"},
		{name: "replacement fixture link", doc: index, want: "[replacement.md](../internal/cli/testdata/release-note-fixtures/replacement.md)"},
		{name: "withdrawal fixture link", doc: index, want: "[withdrawal.md](../internal/cli/testdata/release-note-fixtures/withdrawal.md)"},
		{name: "security fixture link", doc: index, want: "[security-sensitive.md](../internal/cli/testdata/release-note-fixtures/security-sensitive.md)"},
		{name: "fixture test command", doc: index, want: "go test -count=1 ./internal/cli -run TestReleaseNoteFixturesAreLinkedAndComplete"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}

	commonRequired := []string{
		"Affected version:",
		"Who is affected:",
		"Required consumer action:",
		"What to download:",
		"Verification:",
		"covenant release verify --dir . --public-key covenant-release-public-key.json",
		"covenant release report --dir . --public-key covenant-release-public-key.json",
		"gh attestation verify manifest.json --repo uesugitorachiyo/ao-covenant",
		"Do not include private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths.",
	}
	for name, fixture := range fixtures {
		for _, want := range commonRequired {
			if !strings.Contains(fixture, want) {
				t.Fatalf("%s fixture missing %q", name, want)
			}
		}
		for _, forbidden := range []string{"BEGIN PRIVATE KEY", "private_key", "/Users/", "C:\\Users\\", "token=", "password="} {
			if strings.Contains(fixture, forbidden) {
				t.Fatalf("%s fixture contains forbidden sensitive marker %q", name, forbidden)
			}
		}
	}

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "normal title", doc: fixtures["normal"], want: "## AO Covenant v0.1.0"},
		{name: "normal summary", doc: fixtures["normal"], want: "Summary:"},
		{name: "normal no action", doc: fixtures["normal"], want: "No existing installation action is required"},
		{name: "replacement title", doc: fixtures["replacement"], want: "## Release Notice For v0.1.0"},
		{name: "replacement status", doc: fixtures["replacement"], want: "Status:"},
		{name: "replacement policy", doc: fixtures["replacement"], want: "release-replacement-policy.json"},
		{name: "replacement schema", doc: fixtures["replacement"], want: "covenant.release-replacement-policy.v1"},
		{name: "withdrawal status", doc: fixtures["withdrawal"], want: "withdrawn"},
		{name: "withdrawal stop", doc: fixtures["withdrawal"], want: "Stop using v0.1.0"},
		{name: "security title", doc: fixtures["security-sensitive"], want: "## Security-Sensitive Release Note For v0.1.0"},
		{name: "security safe impact", doc: fixtures["security-sensitive"], want: "safe impact statement"},
		{name: "security routing", doc: fixtures["security-sensitive"], want: "Security routing:"},
		{name: "security no exploit", doc: fixtures["security-sensitive"], want: "Do not include exploit payloads or secret values."},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}
