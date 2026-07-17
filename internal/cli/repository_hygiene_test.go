package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRepositoryIgnoreRulesCoverSensitiveLocalArtifacts(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join("..", "..", ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	ignore := string(bytes)

	for _, pattern := range []string{
		".covenant/",
		"dist/",
		"bin/",
		".env",
		".env.*",
		"*.pem",
		"*.p12",
		"*.pfx",
		"*.key",
		"covenant-private-key.json",
		"covenant-release-private-key.json",
		"*private-key*.json",
	} {
		if !strings.Contains(ignore, pattern) {
			t.Fatalf(".gitignore missing sensitive artifact pattern %q", pattern)
		}
	}
}

func TestTrackedRepositoryFilesDoNotContainLocalSecretsOrMachinePaths(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = repoRoot
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	localPathPatterns := []*regexp.Regexp{
		regexp.MustCompile(`/Users/[A-Za-z0-9._-]+/`),
		regexp.MustCompile(`/home/[A-Za-z0-9._-]+/`),
		regexp.MustCompile(`C:\\Users\\[^\\]+\\`),
	}
	privatePEM := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	for _, rawPath := range bytes.Split(output, []byte{0}) {
		if len(rawPath) == 0 {
			continue
		}
		path := filepath.ToSlash(string(rawPath))
		base := filepath.Base(path)
		if strings.HasPrefix(path, ".covenant/") {
			t.Fatalf("tracked generated AO Covenant artifact %q", path)
		}
		if strings.Contains(path, ".covenant/release-readiness/") {
			t.Fatalf("tracked release-readiness artifact %q", path)
		}
		if base == "covenant-private-key.json" ||
			base == "covenant-release-private-key.json" ||
			base == "ao-covenant-bundle-private-key.json" {
			t.Fatalf("tracked private key file %q", path)
		}

		bytes, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			t.Fatalf("read tracked file %s: %v", path, err)
		}
		text := string(bytes)
		if privatePEM.MatchString(text) {
			t.Fatalf("tracked file %q contains a private key PEM block", path)
		}
		for _, pattern := range localPathPatterns {
			if match := pattern.FindString(text); match != "" {
				t.Fatalf("tracked file %q contains local machine path %q", path, match)
			}
		}
	}
}

func TestPublicRepoPolicyScannerPasses(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	var cmd *exec.Cmd
	if _, err := exec.LookPath("bash"); err == nil {
		cmd = exec.Command("bash", "scripts/check-public-repo-policy.sh")
	} else {
		python := "python"
		if path, err := exec.LookPath("python3"); err == nil {
			python = path
		}
		cmd = exec.Command(python, "scripts/check-public-repo-policy.py")
	}
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("public repo policy scanner failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "public repo policy check passed") {
		t.Fatalf("public repo policy scanner output missing pass status:\n%s", output)
	}
}
