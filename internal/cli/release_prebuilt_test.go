package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleasePackageCommandAcceptsBoundedPrebuiltCandidate(t *testing.T) {
	root := t.TempDir()
	prebuilt := filepath.Join(root, "native-covenant")
	if err := os.WriteFile(prebuilt, []byte("native-candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := RunWithInput(
		[]string{
			"covenant",
			"release",
			"package",
			"--source", root,
			"--out", filepath.Join(root, "dist"),
			"--version", "v0.1.0",
			"--commit", strings.Repeat("a", 40),
			"--date", "2026-07-20T00:00:00Z",
			"--target", "linux/amd64",
			"--prebuilt", "linux/amd64=" + prebuilt,
			"--json",
		},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("release package exit = %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version": "covenant.release-package-result.v1"`) {
		t.Fatalf("release package output missing schema:\n%s", stdout.String())
	}
}

func TestReleasePackageCommandRejectsMalformedPrebuiltMapping(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunWithInput(
		[]string{"covenant", "release", "package", "--prebuilt", "linux/amd64"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)
	if code != 2 || !strings.Contains(stderr.String(), "target=path") {
		t.Fatalf("exit = %d stderr = %q, want malformed prebuilt rejection", code, stderr.String())
	}
}
