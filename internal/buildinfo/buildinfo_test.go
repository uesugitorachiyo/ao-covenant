package buildinfo

import "testing"

func TestBuildInfoCurrentUsesInjectedValues(t *testing.T) {
	oldVersion := Version
	oldCommit := Commit
	oldDate := Date
	t.Cleanup(func() {
		Version = oldVersion
		Commit = oldCommit
		Date = oldDate
	})
	Version = "v0.1.0"
	Commit = "abc123"
	Date = "2026-06-11T00:00:00Z"

	info := Current()

	if info.Version != "v0.1.0" {
		t.Fatalf("version = %q, want v0.1.0", info.Version)
	}
	if info.Commit != "abc123" {
		t.Fatalf("commit = %q, want abc123", info.Commit)
	}
	if info.Date != "2026-06-11T00:00:00Z" {
		t.Fatalf("date = %q, want 2026-06-11T00:00:00Z", info.Date)
	}
	if info.GoVersion == "" {
		t.Fatalf("go version is empty")
	}
	if info.OS == "" {
		t.Fatalf("os is empty")
	}
	if info.Arch == "" {
		t.Fatalf("arch is empty")
	}
}
