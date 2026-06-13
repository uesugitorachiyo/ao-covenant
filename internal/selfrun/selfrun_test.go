package selfrun

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
)

func TestExecuteCompilesRunsAndVerifiesSelfRun(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, BriefPath), "Produce AO Covenant self-run evidence for this repository.")
	outDir := filepath.Join(workspace, ".covenant", "self-run")

	result, err := Execute(context.Background(), Options{
		WorkspaceDir: workspace,
		OutDir:       outDir,
		RunID:        "self-run-test",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	for _, path := range []string{
		result.ContractPath,
		result.ContractDigestPath,
		result.LedgerPath,
		result.EvidencePackPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	if !result.Verification.Verified {
		t.Fatalf("verification = false, want true")
	}
	if result.Verification.RunID != "self-run-test" {
		t.Fatalf("verification run id = %q, want self-run-test", result.Verification.RunID)
	}
	if result.Verification.FailureCount != 0 {
		t.Fatalf("failure count = %d, want 0", result.Verification.FailureCount)
	}

	bytes, err := os.ReadFile(result.ContractPath)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c contract.Contract
	if err := json.Unmarshal(bytes, &c); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if len(c.Workspace.Reads) != 1 || c.Workspace.Reads[0] != BriefPath {
		t.Fatalf("workspace reads = %v, want %s", c.Workspace.Reads, BriefPath)
	}
}

func TestExecuteVerifiesSelfRunWithExternalOutDir(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, BriefPath), "Produce AO Covenant self-run evidence for this repository.")
	outDir := t.TempDir()

	result, err := Execute(context.Background(), Options{
		WorkspaceDir: workspace,
		OutDir:       outDir,
		RunID:        "self-run-external",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if !result.Verification.Verified {
		t.Fatalf("verification = false, want true")
	}
	if result.Verification.ArtifactCount == 0 {
		t.Fatalf("artifact count = 0, want recorded artifacts")
	}
}

func mustWrite(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
