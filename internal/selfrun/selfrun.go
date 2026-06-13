package selfrun

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	runner "github.com/uesugitorachiyo/ao-covenant/internal/run"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
	"github.com/uesugitorachiyo/ao-covenant/internal/verify"
)

const BriefPath = "examples/self-run/brief.md"

type Options struct {
	WorkspaceDir string
	OutDir       string
	RunID        string
}

type Result struct {
	ContractPath       string
	ContractDigestPath string
	ContractDigest     string
	RunDir             string
	LedgerPath         string
	EvidencePackPath   string
	Verification       verify.Result
}

func Execute(ctx context.Context, opts Options) (Result, error) {
	workspaceDir := defaultString(opts.WorkspaceDir, ".")
	outDir := defaultString(opts.OutDir, filepath.Join(".covenant", "self-run"))
	runID := defaultString(opts.RunID, "self-run")

	briefPath := filepath.Join(workspaceDir, filepath.FromSlash(BriefPath))
	brief, err := os.ReadFile(briefPath)
	if err != nil {
		return Result{}, fmt.Errorf("read self-run brief: %w", err)
	}
	c, err := contract.CompileBriefWithSource(string(brief), BriefPath)
	if err != nil {
		return Result{}, fmt.Errorf("compile self-run brief: %w", err)
	}
	if err := schema.ValidateValue(schema.ContractSchemaID, c); err != nil {
		return Result{}, fmt.Errorf("validate self-run contract: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create self-run out dir: %w", err)
	}
	contractPath := filepath.Join(outDir, "contract.json")
	if err := writeContract(contractPath, c); err != nil {
		return Result{}, fmt.Errorf("write self-run contract: %w", err)
	}
	digest, err := contract.Digest(c)
	if err != nil {
		return Result{}, fmt.Errorf("digest self-run contract: %w", err)
	}
	digestPath := contractPath + ".sha256"
	if err := os.WriteFile(digestPath, []byte(digest+"\n"), 0o644); err != nil {
		return Result{}, fmt.Errorf("write self-run contract digest: %w", err)
	}

	runResult, err := runner.Execute(ctx, c, runner.Options{
		WorkspaceDir: workspaceDir,
		OutDir:       filepath.Join(outDir, "runs"),
		RunID:        runID,
	})
	if err != nil {
		return Result{}, fmt.Errorf("run self-run contract: %w", err)
	}
	verification, err := verify.Verify(verify.Options{
		LedgerPath:   runResult.LedgerPath,
		EvidencePath: runResult.EvidencePackPath,
		WorkspaceDir: workspaceDir,
	})
	if err != nil {
		return Result{}, fmt.Errorf("verify self-run evidence: %w", err)
	}

	return Result{
		ContractPath:       contractPath,
		ContractDigestPath: digestPath,
		ContractDigest:     digest,
		RunDir:             runResult.RunDir,
		LedgerPath:         runResult.LedgerPath,
		EvidencePackPath:   runResult.EvidencePackPath,
		Verification:       verification,
	}, nil
}

func writeContract(path string, c contract.Contract) error {
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(bytes, '\n'), 0o644)
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
