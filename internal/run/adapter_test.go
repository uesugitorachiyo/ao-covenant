package run

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
)

func TestDefaultActionAdapterWritesFileArtifact(t *testing.T) {
	workspace := t.TempDir()
	adapter := defaultActionAdapter{}

	result, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: workspace,
		Objective:     "Create a demo report.",
		Task: contract.Task{
			ID: "scripted_change",
		},
		Action: contract.ActionRef{
			Type:     "file.write",
			Resource: "demo-output/report.txt",
		},
		ActionIndex: 0,
	})

	if err != nil {
		t.Fatalf("ExecuteAction error: %v", err)
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1", len(result.Artifacts))
	}
	artifact := result.Artifacts[0]
	if artifact.SchemaVersion != ArtifactRefSchemaVersion {
		t.Fatalf("schema version = %q, want %q", artifact.SchemaVersion, ArtifactRefSchemaVersion)
	}
	if artifact.ArtifactID != "scripted_change-artifact-1" {
		t.Fatalf("artifact id = %q, want scripted_change-artifact-1", artifact.ArtifactID)
	}
	if artifact.Path != "demo-output/report.txt" {
		t.Fatalf("path = %q, want demo-output/report.txt", artifact.Path)
	}
	if !strings.HasPrefix(artifact.URI, "covenant-artifact://sha256/") {
		t.Fatalf("uri = %q, want covenant artifact uri", artifact.URI)
	}
	if _, err := fileDigest(filepath.Join(workspace, "demo-output", "report.txt")); err != nil {
		t.Fatalf("written artifact digest: %v", err)
	}
}

func TestDefaultActionAdapterReadsFileArtifact(t *testing.T) {
	workspace := t.TempDir()
	readPath := filepath.Join(workspace, "briefs", "input.md")
	if err := os.MkdirAll(filepath.Dir(readPath), 0o755); err != nil {
		t.Fatalf("mkdir read dir: %v", err)
	}
	if err := os.WriteFile(readPath, []byte("Evidence input.\n"), 0o644); err != nil {
		t.Fatalf("write read input: %v", err)
	}
	adapter := defaultActionAdapter{}

	result, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: workspace,
		Task: contract.Task{
			ID: "inspect_source",
		},
		Action: contract.ActionRef{
			Type:     "file.read",
			Resource: "briefs/input.md",
		},
		ActionIndex: 0,
	})

	if err != nil {
		t.Fatalf("ExecuteAction error: %v", err)
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1", len(result.Artifacts))
	}
	artifact := result.Artifacts[0]
	if artifact.ArtifactID != "inspect_source-read-1" {
		t.Fatalf("artifact id = %q, want inspect_source-read-1", artifact.ArtifactID)
	}
	if artifact.Path != "briefs/input.md" {
		t.Fatalf("path = %q, want briefs/input.md", artifact.Path)
	}
	expectedDigest, err := fileDigest(readPath)
	if err != nil {
		t.Fatalf("digest read input: %v", err)
	}
	if artifact.Digest != expectedDigest {
		t.Fatalf("digest = %q, want %q", artifact.Digest, expectedDigest)
	}
	if artifact.URI != "covenant-artifact://sha256/"+expectedDigest {
		t.Fatalf("uri = %q, want digest URI", artifact.URI)
	}
}

func TestDefaultActionAdapterRejectsFileReadDirectory(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "briefs"), 0o755); err != nil {
		t.Fatalf("mkdir read dir: %v", err)
	}
	adapter := defaultActionAdapter{}

	_, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: workspace,
		Task: contract.Task{
			ID: "inspect_source",
		},
		Action: contract.ActionRef{
			Type:     "file.read",
			Resource: "briefs",
		},
		ActionIndex: 0,
	})

	if err == nil {
		t.Fatalf("ExecuteAction error = nil, want directory rejection")
	}
	if !strings.Contains(err.Error(), "file.read resource \"briefs\" is a directory") {
		t.Fatalf("ExecuteAction error = %v, want directory rejection", err)
	}
}

func TestDefaultActionAdapterRejectsProcessWhenNotAllowlisted(t *testing.T) {
	adapter := defaultActionAdapter{}

	_, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: t.TempDir(),
		Task: contract.Task{
			ID: "scripted_change",
		},
		Action: contract.ActionRef{
			Type:     "process.spawn",
			Resource: "make test",
		},
		ActionIndex: 0,
	})

	if err == nil {
		t.Fatalf("ExecuteAction error = nil, want fail-closed error")
	}
	if !strings.Contains(err.Error(), "process.spawn resource \"make test\" is not allowlisted") {
		t.Fatalf("ExecuteAction error = %v, want allowlist error", err)
	}
}

func TestDefaultActionAdapterRunsAllowlistedProcessAndCapturesOutput(t *testing.T) {
	workspace := t.TempDir()
	adapter := defaultActionAdapter{processAllowlist: []string{"go version"}}

	result, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: workspace,
		Task: contract.Task{
			ID:          "scripted_change",
			TimeoutSecs: 5,
		},
		Action: contract.ActionRef{
			Type:     "process.spawn",
			Resource: "go version",
		},
		ActionIndex: 0,
	})

	if err != nil {
		t.Fatalf("ExecuteAction error: %v", err)
	}
	if len(result.Artifacts) != 2 {
		t.Fatalf("artifacts len = %d, want stdout and stderr artifacts", len(result.Artifacts))
	}
	stdoutArtifact := result.Artifacts[0]
	if stdoutArtifact.ArtifactID != "scripted_change-process-1-stdout" {
		t.Fatalf("stdout artifact id = %q", stdoutArtifact.ArtifactID)
	}
	stdoutBytes, err := os.ReadFile(filepath.Join(workspace, stdoutArtifact.Path))
	if err != nil {
		t.Fatalf("read stdout artifact: %v", err)
	}
	if !strings.Contains(string(stdoutBytes), "go version") {
		t.Fatalf("stdout artifact = %q, want go version", string(stdoutBytes))
	}
	stderrArtifact := result.Artifacts[1]
	stderrBytes, err := os.ReadFile(filepath.Join(workspace, stderrArtifact.Path))
	if err != nil {
		t.Fatalf("read stderr artifact: %v", err)
	}
	if string(stderrBytes) != "" {
		t.Fatalf("stderr artifact = %q, want empty", string(stderrBytes))
	}
}

func TestDefaultActionAdapterTimesOutAllowlistedProcess(t *testing.T) {
	workspace := t.TempDir()
	adapter := defaultActionAdapter{processAllowlist: []string{"go env"}}

	_, err := adapter.ExecuteAction(context.Background(), ActionRequest{
		WorkspaceRoot: workspace,
		Task: contract.Task{
			ID:          "scripted_change",
			TimeoutSecs: -1,
		},
		Action: contract.ActionRef{
			Type:     "process.spawn",
			Resource: "go env",
		},
		ActionIndex: 0,
	})

	if err == nil {
		t.Fatalf("ExecuteAction error = nil, want timeout")
	}
	if !strings.Contains(err.Error(), "process.spawn timed out") {
		t.Fatalf("ExecuteAction error = %v, want timeout", err)
	}
}
