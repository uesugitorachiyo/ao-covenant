package run

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
)

type ActionAdapter interface {
	ExecuteAction(ctx context.Context, req ActionRequest) (ActionResult, error)
}

type ActionRequest struct {
	WorkspaceRoot string
	Objective     string
	Task          contract.Task
	Action        contract.ActionRef
	ActionIndex   int
}

type ActionResult struct {
	Artifacts []ArtifactRef
}

type defaultActionAdapter struct {
	processAllowlist []string
}

func (a defaultActionAdapter) ExecuteAction(ctx context.Context, req ActionRequest) (ActionResult, error) {
	if err := ctx.Err(); err != nil {
		return ActionResult{}, err
	}
	switch req.Action.Type {
	case "file.write":
		artifact, err := executeFileWrite(req)
		if err != nil {
			return ActionResult{}, err
		}
		return ActionResult{Artifacts: []ArtifactRef{artifact}}, nil
	case "file.read":
		artifact, err := executeFileRead(req)
		if err != nil {
			return ActionResult{}, err
		}
		return ActionResult{Artifacts: []ArtifactRef{artifact}}, nil
	case "process.spawn":
		return a.executeProcess(ctx, req)
	case "network.request":
		return ActionResult{}, fmt.Errorf("no default adapter for %s", req.Action.Type)
	default:
		return ActionResult{}, fmt.Errorf("unsupported side effect type %q", req.Action.Type)
	}
}

func (a defaultActionAdapter) executeProcess(ctx context.Context, req ActionRequest) (ActionResult, error) {
	if !containsExact(a.processAllowlist, req.Action.Resource) {
		return ActionResult{}, fmt.Errorf("process.spawn resource %q is not allowlisted", req.Action.Resource)
	}
	fields := strings.Fields(req.Action.Resource)
	if len(fields) == 0 {
		return ActionResult{}, fmt.Errorf("process.spawn resource is empty")
	}
	timeout := time.Duration(req.Task.TimeoutSecs) * time.Second
	if req.Task.TimeoutSecs <= 0 {
		timeout = -time.Nanosecond
	}
	processCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(processCtx, fields[0], fields[1:]...)
	cmd.Dir = req.WorkspaceRoot
	cmd.Env = minimalProcessEnv()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if processCtx.Err() == context.DeadlineExceeded {
		return ActionResult{}, fmt.Errorf("process.spawn timed out after %s", timeout)
	}
	if err != nil {
		return ActionResult{}, fmt.Errorf("process.spawn %q failed: %w", req.Action.Resource, err)
	}

	stdoutArtifact, err := writeProcessArtifact(req, "stdout", stdout.Bytes())
	if err != nil {
		return ActionResult{}, err
	}
	stderrArtifact, err := writeProcessArtifact(req, "stderr", stderr.Bytes())
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{Artifacts: []ArtifactRef{stdoutArtifact, stderrArtifact}}, nil
}

func executeFileWrite(req ActionRequest) (ArtifactRef, error) {
	target, err := safeJoin(req.WorkspaceRoot, req.Action.Resource)
	if err != nil {
		return ArtifactRef{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return ArtifactRef{}, fmt.Errorf("create output dir: %w", err)
	}
	contents := fmt.Sprintf("AO Covenant demo output\n\nobjective: %s\ntask: %s\n", req.Objective, req.Task.ID)
	if err := os.WriteFile(target, []byte(contents), 0o644); err != nil {
		return ArtifactRef{}, fmt.Errorf("write side effect %q: %w", req.Action.Resource, err)
	}
	digest, err := fileDigest(target)
	if err != nil {
		return ArtifactRef{}, err
	}
	return ArtifactRef{
		SchemaVersion: ArtifactRefSchemaVersion,
		ArtifactID:    fmt.Sprintf("%s-artifact-%d", req.Task.ID, req.ActionIndex+1),
		URI:           "covenant-artifact://sha256/" + digest,
		Digest:        digest,
		MediaType:     "text/plain",
		Path:          slashClean(req.Action.Resource),
	}, nil
}

func executeFileRead(req ActionRequest) (ArtifactRef, error) {
	target, err := safeJoin(req.WorkspaceRoot, req.Action.Resource)
	if err != nil {
		return ArtifactRef{}, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return ArtifactRef{}, fmt.Errorf("read side effect %q: %w", req.Action.Resource, err)
	}
	if info.IsDir() {
		return ArtifactRef{}, fmt.Errorf("file.read resource %q is a directory", req.Action.Resource)
	}
	digest, err := fileDigest(target)
	if err != nil {
		return ArtifactRef{}, fmt.Errorf("digest read side effect %q: %w", req.Action.Resource, err)
	}
	return ArtifactRef{
		SchemaVersion: ArtifactRefSchemaVersion,
		ArtifactID:    fmt.Sprintf("%s-read-%d", req.Task.ID, req.ActionIndex+1),
		URI:           "covenant-artifact://sha256/" + digest,
		Digest:        digest,
		MediaType:     "text/plain",
		Path:          slashClean(req.Action.Resource),
	}, nil
}

func writeProcessArtifact(req ActionRequest, stream string, contents []byte) (ArtifactRef, error) {
	artifactID := fmt.Sprintf("%s-process-%d-%s", req.Task.ID, req.ActionIndex+1, stream)
	artifactPath := fmt.Sprintf(".covenant/process/%s.txt", artifactID)
	target, err := safeJoin(req.WorkspaceRoot, artifactPath)
	if err != nil {
		return ArtifactRef{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return ArtifactRef{}, fmt.Errorf("create process artifact dir: %w", err)
	}
	if err := os.WriteFile(target, contents, 0o644); err != nil {
		return ArtifactRef{}, fmt.Errorf("write process %s artifact: %w", stream, err)
	}
	digest, err := fileDigest(target)
	if err != nil {
		return ArtifactRef{}, err
	}
	return ArtifactRef{
		SchemaVersion: ArtifactRefSchemaVersion,
		ArtifactID:    artifactID,
		URI:           "covenant-artifact://sha256/" + digest,
		Digest:        digest,
		MediaType:     "text/plain",
		Path:          artifactPath,
	}, nil
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func minimalProcessEnv() []string {
	env := []string{}
	if value := os.Getenv("SystemRoot"); value != "" {
		env = append(env, "SystemRoot="+value)
	}
	if value := os.Getenv("WINDIR"); value != "" {
		env = append(env, "WINDIR="+value)
	}
	return env
}
