package run

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/closure"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func Execute(ctx context.Context, c contract.Contract, opts Options) (Result, error) {
	if err := schema.ValidateValue(schema.ContractSchemaID, c); err != nil {
		return Result{}, err
	}
	if err := contract.Validate(c); err != nil {
		return Result{}, err
	}
	workspaceDir, err := absoluteDir(opts.WorkspaceDir, "workspace")
	if err != nil {
		return Result{}, err
	}
	outDir, err := absoluteDir(opts.OutDir, "out")
	if err != nil {
		return Result{}, err
	}
	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		runID = fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
	}
	if err := validateRunID(runID); err != nil {
		return Result{}, err
	}

	workspaceRoot, err := safeJoin(workspaceDir, c.Workspace.Root)
	if err != nil {
		return Result{}, fmt.Errorf("workspace root: %w", err)
	}
	if err := verifyDeclaredReads(workspaceRoot, c.Workspace.Reads); err != nil {
		return Result{}, err
	}
	actionAdapter := opts.ActionAdapter
	if actionAdapter == nil {
		actionAdapter = defaultActionAdapter{processAllowlist: opts.ProcessAllowlist}
	}

	contractDigest, err := contract.Digest(c)
	if err != nil {
		return Result{}, err
	}
	runDir := filepath.Join(outDir, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create run dir: %w", err)
	}
	inputSnapshots, err := snapshotDeclaredReads(workspaceRoot, runDir, c.Workspace.Reads)
	if err != nil {
		return Result{}, err
	}
	ledgerPath := filepath.Join(runDir, "events.ndjson")
	ledgerFile, err := os.Create(ledgerPath)
	if err != nil {
		return Result{}, fmt.Errorf("create ledger: %w", err)
	}
	defer ledgerFile.Close()

	recorder := &eventRecorder{
		writer:       bufio.NewWriter(ledgerFile),
		runID:        runID,
		previousHash: GenesisEventHash,
	}
	if _, err := recorder.emit("run_started", "", "success", "run accepted", nil); err != nil {
		return Result{}, err
	}

	states := map[string]*taskState{}
	for _, task := range c.Tasks {
		states[task.ID] = &taskState{task: task}
	}
	var artifacts []ArtifactRef
	taskArtifactIDs := map[string][]string{}
	var policyDecisions []policy.Decision
	var failures []FailureRecord
	evidencePath := filepath.Join(runDir, "evidence-pack.json")
	for completed := 0; completed < len(c.Tasks); {
		progress := false
		for _, task := range c.Tasks {
			state := states[task.ID]
			if state.status == "success" {
				continue
			}
			if !dependenciesComplete(states, task.DependsOn) {
				continue
			}
			progress = true
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			if _, err := recorder.emit("task_started", task.ID, "success", "task started", nil); err != nil {
				return Result{}, err
			}
			taskPolicyDecisions := evaluateTaskPolicy(c, task, opts.RevokedApprovalTicketIDs)
			for _, decision := range taskPolicyDecisions {
				eventStatus := "success"
				if decision.Decision == policy.DecisionDeny {
					eventStatus = "failed"
				}
				if _, err := recorder.emitPolicyDecision(task.ID, eventStatus, decision); err != nil {
					return Result{}, err
				}
				policyDecisions = append(policyDecisions, decision)
			}
			if denied := firstDeniedDecision(taskPolicyDecisions); denied != nil {
				state.status = "failed"
				runErr := fmt.Errorf("policy denied task %q side effect %q on %q: %s", task.ID, denied.EffectType, denied.Resource, denied.Reason)
				failureEvent, _ := recorder.emit("task_finished", task.ID, "failed", runErr.Error(), nil)
				failures = append(failures, newFailureRecord(len(failures)+1, failureEvent, FailurePhasePolicy, runErr.Error()))
				result, finishErr := finishRun(recorder, c, states, taskArtifactIDs, runDir, ledgerPath, evidencePath, runID, contractDigest, "failed", "run failed", artifacts, inputSnapshots, policyDecisions, failures)
				if finishErr != nil {
					return result, finishErr
				}
				return result, runErr
			}
			taskArtifacts, err := executeTask(ctx, workspaceRoot, c, task, states, actionAdapter)
			if err != nil {
				state.status = "failed"
				failureEvent, _ := recorder.emit("task_finished", task.ID, "failed", err.Error(), nil)
				failures = append(failures, newFailureRecord(len(failures)+1, failureEvent, failurePhaseForTask(task), err.Error()))
				result, finishErr := finishRun(recorder, c, states, taskArtifactIDs, runDir, ledgerPath, evidencePath, runID, contractDigest, "failed", "run failed", artifacts, inputSnapshots, policyDecisions, failures)
				if finishErr != nil {
					return result, finishErr
				}
				return result, err
			}
			for _, artifact := range taskArtifacts {
				event, err := recorder.emit("artifact_recorded", task.ID, "success", artifact.Path, []string{artifact.ArtifactID})
				if err != nil {
					return Result{}, err
				}
				artifact.ProducerEventID = event.EventID
				artifacts = append(artifacts, artifact)
				taskArtifactIDs[task.ID] = append(taskArtifactIDs[task.ID], artifact.ArtifactID)
			}
			if _, err := recorder.emit("task_finished", task.ID, "success", "task completed", artifactIDs(taskArtifacts)); err != nil {
				return Result{}, err
			}
			state.status = "success"
			completed++
		}
		if !progress {
			return Result{}, fmt.Errorf("task graph made no progress")
		}
	}
	if err := verifyRequiredObligations(c, states); err != nil {
		return Result{}, err
	}
	return finishRun(recorder, c, states, taskArtifactIDs, runDir, ledgerPath, evidencePath, runID, contractDigest, "success", "run completed", artifacts, inputSnapshots, policyDecisions, failures)
}

func finishRun(recorder *eventRecorder, c contract.Contract, states map[string]*taskState, taskArtifacts map[string][]string, runDir string, ledgerPath string, evidencePath string, runID string, contractDigest string, status string, message string, artifacts []ArtifactRef, inputSnapshots []InputSnapshot, policyDecisions []policy.Decision, failures []FailureRecord) (Result, error) {
	if _, err := recorder.emit("run_finished", "", status, message, nil); err != nil {
		return Result{}, err
	}
	if err := recorder.flush(); err != nil {
		return Result{}, err
	}
	ledgerDigest, err := fileDigest(ledgerPath)
	if err != nil {
		return Result{}, err
	}
	closureMatrix := closure.Evaluate(closure.Input{
		RunID:           runID,
		ContractDigest:  contractDigest,
		RunStatus:       status,
		Obligations:     c.Obligations,
		Tasks:           c.Tasks,
		TaskStatuses:    taskStatuses(states),
		TaskArtifacts:   taskArtifacts,
		PolicyDecisions: policyDecisions,
	})
	evidence := EvidencePack{
		SchemaVersion:    EvidencePackSchemaVersion,
		RunID:            runID,
		ContractDigest:   contractDigest,
		LedgerDigest:     ledgerDigest,
		RunStatus:        status,
		ArtifactManifest: nonNilArtifacts(artifacts),
		InputSnapshots:   nonNilInputSnapshots(inputSnapshots),
		PolicyDecisions:  nonNilPolicyDecisions(policyDecisions),
		Failures:         nonNilFailures(failures),
		ClosureMatrix:    closureMatrix,
	}
	if err := schema.ValidateValue(schema.EvidencePackSchemaID, evidence); err != nil {
		return Result{}, err
	}
	if err := writeJSON(evidencePath, evidence); err != nil {
		return Result{}, err
	}
	return Result{
		RunDir:           runDir,
		LedgerPath:       ledgerPath,
		EvidencePackPath: evidencePath,
		EvidencePack:     evidence,
	}, nil
}

func newFailureRecord(sequence int, event Event, phase string, reason string) FailureRecord {
	return FailureRecord{
		SchemaVersion: FailureSchemaVersion,
		FailureID:     fmt.Sprintf("failure-%06d", sequence),
		EventID:       event.EventID,
		TaskID:        event.TaskID,
		Phase:         phase,
		Reason:        reason,
	}
}

func failurePhaseForTask(task contract.Task) string {
	switch task.Kind {
	case "scripted", "shell", "agent":
		return FailurePhaseAdapter
	case "verify", "review", "evaluate":
		return FailurePhaseExecution
	default:
		return FailurePhaseExecution
	}
}

func nonNilArtifacts(artifacts []ArtifactRef) []ArtifactRef {
	if artifacts == nil {
		return []ArtifactRef{}
	}
	return artifacts
}

func nonNilInputSnapshots(snapshots []InputSnapshot) []InputSnapshot {
	if snapshots == nil {
		return []InputSnapshot{}
	}
	return snapshots
}

func nonNilPolicyDecisions(decisions []policy.Decision) []policy.Decision {
	if decisions == nil {
		return []policy.Decision{}
	}
	return decisions
}

func nonNilFailures(failures []FailureRecord) []FailureRecord {
	if failures == nil {
		return []FailureRecord{}
	}
	return failures
}

func taskStatuses(states map[string]*taskState) map[string]string {
	statuses := map[string]string{}
	for taskID, state := range states {
		statuses[taskID] = state.status
	}
	return statuses
}

func evaluateTaskPolicy(c contract.Contract, task contract.Task, revokedApprovalTicketIDs map[string]bool) []policy.Decision {
	actions := make([]policy.ActionRef, 0, len(task.DeclaredSideEffects))
	for _, action := range task.DeclaredSideEffects {
		actions = append(actions, policy.ActionRef{
			Type:     action.Type,
			Resource: action.Resource,
		})
	}
	return policy.EvaluateTask(policy.Input{
		Mode:                     c.Policy.Mode,
		WorkspaceReads:           c.Workspace.Reads,
		WorkspaceWrites:          c.Workspace.Writes,
		TaskID:                   task.ID,
		Actions:                  actions,
		Approvals:                c.Approvals,
		EvaluationTime:           time.Now().UTC(),
		RevokedApprovalTicketIDs: revokedApprovalTicketIDs,
	})
}

func firstDeniedDecision(decisions []policy.Decision) *policy.Decision {
	for i := range decisions {
		if decisions[i].Decision == policy.DecisionDeny {
			return &decisions[i]
		}
	}
	return nil
}

func executeTask(ctx context.Context, workspaceRoot string, c contract.Contract, task contract.Task, states map[string]*taskState, adapter ActionAdapter) ([]ArtifactRef, error) {
	switch task.Kind {
	case "scripted", "shell", "agent":
		return executeSideEffects(ctx, workspaceRoot, c, task, adapter)
	case "verify":
		return nil, verifyWorkspaceWrites(workspaceRoot, c.Workspace.Writes)
	case "review":
		return nil, verifyDependenciesSucceeded(states, task.DependsOn)
	case "evaluate":
		return nil, verifyRequiredObligations(c, states)
	default:
		return nil, fmt.Errorf("unsupported task kind %q", task.Kind)
	}
}

func executeSideEffects(ctx context.Context, workspaceRoot string, c contract.Contract, task contract.Task, adapter ActionAdapter) ([]ArtifactRef, error) {
	var artifacts []ArtifactRef
	for index, sideEffect := range task.DeclaredSideEffects {
		result, err := adapter.ExecuteAction(ctx, ActionRequest{
			WorkspaceRoot: workspaceRoot,
			Objective:     c.Objective,
			Task:          task,
			Action:        sideEffect,
			ActionIndex:   index,
		})
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, result.Artifacts...)
	}
	return artifacts, nil
}

func snapshotDeclaredReads(workspaceRoot string, runDir string, reads []string) ([]InputSnapshot, error) {
	snapshots := make([]InputSnapshot, 0, len(reads))
	for index, readPath := range reads {
		snapshot, err := writeInputSnapshot(workspaceRoot, runDir, readPath, index)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func writeInputSnapshot(workspaceRoot string, runDir string, sourcePath string, index int) (InputSnapshot, error) {
	source, err := safeJoin(workspaceRoot, sourcePath)
	if err != nil {
		return InputSnapshot{}, err
	}
	info, err := os.Stat(source)
	if err != nil {
		return InputSnapshot{}, fmt.Errorf("snapshot input %q: %w", sourcePath, err)
	}
	if info.IsDir() {
		return InputSnapshot{}, fmt.Errorf("snapshot input %q is a directory", sourcePath)
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		return InputSnapshot{}, fmt.Errorf("read input snapshot source %q: %w", sourcePath, err)
	}
	normalizedSource := slashClean(sourcePath)
	snapshotPath := slashClean("input-snapshots/" + normalizedSource)
	target, err := safeJoin(runDir, snapshotPath)
	if err != nil {
		return InputSnapshot{}, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return InputSnapshot{}, fmt.Errorf("create input snapshot dir: %w", err)
	}
	if err := os.WriteFile(target, contents, 0o644); err != nil {
		return InputSnapshot{}, fmt.Errorf("write input snapshot %q: %w", snapshotPath, err)
	}
	digest, err := fileDigest(target)
	if err != nil {
		return InputSnapshot{}, fmt.Errorf("digest input snapshot %q: %w", snapshotPath, err)
	}
	return InputSnapshot{
		SchemaVersion: InputSnapshotSchemaVersion,
		SnapshotID:    snapshotID(index),
		SourcePath:    normalizedSource,
		SnapshotPath:  snapshotPath,
		Digest:        digest,
		MediaType:     mediaTypeForPath(normalizedSource),
	}, nil
}

func snapshotID(index int) string {
	return fmt.Sprintf("input-%06d", index+1)
}

func mediaTypeForPath(filePath string) string {
	switch strings.ToLower(path.Ext(filePath)) {
	case ".md", ".markdown":
		return "text/markdown"
	case ".txt", ".log":
		return "text/plain"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

func verifyDeclaredReads(workspaceRoot string, reads []string) error {
	for _, readPath := range reads {
		target, err := safeJoin(workspaceRoot, readPath)
		if err != nil {
			return err
		}
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("declared read %q is unavailable: %w", readPath, err)
		}
		if info.IsDir() {
			return fmt.Errorf("declared read %q is a directory", readPath)
		}
	}
	return nil
}

func verifyWorkspaceWrites(workspaceRoot string, writes []string) error {
	for _, writePath := range writes {
		target, err := safeJoin(workspaceRoot, writePath)
		if err != nil {
			return err
		}
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("declared write %q is unavailable: %w", writePath, err)
		}
		if info.IsDir() || info.Size() == 0 {
			return fmt.Errorf("declared write %q is not a non-empty file", writePath)
		}
	}
	return nil
}

func verifyDependenciesSucceeded(states map[string]*taskState, deps []string) error {
	for _, dep := range deps {
		if states[dep].status != "success" {
			return fmt.Errorf("dependency %q did not succeed", dep)
		}
	}
	return nil
}

func verifyRequiredObligations(c contract.Contract, states map[string]*taskState) error {
	satisfied := map[string]bool{}
	for _, state := range states {
		if state.status != "success" {
			continue
		}
		for _, obligationID := range state.task.Obligations {
			satisfied[obligationID] = true
		}
	}
	for _, obligation := range c.Obligations {
		if obligation.Required && !satisfied[obligation.ID] {
			return fmt.Errorf("required obligation %q was not satisfied", obligation.ID)
		}
	}
	return nil
}

func dependenciesComplete(states map[string]*taskState, deps []string) bool {
	for _, dep := range deps {
		if states[dep].status != "success" {
			return false
		}
	}
	return true
}

func artifactIDs(artifacts []ArtifactRef) []string {
	if len(artifacts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		ids = append(ids, artifact.ArtifactID)
	}
	return ids
}

func writeJSON(filePath string, value any) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filePath, bytes, 0o644)
}

func fileDigest(filePath string) (string, error) {
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func absoluteDir(raw string, label string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%s dir is required", label)
	}
	absolute, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	return absolute, nil
}

func validateRunID(raw string) error {
	if raw == "" {
		return fmt.Errorf("run id is required")
	}
	if raw != strings.TrimSpace(raw) {
		return fmt.Errorf("run id %q contains surrounding whitespace", raw)
	}
	if raw != strings.ToLower(raw) {
		return fmt.Errorf("run id %q must be lowercase", raw)
	}
	if isReservedWindowsName(raw) {
		return fmt.Errorf("run id %q is reserved on Windows", raw)
	}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("run id %q contains invalid character %q", raw, r)
	}
	return nil
}

func isReservedWindowsName(id string) bool {
	switch id {
	case "con", "prn", "aux", "nul":
		return true
	}
	if len(id) == 4 && (strings.HasPrefix(id, "com") || strings.HasPrefix(id, "lpt")) {
		return id[3] >= '1' && id[3] <= '9'
	}
	return false
}

func safeJoin(base string, workspacePath string) (string, error) {
	normalized := slashClean(workspacePath)
	if normalized == "" || normalized == "." {
		return base, nil
	}
	if strings.HasPrefix(strings.ReplaceAll(workspacePath, "\\", "/"), "//") {
		return "", fmt.Errorf("path %q escapes workspace", workspacePath)
	}
	if path.IsAbs(normalized) || hasWindowsDrivePrefix(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("path %q escapes workspace", workspacePath)
	}
	return filepath.Join(base, filepath.FromSlash(normalized)), nil
}

func slashClean(raw string) string {
	return path.Clean(strings.ReplaceAll(raw, "\\", "/"))
}

func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 {
		return false
	}
	drive := p[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) && p[1] == ':'
}

type eventRecorder struct {
	writer       *bufio.Writer
	runID        string
	sequence     int
	previousHash string
}

func (r *eventRecorder) emit(eventType string, taskID string, status string, message string, artifactIDs []string) (Event, error) {
	r.sequence++
	event := Event{
		SchemaVersion:     EventSchemaVersion,
		EventID:           fmt.Sprintf("event-%06d", r.sequence),
		Sequence:          r.sequence,
		RunID:             r.runID,
		PreviousEventHash: r.previousHash,
		Type:              eventType,
		TaskID:            taskID,
		Status:            status,
		Message:           message,
		ArtifactIDs:       artifactIDs,
	}
	eventHash, err := EventContentHash(event)
	if err != nil {
		return Event{}, err
	}
	event.EventHash = eventHash
	if err := schema.ValidateValue(schema.EventSchemaID, event); err != nil {
		return Event{}, err
	}
	bytes, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if _, err := r.writer.Write(bytes); err != nil {
		return Event{}, err
	}
	if err := r.writer.WriteByte('\n'); err != nil {
		return Event{}, err
	}
	r.previousHash = event.EventHash
	return event, nil
}

func (r *eventRecorder) emitPolicyDecision(taskID string, status string, decision policy.Decision) (Event, error) {
	r.sequence++
	event := Event{
		SchemaVersion:     EventSchemaVersion,
		EventID:           fmt.Sprintf("event-%06d", r.sequence),
		Sequence:          r.sequence,
		RunID:             r.runID,
		PreviousEventHash: r.previousHash,
		Type:              "policy_decided",
		TaskID:            taskID,
		Status:            status,
		Message:           decision.Reason,
		DecisionID:        decision.DecisionID,
		Decision:          decision.Decision,
		EffectType:        decision.EffectType,
		Resource:          decision.Resource,
		ApprovalTicketID:  decision.ApprovalTicketID,
	}
	eventHash, err := EventContentHash(event)
	if err != nil {
		return Event{}, err
	}
	event.EventHash = eventHash
	if err := schema.ValidateValue(schema.EventSchemaID, event); err != nil {
		return Event{}, err
	}
	bytes, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if _, err := r.writer.Write(bytes); err != nil {
		return Event{}, err
	}
	if err := r.writer.WriteByte('\n'); err != nil {
		return Event{}, err
	}
	r.previousHash = event.EventHash
	return event, nil
}

func (r *eventRecorder) flush() error {
	return r.writer.Flush()
}

func EventContentHash(event Event) (string, error) {
	payload := eventHashPayload{
		SchemaVersion:     event.SchemaVersion,
		EventID:           event.EventID,
		Sequence:          event.Sequence,
		RunID:             event.RunID,
		PreviousEventHash: event.PreviousEventHash,
		Type:              event.Type,
		TaskID:            event.TaskID,
		Status:            event.Status,
		Message:           event.Message,
		ArtifactIDs:       event.ArtifactIDs,
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

type eventHashPayload struct {
	SchemaVersion     string   `json:"schema_version"`
	EventID           string   `json:"event_id"`
	Sequence          int      `json:"sequence"`
	RunID             string   `json:"run_id"`
	PreviousEventHash string   `json:"previous_event_hash"`
	Type              string   `json:"type"`
	TaskID            string   `json:"task_id,omitempty"`
	Status            string   `json:"status"`
	Message           string   `json:"message,omitempty"`
	ArtifactIDs       []string `json:"artifact_ids,omitempty"`
}
