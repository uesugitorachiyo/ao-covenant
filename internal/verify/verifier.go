package verify

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/run"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func Verify(opts Options) (Result, error) {
	ledger, err := readLedger(opts.LedgerPath)
	if err != nil {
		return Result{}, err
	}
	events := ledger.events
	if len(events) == 0 {
		return Result{}, fmt.Errorf("ledger has no events")
	}
	if err := verifyChain(events); err != nil {
		return Result{}, err
	}
	ledgerDigest, err := fileDigest(opts.LedgerPath)
	if err != nil {
		return Result{}, err
	}
	evidence, err := readEvidence(opts.EvidencePath)
	if err != nil {
		return Result{}, err
	}
	if evidence.LedgerDigest != ledgerDigest {
		return Result{}, fmt.Errorf("ledger digest mismatch: evidence %s != actual %s", evidence.LedgerDigest, ledgerDigest)
	}
	if evidence.RunID != events[0].RunID {
		return Result{}, fmt.Errorf("run id mismatch: evidence %s != ledger %s", evidence.RunID, events[0].RunID)
	}
	if err := verifyInputSnapshots(filepath.Dir(opts.EvidencePath), evidence.InputSnapshots); err != nil {
		return Result{}, err
	}
	workspaceDir, err := resolveWorkspaceDir(opts)
	if err != nil {
		return Result{}, err
	}
	if err := verifyArtifacts(workspaceDir, evidence.ArtifactManifest); err != nil {
		return Result{}, err
	}
	if err := verifyEvidenceProvenance(evidence, events); err != nil {
		return Result{}, err
	}
	if err := verifyRevokedApprovalTickets(evidence.PolicyDecisions, opts.RevokedApprovalTicketIDs); err != nil {
		return Result{}, err
	}
	failures, err := summarizeFailures(evidence.Failures, ledger.eventLines)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion:      ResultSchemaVersion,
		Verified:           true,
		RunID:              evidence.RunID,
		EventCount:         len(events),
		ArtifactCount:      len(evidence.ArtifactManifest),
		InputSnapshotCount: len(evidence.InputSnapshots),
		FailureCount:       len(evidence.Failures),
		Failures:           failures,
		PolicyExplanations: policy.ExplainDecisions(evidence.PolicyDecisions),
		LedgerDigest:       ledgerDigest,
		LastEventHash:      events[len(events)-1].EventHash,
	}, nil
}

func readLedger(path string) (ledgerData, error) {
	file, err := os.Open(path)
	if err != nil {
		return ledgerData{}, fmt.Errorf("open ledger: %w", err)
	}
	defer file.Close()

	var events []run.Event
	eventLines := map[string]int{}
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		if err := schema.ValidateBytes(schema.EventSchemaID, scanner.Bytes()); err != nil {
			return ledgerData{}, err
		}
		var event run.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return ledgerData{}, fmt.Errorf("decode ledger event: %w", err)
		}
		events = append(events, event)
		eventLines[event.EventID] = line
	}
	if err := scanner.Err(); err != nil {
		return ledgerData{}, fmt.Errorf("scan ledger: %w", err)
	}
	return ledgerData{events: events, eventLines: eventLines}, nil
}

func verifyChain(events []run.Event) error {
	previous := run.GenesisEventHash
	runID := events[0].RunID
	for _, event := range events {
		if event.RunID != runID {
			return fmt.Errorf("run id changed at event %s", event.EventID)
		}
		if event.PreviousEventHash != previous {
			return fmt.Errorf("previous hash mismatch at event %s", event.EventID)
		}
		recomputed, err := run.EventContentHash(event)
		if err != nil {
			return fmt.Errorf("hash event %s: %w", event.EventID, err)
		}
		if event.EventHash != recomputed {
			return fmt.Errorf("event hash mismatch at event %s", event.EventID)
		}
		previous = event.EventHash
	}
	return nil
}

func readEvidence(path string) (run.EvidencePack, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return run.EvidencePack{}, fmt.Errorf("read evidence: %w", err)
	}
	if err := schema.ValidateBytes(schema.EvidencePackSchemaID, bytes); err != nil {
		return run.EvidencePack{}, err
	}
	var evidence run.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		return run.EvidencePack{}, fmt.Errorf("decode evidence: %w", err)
	}
	return evidence, nil
}

func resolveWorkspaceDir(opts Options) (string, error) {
	if strings.TrimSpace(opts.WorkspaceDir) != "" {
		return absoluteDir(opts.WorkspaceDir, "workspace")
	}
	if inferred, ok := inferWorkspaceFromLedger(opts.LedgerPath); ok {
		return inferred, nil
	}
	return absoluteDir(".", "workspace")
}

func inferWorkspaceFromLedger(ledgerPath string) (string, bool) {
	absolute, err := filepath.Abs(ledgerPath)
	if err != nil {
		return "", false
	}
	cleaned := filepath.Clean(absolute)
	if filepath.Base(cleaned) != "events.ndjson" {
		return "", false
	}
	runDir := filepath.Dir(cleaned)
	runsDir := filepath.Dir(runDir)
	covenantDir := filepath.Dir(runsDir)
	if filepath.Base(runsDir) != "runs" || filepath.Base(covenantDir) != ".covenant" {
		return "", false
	}
	return filepath.Dir(covenantDir), true
}

func verifyArtifacts(workspaceDir string, artifacts []run.ArtifactRef) error {
	for _, artifact := range artifacts {
		expectedURI := "covenant-artifact://sha256/" + artifact.Digest
		if artifact.URI != expectedURI {
			return fmt.Errorf("artifact %s URI %q does not match digest %q", artifact.ArtifactID, artifact.URI, artifact.Digest)
		}
		target, err := workspaceArtifactPath(workspaceDir, artifact.Path)
		if err != nil {
			return fmt.Errorf("artifact %s path %q: %w", artifact.ArtifactID, artifact.Path, err)
		}
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("artifact %s path %q: %w", artifact.ArtifactID, artifact.Path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("artifact %s path %q is a directory", artifact.ArtifactID, artifact.Path)
		}
		actualDigest, err := fileDigest(target)
		if err != nil {
			return fmt.Errorf("artifact %s path %q: %w", artifact.ArtifactID, artifact.Path, err)
		}
		if actualDigest != artifact.Digest {
			return fmt.Errorf("artifact digest mismatch for %s path %q: evidence %s != actual %s", artifact.ArtifactID, artifact.Path, artifact.Digest, actualDigest)
		}
	}
	return nil
}

func verifyInputSnapshots(runDir string, snapshots []run.InputSnapshot) error {
	for _, snapshot := range snapshots {
		target, err := inputSnapshotPath(runDir, snapshot.SnapshotPath)
		if err != nil {
			return fmt.Errorf("input snapshot %s path %q: %w", snapshot.SnapshotID, snapshot.SnapshotPath, err)
		}
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("input snapshot %s path %q: %w", snapshot.SnapshotID, snapshot.SnapshotPath, err)
		}
		if info.IsDir() {
			return fmt.Errorf("input snapshot %s path %q is a directory", snapshot.SnapshotID, snapshot.SnapshotPath)
		}
		actualDigest, err := fileDigest(target)
		if err != nil {
			return fmt.Errorf("input snapshot %s path %q: %w", snapshot.SnapshotID, snapshot.SnapshotPath, err)
		}
		if actualDigest != snapshot.Digest {
			return fmt.Errorf("input snapshot digest mismatch for %s path %q: evidence %s != actual %s", snapshot.SnapshotID, snapshot.SnapshotPath, snapshot.Digest, actualDigest)
		}
	}
	return nil
}

func verifyEvidenceProvenance(evidence run.EvidencePack, events []run.Event) error {
	eventByID := eventMap(events)
	artifactByID := artifactMap(evidence.ArtifactManifest)
	policyByID := policyDecisionMap(evidence.PolicyDecisions)
	policyEvents := policyEventIndex(events)

	for _, decision := range evidence.PolicyDecisions {
		if !policyEvents.consume(decision) {
			return fmt.Errorf("policy decision %s missing matching ledger policy_decided event", decision.DecisionID)
		}
	}

	for _, artifact := range evidence.ArtifactManifest {
		event, ok := eventByID[artifact.ProducerEventID]
		if !ok {
			return fmt.Errorf("artifact %s references missing producer event %s", artifact.ArtifactID, artifact.ProducerEventID)
		}
		if event.Type != "artifact_recorded" {
			return fmt.Errorf("artifact %s producer event %s has type %s, want artifact_recorded", artifact.ArtifactID, artifact.ProducerEventID, event.Type)
		}
		if !containsString(event.ArtifactIDs, artifact.ArtifactID) {
			return fmt.Errorf("artifact %s producer event %s does not include artifact %s", artifact.ArtifactID, artifact.ProducerEventID, artifact.ArtifactID)
		}
	}

	for _, row := range evidence.ClosureMatrix.Rows {
		taskIDs := stringSet(row.TaskIDs)
		for _, artifactID := range row.ArtifactIDs {
			artifact, ok := artifactByID[artifactID]
			if !ok {
				return fmt.Errorf("closure row %s references missing artifact %s", row.ObligationID, artifactID)
			}
			event, ok := eventByID[artifact.ProducerEventID]
			if !ok {
				return fmt.Errorf("closure row %s artifact %s references missing producer event %s", row.ObligationID, artifactID, artifact.ProducerEventID)
			}
			if !taskIDs[event.TaskID] {
				return fmt.Errorf("closure row %s artifact %s was produced by task %s not claimed by closure row", row.ObligationID, artifactID, event.TaskID)
			}
		}
		for _, artifact := range evidence.ArtifactManifest {
			event, ok := eventByID[artifact.ProducerEventID]
			if !ok {
				continue
			}
			if taskIDs[event.TaskID] && !containsString(row.ArtifactIDs, artifact.ArtifactID) {
				return fmt.Errorf("closure row %s missing artifact %s for claimed task %s", row.ObligationID, artifact.ArtifactID, event.TaskID)
			}
		}
		for _, decisionID := range row.PolicyDecisionIDs {
			decision, ok := policyByID[decisionID]
			if !ok {
				return fmt.Errorf("closure row %s references missing policy decision %s", row.ObligationID, decisionID)
			}
			if !taskIDs[decision.TaskID] {
				return fmt.Errorf("closure row %s policy decision %s belongs to task %s not claimed by closure row", row.ObligationID, decisionID, decision.TaskID)
			}
		}
		for _, decision := range evidence.PolicyDecisions {
			if taskIDs[decision.TaskID] && !containsString(row.PolicyDecisionIDs, decision.DecisionID) {
				return fmt.Errorf("closure row %s missing policy decision %s for claimed task %s", row.ObligationID, decision.DecisionID, decision.TaskID)
			}
		}
	}
	return nil
}

type policyEventsByKey struct {
	byDecisionID map[string]int
	legacy       map[string]int
}

func policyEventIndex(events []run.Event) policyEventsByKey {
	index := policyEventsByKey{
		byDecisionID: map[string]int{},
		legacy:       map[string]int{},
	}
	for _, event := range events {
		if event.Type != "policy_decided" {
			continue
		}
		if event.DecisionID != "" {
			index.byDecisionID[event.DecisionID]++
			continue
		}
		index.legacy[policyEventKey(event.TaskID, event.Status, event.Message)]++
	}
	return index
}

func (index policyEventsByKey) consume(decision policy.Decision) bool {
	if index.byDecisionID[decision.DecisionID] > 0 {
		index.byDecisionID[decision.DecisionID]--
		return true
	}
	key := policyEventKey(decision.TaskID, policyEventStatus(decision.Decision), decision.Reason)
	if index.legacy[key] == 0 {
		return false
	}
	index.legacy[key]--
	return true
}

func policyEventKey(taskID string, status string, reason string) string {
	return taskID + "\x00" + status + "\x00" + reason
}

func policyEventStatus(decision string) string {
	switch decision {
	case policy.DecisionDeny:
		return "failed"
	default:
		return "success"
	}
}

func verifyRevokedApprovalTickets(decisions []policy.Decision, revoked map[string]bool) error {
	if len(revoked) == 0 {
		return nil
	}
	for _, decision := range decisions {
		if decision.ApprovalTicketID != "" && revoked[decision.ApprovalTicketID] {
			return fmt.Errorf("policy decision %s references revoked approval ticket %q", decision.DecisionID, decision.ApprovalTicketID)
		}
	}
	return nil
}

func eventMap(events []run.Event) map[string]run.Event {
	byID := make(map[string]run.Event, len(events))
	for _, event := range events {
		byID[event.EventID] = event
	}
	return byID
}

func artifactMap(artifacts []run.ArtifactRef) map[string]run.ArtifactRef {
	byID := make(map[string]run.ArtifactRef, len(artifacts))
	for _, artifact := range artifacts {
		byID[artifact.ArtifactID] = artifact
	}
	return byID
}

func policyDecisionMap(decisions []policy.Decision) map[string]policy.Decision {
	byID := make(map[string]policy.Decision, len(decisions))
	for _, decision := range decisions {
		byID[decision.DecisionID] = decision
	}
	return byID
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func inputSnapshotPath(runDir string, snapshotPath string) (string, error) {
	normalized := slashClean(snapshotPath)
	if normalized == "" || normalized == "." {
		return "", fmt.Errorf("snapshot path is required")
	}
	if strings.HasPrefix(strings.ReplaceAll(snapshotPath, "\\", "/"), "//") {
		return "", fmt.Errorf("escapes run directory")
	}
	if path.IsAbs(normalized) || hasWindowsDrivePrefix(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("escapes run directory")
	}
	if normalized != "input-snapshots" && !strings.HasPrefix(normalized, "input-snapshots/") {
		return "", fmt.Errorf("must be under input-snapshots")
	}
	return filepath.Join(runDir, filepath.FromSlash(normalized)), nil
}

func workspaceArtifactPath(workspaceDir string, artifactPath string) (string, error) {
	normalized := slashClean(artifactPath)
	if normalized == "" || normalized == "." {
		return "", fmt.Errorf("artifact path is required")
	}
	if strings.HasPrefix(strings.ReplaceAll(artifactPath, "\\", "/"), "//") {
		return "", fmt.Errorf("escapes workspace")
	}
	if path.IsAbs(normalized) || hasWindowsDrivePrefix(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("escapes workspace")
	}
	return filepath.Join(workspaceDir, filepath.FromSlash(normalized)), nil
}

func summarizeFailures(records []run.FailureRecord, eventLines map[string]int) ([]FailureSummary, error) {
	summaries := make([]FailureSummary, 0, len(records))
	for _, record := range records {
		line, ok := eventLines[record.EventID]
		if !ok {
			return nil, fmt.Errorf("failure %s references missing ledger event %s", record.FailureID, record.EventID)
		}
		summaries = append(summaries, FailureSummary{
			FailureID: record.FailureID,
			EventID:   record.EventID,
			EventLine: line,
			TaskID:    record.TaskID,
			Phase:     record.Phase,
			Reason:    record.Reason,
		})
	}
	return summaries, nil
}

type ledgerData struct {
	events     []run.Event
	eventLines map[string]int
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

func fileDigest(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
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
