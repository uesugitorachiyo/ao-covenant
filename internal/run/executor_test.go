package run

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/closure"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestExecuteWritesLedgerEvidencePackAndWorkspaceOutput(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")

	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	expectedDigest, err := contract.Digest(c)
	if err != nil {
		t.Fatalf("Digest error: %v", err)
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-test",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	reportPath := filepath.Join(workspace, "demo-output", "report.txt")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if len(reportBytes) == 0 {
		t.Fatalf("report is empty")
	}

	events := readEvents(t, result.LedgerPath)
	assertEventHashChain(t, events)
	for _, event := range events {
		if err := schema.ValidateValue(schema.EventSchemaID, event); err != nil {
			t.Fatalf("event %s schema validation: %v", event.EventID, err)
		}
	}
	eventTypes := make([]string, 0, len(events))
	for _, event := range events {
		eventTypes = append(eventTypes, event.Type)
	}
	for _, want := range []string{"run_started", "task_started", "artifact_recorded", "task_finished", "run_finished"} {
		if !slices.Contains(eventTypes, want) {
			t.Fatalf("event types = %v, want %q", eventTypes, want)
		}
	}

	evidenceBytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence pack: %v", err)
	}
	var evidence EvidencePack
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("decode evidence pack: %v", err)
	}
	if err := schema.ValidateValue(schema.EvidencePackSchemaID, evidence); err != nil {
		t.Fatalf("evidence schema validation: %v", err)
	}
	if evidence.RunStatus != "success" {
		t.Fatalf("run_status = %q, want success", evidence.RunStatus)
	}
	if evidence.ContractDigest != expectedDigest {
		t.Fatalf("contract_digest = %q, want %q", evidence.ContractDigest, expectedDigest)
	}
	ledgerDigest, err := fileDigest(result.LedgerPath)
	if err != nil {
		t.Fatalf("ledger digest: %v", err)
	}
	if evidence.LedgerDigest != ledgerDigest {
		t.Fatalf("ledger_digest = %q, want %q", evidence.LedgerDigest, ledgerDigest)
	}
	if len(evidence.ArtifactManifest) == 0 {
		t.Fatalf("artifact manifest is empty")
	}
	if evidence.ArtifactManifest[0].Path != "demo-output/report.txt" {
		t.Fatalf("first artifact path = %q, want demo-output/report.txt", evidence.ArtifactManifest[0].Path)
	}
	if evidence.ClosureMatrix.Status != "accepted" {
		t.Fatalf("closure status = %q, want accepted", evidence.ClosureMatrix.Status)
	}
	if len(evidence.Failures) != 0 {
		t.Fatalf("failures = %+v, want empty", evidence.Failures)
	}
	for _, row := range evidence.ClosureMatrix.Rows {
		if row.Required && row.Status != "closed" {
			t.Fatalf("required closure row = %+v, want closed", row)
		}
	}
	requestedFileRow := findClosureRow(t, evidence, "obl_requested_file")
	if len(requestedFileRow.ArtifactIDs) != 1 {
		t.Fatalf("requested file artifact ids = %v, want one artifact", requestedFileRow.ArtifactIDs)
	}
	if len(requestedFileRow.PolicyDecisionIDs) != 1 {
		t.Fatalf("requested file policy decision ids = %v, want one decision", requestedFileRow.PolicyDecisionIDs)
	}
}

func TestExecuteSnapshotsDeclaredReadsIntoRunEvidence(t *testing.T) {
	workspace := t.TempDir()
	briefPath := filepath.Join(workspace, "examples", "risky-change", "brief.md")
	mustWrite(t, briefPath, "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-input-snapshot",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if len(result.EvidencePack.InputSnapshots) != 1 {
		t.Fatalf("input snapshots len = %d, want 1", len(result.EvidencePack.InputSnapshots))
	}
	snapshot := result.EvidencePack.InputSnapshots[0]
	if snapshot.SchemaVersion != InputSnapshotSchemaVersion {
		t.Fatalf("schema version = %q, want %q", snapshot.SchemaVersion, InputSnapshotSchemaVersion)
	}
	if snapshot.SnapshotID != "input-000001" {
		t.Fatalf("snapshot id = %q, want input-000001", snapshot.SnapshotID)
	}
	if snapshot.SourcePath != "examples/risky-change/brief.md" {
		t.Fatalf("source path = %q, want examples/risky-change/brief.md", snapshot.SourcePath)
	}
	if snapshot.SnapshotPath != "input-snapshots/examples/risky-change/brief.md" {
		t.Fatalf("snapshot path = %q", snapshot.SnapshotPath)
	}
	snapshotBytes, err := os.ReadFile(filepath.Join(result.RunDir, snapshot.SnapshotPath))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if string(snapshotBytes) != "Create a demo report." {
		t.Fatalf("snapshot = %q", string(snapshotBytes))
	}
	expectedDigest, err := fileDigest(briefPath)
	if err != nil {
		t.Fatalf("brief digest: %v", err)
	}
	if snapshot.Digest != expectedDigest {
		t.Fatalf("snapshot digest = %q, want %q", snapshot.Digest, expectedDigest)
	}
	if snapshot.MediaType != "text/markdown" {
		t.Fatalf("media type = %q, want text/markdown", snapshot.MediaType)
	}
}

func TestExecuteRecordsPolicyDecisionsInEvidence(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-policy",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if len(result.EvidencePack.PolicyDecisions) != 1 {
		t.Fatalf("policy decisions len = %d, want 1", len(result.EvidencePack.PolicyDecisions))
	}
	if result.EvidencePack.PolicyDecisions[0].Decision != policy.DecisionAllow {
		t.Fatalf("policy decision = %q, want allow", result.EvidencePack.PolicyDecisions[0].Decision)
	}
	if len(result.EvidencePack.Failures) != 0 {
		t.Fatalf("failures = %+v, want empty", result.EvidencePack.Failures)
	}
	events := readEvents(t, result.LedgerPath)
	eventTypes := make([]string, 0, len(events))
	for _, event := range events {
		eventTypes = append(eventTypes, event.Type)
	}
	if !slices.Contains(eventTypes, "policy_decided") {
		t.Fatalf("event types = %v, want policy_decided", eventTypes)
	}
	policyEvent := findEventByType(t, events, "policy_decided")
	decision := result.EvidencePack.PolicyDecisions[0]
	if policyEvent.DecisionID != decision.DecisionID {
		t.Fatalf("policy event decision id = %q, want %q", policyEvent.DecisionID, decision.DecisionID)
	}
	if policyEvent.Decision != decision.Decision || policyEvent.EffectType != decision.EffectType || policyEvent.Resource != decision.Resource {
		t.Fatalf("policy event = %+v, want decision/effect/resource from %+v", policyEvent, decision)
	}
	if policyEvent.TaskID != decision.TaskID || policyEvent.Message != decision.Reason {
		t.Fatalf("policy event = %+v, want task/reason from %+v", policyEvent, decision)
	}
	if policyEvent.DecisionID == "" || policyEvent.Decision == "" || policyEvent.EffectType == "" || policyEvent.Resource == "" {
		t.Fatalf("policy event missing strict policy metadata: %+v", policyEvent)
	}
}

func TestEventContentHashBindsPolicyDecisionFields(t *testing.T) {
	base := Event{
		SchemaVersion:     EventSchemaVersion,
		EventID:           "event-000001",
		Sequence:          1,
		RunID:             "run-policy-hash",
		PreviousEventHash: GenesisEventHash,
		Type:              "policy_decided",
		TaskID:            "scripted_change",
		Status:            "allowed",
		Message:           "allowed file.write on demo-output/report.txt",
		DecisionID:        "policy-scripted_change-1",
		Decision:          policy.DecisionAllow,
		EffectType:        "file.write",
		Resource:          "demo-output/report.txt",
		ApprovalTicketID:  "approve-file-write",
	}
	baseHash, err := EventContentHash(base)
	if err != nil {
		t.Fatal(err)
	}
	variants := map[string]Event{
		"decision id": {
			DecisionID: "policy-scripted_change-2",
		},
		"decision": {
			Decision: policy.DecisionDeny,
		},
		"effect type": {
			EffectType: "process.spawn",
		},
		"resource": {
			Resource: "demo-output/other.txt",
		},
		"approval ticket id": {
			ApprovalTicketID: "approve-other-ticket",
		},
	}
	for name, overlay := range variants {
		changed := base
		if overlay.DecisionID != "" {
			changed.DecisionID = overlay.DecisionID
		}
		if overlay.Decision != "" {
			changed.Decision = overlay.Decision
		}
		if overlay.EffectType != "" {
			changed.EffectType = overlay.EffectType
		}
		if overlay.Resource != "" {
			changed.Resource = overlay.Resource
		}
		if overlay.ApprovalTicketID != "" {
			changed.ApprovalTicketID = overlay.ApprovalTicketID
		}
		changedHash, err := EventContentHash(changed)
		if err != nil {
			t.Fatal(err)
		}
		if changedHash == baseHash {
			t.Fatalf("%s change did not alter event content hash %s", name, baseHash)
		}
	}
}

func TestEventContentHashBindsPolicyDecisionFieldsFromFixture(t *testing.T) {
	var fixture struct {
		Schema    string `json:"schema"`
		Status    string `json:"status"`
		BaseEvent Event  `json:"base_event"`
		Variants  []struct {
			Name           string `json:"name"`
			Override       Event  `json:"override"`
			MustChangeHash bool   `json:"must_change_hash"`
		} `json:"variants"`
	}
	bytes, err := os.ReadFile(filepath.Join("testdata", "policy_event_hash_fields.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "covenant.test.policy-event-hash-fields.v1" || fixture.Status != "ready" || len(fixture.Variants) == 0 {
		t.Fatalf("bad policy hash fixture metadata: %+v", fixture)
	}
	baseHash, err := EventContentHash(fixture.BaseEvent)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range fixture.Variants {
		changed := overlayPolicyHashEvent(fixture.BaseEvent, variant.Override)
		changedHash, err := EventContentHash(changed)
		if err != nil {
			t.Fatal(err)
		}
		if variant.MustChangeHash && changedHash == baseHash {
			t.Fatalf("fixture variant %q did not alter event content hash %s", variant.Name, baseHash)
		}
	}
}

func overlayPolicyHashEvent(base Event, override Event) Event {
	if override.DecisionID != "" {
		base.DecisionID = override.DecisionID
	}
	if override.Decision != "" {
		base.Decision = override.Decision
	}
	if override.EffectType != "" {
		base.EffectType = override.EffectType
	}
	if override.Resource != "" {
		base.Resource = override.Resource
	}
	if override.ApprovalTicketID != "" {
		base.ApprovalTicketID = override.ApprovalTicketID
	}
	return base
}

func TestExecuteUsesActionAdapterForFileWrite(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	adapter := &recordingActionAdapter{delegate: defaultActionAdapter{}}

	_, err = Execute(context.Background(), c, Options{
		WorkspaceDir:  workspace,
		OutDir:        filepath.Join(workspace, ".covenant", "runs"),
		RunID:         "run-adapter",
		ActionAdapter: adapter,
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	if len(adapter.requests) != 1 {
		t.Fatalf("adapter calls = %d, want 1", len(adapter.requests))
	}
	request := adapter.requests[0]
	if request.Task.ID != "scripted_change" {
		t.Fatalf("adapter task = %q, want scripted_change", request.Task.ID)
	}
	if request.Action.Type != "file.write" || request.Action.Resource != "demo-output/report.txt" {
		t.Fatalf("adapter action = %+v, want demo output file.write", request.Action)
	}
}

func TestExecuteRecordsDeclaredFileReadArtifact(t *testing.T) {
	workspace := t.TempDir()
	briefPath := filepath.Join(workspace, "examples", "risky-change", "brief.md")
	mustWrite(t, briefPath, "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = append([]contract.ActionRef{
		{Type: "file.read", Resource: "examples/risky-change/brief.md"},
	}, c.Tasks[0].DeclaredSideEffects...)

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-read-artifact",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if result.EvidencePack.RunStatus != "success" {
		t.Fatalf("run status = %q, want success", result.EvidencePack.RunStatus)
	}
	if len(result.EvidencePack.PolicyDecisions) != 2 {
		t.Fatalf("policy decisions len = %d, want 2", len(result.EvidencePack.PolicyDecisions))
	}
	readArtifact, ok := findArtifactByPath(result.EvidencePack, "examples/risky-change/brief.md")
	if !ok {
		t.Fatalf("read artifact not found in %+v", result.EvidencePack.ArtifactManifest)
	}
	if readArtifact.ArtifactID != "scripted_change-read-1" {
		t.Fatalf("read artifact id = %q, want scripted_change-read-1", readArtifact.ArtifactID)
	}
	expectedDigest, err := fileDigest(briefPath)
	if err != nil {
		t.Fatalf("brief digest: %v", err)
	}
	if readArtifact.Digest != expectedDigest {
		t.Fatalf("read digest = %q, want %q", readArtifact.Digest, expectedDigest)
	}
	events := readEvents(t, result.LedgerPath)
	foundReadEvent := false
	for _, event := range events {
		if event.Type == "artifact_recorded" && slices.Contains(event.ArtifactIDs, "scripted_change-read-1") {
			foundReadEvent = true
		}
	}
	if !foundReadEvent {
		t.Fatalf("ledger events did not record read artifact: %+v", events)
	}
}

func TestExecuteDoesNotCallAdapterWhenPolicyDenies(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "network.request", Resource: "api.example.test"},
	}
	adapter := &recordingActionAdapter{err: nil}

	_, err = Execute(context.Background(), c, Options{
		WorkspaceDir:  workspace,
		OutDir:        filepath.Join(workspace, ".covenant", "runs"),
		RunID:         "run-policy-before-adapter",
		ActionAdapter: adapter,
	})

	if err == nil {
		t.Fatalf("Execute error = nil, want policy denial")
	}
	if len(adapter.requests) != 0 {
		t.Fatalf("adapter calls = %d, want 0", len(adapter.requests))
	}
}

func TestExecuteFailsClosedForApprovedProcessEffect(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: "make-test"},
	}
	c.Workspace.Writes = []string{}
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "approve-process",
			TaskID:        "scripted_change",
			EffectType:    "process.spawn",
			Resource:      "make-test",
			Approved:      true,
			Reason:        "exercise fail-closed default process adapter",
		},
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-approved-process",
	})

	if err == nil {
		t.Fatalf("Execute error = nil, want default adapter failure")
	}
	if !strings.Contains(err.Error(), "process.spawn resource \"make-test\" is not allowlisted") {
		t.Fatalf("Execute error = %v, want process allowlist failure", err)
	}
	if result.EvidencePack.RunStatus != "failed" {
		t.Fatalf("run status = %q, want failed", result.EvidencePack.RunStatus)
	}
	if len(result.EvidencePack.PolicyDecisions) != 1 {
		t.Fatalf("policy decisions len = %d, want 1", len(result.EvidencePack.PolicyDecisions))
	}
	if result.EvidencePack.PolicyDecisions[0].Decision != policy.DecisionAllow {
		t.Fatalf("policy decision = %q, want allow", result.EvidencePack.PolicyDecisions[0].Decision)
	}
	if result.EvidencePack.PolicyDecisions[0].ApprovalTicketID != "approve-process" {
		t.Fatalf("approval ticket = %q, want approve-process", result.EvidencePack.PolicyDecisions[0].ApprovalTicketID)
	}
	assertSingleFailure(t, result.EvidencePack, FailurePhaseAdapter, "scripted_change", "not allowlisted")
	if _, statErr := os.Stat(result.EvidencePackPath); statErr != nil {
		t.Fatalf("evidence pack stat error = %v", statErr)
	}
}

func TestExecuteRunsApprovedAllowlistedProcessEffect(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: "go version"},
	}
	c.Workspace.Writes = []string{}
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "approve-process",
			TaskID:        "scripted_change",
			EffectType:    "process.spawn",
			Resource:      "go version",
			Approved:      true,
			Reason:        "operator approved go version",
		},
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir:     workspace,
		OutDir:           filepath.Join(workspace, ".covenant", "runs"),
		RunID:            "run-allowed-process",
		ProcessAllowlist: []string{"go version"},
	})

	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if result.EvidencePack.RunStatus != "success" {
		t.Fatalf("run status = %q, want success", result.EvidencePack.RunStatus)
	}
	if len(result.EvidencePack.Failures) != 0 {
		t.Fatalf("failures = %+v, want empty", result.EvidencePack.Failures)
	}
	requestedFileRow := findClosureRow(t, result.EvidencePack, "obl_requested_file")
	if len(requestedFileRow.ArtifactIDs) != 2 {
		t.Fatalf("requested file artifact ids = %v, want stdout and stderr artifacts", requestedFileRow.ArtifactIDs)
	}
	stdoutPath := filepath.Join(workspace, ".covenant", "process", "scripted_change-process-1-stdout.txt")
	stdoutBytes, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatalf("read stdout artifact: %v", err)
	}
	if !strings.Contains(string(stdoutBytes), "go version") {
		t.Fatalf("stdout artifact = %q, want go version", string(stdoutBytes))
	}
}

func TestExecuteDeniesRevokedApprovalTicket(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: "go version"},
	}
	c.Workspace.Writes = []string{}
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "approve-process",
			TaskID:        "scripted_change",
			EffectType:    "process.spawn",
			Resource:      "go version",
			Approved:      true,
			Reason:        "operator approved go version",
		},
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir:             workspace,
		OutDir:                   filepath.Join(workspace, ".covenant", "runs"),
		RunID:                    "run-revoked-process",
		ProcessAllowlist:         []string{"go version"},
		RevokedApprovalTicketIDs: map[string]bool{"approve-process": true},
	})

	if err == nil {
		t.Fatalf("Execute error = nil, want revoked approval denial")
	}
	if !strings.Contains(err.Error(), `approval ticket "approve-process" is revoked`) {
		t.Fatalf("Execute error = %v, want revoked approval", err)
	}
	if result.EvidencePack.RunStatus != "failed" {
		t.Fatalf("run status = %q, want failed", result.EvidencePack.RunStatus)
	}
	if len(result.EvidencePack.PolicyDecisions) != 1 {
		t.Fatalf("policy decisions len = %d, want 1", len(result.EvidencePack.PolicyDecisions))
	}
	decision := result.EvidencePack.PolicyDecisions[0]
	if decision.Decision != policy.DecisionDeny || decision.ApprovalTicketID != "approve-process" {
		t.Fatalf("policy decision = %+v, want denied revoked approval", decision)
	}
	assertSingleFailure(t, result.EvidencePack, FailurePhasePolicy, "scripted_change", "revoked")
}

func TestExecuteDeniesNetworkSideEffectBeforeTaskOutput(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "network.request", Resource: "api.example.test"},
		{Type: "file.write", Resource: "demo-output/report.txt"},
	}

	result, err := Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-denied",
	})
	if err == nil {
		t.Fatalf("Execute error = nil, want policy denial")
	}
	if result.EvidencePack.RunStatus != "failed" {
		t.Fatalf("run status = %q, want failed", result.EvidencePack.RunStatus)
	}
	if result.EvidencePack.ClosureMatrix.Status != "rejected" {
		t.Fatalf("closure status = %q, want rejected", result.EvidencePack.ClosureMatrix.Status)
	}
	if len(result.EvidencePack.PolicyDecisions) == 0 {
		t.Fatalf("policy decisions is empty")
	}
	if result.EvidencePack.PolicyDecisions[0].Decision != policy.DecisionDeny {
		t.Fatalf("first policy decision = %q, want deny", result.EvidencePack.PolicyDecisions[0].Decision)
	}
	assertSingleFailure(t, result.EvidencePack, FailurePhasePolicy, "scripted_change", "policy denied task")
	if _, statErr := os.Stat(filepath.Join(workspace, "demo-output", "report.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("report stat error = %v, want file not to exist", statErr)
	}
	if _, statErr := os.Stat(result.EvidencePackPath); statErr != nil {
		t.Fatalf("evidence pack stat error = %v", statErr)
	}
}

func TestExecuteRejectsMissingReadBeforeSideEffects(t *testing.T) {
	workspace := t.TempDir()
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}

	_, err = Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "run-missing-read",
	})
	if err == nil {
		t.Fatalf("Execute error = nil, want missing read failure")
	}
	if _, statErr := os.Stat(filepath.Join(workspace, "demo-output", "report.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("report stat error = %v, want file not to exist", statErr)
	}
}

func TestExecuteRejectsSchemaInvalidContractBeforeRunDirectory(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DependsOn = nil
	outDir := filepath.Join(workspace, ".covenant", "runs")

	_, err = Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       outDir,
		RunID:        "run-schema-invalid",
	})

	if err == nil {
		t.Fatalf("Execute error = nil, want schema validation failure")
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("Execute error = %v, want schema validation failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "run-schema-invalid")); !os.IsNotExist(statErr) {
		t.Fatalf("run dir stat error = %v, want directory not to exist", statErr)
	}
}

func TestExecuteRejectsEscapingRunID(t *testing.T) {
	workspace := t.TempDir()
	mustWrite(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}

	_, err = Execute(context.Background(), c, Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "../escape",
	})
	if err == nil {
		t.Fatalf("Execute error = nil, want run id rejection")
	}
	if _, statErr := os.Stat(filepath.Join(workspace, ".covenant", "escape")); !os.IsNotExist(statErr) {
		t.Fatalf("escaped run dir stat error = %v, want file not to exist", statErr)
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

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode ledger event: %v", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan ledger: %v", err)
	}
	return events
}

func findEventByType(t *testing.T, events []Event, eventType string) Event {
	t.Helper()
	for _, event := range events {
		if event.Type == eventType {
			return event
		}
	}
	t.Fatalf("event type %s not found", eventType)
	return Event{}
}

func assertEventHashChain(t *testing.T, events []Event) {
	t.Helper()
	if len(events) == 0 {
		t.Fatalf("events is empty")
	}
	previous := GenesisEventHash
	for _, event := range events {
		if event.PreviousEventHash != previous {
			t.Fatalf("event %s previous hash = %q, want %q", event.EventID, event.PreviousEventHash, previous)
		}
		recomputed, err := EventContentHash(event)
		if err != nil {
			t.Fatalf("recompute event hash: %v", err)
		}
		if event.EventHash != recomputed {
			t.Fatalf("event %s hash = %q, want %q", event.EventID, event.EventHash, recomputed)
		}
		previous = event.EventHash
	}
}

func findClosureRow(t *testing.T, evidence EvidencePack, obligationID string) closure.Row {
	t.Helper()
	for _, row := range evidence.ClosureMatrix.Rows {
		if row.ObligationID == obligationID {
			return row
		}
	}
	t.Fatalf("closure row %q not found in %+v", obligationID, evidence.ClosureMatrix.Rows)
	return closure.Row{}
}

func findArtifactByPath(evidence EvidencePack, path string) (ArtifactRef, bool) {
	for _, artifact := range evidence.ArtifactManifest {
		if artifact.Path == path {
			return artifact, true
		}
	}
	return ArtifactRef{}, false
}

func assertSingleFailure(t *testing.T, evidence EvidencePack, phase string, taskID string, reasonContains string) {
	t.Helper()
	if len(evidence.Failures) != 1 {
		t.Fatalf("failures len = %d, want 1: %+v", len(evidence.Failures), evidence.Failures)
	}
	failure := evidence.Failures[0]
	if failure.SchemaVersion != FailureSchemaVersion {
		t.Fatalf("failure schema version = %q, want %q", failure.SchemaVersion, FailureSchemaVersion)
	}
	if failure.FailureID != "failure-000001" {
		t.Fatalf("failure id = %q, want failure-000001", failure.FailureID)
	}
	if !strings.HasPrefix(failure.EventID, "event-") {
		t.Fatalf("failure event id = %q, want event id", failure.EventID)
	}
	if failure.TaskID != taskID {
		t.Fatalf("failure task id = %q, want %q", failure.TaskID, taskID)
	}
	if failure.Phase != phase {
		t.Fatalf("failure phase = %q, want %q", failure.Phase, phase)
	}
	if !strings.Contains(failure.Reason, reasonContains) {
		t.Fatalf("failure reason = %q, want containing %q", failure.Reason, reasonContains)
	}
}

type recordingActionAdapter struct {
	requests []ActionRequest
	delegate ActionAdapter
	result   ActionResult
	err      error
}

func (a *recordingActionAdapter) ExecuteAction(ctx context.Context, req ActionRequest) (ActionResult, error) {
	a.requests = append(a.requests, req)
	if a.delegate != nil {
		return a.delegate.ExecuteAction(ctx, req)
	}
	return a.result, a.err
}
