package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/run"
)

func TestVerifyAcceptsGeneratedRun(t *testing.T) {
	result := generateRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !verification.Verified {
		t.Fatalf("verified = false, want true")
	}
	if verification.RunID != "verify-test" {
		t.Fatalf("run id = %q, want verify-test", verification.RunID)
	}
	if verification.EventCount == 0 {
		t.Fatalf("event count is zero")
	}
	if verification.LedgerDigest != result.EvidencePack.LedgerDigest {
		t.Fatalf("ledger digest = %q, want %q", verification.LedgerDigest, result.EvidencePack.LedgerDigest)
	}
	if verification.FailureCount != 0 {
		t.Fatalf("failure count = %d, want 0", verification.FailureCount)
	}
}

func TestVerifyRejectsRevokedApprovalTicketEvidence(t *testing.T) {
	result := generateApprovedProcessRun(t)

	_, err := Verify(Options{
		LedgerPath:               result.LedgerPath,
		EvidencePath:             result.EvidencePackPath,
		RevokedApprovalTicketIDs: map[string]bool{"approve-process": true},
	})

	if err == nil || !strings.Contains(err.Error(), `policy decision policy-scripted_change-1 references revoked approval ticket "approve-process"`) {
		t.Fatalf("Verify error = %v, want revoked approval ticket", err)
	}
}

func TestVerifyRejectsPolicyEventDecisionIDMismatch(t *testing.T) {
	result := generateRun(t)
	events := readLedgerEventsForTest(t, result.LedgerPath)
	for i := range events {
		if events[i].Type == "policy_decided" {
			events[i].DecisionID = "policy-other_task-1"
			break
		}
	}
	ledgerBytes := encodeLedgerEventsForTest(t, events)
	if err := os.WriteFile(result.LedgerPath, ledgerBytes, 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	evidence := readEvidenceForTest(t, result)
	sum := sha256.Sum256(ledgerBytes)
	evidence.LedgerDigest = hex.EncodeToString(sum[:])
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})

	if err == nil || !strings.Contains(err.Error(), "policy decision policy-scripted_change-1 missing matching ledger policy_decided event") {
		t.Fatalf("Verify error = %v, want missing matching policy event", err)
	}
}

func TestVerifyReportsArtifactCount(t *testing.T) {
	result := generateRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if verification.ArtifactCount != len(result.EvidencePack.ArtifactManifest) {
		t.Fatalf("artifact count = %d, want %d", verification.ArtifactCount, len(result.EvidencePack.ArtifactManifest))
	}
}

func TestVerifyReportsInputSnapshotCount(t *testing.T) {
	result := generateRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if verification.InputSnapshotCount != len(result.EvidencePack.InputSnapshots) {
		t.Fatalf("input snapshot count = %d, want %d", verification.InputSnapshotCount, len(result.EvidencePack.InputSnapshots))
	}
}

func TestVerifyIgnoresMutatedWorkspaceReadWhenSnapshotMatches(t *testing.T) {
	result := generateRun(t)
	snapshot := result.EvidencePack.InputSnapshots[0]
	sourcePath := filepath.Join(generatedRunWorkspace(t, result), snapshot.SourcePath)
	if err := os.WriteFile(sourcePath, []byte("mutated source after run\n"), 0o644); err != nil {
		t.Fatalf("mutate source: %v", err)
	}

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !verification.Verified {
		t.Fatalf("verified = false, want true")
	}
}

func TestVerifyRejectsTamperedInputSnapshot(t *testing.T) {
	result := generateRun(t)
	snapshot := result.EvidencePack.InputSnapshots[0]
	snapshotPath := filepath.Join(filepath.Dir(result.EvidencePackPath), snapshot.SnapshotPath)
	if err := os.WriteFile(snapshotPath, []byte("tampered snapshot\n"), 0o644); err != nil {
		t.Fatalf("tamper input snapshot: %v", err)
	}

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "input snapshot digest mismatch") {
		t.Fatalf("Verify error = %v, want input snapshot digest mismatch", err)
	}
}

func TestVerifyRejectsMissingInputSnapshot(t *testing.T) {
	result := generateRun(t)
	snapshot := result.EvidencePack.InputSnapshots[0]
	snapshotPath := filepath.Join(filepath.Dir(result.EvidencePackPath), snapshot.SnapshotPath)
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatalf("remove input snapshot: %v", err)
	}

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "input snapshot input-000001 path") {
		t.Fatalf("Verify error = %v, want missing input snapshot path error", err)
	}
}

func TestVerifyRejectsTamperedArtifact(t *testing.T) {
	result := generateRun(t)
	artifactPath := filepath.Join(generatedRunWorkspace(t, result), result.EvidencePack.ArtifactManifest[0].Path)
	if err := os.WriteFile(artifactPath, []byte("tampered artifact\n"), 0o644); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "artifact digest mismatch") {
		t.Fatalf("Verify error = %v, want artifact digest mismatch", err)
	}
}

func TestVerifyRejectsMissingArtifact(t *testing.T) {
	result := generateRun(t)
	artifactPath := filepath.Join(generatedRunWorkspace(t, result), result.EvidencePack.ArtifactManifest[0].Path)
	if err := os.Remove(artifactPath); err != nil {
		t.Fatalf("remove artifact: %v", err)
	}

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "artifact scripted_change-artifact-1 path") {
		t.Fatalf("Verify error = %v, want missing artifact path error", err)
	}
}

func TestVerifyRejectsArtifactWithMissingProducerEvent(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	evidence.ArtifactManifest[0].ProducerEventID = "event-999999"
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "artifact scripted_change-artifact-1 references missing producer event event-999999") {
		t.Fatalf("Verify error = %v, want missing producer event", err)
	}
}

func TestVerifyRejectsArtifactProducerEventWithoutArtifactID(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	oldArtifactID := evidence.ArtifactManifest[0].ArtifactID
	evidence.ArtifactManifest[0].ArtifactID = "renamed-artifact"
	for rowIndex := range evidence.ClosureMatrix.Rows {
		for artifactIndex, artifactID := range evidence.ClosureMatrix.Rows[rowIndex].ArtifactIDs {
			if artifactID == oldArtifactID {
				evidence.ClosureMatrix.Rows[rowIndex].ArtifactIDs[artifactIndex] = "renamed-artifact"
			}
		}
	}
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "producer event") || !strings.Contains(err.Error(), "does not include artifact renamed-artifact") {
		t.Fatalf("Verify error = %v, want producer event artifact id mismatch", err)
	}
}

func TestVerifyRejectsClosureArtifactMissingFromManifest(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	rowIndex := closureRowIndex(t, evidence, "obl_requested_file")
	evidence.ClosureMatrix.Rows[rowIndex].ArtifactIDs = append(evidence.ClosureMatrix.Rows[rowIndex].ArtifactIDs, "missing-artifact")
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "closure row obl_requested_file references missing artifact missing-artifact") {
		t.Fatalf("Verify error = %v, want missing closure artifact", err)
	}
}

func TestVerifyRejectsClosureArtifactFromUnclaimedTask(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	sourceRowIndex := closureRowIndex(t, evidence, "obl_requested_file")
	targetRowIndex := closureRowIndex(t, evidence, "obl_verify_passes")
	artifactID := evidence.ClosureMatrix.Rows[sourceRowIndex].ArtifactIDs[0]
	evidence.ClosureMatrix.Rows[targetRowIndex].ArtifactIDs = append(evidence.ClosureMatrix.Rows[targetRowIndex].ArtifactIDs, artifactID)
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "closure row obl_verify_passes") || !strings.Contains(err.Error(), "was produced by task scripted_change not claimed by closure row") {
		t.Fatalf("Verify error = %v, want unclaimed task artifact", err)
	}
}

func TestVerifyRejectsClosurePolicyDecisionMissingFromEvidence(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	rowIndex := closureRowIndex(t, evidence, "obl_requested_file")
	evidence.ClosureMatrix.Rows[rowIndex].PolicyDecisionIDs = append(evidence.ClosureMatrix.Rows[rowIndex].PolicyDecisionIDs, "missing-policy")
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "closure row obl_requested_file references missing policy decision missing-policy") {
		t.Fatalf("Verify error = %v, want missing closure policy decision", err)
	}
}

func TestVerifyRejectsClosureMissingPolicyDecisionForClaimedTask(t *testing.T) {
	result := generateRun(t)
	evidence := readEvidenceForTest(t, result)
	rowIndex := closureRowIndex(t, evidence, "obl_requested_file")
	evidence.ClosureMatrix.Rows[rowIndex].PolicyDecisionIDs = []string{}
	writeEvidenceForTest(t, result, evidence)

	_, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "closure row obl_requested_file missing policy decision") {
		t.Fatalf("Verify error = %v, want missing claimed task policy decision", err)
	}
}

func TestVerifyReportsFailureCountForFailedRun(t *testing.T) {
	result := generatePolicyDeniedRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if verification.FailureCount != 1 {
		t.Fatalf("failure count = %d, want 1", verification.FailureCount)
	}
}

func TestVerifyReportsFailureSummaryWithLedgerLine(t *testing.T) {
	result := generatePolicyDeniedRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if len(verification.Failures) != 1 {
		t.Fatalf("failures len = %d, want 1", len(verification.Failures))
	}
	failure := verification.Failures[0]
	if failure.FailureID != "failure-000001" {
		t.Fatalf("failure id = %q, want failure-000001", failure.FailureID)
	}
	if failure.EventID == "" {
		t.Fatalf("event id is empty")
	}
	if failure.EventLine == 0 {
		t.Fatalf("event line = 0, want ledger line")
	}
	if failure.TaskID != "scripted_change" {
		t.Fatalf("task id = %q, want scripted_change", failure.TaskID)
	}
	if failure.Phase != run.FailurePhasePolicy {
		t.Fatalf("phase = %q, want %q", failure.Phase, run.FailurePhasePolicy)
	}
	if !strings.Contains(failure.Reason, "policy denied task") {
		t.Fatalf("reason = %q, want policy denial", failure.Reason)
	}
}

func TestVerifyReportsPolicyExplanations(t *testing.T) {
	result := generatePolicyDeniedRun(t)

	verification, err := Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if len(verification.PolicyExplanations) != 1 {
		t.Fatalf("policy explanations len = %d, want 1", len(verification.PolicyExplanations))
	}
	explanation := verification.PolicyExplanations[0]
	if explanation.DecisionID != "policy-scripted_change-1" || explanation.Decision != "deny" || explanation.Summary != "denied network.request on api.example.test" {
		t.Fatalf("policy explanation = %+v", explanation)
	}
	if explanation.OperatorAction != "attach an approved ticket matching task, effect, and resource" {
		t.Fatalf("operator action = %q", explanation.OperatorAction)
	}
}

func TestVerifyRejectsFailureReferencingMissingLedgerEvent(t *testing.T) {
	result := generatePolicyDeniedRun(t)
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var evidence run.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	evidence.Failures[0].EventID = "event-999999"
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "failure failure-000001 references missing ledger event event-999999") {
		t.Fatalf("Verify error = %v, want missing ledger event", err)
	}
}

func TestVerifyRejectsTamperedLedger(t *testing.T) {
	result := generateRun(t)
	bytes, err := os.ReadFile(result.LedgerPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	tampered := strings.Replace(string(bytes), "run accepted", "run changed", 1)
	if err := os.WriteFile(result.LedgerPath, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write tampered ledger: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "event hash mismatch") {
		t.Fatalf("Verify error = %v, want event hash mismatch", err)
	}
}

func TestVerifyRejectsEvidenceLedgerDigestMismatch(t *testing.T) {
	result := generateRun(t)
	var evidence run.EvidencePack
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	evidence.LedgerDigest = strings.Repeat("0", 64)
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "ledger digest mismatch") {
		t.Fatalf("Verify error = %v, want ledger digest mismatch", err)
	}
}

func TestVerifyRejectsLedgerEventWithAdditionalProperty(t *testing.T) {
	result := generateRun(t)
	bytes, err := os.ReadFile(result.LedgerPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(bytes)), "\n")
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("decode first event: %v", err)
	}
	first["unexpected"] = true
	changed, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("encode first event: %v", err)
	}
	lines[0] = string(changed)
	if err := os.WriteFile(result.LedgerPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.event.v1") {
		t.Fatalf("Verify error = %v, want event schema validation failure", err)
	}
}

func TestVerifyRejectsEvidenceArtifactPathEscape(t *testing.T) {
	result := generateRun(t)
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var evidence run.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	evidence.ArtifactManifest[0].Path = "../outside.txt"
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-pack.v1") {
		t.Fatalf("Verify error = %v, want artifact path schema validation failure", err)
	}
}

func TestVerifyRejectsEvidenceWithAdditionalProperty(t *testing.T) {
	result := generateRun(t)
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	evidence["unexpected"] = true
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-pack.v1") {
		t.Fatalf("Verify error = %v, want evidence schema validation failure", err)
	}
}

func TestVerifyRejectsEvidenceMissingFailures(t *testing.T) {
	result := generateRun(t)
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	delete(evidence, "failures")
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}

	_, err = Verify(Options{
		LedgerPath:   result.LedgerPath,
		EvidencePath: result.EvidencePackPath,
	})
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-pack.v1") {
		t.Fatalf("Verify error = %v, want evidence schema validation failure", err)
	}
}

func generateRun(t *testing.T) run.Result {
	t.Helper()
	workspace := t.TempDir()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	result, err := run.Execute(context.Background(), c, run.Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "verify-test",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	return result
}

func generatePolicyDeniedRun(t *testing.T) run.Result {
	t.Helper()
	workspace := t.TempDir()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "network.request", Resource: "api.example.test"},
	}
	result, err := run.Execute(context.Background(), c, run.Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "verify-failed",
	})
	if err == nil {
		t.Fatalf("Execute error = nil, want policy denial")
	}
	return result
}

func generateApprovedProcessRun(t *testing.T) run.Result {
	t.Helper()
	workspace := t.TempDir()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
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
	result, err := run.Execute(context.Background(), c, run.Options{
		WorkspaceDir:     workspace,
		OutDir:           filepath.Join(workspace, ".covenant", "runs"),
		RunID:            "verify-approved-process",
		ProcessAllowlist: []string{"go version"},
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	return result
}

func readEvidenceForTest(t *testing.T, result run.Result) run.EvidencePack {
	t.Helper()
	bytes, err := os.ReadFile(result.EvidencePackPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var evidence run.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	return evidence
}

func writeEvidenceForTest(t *testing.T, result run.Result, evidence run.EvidencePack) {
	t.Helper()
	changed, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	if err := os.WriteFile(result.EvidencePackPath, append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
}

func readLedgerEventsForTest(t *testing.T, path string) []run.Event {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(bytes)), "\n")
	events := make([]run.Event, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event run.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode ledger event: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func encodeLedgerEventsForTest(t *testing.T, events []run.Event) []byte {
	t.Helper()
	previous := run.GenesisEventHash
	var b strings.Builder
	for i := range events {
		events[i].PreviousEventHash = previous
		events[i].EventHash = ""
		hash, err := run.EventContentHash(events[i])
		if err != nil {
			t.Fatalf("hash event %s: %v", events[i].EventID, err)
		}
		events[i].EventHash = hash
		previous = hash
		bytes, err := json.Marshal(events[i])
		if err != nil {
			t.Fatalf("encode event %s: %v", events[i].EventID, err)
		}
		b.Write(bytes)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func closureRowIndex(t *testing.T, evidence run.EvidencePack, obligationID string) int {
	t.Helper()
	for index, row := range evidence.ClosureMatrix.Rows {
		if row.ObligationID == obligationID {
			return index
		}
	}
	t.Fatalf("closure row %q not found in %+v", obligationID, evidence.ClosureMatrix.Rows)
	return -1
}

func mustWriteFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func generatedRunWorkspace(t *testing.T, result run.Result) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(result.LedgerPath))))
}
