package closure

import (
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

func TestEvaluateAcceptsClosedRequiredObligations(t *testing.T) {
	matrix := Evaluate(Input{
		RunID:          "run-test",
		ContractDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RunStatus:      "success",
		Obligations: []contract.Obligation{
			{ID: "obl_requested_file", Required: true},
			{ID: "obl_verify_passes", Required: true},
		},
		Tasks: []contract.Task{
			{ID: "scripted_change", Obligations: []string{"obl_requested_file"}},
			{ID: "verify_change", Obligations: []string{"obl_verify_passes"}},
		},
		TaskStatuses: map[string]string{
			"scripted_change": "success",
			"verify_change":   "success",
		},
		TaskArtifacts: map[string][]string{
			"scripted_change": {"scripted_change-artifact-1"},
		},
		PolicyDecisions: []policy.Decision{
			{
				DecisionID: "policy-scripted_change-1",
				TaskID:     "scripted_change",
				Decision:   policy.DecisionAllow,
			},
		},
	})

	if matrix.Status != StatusAccepted {
		t.Fatalf("matrix status = %q, want %q", matrix.Status, StatusAccepted)
	}
	if len(matrix.Rows) != 2 {
		t.Fatalf("rows len = %d, want 2", len(matrix.Rows))
	}
	row := findRow(t, matrix, "obl_requested_file")
	if row.Status != RowStatusClosed {
		t.Fatalf("requested file row status = %q, want %q", row.Status, RowStatusClosed)
	}
	if len(row.ArtifactIDs) != 1 || row.ArtifactIDs[0] != "scripted_change-artifact-1" {
		t.Fatalf("artifact ids = %v, want scripted_change-artifact-1", row.ArtifactIDs)
	}
	if len(row.PolicyDecisionIDs) != 1 || row.PolicyDecisionIDs[0] != "policy-scripted_change-1" {
		t.Fatalf("policy decision ids = %v, want policy-scripted_change-1", row.PolicyDecisionIDs)
	}
}

func TestEvaluateRejectsMissingRequiredObligationClosure(t *testing.T) {
	matrix := Evaluate(Input{
		RunID:          "run-test",
		ContractDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RunStatus:      "success",
		Obligations: []contract.Obligation{
			{ID: "obl_requested_file", Required: true},
			{ID: "obl_verify_passes", Required: true},
		},
		Tasks: []contract.Task{
			{ID: "scripted_change", Obligations: []string{"obl_requested_file"}},
			{ID: "verify_change", Obligations: []string{"obl_verify_passes"}},
		},
		TaskStatuses: map[string]string{
			"scripted_change": "success",
			"verify_change":   "failed",
		},
	})

	if matrix.Status != StatusRejected {
		t.Fatalf("matrix status = %q, want %q", matrix.Status, StatusRejected)
	}
	row := findRow(t, matrix, "obl_verify_passes")
	if row.Status != RowStatusOpen {
		t.Fatalf("verify row status = %q, want %q", row.Status, RowStatusOpen)
	}
	if row.Reason == "" {
		t.Fatalf("open row reason is empty")
	}
}

func TestEvaluateDoesNotRejectOpenOptionalObligation(t *testing.T) {
	matrix := Evaluate(Input{
		RunID:          "run-test",
		ContractDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RunStatus:      "success",
		Obligations: []contract.Obligation{
			{ID: "obl_required", Required: true},
			{ID: "obl_optional", Required: false},
		},
		Tasks: []contract.Task{
			{ID: "required_task", Obligations: []string{"obl_required"}},
			{ID: "optional_task", Obligations: []string{"obl_optional"}},
		},
		TaskStatuses: map[string]string{
			"required_task": "success",
			"optional_task": "failed",
		},
	})

	if matrix.Status != StatusAccepted {
		t.Fatalf("matrix status = %q, want %q", matrix.Status, StatusAccepted)
	}
	row := findRow(t, matrix, "obl_optional")
	if row.Status != RowStatusOpen {
		t.Fatalf("optional row status = %q, want %q", row.Status, RowStatusOpen)
	}
	if row.ArtifactIDs == nil {
		t.Fatalf("optional row artifact ids = nil, want empty array")
	}
	if row.PolicyDecisionIDs == nil {
		t.Fatalf("optional row policy decision ids = nil, want empty array")
	}
}

func findRow(t *testing.T, matrix Matrix, obligationID string) Row {
	t.Helper()
	for _, row := range matrix.Rows {
		if row.ObligationID == obligationID {
			return row
		}
	}
	t.Fatalf("row %q not found in %+v", obligationID, matrix.Rows)
	return Row{}
}
