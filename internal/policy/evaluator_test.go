package policy

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateTaskAllowsDeclaredWorkspaceWrite(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:            "strict",
		WorkspaceWrites: []string{"demo-output/report.txt"},
		TaskID:          "scripted_change",
		Actions: []ActionRef{
			{Type: "file.write", Resource: "demo-output/report.txt"},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", decisions[0].Decision, DecisionAllow)
	}
}

func TestEvaluateTaskDeniesNetworkWithoutApproval(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "fetch_data",
		Actions: []ActionRef{
			{Type: "network.request", Resource: "api.example.test"},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionDeny {
		t.Fatalf("decision = %q, want %q", decisions[0].Decision, DecisionDeny)
	}
	if decisions[0].ApprovalTicketID != "" {
		t.Fatalf("approval ticket id = %q, want empty", decisions[0].ApprovalTicketID)
	}
}

func TestEvaluateTaskAllowsNetworkWithMatchingApprovedTicket(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "fetch_data",
		Actions: []ActionRef{
			{Type: "network.request", Resource: "api.example.test"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_network",
				TaskID:        "fetch_data",
				EffectType:    "network.request",
				Resource:      "api.example.test",
				Approved:      true,
				Reason:        "test fixture allows this network request",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionAllow {
		t.Fatalf("decision = %q, want %q", decisions[0].Decision, DecisionAllow)
	}
	if decisions[0].ApprovalTicketID != "ticket_network" {
		t.Fatalf("approval ticket id = %q, want ticket_network", decisions[0].ApprovalTicketID)
	}
}

func TestEvaluateTaskDeniesUnapprovedProcessSpawn(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "spawn_tool",
		Actions: []ActionRef{
			{Type: "process.spawn", Resource: "go-test"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_process",
				TaskID:        "spawn_tool",
				EffectType:    "process.spawn",
				Resource:      "go-test",
				Approved:      false,
				Reason:        "explicitly not approved",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionDeny {
		t.Fatalf("decision = %q, want %q", decisions[0].Decision, DecisionDeny)
	}
}

func TestEvaluateTaskDeniesExpiredApprovalTicket(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:           "strict",
		TaskID:         "spawn_tool",
		EvaluationTime: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		Actions: []ActionRef{
			{Type: "process.spawn", Resource: "make-test"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_process",
				TaskID:        "spawn_tool",
				EffectType:    "process.spawn",
				Resource:      "make-test",
				Approved:      true,
				Reason:        "operator approved local test command",
				ExpiresAt:     "2026-06-12T11:59:59Z",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", decisions[0].Decision)
	}
	if !strings.Contains(decisions[0].Reason, `approval ticket "ticket_process" expired at 2026-06-12T11:59:59Z`) {
		t.Fatalf("reason = %q, want expired ticket", decisions[0].Reason)
	}
}

func TestEvaluateTaskAllowsFutureApprovalTicket(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:           "strict",
		TaskID:         "spawn_tool",
		EvaluationTime: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC),
		Actions: []ActionRef{
			{Type: "process.spawn", Resource: "make-test"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_process",
				TaskID:        "spawn_tool",
				EffectType:    "process.spawn",
				Resource:      "make-test",
				Approved:      true,
				Reason:        "operator approved local test command",
				ExpiresAt:     "2026-06-12T12:00:01Z",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	if decisions[0].Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow", decisions[0].Decision)
	}
	if decisions[0].ApprovalTicketID != "ticket_process" {
		t.Fatalf("approval ticket id = %q, want ticket_process", decisions[0].ApprovalTicketID)
	}
}

func TestEvaluateTaskDeniesRevokedApprovalTicket(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "spawn_tool",
		Actions: []ActionRef{
			{Type: "process.spawn", Resource: "make-test"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_process",
				TaskID:        "spawn_tool",
				EffectType:    "process.spawn",
				Resource:      "make-test",
				Approved:      true,
				Reason:        "operator approved local test command",
			},
		},
		RevokedApprovalTicketIDs: map[string]bool{"ticket_process": true},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	decision := decisions[0]
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if decision.ApprovalTicketID != "ticket_process" {
		t.Fatalf("approval ticket id = %q, want ticket_process", decision.ApprovalTicketID)
	}
	if !strings.Contains(decision.Reason, `approval ticket "ticket_process" is revoked`) {
		t.Fatalf("reason = %q, want revoked ticket", decision.Reason)
	}
}

func TestExplainDecisionAllowsDeclaredWorkspaceWrite(t *testing.T) {
	explanation := ExplainDecision(Decision{
		DecisionID: "policy-scripted_change-1",
		TaskID:     "scripted_change",
		EffectType: "file.write",
		Resource:   "demo-output/report.txt",
		Decision:   DecisionAllow,
		Reason:     "declared workspace write",
	})

	if explanation.Summary != "allowed file.write on demo-output/report.txt" {
		t.Fatalf("summary = %q", explanation.Summary)
	}
	if explanation.OperatorAction != "" {
		t.Fatalf("operator action = %q, want empty", explanation.OperatorAction)
	}
	if explanation.Detail == "" || !containsAll(explanation.Detail, []string{"scripted_change", "file.write", "declared workspace write"}) {
		t.Fatalf("detail = %q, want task, effect, and reason", explanation.Detail)
	}
}

func TestExplainDecisionDeniesProcessWithoutTicket(t *testing.T) {
	explanation := ExplainDecision(Decision{
		DecisionID: "policy-spawn_tool-1",
		TaskID:     "spawn_tool",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Decision:   DecisionDeny,
		Reason:     "process.spawn requires an approved ticket",
	})

	if explanation.Summary != "denied process.spawn on make-test" {
		t.Fatalf("summary = %q", explanation.Summary)
	}
	if explanation.OperatorAction != "attach an approved ticket matching task, effect, and resource" {
		t.Fatalf("operator action = %q", explanation.OperatorAction)
	}
	if !containsAll(explanation.Detail, []string{"spawn_tool", "process.spawn", "make-test", "process.spawn requires an approved ticket"}) {
		t.Fatalf("detail = %q, want task, effect, resource, and reason", explanation.Detail)
	}
}

func TestFilterDecisionsByTaskEffectResourceAndDecision(t *testing.T) {
	decisions := []Decision{
		{
			DecisionID: "policy-draft-1",
			TaskID:     "draft_release",
			EffectType: "file.write",
			Resource:   "reports/release.md",
			Decision:   DecisionAllow,
		},
		{
			DecisionID: "policy-verify-1",
			TaskID:     "verify_release",
			EffectType: "process.spawn",
			Resource:   "go test ./...",
			Decision:   DecisionDeny,
		},
		{
			DecisionID: "policy-draft-2",
			TaskID:     "draft_release",
			EffectType: "network.request",
			Resource:   "api.example.test",
			Decision:   DecisionDeny,
		},
	}

	filtered := FilterDecisions(decisions, DecisionFilters{
		TaskID:     "draft_release",
		EffectType: "network.request",
		Resource:   "api.example.test",
		Decision:   DecisionDeny,
	})

	if len(filtered) != 1 || filtered[0].DecisionID != "policy-draft-2" {
		t.Fatalf("filtered = %+v, want policy-draft-2", filtered)
	}
}

func TestFilterDecisionsByApprovalState(t *testing.T) {
	decisions := []Decision{
		{
			DecisionID: "policy-write-1",
			TaskID:     "draft_release",
			EffectType: "file.write",
			Resource:   "reports/release.md",
			Decision:   DecisionAllow,
		},
		{
			DecisionID:       "policy-process-1",
			TaskID:           "spawn_tool",
			EffectType:       "process.spawn",
			Resource:         "go version",
			Decision:         DecisionAllow,
			ApprovalTicketID: "ticket_process",
		},
	}

	withApproval := FilterDecisions(decisions, DecisionFilters{ApprovalState: ApprovalStateWithTicket})
	withoutApproval := FilterDecisions(decisions, DecisionFilters{ApprovalState: ApprovalStateWithoutTicket})

	if len(withApproval) != 1 || withApproval[0].DecisionID != "policy-process-1" {
		t.Fatalf("with approval = %+v, want process decision", withApproval)
	}
	if len(withoutApproval) != 1 || withoutApproval[0].DecisionID != "policy-write-1" {
		t.Fatalf("without approval = %+v, want write decision", withoutApproval)
	}
}

func containsAll(value string, needles []string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
