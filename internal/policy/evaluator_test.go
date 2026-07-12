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

func TestEvaluateTaskDeniesFullRSIClaimWithoutEvidenceApproval(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "publish_rsi_claim",
		Actions: []ActionRef{
			{Type: "claim.publish", Resource: "full-autonomous-self-mutating-rsi"},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	decision := decisions[0]
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if !containsAll(decision.Reason, []string{"full_autonomous_self_mutating_rsi", "bounded_governed_rsi", "mutation authority", "rollback", "live self-change"}) {
		t.Fatalf("reason = %q, want full RSI evidence requirements", decision.Reason)
	}
}

func TestEvaluateTaskDeniesFullRSIClaimWithGenericApproval(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "publish_rsi_claim",
		Actions: []ActionRef{
			{Type: "claim.publish", Resource: "full-autonomous-self-mutating-rsi"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_full_rsi",
				TaskID:        "publish_rsi_claim",
				EffectType:    "claim.publish",
				Resource:      "full-autonomous-self-mutating-rsi",
				Approved:      true,
				Reason:        "operator approves stronger RSI claim",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	decision := decisions[0]
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if decision.ApprovalTicketID != "ticket_full_rsi" {
		t.Fatalf("approval ticket id = %q, want ticket_full_rsi", decision.ApprovalTicketID)
	}
	if !containsAll(decision.Reason, []string{"approval ticket", "missing", "full_autonomous_self_mutating_rsi", "bounded_governed_rsi", "mutation authority", "rollback", "live self-change"}) {
		t.Fatalf("reason = %q, want missing full RSI evidence requirements", decision.Reason)
	}
}

func TestEvaluateTaskDeniesFullRSIClaimWithRetainedRollbackOnly(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "publish_rsi_claim",
		Actions: []ActionRef{
			{Type: "claim.publish", Resource: "full-autonomous-self-mutating-rsi"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_full_rsi_rollback",
				TaskID:        "publish_rsi_claim",
				EffectType:    "claim.publish",
				Resource:      "full-autonomous-self-mutating-rsi",
				Approved:      true,
				Reason:        "retained rollback rehearsal evidence from AO2 and AO Forge only",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	decision := decisions[0]
	if decision.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", decision.Decision)
	}
	if decision.ApprovalTicketID != "ticket_full_rsi_rollback" {
		t.Fatalf("approval ticket id = %q, want ticket_full_rsi_rollback", decision.ApprovalTicketID)
	}
	if !containsAll(decision.Reason, []string{"retained rollback rehearsal", "insufficient", "full_autonomous_self_mutating_rsi", "bounded_governed_rsi", "mutation authority", "live self-change"}) {
		t.Fatalf("reason = %q, want retained rollback to be insufficient without remaining full RSI evidence", decision.Reason)
	}
}

func TestEvaluateTaskAllowsFullRSIClaimWithEvidenceApproval(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:   "strict",
		TaskID: "publish_rsi_claim",
		Actions: []ActionRef{
			{Type: "claim.publish", Resource: "full-autonomous-self-mutating-rsi"},
		},
		Approvals: []ApprovalTicket{
			{
				SchemaVersion: ApprovalTicketSchemaVersion,
				TicketID:      "ticket_full_rsi",
				TaskID:        "publish_rsi_claim",
				EffectType:    "claim.publish",
				Resource:      "full-autonomous-self-mutating-rsi",
				Approved:      true,
				Reason:        "mutation authority evidence, rollback evidence, and live self-change evidence verified by AO Covenant",
			},
		},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	decision := decisions[0]
	if decision.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow: %+v", decision.Decision, decision)
	}
	if decision.ApprovalTicketID != "ticket_full_rsi" {
		t.Fatalf("approval ticket id = %q, want ticket_full_rsi", decision.ApprovalTicketID)
	}
	if !containsAll(decision.Reason, []string{"approved full RSI claim evidence", "full_autonomous_self_mutating_rsi"}) {
		t.Fatalf("reason = %q, want full RSI approval reason", decision.Reason)
	}
}

func TestAO2FirstSpineIncludesRSIClaimBoundaryGate(t *testing.T) {
	spine := AO2FirstSpine("covenant.policy-spine-result.v1")

	found := false
	for _, responsibility := range spine.Responsibilities {
		if responsibility.Name != "rsi-claim-boundary" {
			continue
		}
		found = true
		if responsibility.Owner != "ao-covenant" {
			t.Fatalf("owner = %q, want ao-covenant", responsibility.Owner)
		}
		for _, want := range []string{"claim.publish side-effect policy", "bounded_governed_rsi claim level", "full_autonomous_self_mutating_rsi claim level", "mutation authority evidence", "rollback evidence", "live self-change evidence"} {
			if !containsString(responsibility.Gates, want) {
				t.Fatalf("rsi claim boundary gates = %#v, missing %q", responsibility.Gates, want)
			}
		}
	}
	if !found {
		t.Fatalf("policy spine missing rsi-claim-boundary responsibility: %+v", spine.Responsibilities)
	}
}

func TestScopedCredentialPolicyChecklistAvoidsCredentialInspection(t *testing.T) {
	checklist := ScopedCredentialPolicyChecklist("covenant.scoped-credential-policy-checklist.v1")
	if checklist.SchemaVersion != "covenant.scoped-credential-policy-checklist.v1" ||
		checklist.Status != "ready" ||
		checklist.Scope != "metadata_and_operator_checklist_only" ||
		len(checklist.Checks) < 5 ||
		checklist.CredentialValueInspectionAllowed ||
		checklist.CredentialValuesInspected ||
		checklist.CredentialValuesStored ||
		checklist.RequiresCredentialMaterial ||
		checklist.SafeToExecute ||
		checklist.ExecutesWork ||
		checklist.ApprovesWork ||
		checklist.MutatesRepositories ||
		checklist.ProviderCallsAllowed ||
		checklist.ReleaseOrPublishAllowed ||
		checklist.ClaimsAuthorityAdvance ||
		!checklist.RSIRemainsDenied {
		t.Fatalf("credential checklist widened authority or inspected credentials: %+v", checklist)
	}
	for _, check := range checklist.Checks {
		if check.Status != "passed" || check.RequiresCredentialValue {
			t.Fatalf("credential checklist check must be passed without values: %+v", check)
		}
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

func TestExplainDecisionDeniesFullRSIClaimWithEvidenceRequirements(t *testing.T) {
	explanation := ExplainDecision(Decision{
		DecisionID: "policy-publish_rsi_claim-1",
		TaskID:     "publish_rsi_claim",
		EffectType: "claim.publish",
		Resource:   "full-autonomous-self-mutating-rsi",
		Decision:   DecisionDeny,
		Reason:     "claim_level=full_autonomous_self_mutating_rsi is denied; downgrade to claim_level=bounded_governed_rsi until mutation authority, rollback, and live self-change evidence exist",
	})

	if explanation.Summary != "denied claim.publish on full-autonomous-self-mutating-rsi" {
		t.Fatalf("summary = %q", explanation.Summary)
	}
	if explanation.OperatorAction != "attach an approved full-RSI evidence ticket or downgrade to claim_level=bounded_governed_rsi" {
		t.Fatalf("operator action = %q", explanation.OperatorAction)
	}
	if !containsAll(explanation.Detail, []string{"claim.publish", "full-autonomous-self-mutating-rsi", "claim_level=full_autonomous_self_mutating_rsi", "claim_level=bounded_governed_rsi", "mutation authority", "rollback", "live self-change"}) {
		t.Fatalf("detail = %q, want full RSI evidence requirements", explanation.Detail)
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

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
