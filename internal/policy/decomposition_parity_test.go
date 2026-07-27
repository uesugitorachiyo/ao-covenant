package policy

import "testing"

func TestProtectedResourceNormalizationParityAcrossOwnershipBoundary(t *testing.T) {
	tests := []struct {
		name     string
		reads    []string
		writes   []string
		action   ActionRef
		decision string
		reason   string
		resource string
	}{
		{
			name:     "windows separators normalize to declared write",
			writes:   []string{`reports\staging\..\final.json`},
			action:   ActionRef{Type: "file.write", Resource: "reports/final.json"},
			decision: DecisionAllow,
			reason:   "declared workspace write",
			resource: "reports/final.json",
		},
		{
			name:     "dot segments normalize to declared read",
			reads:    []string{"config/./public.json"},
			action:   ActionRef{Type: "file.read", Resource: `config\public.json`},
			decision: DecisionAllow,
			reason:   "declared workspace read",
			resource: "config/public.json",
		},
		{
			name:     "directory prefix does not authorize child write",
			writes:   []string{"reports"},
			action:   ActionRef{Type: "file.write", Resource: "reports/final.json"},
			decision: DecisionDeny,
			reason:   "file write is not declared in workspace writes",
			resource: "reports/final.json",
		},
		{
			name:     "similar prefix does not authorize sibling read",
			reads:    []string{"config/public.json"},
			action:   ActionRef{Type: "file.read", Resource: "config/public.json.backup"},
			decision: DecisionDeny,
			reason:   "file read is not declared in workspace reads",
			resource: "config/public.json.backup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions := EvaluateTask(Input{
				Mode:            "strict",
				TaskID:          "decomposition_parity",
				WorkspaceReads:  tt.reads,
				WorkspaceWrites: tt.writes,
				Actions:         []ActionRef{tt.action},
			})
			if len(decisions) != 1 {
				t.Fatalf("decisions len = %d, want 1", len(decisions))
			}
			got := decisions[0]
			if got.Decision != tt.decision || got.Reason != tt.reason || got.Resource != tt.resource {
				t.Fatalf("protected resource parity changed: %+v", got)
			}
		})
	}
}

func TestUnsupportedPolicyModeRemainsFailClosedAcrossOwnershipBoundary(t *testing.T) {
	decisions := EvaluateTask(Input{
		Mode:            "permissive",
		TaskID:          "decomposition_parity",
		WorkspaceWrites: []string{"reports/final.json"},
		Actions:         []ActionRef{{Type: "file.write", Resource: "reports/final.json"}},
	})

	if len(decisions) != 1 {
		t.Fatalf("decisions len = %d, want 1", len(decisions))
	}
	got := decisions[0]
	if got.Decision != DecisionDeny ||
		got.Reason != `unsupported policy mode "permissive"` ||
		got.ApprovalTicketID != "" {
		t.Fatalf("unsupported mode widened authority: %+v", got)
	}
}
