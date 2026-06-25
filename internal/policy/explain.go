package policy

import (
	"fmt"
	"strings"
)

type Explanation struct {
	DecisionID       string `json:"decision_id"`
	TaskID           string `json:"task_id"`
	EffectType       string `json:"effect_type"`
	Resource         string `json:"resource"`
	Decision         string `json:"decision"`
	Reason           string `json:"reason"`
	ApprovalTicketID string `json:"approval_ticket_id,omitempty"`
	Summary          string `json:"summary"`
	Detail           string `json:"detail"`
	OperatorAction   string `json:"operator_action,omitempty"`
}

func ExplainDecision(decision Decision) Explanation {
	explanation := Explanation{
		DecisionID:       decision.DecisionID,
		TaskID:           decision.TaskID,
		EffectType:       decision.EffectType,
		Resource:         decision.Resource,
		Decision:         decision.Decision,
		Reason:           decision.Reason,
		ApprovalTicketID: decision.ApprovalTicketID,
		Summary:          fmt.Sprintf("%s %s on %s", decisionVerb(decision.Decision), decision.EffectType, decision.Resource),
		Detail: fmt.Sprintf(
			"Task %s requested %s on %s. Policy decision: %s. Reason: %s.",
			decision.TaskID,
			decision.EffectType,
			decision.Resource,
			decision.Decision,
			decision.Reason,
		),
	}
	if decision.ApprovalTicketID != "" {
		explanation.Detail += fmt.Sprintf(" Approval ticket: %s.", decision.ApprovalTicketID)
	}
	if decision.Decision == DecisionDeny {
		explanation.OperatorAction = operatorActionForDeny(decision)
	}
	return explanation
}

func ExplainDecisions(decisions []Decision) []Explanation {
	explanations := make([]Explanation, 0, len(decisions))
	for _, decision := range decisions {
		explanations = append(explanations, ExplainDecision(decision))
	}
	return explanations
}

func operatorActionForDeny(decision Decision) string {
	if strings.HasPrefix(decision.Reason, "unsupported policy mode") {
		return "use strict policy mode"
	}
	switch decision.EffectType {
	case "file.write":
		return "add the resource to workspace.writes or remove the task side effect"
	case "file.read":
		return "add the resource to workspace.reads or remove the task side effect"
	case "network.request", "process.spawn":
		return "attach an approved ticket matching task, effect, and resource"
	case "claim.publish":
		if decision.Resource == "full-autonomous-self-mutating-rsi" {
			return "attach an approved full-RSI evidence ticket or downgrade the claim to bounded governed RSI"
		}
		return "attach an approved ticket matching task, effect, and resource"
	default:
		return "use a supported side effect type or remove the task side effect"
	}
}

func decisionVerb(decision string) string {
	switch decision {
	case DecisionAllow:
		return "allowed"
	case DecisionDeny:
		return "denied"
	default:
		return decision
	}
}
