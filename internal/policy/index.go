package policy

const (
	ApprovalStateAny           = ""
	ApprovalStateWithTicket    = "with-ticket"
	ApprovalStateWithoutTicket = "without-ticket"
)

type DecisionFilters struct {
	TaskID        string
	EffectType    string
	Resource      string
	Decision      string
	ApprovalState string
}

func FilterDecisions(decisions []Decision, filters DecisionFilters) []Decision {
	filtered := make([]Decision, 0, len(decisions))
	for _, decision := range decisions {
		if MatchesDecisionFilters(decision, filters) {
			filtered = append(filtered, decision)
		}
	}
	return filtered
}

func MatchesDecisionFilters(decision Decision, filters DecisionFilters) bool {
	if filters.TaskID != "" && decision.TaskID != filters.TaskID {
		return false
	}
	if filters.EffectType != "" && decision.EffectType != filters.EffectType {
		return false
	}
	if filters.Resource != "" && normalizeResource(decision.Resource) != normalizeResource(filters.Resource) {
		return false
	}
	if filters.Decision != "" && decision.Decision != filters.Decision {
		return false
	}
	switch filters.ApprovalState {
	case ApprovalStateAny:
		return true
	case ApprovalStateWithTicket:
		return decision.ApprovalTicketID != ""
	case ApprovalStateWithoutTicket:
		return decision.ApprovalTicketID == ""
	default:
		return false
	}
}
