package policy

import (
	"fmt"
	"path"
	"strings"
	"time"
)

func EvaluateTask(input Input) []Decision {
	decisions := make([]Decision, 0, len(input.Actions))
	for index, action := range input.Actions {
		decision := Decision{
			SchemaVersion: DecisionSchemaVersion,
			DecisionID:    fmt.Sprintf("policy-%s-%d", input.TaskID, index+1),
			TaskID:        input.TaskID,
			EffectType:    action.Type,
			Resource:      normalizeResource(action.Resource),
		}
		verdict, reason, ticketID := evaluateAction(input, action)
		decision.Decision = verdict
		decision.Reason = reason
		decision.ApprovalTicketID = ticketID
		decisions = append(decisions, decision)
	}
	return decisions
}

func evaluateAction(input Input, action ActionRef) (string, string, string) {
	if input.Mode != "strict" {
		return DecisionDeny, fmt.Sprintf("unsupported policy mode %q", input.Mode), ""
	}
	resource := normalizeResource(action.Resource)
	switch action.Type {
	case "file.write":
		if containsNormalized(input.WorkspaceWrites, resource) {
			return DecisionAllow, "declared workspace write", ""
		}
		return DecisionDeny, "file write is not declared in workspace writes", ""
	case "file.read":
		if containsNormalized(input.WorkspaceReads, resource) {
			return DecisionAllow, "declared workspace read", ""
		}
		return DecisionDeny, "file read is not declared in workspace reads", ""
	case "network.request", "process.spawn":
		ticket, ticketStatus := matchingApprovedTicket(input.Approvals, input.TaskID, action.Type, resource, evaluationTime(input))
		if ticketStatus == ticketStatusValid {
			if input.RevokedApprovalTicketIDs[ticket.TicketID] {
				return DecisionDeny, fmt.Sprintf("approval ticket %q is revoked", ticket.TicketID), ticket.TicketID
			}
			return DecisionAllow, "approved by ticket", ticket.TicketID
		}
		if ticketStatus == ticketStatusExpired {
			return DecisionDeny, fmt.Sprintf("approval ticket %q expired at %s", ticket.TicketID, ticket.ExpiresAt), ""
		}
		if ticketStatus == ticketStatusInvalidExpiration {
			return DecisionDeny, fmt.Sprintf("approval ticket %q has invalid expires_at %q", ticket.TicketID, ticket.ExpiresAt), ""
		}
		return DecisionDeny, action.Type + " requires an approved ticket", ""
	case "claim.publish":
		return evaluateClaimPublish(input, action, resource)
	default:
		return DecisionDeny, "unknown side effect type", ""
	}
}

func evaluateClaimPublish(input Input, action ActionRef, resource string) (string, string, string) {
	ticket, ticketStatus := matchingApprovedTicket(input.Approvals, input.TaskID, action.Type, resource, evaluationTime(input))
	if ticketStatus == ticketStatusExpired {
		return DecisionDeny, fmt.Sprintf("approval ticket %q expired at %s", ticket.TicketID, ticket.ExpiresAt), ""
	}
	if ticketStatus == ticketStatusInvalidExpiration {
		return DecisionDeny, fmt.Sprintf("approval ticket %q has invalid expires_at %q", ticket.TicketID, ticket.ExpiresAt), ""
	}
	if resource != "full-autonomous-self-mutating-rsi" {
		if ticketStatus == ticketStatusValid {
			if input.RevokedApprovalTicketIDs[ticket.TicketID] {
				return DecisionDeny, fmt.Sprintf("approval ticket %q is revoked", ticket.TicketID), ticket.TicketID
			}
			return DecisionAllow, "approved claim publication", ticket.TicketID
		}
		return DecisionDeny, "claim.publish requires an approved ticket", ""
	}
	if ticketStatus != ticketStatusValid {
		return DecisionDeny, "full autonomous self-mutating RSI claim requires mutation authority, rollback, and live self-change evidence", ""
	}
	if input.RevokedApprovalTicketIDs[ticket.TicketID] {
		return DecisionDeny, fmt.Sprintf("approval ticket %q is revoked", ticket.TicketID), ticket.TicketID
	}
	if !fullRSIEvidenceReason(ticket.Reason) {
		return DecisionDeny, fmt.Sprintf("approval ticket %q is missing mutation authority, rollback, and live self-change evidence", ticket.TicketID), ticket.TicketID
	}
	return DecisionAllow, "approved full RSI claim evidence", ticket.TicketID
}

func fullRSIEvidenceReason(reason string) bool {
	normalized := strings.ToLower(reason)
	for _, required := range []string{"mutation authority", "rollback", "live self-change"} {
		if !strings.Contains(normalized, required) {
			return false
		}
	}
	return true
}

type ticketStatus string

const (
	ticketStatusMissing           ticketStatus = "missing"
	ticketStatusValid             ticketStatus = "valid"
	ticketStatusExpired           ticketStatus = "expired"
	ticketStatusInvalidExpiration ticketStatus = "invalid_expiration"
)

func matchingApprovedTicket(approvals []ApprovalTicket, taskID string, effectType string, resource string, now time.Time) (ApprovalTicket, ticketStatus) {
	for _, ticket := range approvals {
		if ticket.TaskID == taskID &&
			ticket.EffectType == effectType &&
			normalizeResource(ticket.Resource) == resource &&
			ticket.Approved {
			if ticket.ExpiresAt == "" {
				return ticket, ticketStatusValid
			}
			expiresAt, err := time.Parse(time.RFC3339, ticket.ExpiresAt)
			if err != nil {
				return ticket, ticketStatusInvalidExpiration
			}
			if !expiresAt.After(now) {
				return ticket, ticketStatusExpired
			}
			return ticket, ticketStatusValid
		}
	}
	return ApprovalTicket{}, ticketStatusMissing
}

func evaluationTime(input Input) time.Time {
	if !input.EvaluationTime.IsZero() {
		return input.EvaluationTime.UTC()
	}
	return time.Now().UTC()
}

func containsNormalized(values []string, resource string) bool {
	for _, value := range values {
		if normalizeResource(value) == resource {
			return true
		}
	}
	return false
}

func normalizeResource(raw string) string {
	return path.Clean(strings.ReplaceAll(raw, "\\", "/"))
}
