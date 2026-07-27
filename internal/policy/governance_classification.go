package policy

import (
	"fmt"
	"strings"
)

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
		return DecisionDeny, fmt.Sprintf("claim_level=%s is denied; downgrade to claim_level=%s until mutation authority, rollback, and live self-change evidence exist", ClaimLevelFullAutonomousSelfMutatingRSI, ClaimLevelBoundedGovernedRSI), ""
	}
	if input.RevokedApprovalTicketIDs[ticket.TicketID] {
		return DecisionDeny, fmt.Sprintf("approval ticket %q is revoked", ticket.TicketID), ticket.TicketID
	}
	if !fullRSIEvidenceReason(ticket.Reason) {
		return DecisionDeny, fullRSIMissingEvidenceReason(ticket), ticket.TicketID
	}
	return DecisionAllow, fmt.Sprintf("approved full RSI claim evidence for claim_level=%s", ClaimLevelFullAutonomousSelfMutatingRSI), ticket.TicketID
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

func fullRSIMissingEvidenceReason(ticket ApprovalTicket) string {
	normalized := strings.ToLower(ticket.Reason)
	if strings.Contains(normalized, "rollback") &&
		!strings.Contains(normalized, "mutation authority") &&
		!strings.Contains(normalized, "live self-change") {
		return fmt.Sprintf("approval ticket %q includes retained rollback rehearsal evidence, but retained rollback rehearsal alone is insufficient for claim_level=%s; downgrade to claim_level=%s until mutation authority and live self-change evidence also exist", ticket.TicketID, ClaimLevelFullAutonomousSelfMutatingRSI, ClaimLevelBoundedGovernedRSI)
	}
	return fmt.Sprintf("approval ticket %q is missing evidence for claim_level=%s; downgrade to claim_level=%s until mutation authority, rollback, and live self-change evidence exist", ticket.TicketID, ClaimLevelFullAutonomousSelfMutatingRSI, ClaimLevelBoundedGovernedRSI)
}
