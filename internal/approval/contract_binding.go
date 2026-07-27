package approval

import (
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func ValidateAgainstContract(c contract.Contract, ticket policy.ApprovalTicket) error {
	if err := ValidateTicket(ticket); err != nil {
		return err
	}
	_, err := Attach(c, ticket)
	return err
}

func Attach(c contract.Contract, ticket policy.ApprovalTicket) (contract.Contract, error) {
	if err := ValidateTicket(ticket); err != nil {
		return contract.Contract{}, err
	}
	updated := c
	updated.Approvals = appendOrReplaceApproval(c.Approvals, ticket)
	if err := schema.ValidateValue(schema.ContractSchemaID, updated); err != nil {
		return contract.Contract{}, err
	}
	if err := contract.Validate(updated); err != nil {
		return contract.Contract{}, err
	}
	return updated, nil
}

func appendOrReplaceApproval(approvals []policy.ApprovalTicket, ticket policy.ApprovalTicket) []policy.ApprovalTicket {
	next := make([]policy.ApprovalTicket, 0, len(approvals)+1)
	replaced := false
	for _, existing := range approvals {
		if existing.TicketID == ticket.TicketID {
			next = append(next, ticket)
			replaced = true
			continue
		}
		next = append(next, existing)
	}
	if !replaced {
		next = append(next, ticket)
	}
	return next
}
