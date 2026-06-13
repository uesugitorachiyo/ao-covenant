package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const RevocationListSchemaVersion = "covenant.approval-revocations.v1"

type CreateInput struct {
	TicketID   string
	TaskID     string
	EffectType string
	Resource   string
	Approved   bool
	Reason     string
	OperatorID string
	ExpiresAt  string
}

type RevocationList struct {
	SchemaVersion  string          `json:"schema_version"`
	RevokedTickets []RevokedTicket `json:"revoked_tickets"`
}

type RevokedTicket struct {
	TicketID string `json:"ticket_id"`
	Reason   string `json:"reason"`
}

func Create(input CreateInput) (policy.ApprovalTicket, error) {
	ticketID := strings.TrimSpace(input.TicketID)
	if ticketID == "" {
		ticketID = defaultTicketID(input.TaskID, input.EffectType, input.Resource)
	}
	ticket := policy.ApprovalTicket{
		SchemaVersion: policy.ApprovalTicketSchemaVersion,
		TicketID:      ticketID,
		TaskID:        strings.TrimSpace(input.TaskID),
		EffectType:    strings.TrimSpace(input.EffectType),
		Resource:      strings.TrimSpace(input.Resource),
		Approved:      input.Approved,
		Reason:        strings.TrimSpace(input.Reason),
		OperatorID:    strings.TrimSpace(input.OperatorID),
		ExpiresAt:     strings.TrimSpace(input.ExpiresAt),
	}
	if err := ValidateTicket(ticket); err != nil {
		return policy.ApprovalTicket{}, err
	}
	return ticket, nil
}

func ValidateRevocationList(list RevocationList) error {
	if err := schema.ValidateValue(schema.ApprovalRevocationsSchemaID, list); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, revoked := range list.RevokedTickets {
		ticketID := strings.TrimSpace(revoked.TicketID)
		if ticketID == "" {
			return fmt.Errorf("revoked ticket id is required")
		}
		if ticketID != revoked.TicketID {
			return fmt.Errorf("revoked ticket id %q contains surrounding whitespace", revoked.TicketID)
		}
		if seen[ticketID] {
			return fmt.Errorf("duplicate revoked ticket id %q", ticketID)
		}
		seen[ticketID] = true
		if strings.TrimSpace(revoked.Reason) == "" {
			return fmt.Errorf("revoked ticket %q reason is required", ticketID)
		}
	}
	return nil
}

func ReadRevocationList(path string) (RevocationList, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return RevocationList{}, fmt.Errorf("read approval revocation list: %w", err)
	}
	if err := schema.ValidateBytes(schema.ApprovalRevocationsSchemaID, bytes); err != nil {
		return RevocationList{}, err
	}
	var list RevocationList
	if err := json.Unmarshal(bytes, &list); err != nil {
		return RevocationList{}, fmt.Errorf("decode approval revocation list: %w", err)
	}
	if err := ValidateRevocationList(list); err != nil {
		return RevocationList{}, err
	}
	return list, nil
}

func WriteRevocationList(path string, list RevocationList) error {
	if err := ValidateRevocationList(list); err != nil {
		return err
	}
	if err := schema.WriteJSONFile(path, schema.ApprovalRevocationsSchemaID, list, 0o644); err != nil {
		return fmt.Errorf("write approval revocation list: %w", err)
	}
	return nil
}

func RevokedTicketIDs(lists []RevocationList) map[string]bool {
	ids := map[string]bool{}
	for _, list := range lists {
		for _, revoked := range list.RevokedTickets {
			ids[revoked.TicketID] = true
		}
	}
	return ids
}

func ValidateTicket(ticket policy.ApprovalTicket) error {
	if strings.TrimSpace(ticket.ExpiresAt) != "" {
		if _, err := time.Parse(time.RFC3339, ticket.ExpiresAt); err != nil {
			return fmt.Errorf("approval ticket %q expires_at must be RFC3339: %w", ticket.TicketID, err)
		}
	}
	if err := schema.ValidateValue(schema.ApprovalTicketSchemaID, ticket); err != nil {
		return err
	}
	return nil
}

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

func ReadTicket(path string) (policy.ApprovalTicket, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return policy.ApprovalTicket{}, fmt.Errorf("read approval ticket: %w", err)
	}
	if err := schema.ValidateBytes(schema.ApprovalTicketSchemaID, bytes); err != nil {
		return policy.ApprovalTicket{}, err
	}
	var ticket policy.ApprovalTicket
	if err := json.Unmarshal(bytes, &ticket); err != nil {
		return policy.ApprovalTicket{}, fmt.Errorf("decode approval ticket: %w", err)
	}
	return ticket, nil
}

func WriteTicket(path string, ticket policy.ApprovalTicket) error {
	if err := ValidateTicket(ticket); err != nil {
		return err
	}
	if err := schema.WriteJSONFile(path, schema.ApprovalTicketSchemaID, ticket, 0o644); err != nil {
		return fmt.Errorf("write approval ticket: %w", err)
	}
	return nil
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

func defaultTicketID(taskID string, effectType string, resource string) string {
	return "approval-" + portableFragment(taskID) + "-" + portableFragment(effectType) + "-" + portableFragment(resource)
}

func portableFragment(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastHyphen := false
	lastUnderscore := false
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			lastHyphen = false
			lastUnderscore = false
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !lastHyphen {
				b.WriteByte('-')
				lastHyphen = true
				lastUnderscore = false
			}
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
			lastHyphen = false
		}
	}
	return strings.Trim(b.String(), "_-")
}
