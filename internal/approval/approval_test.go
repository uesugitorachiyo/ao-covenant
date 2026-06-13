package approval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

func TestCreateBuildsSchemaValidApprovedTicket(t *testing.T) {
	ticket, err := Create(CreateInput{
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Approved:   true,
		Reason:     "operator approved local test command",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if ticket.SchemaVersion != policy.ApprovalTicketSchemaVersion {
		t.Fatalf("schema version = %q, want %q", ticket.SchemaVersion, policy.ApprovalTicketSchemaVersion)
	}
	if ticket.TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("ticket id = %q", ticket.TicketID)
	}
	if ticket.TaskID != "scripted_change" || ticket.EffectType != "process.spawn" || ticket.Resource != "make-test" {
		t.Fatalf("ticket fields = %+v", ticket)
	}
	if !ticket.Approved {
		t.Fatalf("approved = false, want true")
	}
}

func TestCreatePreservesOperatorAndExpiration(t *testing.T) {
	ticket, err := Create(CreateInput{
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Approved:   true,
		Reason:     "operator approved local test command",
		OperatorID: "operator_alice",
		ExpiresAt:  "2099-01-02T03:04:05Z",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if ticket.OperatorID != "operator_alice" {
		t.Fatalf("operator id = %q, want operator_alice", ticket.OperatorID)
	}
	if ticket.ExpiresAt != "2099-01-02T03:04:05Z" {
		t.Fatalf("expires at = %q", ticket.ExpiresAt)
	}
}

func TestValidateTicketRejectsInvalidExpiration(t *testing.T) {
	ticket := policy.ApprovalTicket{
		SchemaVersion: policy.ApprovalTicketSchemaVersion,
		TicketID:      "ticket_process",
		TaskID:        "scripted_change",
		EffectType:    "process.spawn",
		Resource:      "make-test",
		Approved:      true,
		Reason:        "operator approved local test command",
		ExpiresAt:     "tomorrow",
	}

	err := ValidateTicket(ticket)

	if err == nil || !strings.Contains(err.Error(), "expires_at must be RFC3339") {
		t.Fatalf("ValidateTicket error = %v, want RFC3339 expiration failure", err)
	}
}

func TestValidateTicketRejectsSchemaInvalidTicket(t *testing.T) {
	ticket := policy.ApprovalTicket{
		SchemaVersion: policy.ApprovalTicketSchemaVersion,
		TicketID:      "BadTicket",
		TaskID:        "scripted_change",
		EffectType:    "process.spawn",
		Resource:      "make-test",
		Approved:      true,
		Reason:        "operator approved local test command",
	}

	err := ValidateTicket(ticket)

	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.approval-ticket.v1") {
		t.Fatalf("ValidateTicket error = %v, want schema validation failure", err)
	}
}

func TestValidateAgainstContractRequiresDeclaredSideEffect(t *testing.T) {
	c := validApprovalContract(t)
	ticket, err := Create(CreateInput{
		TaskID:     "scripted_change",
		EffectType: "network.request",
		Resource:   "api.example.test",
		Approved:   true,
		Reason:     "operator approved network request",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	err = ValidateAgainstContract(c, ticket)

	if err == nil || !strings.Contains(err.Error(), "does not match a declared side effect") {
		t.Fatalf("ValidateAgainstContract error = %v, want declared side effect mismatch", err)
	}
}

func TestAttachAddsTicketAndValidatesContract(t *testing.T) {
	c := validApprovalContract(t)
	ticket, err := Create(CreateInput{
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Approved:   true,
		Reason:     "operator approved local test command",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	attached, err := Attach(c, ticket)
	if err != nil {
		t.Fatalf("Attach error: %v", err)
	}
	if len(attached.Approvals) != 1 {
		t.Fatalf("approvals len = %d, want 1", len(attached.Approvals))
	}
	if attached.Approvals[0].TicketID != ticket.TicketID {
		t.Fatalf("attached ticket id = %q, want %q", attached.Approvals[0].TicketID, ticket.TicketID)
	}
	if err := contract.Validate(attached); err != nil {
		t.Fatalf("attached contract validation: %v", err)
	}

	attachedAgain, err := Attach(attached, ticket)
	if err != nil {
		t.Fatalf("Attach duplicate error: %v", err)
	}
	if len(attachedAgain.Approvals) != 1 {
		t.Fatalf("approvals len after duplicate attach = %d, want 1", len(attachedAgain.Approvals))
	}
}

func TestReadWriteTicketRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ticket.json")
	ticket, err := Create(CreateInput{
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Approved:   true,
		Reason:     "operator approved local test command",
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}

	if err := WriteTicket(path, ticket); err != nil {
		t.Fatalf("WriteTicket error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ticket file stat: %v", err)
	}
	read, err := ReadTicket(path)
	if err != nil {
		t.Fatalf("ReadTicket error: %v", err)
	}
	if read != ticket {
		t.Fatalf("read ticket = %+v, want %+v", read, ticket)
	}
}

func TestReadWriteRevocationListRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	list := RevocationList{
		SchemaVersion: RevocationListSchemaVersion,
		RevokedTickets: []RevokedTicket{
			{
				TicketID: "ticket_process",
				Reason:   "operator revoked process access",
			},
		},
	}

	if err := WriteRevocationList(path, list); err != nil {
		t.Fatalf("WriteRevocationList error: %v", err)
	}
	read, err := ReadRevocationList(path)
	if err != nil {
		t.Fatalf("ReadRevocationList error: %v", err)
	}

	if read.SchemaVersion != RevocationListSchemaVersion || len(read.RevokedTickets) != 1 || read.RevokedTickets[0].TicketID != "ticket_process" {
		t.Fatalf("read revocation list = %+v", read)
	}
}

func TestValidateRevocationListRejectsSchemaInvalidTicketID(t *testing.T) {
	list := RevocationList{
		SchemaVersion: RevocationListSchemaVersion,
		RevokedTickets: []RevokedTicket{
			{
				TicketID: "Bad Ticket",
				Reason:   "operator revoked malformed ticket",
			},
		},
	}

	err := ValidateRevocationList(list)

	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.approval-revocations.v1") {
		t.Fatalf("ValidateRevocationList error = %v, want schema validation failure", err)
	}
}

func TestReadRevocationListRejectsAdditionalProperty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	contents := `{
  "schema_version": "covenant.approval-revocations.v1",
  "revoked_tickets": [
    {
      "ticket_id": "ticket_process",
      "reason": "operator revoked process access",
      "unexpected": true
    }
  ]
}
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}

	_, err := ReadRevocationList(path)

	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.approval-revocations.v1") {
		t.Fatalf("ReadRevocationList error = %v, want schema validation failure", err)
	}
}

func TestRevokedTicketIDsCombinesLists(t *testing.T) {
	ids := RevokedTicketIDs([]RevocationList{
		{
			SchemaVersion: RevocationListSchemaVersion,
			RevokedTickets: []RevokedTicket{
				{TicketID: "ticket_one", Reason: "first"},
			},
		},
		{
			SchemaVersion: RevocationListSchemaVersion,
			RevokedTickets: []RevokedTicket{
				{TicketID: "ticket_two", Reason: "second"},
				{TicketID: "ticket_one", Reason: "duplicate"},
			},
		},
	})

	if len(ids) != 2 || !ids["ticket_one"] || !ids["ticket_two"] {
		t.Fatalf("ids = %+v, want ticket_one and ticket_two", ids)
	}
}

func validApprovalContract(t *testing.T) contract.Contract {
	t.Helper()
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: "make-test"},
	}
	c.Workspace.Writes = []string{}
	return c
}
