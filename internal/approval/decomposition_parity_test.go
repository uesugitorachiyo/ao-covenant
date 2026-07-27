package approval

import (
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

func TestApprovalReplacementAndContractBindingParityAcrossOwnershipBoundary(t *testing.T) {
	original := validApprovalContract(t)
	first, err := Create(CreateInput{
		TicketID:   "ticket_process",
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   "make-test",
		Approved:   true,
		Reason:     "first bounded approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	attached, err := Attach(original, first)
	if err != nil {
		t.Fatal(err)
	}

	replacement := first
	replacement.Reason = "replacement bounded approval"
	replaced, err := Attach(attached, replacement)
	if err != nil {
		t.Fatal(err)
	}

	if len(original.Approvals) != 0 {
		t.Fatalf("Attach mutated original contract approvals: %+v", original.Approvals)
	}
	if len(replaced.Approvals) != 1 || replaced.Approvals[0] != replacement {
		t.Fatalf("replacement parity changed: %+v", replaced.Approvals)
	}
	if err := ValidateAgainstContract(replaced, replacement); err != nil {
		t.Fatalf("replacement no longer binds to declared contract action: %v", err)
	}
	if _, err := contract.Digest(replaced); err != nil {
		t.Fatalf("attached contract lost canonical digestability: %v", err)
	}

	mismatched := policy.ApprovalTicket{
		SchemaVersion: policy.ApprovalTicketSchemaVersion,
		TicketID:      "ticket_process",
		TaskID:        "scripted_change",
		EffectType:    "process.spawn",
		Resource:      "make-release",
		Approved:      true,
		Reason:        "broadened resource must remain denied",
	}
	if err := ValidateAgainstContract(replaced, mismatched); err == nil {
		t.Fatal("broadened replacement ticket unexpectedly bound to contract")
	}
}
