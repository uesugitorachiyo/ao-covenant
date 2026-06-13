package policy

import "time"

const (
	ApprovalTicketSchemaVersion = "covenant.approval-ticket.v1"
	DecisionSchemaVersion       = "covenant.policy-decision.v1"

	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

type Input struct {
	Mode                     string
	WorkspaceReads           []string
	WorkspaceWrites          []string
	TaskID                   string
	Actions                  []ActionRef
	Approvals                []ApprovalTicket
	EvaluationTime           time.Time
	RevokedApprovalTicketIDs map[string]bool
}

type ActionRef struct {
	Type     string `json:"type"`
	Resource string `json:"resource"`
}

type ApprovalTicket struct {
	SchemaVersion string `json:"schema_version"`
	TicketID      string `json:"ticket_id"`
	TaskID        string `json:"task_id"`
	EffectType    string `json:"effect_type"`
	Resource      string `json:"resource"`
	Approved      bool   `json:"approved"`
	Reason        string `json:"reason"`
	OperatorID    string `json:"operator_id,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

type Decision struct {
	SchemaVersion    string `json:"schema_version"`
	DecisionID       string `json:"decision_id"`
	TaskID           string `json:"task_id"`
	EffectType       string `json:"effect_type"`
	Resource         string `json:"resource"`
	Decision         string `json:"decision"`
	Reason           string `json:"reason"`
	ApprovalTicketID string `json:"approval_ticket_id,omitempty"`
}
