package contract

import "github.com/uesugitorachiyo/ao-covenant/internal/policy"

const ContractSchemaVersion = "covenant.contract.v1"

type Contract struct {
	SchemaVersion string                  `json:"schema_version"`
	Objective     string                  `json:"objective"`
	Workspace     WorkspaceScope          `json:"workspace"`
	Obligations   []Obligation            `json:"obligations"`
	Tasks         []Task                  `json:"tasks"`
	Policy        PolicyProfile           `json:"policy"`
	Approvals     []policy.ApprovalTicket `json:"approvals,omitempty"`
	Evaluator     EvaluatorRules          `json:"evaluator"`
}

type WorkspaceScope struct {
	Root   string   `json:"root"`
	Reads  []string `json:"reads"`
	Writes []string `json:"writes"`
}

type Obligation struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Required bool   `json:"required"`
}

type Task struct {
	ID                  string      `json:"id"`
	Kind                string      `json:"kind"`
	Adapter             string      `json:"adapter"`
	DependsOn           []string    `json:"depends_on"`
	Obligations         []string    `json:"obligations"`
	TimeoutSecs         int         `json:"timeout_seconds"`
	DeclaredSideEffects []ActionRef `json:"declared_side_effects,omitempty"`
}

type ActionRef struct {
	Type     string `json:"type"`
	Resource string `json:"resource"`
}

type PolicyProfile struct {
	Mode string `json:"mode"`
}

type EvaluatorRules struct {
	RequiredObligations []string `json:"required_obligations"`
}
