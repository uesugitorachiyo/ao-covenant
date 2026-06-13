package closure

import (
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

const (
	MatrixSchemaVersion = "covenant.closure-matrix.v1"

	StatusAccepted = "accepted"
	StatusRejected = "rejected"

	RowStatusClosed = "closed"
	RowStatusOpen   = "open"
)

type Input struct {
	RunID           string
	ContractDigest  string
	RunStatus       string
	Obligations     []contract.Obligation
	Tasks           []contract.Task
	TaskStatuses    map[string]string
	TaskArtifacts   map[string][]string
	PolicyDecisions []policy.Decision
}

type Matrix struct {
	SchemaVersion  string `json:"schema_version"`
	RunID          string `json:"run_id"`
	ContractDigest string `json:"contract_digest"`
	Status         string `json:"status"`
	Rows           []Row  `json:"rows"`
}

type Row struct {
	ObligationID      string   `json:"obligation_id"`
	Required          bool     `json:"required"`
	Status            string   `json:"status"`
	TaskIDs           []string `json:"task_ids"`
	ArtifactIDs       []string `json:"artifact_ids"`
	PolicyDecisionIDs []string `json:"policy_decision_ids"`
	Reason            string   `json:"reason"`
}
