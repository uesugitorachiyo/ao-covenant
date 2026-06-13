package run

import (
	"github.com/uesugitorachiyo/ao-covenant/internal/closure"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

const (
	EventSchemaVersion         = "covenant.event.v1"
	ArtifactRefSchemaVersion   = "covenant.artifact-ref.v1"
	InputSnapshotSchemaVersion = "covenant.input-snapshot.v1"
	EvidencePackSchemaVersion  = "covenant.evidence-pack.v1"
	FailureSchemaVersion       = "covenant.failure.v1"
	GenesisEventHash           = "0000000000000000000000000000000000000000000000000000000000000000"

	FailurePhasePolicy    = "policy"
	FailurePhaseAdapter   = "adapter"
	FailurePhaseExecution = "execution"
	FailurePhaseClosure   = "closure"
)

type Options struct {
	WorkspaceDir             string
	OutDir                   string
	RunID                    string
	ActionAdapter            ActionAdapter
	ProcessAllowlist         []string
	RevokedApprovalTicketIDs map[string]bool
}

type Result struct {
	RunDir           string
	LedgerPath       string
	EvidencePackPath string
	EvidencePack     EvidencePack
}

type Event struct {
	SchemaVersion     string   `json:"schema_version"`
	EventID           string   `json:"event_id"`
	Sequence          int      `json:"sequence"`
	RunID             string   `json:"run_id"`
	PreviousEventHash string   `json:"previous_event_hash"`
	EventHash         string   `json:"event_hash"`
	Type              string   `json:"type"`
	TaskID            string   `json:"task_id,omitempty"`
	Status            string   `json:"status"`
	Message           string   `json:"message,omitempty"`
	ArtifactIDs       []string `json:"artifact_ids,omitempty"`
	DecisionID        string   `json:"decision_id,omitempty"`
	Decision          string   `json:"decision,omitempty"`
	EffectType        string   `json:"effect_type,omitempty"`
	Resource          string   `json:"resource,omitempty"`
	ApprovalTicketID  string   `json:"approval_ticket_id,omitempty"`
}

type ArtifactRef struct {
	SchemaVersion   string `json:"schema_version"`
	ArtifactID      string `json:"artifact_id"`
	URI             string `json:"uri"`
	Digest          string `json:"digest"`
	MediaType       string `json:"media_type"`
	ProducerEventID string `json:"producer_event_id"`
	Path            string `json:"path"`
}

type InputSnapshot struct {
	SchemaVersion string `json:"schema_version"`
	SnapshotID    string `json:"snapshot_id"`
	SourcePath    string `json:"source_path"`
	SnapshotPath  string `json:"snapshot_path"`
	Digest        string `json:"digest"`
	MediaType     string `json:"media_type"`
}

type EvidencePack struct {
	SchemaVersion    string            `json:"schema_version"`
	RunID            string            `json:"run_id"`
	ContractDigest   string            `json:"contract_digest"`
	LedgerDigest     string            `json:"ledger_digest"`
	RunStatus        string            `json:"run_status"`
	ArtifactManifest []ArtifactRef     `json:"artifact_manifest"`
	InputSnapshots   []InputSnapshot   `json:"input_snapshots"`
	PolicyDecisions  []policy.Decision `json:"policy_decisions"`
	Failures         []FailureRecord   `json:"failures"`
	ClosureMatrix    closure.Matrix    `json:"closure_matrix"`
}

type FailureRecord struct {
	SchemaVersion string `json:"schema_version"`
	FailureID     string `json:"failure_id"`
	EventID       string `json:"event_id"`
	TaskID        string `json:"task_id,omitempty"`
	Phase         string `json:"phase"`
	Reason        string `json:"reason"`
}

type taskState struct {
	task   contract.Task
	status string
}
