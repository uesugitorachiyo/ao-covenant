package verify

import "github.com/uesugitorachiyo/ao-covenant/internal/policy"

const ResultSchemaVersion = "covenant.verify-result.v1"

type Options struct {
	LedgerPath               string
	EvidencePath             string
	WorkspaceDir             string
	RevokedApprovalTicketIDs map[string]bool
}

type Result struct {
	SchemaVersion      string               `json:"schema_version"`
	Verified           bool                 `json:"verified"`
	RunID              string               `json:"run_id"`
	EventCount         int                  `json:"event_count"`
	ArtifactCount      int                  `json:"artifact_count"`
	InputSnapshotCount int                  `json:"input_snapshot_count"`
	FailureCount       int                  `json:"failure_count"`
	Failures           []FailureSummary     `json:"failures"`
	PolicyExplanations []policy.Explanation `json:"policy_explanations"`
	LedgerDigest       string               `json:"ledger_digest"`
	LastEventHash      string               `json:"last_event_hash"`
	PublicKeySHA256    string               `json:"public_key_sha256,omitempty"`
}

type FailureSummary struct {
	FailureID string `json:"failure_id"`
	EventID   string `json:"event_id"`
	EventLine int    `json:"event_line"`
	TaskID    string `json:"task_id,omitempty"`
	Phase     string `json:"phase"`
	Reason    string `json:"reason"`
}
