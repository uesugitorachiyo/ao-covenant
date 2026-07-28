package policy

import (
	"fmt"

	covenantschema "github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const AutonomousRepairGitHubExecutionPolicyVersion = "covenant.autonomous-repair-github-execution-policy.v1"

type AutonomousRepairGitHubExecutionPolicy struct {
	SchemaVersion                string                                          `json:"schema_version"`
	PolicyID                     string                                          `json:"policy_id"`
	ArchitectureWorkflowContract AutonomousRepairWorkflowContractSource          `json:"architecture_workflow_contract"`
	PushOperatorFork             AutonomousRepairPushOperatorForkPolicy          `json:"push_operator_fork"`
	OpenUpstreamDraftPR          AutonomousRepairOpenUpstreamDraftPRPolicy       `json:"open_upstream_draft_pr"`
	WriteBudget                  AutonomousRepairGitHubWriteBudget               `json:"write_budget"`
	Credentials                  AutonomousRepairGitHubCredentialPolicy          `json:"credentials"`
	Safety                       AutonomousRepairGitHubExecutionSafetyBoundaries `json:"safety"`
}

type AutonomousRepairWorkflowContractSource struct {
	Repository      string `json:"repository"`
	Commit          string `json:"commit"`
	Path            string `json:"path"`
	Schema          string `json:"schema"`
	SourceSHA256    string `json:"source_sha256"`
	SemanticsSHA256 string `json:"semantics_sha256"`
}

type AutonomousRepairPushOperatorForkPolicy struct {
	ForkLookup          string `json:"fork_lookup"`
	ForkAbsent          string `json:"fork_absent"`
	ForkPresent         string `json:"fork_present"`
	BranchAbsent        string `json:"branch_absent"`
	BranchPresent       string `json:"branch_present"`
	ForceUpdateAllowed  bool   `json:"force_update_allowed"`
	UpstreamPushAllowed bool   `json:"upstream_push_allowed"`
}

type AutonomousRepairOpenUpstreamDraftPRPolicy struct {
	Lookup                string `json:"lookup"`
	Absent                string `json:"absent"`
	Present               string `json:"present"`
	UpdateAllowed         bool   `json:"update_allowed"`
	ReadyForReviewAllowed bool   `json:"ready_for_review_allowed"`
	ReviewAllowed         bool   `json:"review_allowed"`
	MergeAllowed          bool   `json:"merge_allowed"`
}

type AutonomousRepairGitHubWriteBudget struct {
	ForkCreates    int `json:"fork_creates"`
	BranchCreates  int `json:"branch_creates"`
	DraftPRCreates int `json:"draft_pr_creates"`
}

type AutonomousRepairGitHubCredentialPolicy struct {
	AmbientOnly bool `json:"ambient_only"`
	Serialized  bool `json:"serialized"`
}

type AutonomousRepairGitHubExecutionSafetyBoundaries struct {
	IssueListGrantsMutationAuthority             bool `json:"issue_list_grants_mutation_authority"`
	SuccessorMayWidenAuthority                   bool `json:"successor_may_widen_authority"`
	UnknownGovernanceDefaultsToExternalDraftOnly bool `json:"unknown_governance_defaults_to_external_draft_only"`
	ExternalMergeAuthorized                      bool `json:"external_merge_authorized"`
}

func DecodeAutonomousRepairGitHubExecutionPolicy(data []byte) (AutonomousRepairGitHubExecutionPolicy, error) {
	var policy AutonomousRepairGitHubExecutionPolicy
	if err := covenantschema.ValidateBytes(covenantschema.AutonomousRepairGitHubExecutionPolicySchemaID, data); err != nil {
		return policy, fmt.Errorf("validate autonomous repair GitHub execution policy: %w", err)
	}
	if err := decodeStrictJSON(data, &policy); err != nil {
		return policy, fmt.Errorf("decode autonomous repair GitHub execution policy: %w", err)
	}
	if !validAutonomousRepairGitHubExecutionPolicy(policy) {
		return policy, fmt.Errorf("policy widens or mismatches autonomous repair GitHub execution authority")
	}
	return policy, nil
}

func validAutonomousRepairGitHubExecutionPolicy(policy AutonomousRepairGitHubExecutionPolicy) bool {
	return policy.SchemaVersion == AutonomousRepairGitHubExecutionPolicyVersion &&
		policy.PolicyID == "autonomous-repair-github-execution-v1" &&
		policy.ArchitectureWorkflowContract.Repository == "uesugitorachiyo/ao-architecture" &&
		policy.ArchitectureWorkflowContract.Commit == "8e6f247b800b60c520b4e967f7553974a20ec2f8" &&
		policy.ArchitectureWorkflowContract.Path == "stack/github-issue-workflow-contracts.json" &&
		policy.ArchitectureWorkflowContract.Schema == "ao.architecture.github-issue-workflow-contracts.v0.1" &&
		policy.ArchitectureWorkflowContract.SourceSHA256 == "60bd07fa4e02d38f0321aa138bb53ca3f89e44499621a7e0369065bca88889ae" &&
		policy.ArchitectureWorkflowContract.SemanticsSHA256 == "2c6835289c508cd2954df545f93a1262c0616de87917bb1f749488376087b9b4" &&
		policy.PushOperatorFork.ForkLookup == "required_before_write" &&
		policy.PushOperatorFork.ForkAbsent == "create_then_exact_readback" &&
		policy.PushOperatorFork.ForkPresent == "reuse_only_exact_owner_parent_and_default_branch" &&
		policy.PushOperatorFork.BranchAbsent == "create_at_exact_approved_head" &&
		policy.PushOperatorFork.BranchPresent == "reuse_only_at_exact_approved_head" &&
		!policy.PushOperatorFork.ForceUpdateAllowed &&
		!policy.PushOperatorFork.UpstreamPushAllowed &&
		policy.OpenUpstreamDraftPR.Lookup == "exact_base_head_open_pull_requests" &&
		policy.OpenUpstreamDraftPR.Absent == "create_once_then_exact_readback" &&
		policy.OpenUpstreamDraftPR.Present == "reuse_only_exact_draft_identity" &&
		!policy.OpenUpstreamDraftPR.UpdateAllowed &&
		!policy.OpenUpstreamDraftPR.ReadyForReviewAllowed &&
		!policy.OpenUpstreamDraftPR.ReviewAllowed &&
		!policy.OpenUpstreamDraftPR.MergeAllowed &&
		policy.WriteBudget.ForkCreates == 1 &&
		policy.WriteBudget.BranchCreates == 1 &&
		policy.WriteBudget.DraftPRCreates == 1 &&
		policy.Credentials.AmbientOnly &&
		!policy.Credentials.Serialized &&
		!policy.Safety.IssueListGrantsMutationAuthority &&
		!policy.Safety.SuccessorMayWidenAuthority &&
		policy.Safety.UnknownGovernanceDefaultsToExternalDraftOnly &&
		!policy.Safety.ExternalMergeAuthorized
}
