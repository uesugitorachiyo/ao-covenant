package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	covenantschema "github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const (
	AutonomousRepairGovernancePolicyVersion  = "covenant.autonomous-repair-governance-policy.v1"
	AutonomousRepairGovernanceRequestVersion = "covenant.autonomous-repair-governance-request.v1"
)

var autonomousRepairRiskyPathClasses = []string{
	"dependency",
	"workflow",
	"credential",
	"permission",
	"policy",
	"schema",
	"migration",
	"release",
	"security_boundary",
	"generated_artifact",
}

type AutonomousRepairGovernancePolicy struct {
	SchemaVersion            string                                      `json:"schema_version"`
	PolicyID                 string                                      `json:"policy_id"`
	ArchitectureContract     AutonomousRepairContractSource              `json:"architecture_contract"`
	Defaults                 AutonomousRepairPolicyDefaults              `json:"defaults"`
	RepositoryPolicies       map[string]AutonomousRepairRepositoryPolicy `json:"repository_policies"`
	RiskyPathClasses         []string                                    `json:"risky_path_classes"`
	PermanentlyDeniedActions []string                                    `json:"permanently_denied_actions"`
}

type AutonomousRepairContractSource struct {
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	SchemaIDs  []string `json:"schema_ids"`
}

type AutonomousRepairPolicyDefaults struct {
	DiscoveryMutationAuthorized bool                             `json:"discovery_mutation_authorized"`
	IssueTextCanAuthorize       bool                             `json:"issue_text_can_authorize"`
	RepositoryTextCanAuthorize  bool                             `json:"repository_text_can_authorize"`
	UnknownRepositoryPolicy     AutonomousRepairRepositoryPolicy `json:"unknown_repository_policy"`
	BranchProtectionBypass      bool                             `json:"branch_protection_bypass"`
}

type AutonomousRepairRepositoryPolicy struct {
	RepositoryClass    string   `json:"repository_class"`
	SoleAutoMergeOptIn bool     `json:"sole_auto_merge_opt_in"`
	PushTarget         string   `json:"push_target"`
	PullRequestMode    string   `json:"pull_request_mode"`
	RequiredChecks     []string `json:"required_checks"`
	AllowedActions     []string `json:"allowed_actions"`
}

type AutonomousRepairGovernanceRequest struct {
	SchemaVersion           string                            `json:"schema_version"`
	RequestID               string                            `json:"request_id"`
	Mode                    string                            `json:"mode"`
	Repository              string                            `json:"repository"`
	OwnershipClassAssertion *string                           `json:"ownership_class_assertion,omitempty"`
	IssueNumber             *int                              `json:"issue_number,omitempty"`
	Action                  string                            `json:"action,omitempty"`
	CurrentBaseSHA          string                            `json:"current_base_sha,omitempty"`
	ChangedPathClasses      []string                          `json:"changed_path_classes,omitempty"`
	ApprovedActionDigest    string                            `json:"approved_action_digest,omitempty"`
	RunEnvelope             *ArchitectureRunEnvelope          `json:"run_envelope,omitempty"`
	CandidateDecision       *ArchitectureCandidateDecision    `json:"candidate_decision,omitempty"`
	GovernanceDecision      *ArchitectureGovernanceDecision   `json:"governance_decision,omitempty"`
	ReviewerIndependence    *ArchitectureReviewerIndependence `json:"reviewer_independence,omitempty"`
	GitHubActionDigest      *ArchitectureGitHubActionDigest   `json:"github_action_digest,omitempty"`
}

type AutonomousRepairGovernanceDecision struct {
	Authorized         bool   `json:"authorized"`
	MutationAuthorized bool   `json:"mutation_authorized"`
	RepositoryClass    string `json:"repository_class"`
	ReasonCode         string `json:"reason_code"`
}

func DecodeAutonomousRepairGovernancePolicy(data []byte) (AutonomousRepairGovernancePolicy, error) {
	var policy AutonomousRepairGovernancePolicy
	if err := decodeStrictJSON(data, &policy); err != nil {
		return policy, fmt.Errorf("decode autonomous repair governance policy: %w", err)
	}
	if !validAutonomousRepairGovernancePolicy(policy) {
		return policy, fmt.Errorf("policy widens or mismatches autonomous repair authority")
	}
	return policy, nil
}

func DecodeAutonomousRepairGovernanceRequest(data []byte) (AutonomousRepairGovernanceRequest, error) {
	var request AutonomousRepairGovernanceRequest
	if err := covenantschema.ValidateBytes(covenantschema.AutonomousRepairGovernanceRequestSchemaID, data); err != nil {
		return request, fmt.Errorf("validate autonomous repair governance request: %w", err)
	}
	if err := decodeStrictJSON(data, &request); err != nil {
		return request, fmt.Errorf("decode autonomous repair governance request: %w", err)
	}
	if reason := validateAutonomousRepairRequestShape(request); reason != "" {
		return request, fmt.Errorf("%s", reason)
	}
	return request, nil
}

func EvaluateAutonomousRepairGovernance(policy AutonomousRepairGovernancePolicy, request AutonomousRepairGovernanceRequest, now time.Time) AutonomousRepairGovernanceDecision {
	repositoryPolicy, explicitlyConfigured := autonomousRepairRepositoryPolicy(policy, request.Repository)
	repositoryClass := repositoryPolicy.RepositoryClass
	deny := func(reason string) AutonomousRepairGovernanceDecision {
		return AutonomousRepairGovernanceDecision{
			RepositoryClass: repositoryClass,
			ReasonCode:      reason,
		}
	}
	allow := func(reason string, mutation bool) AutonomousRepairGovernanceDecision {
		return AutonomousRepairGovernanceDecision{
			Authorized:         true,
			MutationAuthorized: mutation,
			RepositoryClass:    repositoryClass,
			ReasonCode:         reason,
		}
	}

	if !validAutonomousRepairGovernancePolicy(policy) {
		return deny("invalid_policy")
	}
	if reason := validateAutonomousRepairRequestShape(request); reason != "" {
		return deny("invalid_request")
	}
	if err := covenantschema.ValidateValue(covenantschema.AutonomousRepairGovernanceRequestSchemaID, request); err != nil {
		return deny("malformed_canonical_authority")
	}
	if request.OwnershipClassAssertion != nil &&
		*request.OwnershipClassAssertion != repositoryClass {
		return deny("ownership_assertion_mismatch")
	}
	if request.Mode == "discovery" {
		return allow("read_only_discovery", false)
	}
	if reason := validateArchitectureRepairAuthority(policy, repositoryPolicy, explicitlyConfigured, request, now); reason != "" {
		return deny(reason)
	}

	action := request.Action
	if !slices.Contains(repositoryPolicy.AllowedActions, action) {
		return deny("action_not_allowed_by_repository_policy")
	}
	if slices.Contains(policy.PermanentlyDeniedActions, action) {
		return deny("permanently_denied_action")
	}

	switch repositoryClass {
	case "external":
		if action != "push_operator_fork" && action != "open_upstream_draft_pr" {
			return deny("external_draft_only")
		}
		return allow("external_draft_only", true)
	case "sole_control":
		if action == "auto_merge" {
			if !explicitlyConfigured || !repositoryPolicy.SoleAutoMergeOptIn {
				return deny("sole_control_auto_merge_not_opted_in")
			}
			return allow("sole_control_auto_merge", true)
		}
		return allow("sole_control_bounded_action", true)
	case "team":
		if action == "auto_merge" {
			return deny("team_auto_merge_denied")
		}
		if action == "request_merge_queue" {
			return allow("team_merge_queue", true)
		}
		return allow("team_bounded_action", true)
	default:
		return deny("invalid_repository_class")
	}
}

func validateAutonomousRepairRequestShape(request AutonomousRepairGovernanceRequest) string {
	if request.SchemaVersion != AutonomousRepairGovernanceRequestVersion ||
		request.RequestID == "" ||
		request.Repository == "" {
		return "invalid autonomous repair governance request identity"
	}
	if request.Mode == "discovery" {
		if request.OwnershipClassAssertion != nil ||
			request.IssueNumber != nil ||
			request.Action != "" ||
			request.CurrentBaseSHA != "" ||
			len(request.ChangedPathClasses) != 0 ||
			request.ApprovedActionDigest != "" ||
			request.RunEnvelope != nil ||
			request.CandidateDecision != nil ||
			request.GovernanceDecision != nil ||
			request.ReviewerIndependence != nil ||
			request.GitHubActionDigest != nil {
			return "discovery request contains write authority evidence"
		}
		return ""
	}
	if request.Mode != "write" ||
		request.IssueNumber == nil ||
		*request.IssueNumber < 1 ||
		request.CurrentBaseSHA == "" ||
		request.ApprovedActionDigest == "" ||
		request.RunEnvelope == nil ||
		request.CandidateDecision == nil ||
		request.GovernanceDecision == nil ||
		request.ReviewerIndependence == nil ||
		request.GitHubActionDigest == nil {
		return "write request is missing canonical authority evidence"
	}
	if !slices.Contains([]string{
		"push_operator_fork",
		"open_upstream_draft_pr",
		"open_ready_pr",
		"request_merge_queue",
		"auto_merge",
	}, request.Action) {
		return "write request action is not an Architecture v1 action"
	}
	return ""
}

func autonomousRepairRepositoryPolicy(policy AutonomousRepairGovernancePolicy, repository string) (AutonomousRepairRepositoryPolicy, bool) {
	repositoryPolicy, ok := policy.RepositoryPolicies[repository]
	if ok {
		return repositoryPolicy, true
	}
	return policy.Defaults.UnknownRepositoryPolicy, false
}

func validAutonomousRepairGovernancePolicy(policy AutonomousRepairGovernancePolicy) bool {
	requiredSchemas := []string{
		"ao.architecture.autonomous-issue-repair.run-envelope.v1",
		"ao.architecture.autonomous-issue-repair.discovery-result.v1",
		"ao.architecture.autonomous-issue-repair.candidate-decision.v1",
		"ao.architecture.autonomous-issue-repair.event.v1",
		"ao.architecture.autonomous-issue-repair.checkpoint.v1",
		"ao.architecture.autonomous-issue-repair.governance-decision.v1",
		"ao.architecture.autonomous-issue-repair.reviewer-independence.v1",
		"ao.architecture.autonomous-issue-repair.github-action-digest.v1",
	}
	if policy.SchemaVersion != AutonomousRepairGovernancePolicyVersion ||
		policy.PolicyID != "autonomous-repair-governance-v1" ||
		policy.ArchitectureContract.Repository != "uesugitorachiyo/ao-architecture" ||
		policy.ArchitectureContract.Commit != "b8c64860003238ab45fe7c76d7e8950f80a4043b" ||
		!sameUniqueStrings(policy.ArchitectureContract.SchemaIDs, requiredSchemas) ||
		policy.Defaults.DiscoveryMutationAuthorized ||
		policy.Defaults.IssueTextCanAuthorize ||
		policy.Defaults.RepositoryTextCanAuthorize ||
		policy.Defaults.BranchProtectionBypass ||
		!sameUniqueStrings(policy.RiskyPathClasses, autonomousRepairRiskyPathClasses) ||
		!sameUniqueStrings(policy.PermanentlyDeniedActions, []string{
			"open_ready_pr_external",
			"request_merge_queue_external",
			"auto_merge_external",
			"approve_review",
			"mutate_issue",
		}) ||
		!validAutonomousRepairRepositoryPolicy(policy.Defaults.UnknownRepositoryPolicy, false) ||
		policy.Defaults.UnknownRepositoryPolicy.RepositoryClass != "external" {
		return false
	}
	if len(policy.RepositoryPolicies) == 0 {
		return false
	}
	for repository, repositoryPolicy := range policy.RepositoryPolicies {
		if !validRepositoryName(repository) ||
			!validAutonomousRepairRepositoryPolicy(repositoryPolicy, true) {
			return false
		}
		if strings.HasPrefix(repository, "uesugitorachiyo/ao") &&
			repositoryPolicy.SoleAutoMergeOptIn {
			return false
		}
	}
	return true
}

func validAutonomousRepairRepositoryPolicy(policy AutonomousRepairRepositoryPolicy, allowSole bool) bool {
	if !slices.Contains([]string{"sole_control", "team", "external"}, policy.RepositoryClass) ||
		!slices.Contains([]string{"policy_authorized_branch", "operator_owned_fork"}, policy.PushTarget) ||
		!slices.Contains([]string{"draft_or_ready_by_policy", "upstream_draft_only"}, policy.PullRequestMode) ||
		len(policy.RequiredChecks) == 0 ||
		!uniqueNonemptyStrings(policy.RequiredChecks) ||
		len(policy.AllowedActions) == 0 ||
		!uniqueNonemptyStrings(policy.AllowedActions) {
		return false
	}
	for _, action := range policy.AllowedActions {
		if !slices.Contains([]string{
			"push_operator_fork",
			"open_upstream_draft_pr",
			"open_ready_pr",
			"request_merge_queue",
			"auto_merge",
		}, action) {
			return false
		}
	}
	switch policy.RepositoryClass {
	case "external":
		return !policy.SoleAutoMergeOptIn &&
			policy.PushTarget == "operator_owned_fork" &&
			policy.PullRequestMode == "upstream_draft_only" &&
			everyStringIn(policy.AllowedActions, []string{"push_operator_fork", "open_upstream_draft_pr"})
	case "team":
		return !policy.SoleAutoMergeOptIn &&
			!slices.Contains(policy.AllowedActions, "auto_merge")
	case "sole_control":
		return allowSole
	default:
		return false
	}
}

func validRepositoryName(repository string) bool {
	parts := strings.Split(repository, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func sameUniqueStrings(got []string, want []string) bool {
	return len(got) == len(want) &&
		uniqueNonemptyStrings(got) &&
		everyStringIn(got, want) &&
		everyStringIn(want, got)
}

func uniqueNonemptyStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func everyStringIn(values []string, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
