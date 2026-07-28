package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
)

const (
	AutonomousRepairGovernancePolicyVersion  = "covenant.autonomous-repair-governance-policy.v1"
	AutonomousRepairGovernanceRequestVersion = "covenant.autonomous-repair-governance-request.v1"
)

type AutonomousRepairGovernancePolicy struct {
	SchemaVersion            string                         `json:"schema_version"`
	PolicyID                 string                         `json:"policy_id"`
	ArchitectureContract     AutonomousRepairContractSource `json:"architecture_contract"`
	Defaults                 AutonomousRepairPolicyDefaults `json:"defaults"`
	RiskyPathClasses         []string                       `json:"risky_path_classes"`
	PermanentlyDeniedActions []string                       `json:"permanently_denied_actions"`
}

type AutonomousRepairContractSource struct {
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	SchemaIDs  []string `json:"schema_ids"`
}

type AutonomousRepairPolicyDefaults struct {
	DiscoveryMutationAuthorized bool   `json:"discovery_mutation_authorized"`
	IssueTextCanAuthorize       bool   `json:"issue_text_can_authorize"`
	RepositoryTextCanAuthorize  bool   `json:"repository_text_can_authorize"`
	UnknownRepositoryClass      string `json:"unknown_repository_class"`
	SoleControlAutoMerge        bool   `json:"sole_control_auto_merge"`
	BranchProtectionBypass      bool   `json:"branch_protection_bypass"`
}

type AutonomousRepairGovernanceRequest struct {
	SchemaVersion            string                           `json:"schema_version"`
	RequestID                string                           `json:"request_id"`
	Repository               string                           `json:"repository"`
	IssueNumber              int                              `json:"issue_number"`
	Action                   string                           `json:"action"`
	Ownership                AutonomousRepairOwnership        `json:"ownership"`
	IssueTextAuthorizes      bool                             `json:"issue_text_authorizes"`
	RepositoryTextAuthorizes bool                             `json:"repository_text_authorizes"`
	SecuritySensitive        bool                             `json:"security_sensitive"`
	ChangedPathClasses       []string                         `json:"changed_path_classes"`
	ExpectedChecks           []string                         `json:"expected_checks"`
	ObservedChecks           []AutonomousRepairCheck          `json:"observed_checks"`
	ExpectedHeadSHA          string                           `json:"expected_head_sha"`
	ObservedHeadSHA          string                           `json:"observed_head_sha"`
	ExpectedBaseSHA          string                           `json:"expected_base_sha"`
	CurrentBaseSHA           string                           `json:"current_base_sha"`
	BranchProtectionBypass   bool                             `json:"branch_protection_bypass"`
	ActionDigest             AutonomousRepairActionDigest     `json:"action_digest"`
	Reviewer                 AutonomousRepairReviewerApproval `json:"reviewer"`
}

type AutonomousRepairOwnership struct {
	Source            string `json:"source"`
	RepositoryClass   string `json:"repository_class"`
	Repository        string `json:"repository"`
	AutoMergeOptIn    bool   `json:"auto_merge_opt_in"`
	OperatorOwnedFork bool   `json:"operator_owned_fork"`
	UpstreamDraft     bool   `json:"upstream_draft"`
}

type AutonomousRepairCheck struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
	HeadSHA    string `json:"head_sha"`
}

type AutonomousRepairActionDigest struct {
	Expected    string `json:"expected"`
	Observed    string `json:"observed"`
	Repository  string `json:"repository"`
	IssueNumber int    `json:"issue_number"`
	Action      string `json:"action"`
	BaseSHA     string `json:"base_sha"`
	HeadSHA     string `json:"head_sha"`
	ApprovedAt  string `json:"approved_at"`
	ExpiresAt   string `json:"expires_at"`
}

type AutonomousRepairReviewerApproval struct {
	Kind       string `json:"kind"`
	Approved   bool   `json:"approved"`
	HeadSHA    string `json:"head_sha"`
	ObservedAt string `json:"observed_at"`
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
	if policy.SchemaVersion != AutonomousRepairGovernancePolicyVersion {
		return policy, fmt.Errorf("unsupported policy schema_version %q", policy.SchemaVersion)
	}
	if !validAutonomousRepairGovernancePolicy(policy) {
		return policy, fmt.Errorf("policy widens or mismatches autonomous repair authority")
	}
	return policy, nil
}

func DecodeAutonomousRepairGovernanceRequest(data []byte) (AutonomousRepairGovernanceRequest, error) {
	var request AutonomousRepairGovernanceRequest
	if err := decodeStrictJSON(data, &request); err != nil {
		return request, fmt.Errorf("decode autonomous repair governance request: %w", err)
	}
	if request.SchemaVersion != AutonomousRepairGovernanceRequestVersion {
		return request, fmt.Errorf("unsupported request schema_version %q", request.SchemaVersion)
	}
	if !validAutonomousRepairGovernanceRequest(request) {
		return request, fmt.Errorf("invalid autonomous repair governance request identity")
	}
	return request, nil
}

func EvaluateAutonomousRepairGovernance(policy AutonomousRepairGovernancePolicy, request AutonomousRepairGovernanceRequest, now time.Time) AutonomousRepairGovernanceDecision {
	repositoryClass := request.Ownership.RepositoryClass
	if repositoryClass == "unknown" {
		repositoryClass = policy.Defaults.UnknownRepositoryClass
	}
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
	if !validAutonomousRepairGovernanceRequest(request) {
		return deny("invalid_request")
	}
	if request.IssueTextAuthorizes || request.RepositoryTextAuthorizes {
		return deny("untrusted_text_authority")
	}
	if request.Ownership.Source != "explicit_policy" ||
		request.Ownership.Repository != request.Repository {
		return deny("invalid_authority_source")
	}
	if request.Action == "discover" {
		return allow("read_only_discovery", false)
	}
	if request.SecuritySensitive {
		return deny("security_sensitive")
	}
	if slices.Contains(policy.PermanentlyDeniedActions, request.Action) {
		return deny("permanently_denied_action")
	}
	for _, pathClass := range request.ChangedPathClasses {
		if slices.Contains(policy.RiskyPathClasses, pathClass) {
			return deny("protected_path")
		}
	}
	if request.BranchProtectionBypass {
		return deny("branch_protection_bypass")
	}
	if request.ExpectedHeadSHA == "" || request.ObservedHeadSHA != request.ExpectedHeadSHA ||
		request.ActionDigest.HeadSHA != request.ExpectedHeadSHA {
		return deny("stale_head")
	}
	if request.ExpectedBaseSHA == "" || request.CurrentBaseSHA != request.ExpectedBaseSHA ||
		request.ActionDigest.BaseSHA != request.ExpectedBaseSHA {
		return deny("stale_base")
	}
	if reason := validateAutonomousRepairActionDigest(request, now); reason != "" {
		return deny(reason)
	}
	if reason := validateAutonomousRepairChecks(request); reason != "" {
		return deny(reason)
	}

	switch repositoryClass {
	case "external":
		if request.Action == "open_draft_pr" &&
			request.Ownership.OperatorOwnedFork &&
			request.Ownership.UpstreamDraft {
			return allow("external_draft_only", true)
		}
		return deny("external_draft_only")
	case "sole_control":
		if request.Action == "open_draft_pr" || request.Action == "mark_ready" {
			return allow("sole_control_bounded_action", true)
		}
		if request.Action == "auto_merge" {
			if policy.Defaults.SoleControlAutoMerge || !request.Ownership.AutoMergeOptIn {
				return deny("sole_control_auto_merge_not_opted_in")
			}
			return allow("sole_control_auto_merge", true)
		}
		return deny("action_not_authorized")
	case "team":
		if request.Action == "open_draft_pr" {
			return allow("team_draft", true)
		}
		if request.Action == "mark_ready" ||
			request.Action == "request_merge_queue" ||
			request.Action == "auto_merge" {
			if reason := validateIndependentReviewer(request, now); reason != "" {
				return deny(reason)
			}
			return allow("team_human_approval", true)
		}
		return deny("action_not_authorized")
	default:
		return deny("invalid_repository_class")
	}
}

func validAutonomousRepairGovernanceRequest(request AutonomousRepairGovernanceRequest) bool {
	if request.SchemaVersion != AutonomousRepairGovernanceRequestVersion ||
		request.RequestID == "" ||
		request.Repository == "" ||
		request.IssueNumber < 1 {
		return false
	}
	if !slices.Contains([]string{
		"discover",
		"open_draft_pr",
		"mark_ready",
		"request_merge_queue",
		"auto_merge",
		"issue_mutation",
		"submit_review",
	}, request.Action) {
		return false
	}
	return slices.Contains([]string{"sole_control", "team", "external", "unknown"}, request.Ownership.RepositoryClass)
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
	requiredRiskClasses := []string{
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
	return policy.SchemaVersion == AutonomousRepairGovernancePolicyVersion &&
		policy.PolicyID == "autonomous-repair-governance-v1" &&
		policy.ArchitectureContract.Repository == "uesugitorachiyo/ao-architecture" &&
		policy.ArchitectureContract.Commit == "b8c64860003238ab45fe7c76d7e8950f80a4043b" &&
		sameUniqueStrings(policy.ArchitectureContract.SchemaIDs, requiredSchemas) &&
		!policy.Defaults.DiscoveryMutationAuthorized &&
		!policy.Defaults.IssueTextCanAuthorize &&
		!policy.Defaults.RepositoryTextCanAuthorize &&
		policy.Defaults.UnknownRepositoryClass == "external" &&
		!policy.Defaults.SoleControlAutoMerge &&
		!policy.Defaults.BranchProtectionBypass &&
		sameUniqueStrings(policy.RiskyPathClasses, requiredRiskClasses) &&
		sameUniqueStrings(policy.PermanentlyDeniedActions, []string{"issue_mutation", "submit_review"})
}

func sameUniqueStrings(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotSet := make(map[string]struct{}, len(got))
	for _, value := range got {
		if _, exists := gotSet[value]; exists {
			return false
		}
		gotSet[value] = struct{}{}
	}
	for _, value := range want {
		if _, exists := gotSet[value]; !exists {
			return false
		}
	}
	return true
}

func validateAutonomousRepairActionDigest(request AutonomousRepairGovernanceRequest, now time.Time) string {
	digest := request.ActionDigest
	if digest.Repository != request.Repository ||
		digest.IssueNumber != request.IssueNumber ||
		digest.Action != request.Action {
		return "action_digest_authority_mismatch"
	}
	expectedDigest, err := autonomousRepairActionDigestValue(digest)
	if err != nil || digest.Expected != digest.Observed || digest.Observed != expectedDigest {
		return "action_digest_mismatch"
	}
	approvedAt, approvedErr := time.Parse(time.RFC3339, digest.ApprovedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, digest.ExpiresAt)
	if approvedErr != nil || expiresErr != nil || approvedAt.After(now) || !now.Before(expiresAt) || !approvedAt.Before(expiresAt) {
		return "stale_action_digest"
	}
	return ""
}

func autonomousRepairActionDigestValue(digest AutonomousRepairActionDigest) (string, error) {
	canonical := struct {
		Repository  string `json:"repository"`
		IssueNumber int    `json:"issue_number"`
		Action      string `json:"action"`
		BaseSHA     string `json:"base_sha"`
		HeadSHA     string `json:"head_sha"`
		ApprovedAt  string `json:"approved_at"`
		ExpiresAt   string `json:"expires_at"`
	}{
		Repository:  digest.Repository,
		IssueNumber: digest.IssueNumber,
		Action:      digest.Action,
		BaseSHA:     digest.BaseSHA,
		HeadSHA:     digest.HeadSHA,
		ApprovedAt:  digest.ApprovedAt,
		ExpiresAt:   digest.ExpiresAt,
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateAutonomousRepairChecks(request AutonomousRepairGovernanceRequest) string {
	if len(request.ExpectedChecks) == 0 || len(request.ObservedChecks) == 0 {
		return "missing_required_checks"
	}
	observed := make(map[string]AutonomousRepairCheck, len(request.ObservedChecks))
	for _, check := range request.ObservedChecks {
		if check.Name == "" {
			return "missing_required_checks"
		}
		if _, exists := observed[check.Name]; exists {
			return "duplicate_required_check"
		}
		observed[check.Name] = check
	}
	for _, name := range request.ExpectedChecks {
		check, ok := observed[name]
		if !ok {
			return "missing_required_checks"
		}
		if check.Conclusion != "success" {
			return "failed_required_check"
		}
		if check.HeadSHA != request.ExpectedHeadSHA {
			return "stale_head"
		}
	}
	if len(observed) != len(request.ExpectedChecks) {
		return "required_check_mismatch"
	}
	return ""
}

func validateIndependentReviewer(request AutonomousRepairGovernanceRequest, now time.Time) string {
	reviewer := request.Reviewer
	if !reviewer.Approved || (reviewer.Kind != "human" && reviewer.Kind != "codeowner") {
		return "independent_human_approval_required"
	}
	if reviewer.HeadSHA != request.ExpectedHeadSHA {
		return "stale_reviewer_head"
	}
	observedAt, err := time.Parse(time.RFC3339, reviewer.ObservedAt)
	approvedAt, approvalErr := time.Parse(time.RFC3339, request.ActionDigest.ApprovedAt)
	if err != nil || approvalErr != nil || observedAt.After(now) || observedAt.After(approvedAt) {
		return "stale_reviewer_approval"
	}
	return ""
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
