package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	architectureRunEnvelopeSchema        = "ao.architecture.autonomous-issue-repair.run-envelope.v1"
	architectureCandidateSchema          = "ao.architecture.autonomous-issue-repair.candidate-decision.v1"
	architectureGovernanceSchema         = "ao.architecture.autonomous-issue-repair.governance-decision.v1"
	architectureReviewerSchema           = "ao.architecture.autonomous-issue-repair.reviewer-independence.v1"
	architectureGitHubActionDigestSchema = "ao.architecture.autonomous-issue-repair.github-action-digest.v1"
)

var (
	architectureRunIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,127}$`)
	architectureSHA40Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	architectureSHA64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type ArchitectureRunEnvelope struct {
	Schema            string                         `json:"schema"`
	RunID             string                         `json:"run_id"`
	Loop              ArchitectureRepairLoop         `json:"loop"`
	Trigger           ArchitectureRepairTrigger      `json:"trigger"`
	Discovery         ArchitectureRepairDiscovery    `json:"discovery"`
	Budgets           ArchitectureRepairBudgets      `json:"budgets"`
	Governance        ArchitectureEnvelopeGovernance `json:"governance"`
	Routing           ArchitectureRepairRouting      `json:"routing"`
	CreatedAt         string                         `json:"created_at"`
	ExpiresAt         string                         `json:"expires_at"`
	CanonicalDigest   string                         `json:"canonical_digest"`
	PredecessorDigest *string                        `json:"predecessor_digest"`
	Lineage           ArchitectureRepairLineage      `json:"lineage"`
	StopConditions    []string                       `json:"stop_conditions"`
	TerminalStatuses  []string                       `json:"terminal_statuses"`
}

type ArchitectureRepairLoop struct {
	Goal         string `json:"goal"`
	Trigger      string `json:"trigger"`
	Discovery    string `json:"discovery"`
	Action       string `json:"action"`
	Verification string `json:"verification"`
	State        string `json:"state"`
	HumanGates   string `json:"human_gates"`
}

type ArchitectureRepairTrigger struct {
	Mode             string `json:"mode"`
	CanonicalURL     string `json:"canonical_url"`
	Repository       string `json:"repository"`
	DefaultBranch    string `json:"default_branch"`
	PinnedBaseCommit string `json:"pinned_base_commit"`
}

type ArchitectureRepairDiscovery struct {
	SnapshotLimit  int `json:"snapshot_limit"`
	CandidateLimit int `json:"candidate_limit"`
	SelectedLimit  int `json:"selected_limit"`
}

type ArchitectureRepairBudgets struct {
	WallClockSeconds int `json:"wall_clock_seconds"`
	CloneCount       int `json:"clone_count"`
	TestRuns         int `json:"test_runs"`
	RetryCount       int `json:"retry_count"`
	RepairCount      int `json:"repair_count"`
	PublicationCount int `json:"publication_count"`
}

type ArchitectureEnvelopeGovernance struct {
	OwnershipClass            string   `json:"ownership_class"`
	AllowedActions            []string `json:"allowed_actions"`
	DeniedActions             []string `json:"denied_actions"`
	SoleControlAutoMergeOptIn bool     `json:"sole_control_auto_merge_opt_in"`
}

type ArchitectureRepairRouting struct {
	DefaultBranch        string   `json:"default_branch"`
	PinnedBaseCommit     string   `json:"pinned_base_commit"`
	ForkOwner            *string  `json:"fork_owner"`
	RepairBranch         string   `json:"repair_branch"`
	ProtectedPathClasses []string `json:"protected_path_classes"`
	RequiredChecks       []string `json:"required_checks"`
}

type ArchitectureRepairLineage struct {
	Kind              string  `json:"kind"`
	PredecessorRunID  *string `json:"predecessor_run_id"`
	PredecessorDigest *string `json:"predecessor_digest"`
}

type ArchitectureCandidateDecision struct {
	Schema                 string                           `json:"schema"`
	RunID                  string                           `json:"run_id"`
	Repository             string                           `json:"repository"`
	BaseSHA                string                           `json:"base_sha"`
	IssueNumber            int                              `json:"issue_number"`
	Rank                   int                              `json:"rank"`
	Decision               string                           `json:"decision"`
	Eligibility            ArchitectureCandidateEligibility `json:"eligibility"`
	ReasonCodes            []string                         `json:"reason_codes"`
	EvidenceDigests        []string                         `json:"evidence_digests"`
	ExpectedBehaviorSource string                           `json:"expected_behavior_source"`
	DecidedAt              string                           `json:"decided_at"`
	DecisionDigest         string                           `json:"decision_digest"`
}

type ArchitectureCandidateEligibility struct {
	OpenBug                        bool `json:"open_bug"`
	TargetInRepository             bool `json:"target_in_repository"`
	NoExistingFix                  bool `json:"no_existing_fix"`
	CurrentHeadUnfixed             bool `json:"current_head_unfixed"`
	SecuritySensitive              bool `json:"security_sensitive"`
	PublicReproductionFeasible     bool `json:"public_reproduction_feasible"`
	DeterministicLocalReproduction bool `json:"deterministic_local_reproduction"`
	ExpectedBehaviorGrounded       bool `json:"expected_behavior_grounded"`
	BoundedPolicyCompatible        bool `json:"bounded_policy_compatible"`
}

type ArchitectureGovernanceDecision struct {
	Schema                string                      `json:"schema"`
	RunID                 string                      `json:"run_id"`
	Repository            string                      `json:"repository"`
	BaseSHA               string                      `json:"base_sha"`
	HeadSHA               string                      `json:"head_sha"`
	GovernanceClass       string                      `json:"governance_class"`
	ClassificationSources []string                    `json:"classification_sources"`
	PushTarget            string                      `json:"push_target"`
	PullRequestMode       string                      `json:"pull_request_mode"`
	Merge                 ArchitectureMergeDecision   `json:"merge"`
	ProtectedPathTouched  bool                        `json:"protected_path_touched"`
	RequiredChecks        []ArchitectureRequiredCheck `json:"required_checks"`
	ActionDigestRequired  bool                        `json:"action_digest_required"`
	DecidedAt             string                      `json:"decided_at"`
	DecisionDigest        string                      `json:"decision_digest"`
}

type ArchitectureMergeDecision struct {
	Authorized               bool    `json:"authorized"`
	Mode                     string  `json:"mode"`
	ApprovalKind             string  `json:"approval_kind"`
	ApprovalHeadSHA          *string `json:"approval_head_sha"`
	AutoMergeOptIn           bool    `json:"auto_merge_opt_in"`
	BranchProtectionBypassed bool    `json:"branch_protection_bypassed"`
}

type ArchitectureRequiredCheck struct {
	Name       string `json:"name"`
	Conclusion string `json:"conclusion"`
	HeadSHA    string `json:"head_sha"`
}

type ArchitectureReviewerIndependence struct {
	Schema                    string `json:"schema"`
	RunID                     string `json:"run_id"`
	SubjectDigest             string `json:"subject_digest"`
	ReviewerID                string `json:"reviewer_id"`
	Status                    string `json:"status"`
	DeterministicTestsPrimary bool   `json:"deterministic_tests_primary"`
	SatisfiesTeamMergeGate    bool   `json:"satisfies_team_merge_gate"`
	ReviewedAt                string `json:"reviewed_at"`
	ReviewDigest              string `json:"review_digest"`
}

type ArchitectureGitHubActionDigest struct {
	Schema                     string                      `json:"schema"`
	RunID                      string                      `json:"run_id"`
	Repository                 string                      `json:"repository"`
	IssueNumber                int                         `json:"issue_number"`
	BaseSHA                    string                      `json:"base_sha"`
	HeadSHA                    string                      `json:"head_sha"`
	Fork                       *string                     `json:"fork"`
	Branch                     string                      `json:"branch"`
	PRTitleDigest              string                      `json:"pr_title_digest"`
	PRBodyDigest               string                      `json:"pr_body_digest"`
	DiffDigest                 string                      `json:"diff_digest"`
	RequiredChecks             []ArchitectureRequiredCheck `json:"required_checks"`
	Action                     string                      `json:"action"`
	ApprovedAt                 string                      `json:"approved_at"`
	ExpiresAt                  string                      `json:"expires_at"`
	RunEnvelopeDigest          string                      `json:"run_envelope_digest"`
	CandidateDecisionDigest    string                      `json:"candidate_decision_digest"`
	GovernanceDecisionDigest   string                      `json:"governance_decision_digest"`
	ReviewerIndependenceDigest string                      `json:"reviewer_independence_digest"`
	ActionDigest               string                      `json:"action_digest"`
}

func validateArchitectureRepairAuthority(
	policy AutonomousRepairGovernancePolicy,
	repositoryPolicy AutonomousRepairRepositoryPolicy,
	request AutonomousRepairGovernanceRequest,
	now time.Time,
) string {
	envelope := request.RunEnvelope
	candidate := request.CandidateDecision
	governance := request.GovernanceDecision
	reviewer := request.ReviewerIndependence
	action := request.GitHubActionDigest
	if envelope == nil || candidate == nil || governance == nil || reviewer == nil || action == nil {
		return "missing_canonical_authority"
	}
	if !validArchitectureDocumentShapes(*envelope, *candidate, *governance, *reviewer, *action) {
		return "malformed_canonical_authority"
	}
	for _, document := range []struct {
		value any
		field string
		got   string
	}{
		{*envelope, "canonical_digest", envelope.CanonicalDigest},
		{*candidate, "decision_digest", candidate.DecisionDigest},
		{*governance, "decision_digest", governance.DecisionDigest},
		{*reviewer, "review_digest", reviewer.ReviewDigest},
		{*action, "action_digest", action.ActionDigest},
	} {
		want, err := architectureCanonicalDigest(document.value, document.field)
		if err != nil || want != document.got {
			return "canonical_digest_mismatch"
		}
	}
	if request.ApprovedActionDigest != action.ActionDigest {
		return "approved_action_digest_mismatch"
	}

	runID := action.RunID
	if envelope.RunID != runID || candidate.RunID != runID ||
		governance.RunID != runID || reviewer.RunID != runID {
		return "authority_run_mismatch"
	}
	if request.Repository != action.Repository ||
		envelope.Trigger.Repository != action.Repository ||
		candidate.Repository != action.Repository ||
		governance.Repository != action.Repository {
		return "authority_repository_mismatch"
	}
	if request.IssueNumber == nil || *request.IssueNumber != action.IssueNumber ||
		candidate.IssueNumber != action.IssueNumber {
		return "authority_issue_mismatch"
	}
	if envelope.Trigger.Mode != "explicit_issue" ||
		envelope.Trigger.CanonicalURL != fmt.Sprintf(
			"https://github.com/%s/issues/%d",
			action.Repository,
			action.IssueNumber,
		) {
		return "authority_issue_url_mismatch"
	}
	if request.Action != action.Action {
		return "authority_action_mismatch"
	}
	if request.CurrentBaseSHA != action.BaseSHA ||
		envelope.Trigger.PinnedBaseCommit != action.BaseSHA ||
		envelope.Routing.PinnedBaseCommit != action.BaseSHA ||
		candidate.BaseSHA != action.BaseSHA ||
		governance.BaseSHA != action.BaseSHA {
		return "authority_base_mismatch"
	}
	if governance.HeadSHA != action.HeadSHA {
		return "authority_head_mismatch"
	}
	if action.RunEnvelopeDigest != envelope.CanonicalDigest ||
		action.CandidateDecisionDigest != candidate.DecisionDigest ||
		action.GovernanceDecisionDigest != governance.DecisionDigest ||
		action.ReviewerIndependenceDigest != reviewer.ReviewDigest {
		return "authority_digest_link_mismatch"
	}
	if candidate.Decision != "selected" || !candidateEligible(candidate.Eligibility) {
		if candidate.Eligibility.SecuritySensitive {
			return "security_sensitive"
		}
		return "candidate_not_eligible"
	}

	derivedProtectedPath := false
	for _, pathClass := range request.ChangedPathClasses {
		if slicesContains(policy.RiskyPathClasses, pathClass) {
			derivedProtectedPath = true
			break
		}
	}
	if governance.ProtectedPathTouched != derivedProtectedPath {
		return "protected_path_classification_mismatch"
	}
	if derivedProtectedPath {
		return "protected_path"
	}

	if envelope.Governance.OwnershipClass != repositoryPolicy.RepositoryClass ||
		governance.GovernanceClass != repositoryPolicy.RepositoryClass ||
		envelope.Governance.SoleControlAutoMergeOptIn != repositoryPolicy.SoleAutoMergeOptIn ||
		governance.PushTarget != repositoryPolicy.PushTarget ||
		governance.PullRequestMode != repositoryPolicy.PullRequestMode ||
		!sameUniqueStrings(envelope.Routing.RequiredChecks, repositoryPolicy.RequiredChecks) ||
		!sameUniqueStrings(envelope.Routing.ProtectedPathClasses, policy.RiskyPathClasses) ||
		!slicesContains(envelope.Governance.AllowedActions, action.Action) ||
		!everyStringIn(envelope.Governance.AllowedActions, repositoryPolicy.AllowedActions) ||
		!slicesContains(repositoryPolicy.AllowedActions, action.Action) {
		return "repository_policy_mismatch"
	}
	if repositoryPolicy.RepositoryClass == "external" &&
		(!slicesContains(envelope.Governance.DeniedActions, "open_ready_pr") ||
			!slicesContains(envelope.Governance.DeniedActions, "approve_review") ||
			!slicesContains(envelope.Governance.DeniedActions, "merge") ||
			!slicesContains(envelope.Governance.DeniedActions, "mutate_issue")) {
		return "external_permanent_denials_missing"
	}
	if governance.Merge.BranchProtectionBypassed {
		return "branch_protection_bypass"
	}
	if reason := validateArchitectureRouting(repositoryPolicy, envelope, governance, action); reason != "" {
		return reason
	}
	if reason := validateArchitectureChecks(repositoryPolicy.RequiredChecks, governance, action); reason != "" {
		return reason
	}
	if reviewer.SubjectDigest != action.DiffDigest || !reviewer.DeterministicTestsPrimary {
		return "reviewer_binding_mismatch"
	}
	if reason := validateArchitectureChronology(envelope, candidate, governance, reviewer, action, now); reason != "" {
		return reason
	}
	if reason := validateArchitectureActionClass(repositoryPolicy, governance, reviewer, action); reason != "" {
		return reason
	}
	return ""
}

func validArchitectureDocumentShapes(
	envelope ArchitectureRunEnvelope,
	candidate ArchitectureCandidateDecision,
	governance ArchitectureGovernanceDecision,
	reviewer ArchitectureReviewerIndependence,
	action ArchitectureGitHubActionDigest,
) bool {
	return validArchitectureEnvelopeShape(envelope) &&
		validArchitectureCandidateShape(candidate) &&
		validArchitectureGovernanceShape(governance) &&
		validArchitectureReviewerShape(reviewer) &&
		validArchitectureActionShape(action)
}

func validArchitectureEnvelopeShape(envelope ArchitectureRunEnvelope) bool {
	return envelope.Schema == architectureRunEnvelopeSchema &&
		architectureRunIDPattern.MatchString(envelope.RunID) &&
		envelope.Loop.Goal != "" &&
		envelope.Loop.Trigger != "" &&
		envelope.Loop.Discovery != "" &&
		envelope.Loop.Action != "" &&
		envelope.Loop.Verification != "" &&
		envelope.Loop.State != "" &&
		envelope.Loop.HumanGates != "" &&
		slicesContains([]string{"explicit_issue", "issue_list"}, envelope.Trigger.Mode) &&
		envelope.Trigger.CanonicalURL != "" &&
		validRepositoryName(envelope.Trigger.Repository) &&
		envelope.Trigger.DefaultBranch != "" &&
		architectureSHA40Pattern.MatchString(envelope.Trigger.PinnedBaseCommit) &&
		envelope.Discovery.SnapshotLimit >= 1 &&
		envelope.Discovery.SnapshotLimit <= 50 &&
		envelope.Discovery.CandidateLimit >= 1 &&
		envelope.Discovery.CandidateLimit <= 10 &&
		envelope.Discovery.SelectedLimit == 1 &&
		envelope.Budgets.WallClockSeconds >= 1 &&
		envelope.Budgets.CloneCount >= 0 &&
		envelope.Budgets.TestRuns >= 1 &&
		envelope.Budgets.RetryCount >= 0 &&
		envelope.Budgets.RepairCount >= 0 &&
		envelope.Budgets.RepairCount <= 1 &&
		envelope.Budgets.PublicationCount >= 0 &&
		envelope.Budgets.PublicationCount <= 1 &&
		slicesContains([]string{"sole_control", "team", "external", "unknown"}, envelope.Governance.OwnershipClass) &&
		uniqueNonemptyStrings(envelope.Governance.AllowedActions) &&
		uniqueNonemptyStrings(envelope.Governance.DeniedActions) &&
		envelope.Routing.DefaultBranch != "" &&
		architectureSHA40Pattern.MatchString(envelope.Routing.PinnedBaseCommit) &&
		envelope.Routing.RepairBranch != "" &&
		uniqueNonemptyStrings(envelope.Routing.ProtectedPathClasses) &&
		uniqueNonemptyStrings(envelope.Routing.RequiredChecks) &&
		validRFC3339(envelope.CreatedAt) &&
		validRFC3339(envelope.ExpiresAt) &&
		architectureSHA64Pattern.MatchString(envelope.CanonicalDigest) &&
		validArchitectureLineage(envelope) &&
		uniqueNonemptyStrings(envelope.StopConditions) &&
		uniqueNonemptyStrings(envelope.TerminalStatuses)
}

func validArchitectureLineage(envelope ArchitectureRunEnvelope) bool {
	switch envelope.Lineage.Kind {
	case "origin":
		return envelope.PredecessorDigest == nil &&
			envelope.Lineage.PredecessorRunID == nil &&
			envelope.Lineage.PredecessorDigest == nil
	case "narrower_successor":
		return envelope.PredecessorDigest != nil &&
			envelope.Lineage.PredecessorRunID != nil &&
			envelope.Lineage.PredecessorDigest != nil &&
			*envelope.Lineage.PredecessorDigest == *envelope.PredecessorDigest &&
			architectureSHA64Pattern.MatchString(*envelope.PredecessorDigest) &&
			architectureRunIDPattern.MatchString(*envelope.Lineage.PredecessorRunID)
	default:
		return false
	}
}

func validArchitectureCandidateShape(candidate ArchitectureCandidateDecision) bool {
	return candidate.Schema == architectureCandidateSchema &&
		architectureRunIDPattern.MatchString(candidate.RunID) &&
		validRepositoryName(candidate.Repository) &&
		architectureSHA40Pattern.MatchString(candidate.BaseSHA) &&
		candidate.IssueNumber >= 1 &&
		candidate.Rank >= 1 &&
		candidate.Rank <= 10 &&
		slicesContains([]string{"eligible", "selected", "excluded"}, candidate.Decision) &&
		uniqueNonemptyStrings(candidate.ReasonCodes) &&
		uniqueDigestStrings(candidate.EvidenceDigests) &&
		slicesContains([]string{
			"tests",
			"documentation",
			"protocol",
			"maintainer_statement",
			"unavailable",
		}, candidate.ExpectedBehaviorSource) &&
		validRFC3339(candidate.DecidedAt) &&
		architectureSHA64Pattern.MatchString(candidate.DecisionDigest)
}

func validArchitectureGovernanceShape(governance ArchitectureGovernanceDecision) bool {
	if governance.Schema != architectureGovernanceSchema ||
		!architectureRunIDPattern.MatchString(governance.RunID) ||
		!validRepositoryName(governance.Repository) ||
		!architectureSHA40Pattern.MatchString(governance.BaseSHA) ||
		!architectureSHA40Pattern.MatchString(governance.HeadSHA) ||
		!slicesContains([]string{"sole_control", "team", "external", "unknown"}, governance.GovernanceClass) ||
		!uniqueNonemptyStrings(governance.ClassificationSources) ||
		!everyStringIn(governance.ClassificationSources, []string{
			"repository_policy",
			"branch_rules",
			"codeowners",
			"operator_envelope",
			"unknown_default",
		}) ||
		!slicesContains(governance.ClassificationSources, "repository_policy") ||
		!slicesContains([]string{
			"authorized_operator_repository",
			"policy_authorized_branch",
			"operator_owned_fork",
		}, governance.PushTarget) ||
		!slicesContains([]string{
			"draft_or_ready_by_policy",
			"upstream_draft_only",
		}, governance.PullRequestMode) ||
		!validArchitectureMergeShape(governance.Merge) ||
		!governance.ActionDigestRequired ||
		!validRFC3339(governance.DecidedAt) ||
		!architectureSHA64Pattern.MatchString(governance.DecisionDigest) {
		return false
	}
	return uniqueArchitectureCheckNames(governance.RequiredChecks)
}

func validArchitectureMergeShape(merge ArchitectureMergeDecision) bool {
	if !slicesContains([]string{"never", "manual", "merge_queue", "auto_merge"}, merge.Mode) ||
		!slicesContains([]string{"none", "independent_human", "codeowner"}, merge.ApprovalKind) ||
		merge.BranchProtectionBypassed {
		return false
	}
	if merge.ApprovalHeadSHA != nil &&
		!architectureSHA40Pattern.MatchString(*merge.ApprovalHeadSHA) {
		return false
	}
	if !merge.Authorized {
		return merge.Mode == "never"
	}
	return merge.Mode != "never"
}

func validArchitectureReviewerShape(reviewer ArchitectureReviewerIndependence) bool {
	return reviewer.Schema == architectureReviewerSchema &&
		architectureRunIDPattern.MatchString(reviewer.RunID) &&
		architectureSHA64Pattern.MatchString(reviewer.SubjectDigest) &&
		reviewer.ReviewerID != "" &&
		slicesContains([]string{"independent", "same_vendor", "unavailable", "unverified"}, reviewer.Status) &&
		reviewer.DeterministicTestsPrimary &&
		(reviewer.Status == "independent" || !reviewer.SatisfiesTeamMergeGate) &&
		validRFC3339(reviewer.ReviewedAt) &&
		architectureSHA64Pattern.MatchString(reviewer.ReviewDigest)
}

func validArchitectureActionShape(action ArchitectureGitHubActionDigest) bool {
	if action.Schema != architectureGitHubActionDigestSchema ||
		!architectureRunIDPattern.MatchString(action.RunID) ||
		!validRepositoryName(action.Repository) ||
		action.IssueNumber < 1 ||
		!architectureSHA40Pattern.MatchString(action.BaseSHA) ||
		!architectureSHA40Pattern.MatchString(action.HeadSHA) ||
		action.Branch == "" ||
		!architectureSHA64Pattern.MatchString(action.PRTitleDigest) ||
		!architectureSHA64Pattern.MatchString(action.PRBodyDigest) ||
		!architectureSHA64Pattern.MatchString(action.DiffDigest) ||
		!slicesContains([]string{
			"push_operator_fork",
			"open_upstream_draft_pr",
			"open_ready_pr",
			"request_merge_queue",
			"auto_merge",
		}, action.Action) ||
		!validRFC3339(action.ApprovedAt) ||
		!validRFC3339(action.ExpiresAt) ||
		!architectureSHA64Pattern.MatchString(action.RunEnvelopeDigest) ||
		!architectureSHA64Pattern.MatchString(action.CandidateDecisionDigest) ||
		!architectureSHA64Pattern.MatchString(action.GovernanceDecisionDigest) ||
		!architectureSHA64Pattern.MatchString(action.ReviewerIndependenceDigest) ||
		!architectureSHA64Pattern.MatchString(action.ActionDigest) {
		return false
	}
	if action.Fork != nil && !validRepositoryName(*action.Fork) {
		return false
	}
	return uniqueArchitectureCheckNames(action.RequiredChecks)
}

func uniqueArchitectureCheckNames(checks []ArchitectureRequiredCheck) bool {
	if len(checks) == 0 {
		return false
	}
	names := make([]string, 0, len(checks))
	for _, check := range checks {
		if check.Name == "" ||
			!slicesContains([]string{"success", "failure", "pending", "missing"}, check.Conclusion) ||
			!architectureSHA40Pattern.MatchString(check.HeadSHA) {
			return false
		}
		names = append(names, check.Name)
	}
	return uniqueNonemptyStrings(names)
}

func uniqueDigestStrings(values []string) bool {
	if len(values) == 0 || !uniqueNonemptyStrings(values) {
		return false
	}
	for _, value := range values {
		if !architectureSHA64Pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validRFC3339(value string) bool {
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func candidateEligible(eligibility ArchitectureCandidateEligibility) bool {
	return eligibility.OpenBug &&
		eligibility.TargetInRepository &&
		eligibility.NoExistingFix &&
		eligibility.CurrentHeadUnfixed &&
		!eligibility.SecuritySensitive &&
		eligibility.PublicReproductionFeasible &&
		eligibility.DeterministicLocalReproduction &&
		eligibility.ExpectedBehaviorGrounded &&
		eligibility.BoundedPolicyCompatible
}

func validateArchitectureRouting(
	repositoryPolicy AutonomousRepairRepositoryPolicy,
	envelope *ArchitectureRunEnvelope,
	governance *ArchitectureGovernanceDecision,
	action *ArchitectureGitHubActionDigest,
) string {
	if envelope.Trigger.DefaultBranch != envelope.Routing.DefaultBranch ||
		envelope.Trigger.PinnedBaseCommit != envelope.Routing.PinnedBaseCommit ||
		action.Branch != envelope.Routing.RepairBranch {
		return "routing_mismatch"
	}
	if governance.PushTarget == "operator_owned_fork" {
		if envelope.Routing.ForkOwner == nil || action.Fork == nil {
			return "fork_mismatch"
		}
		repositoryName := strings.SplitN(action.Repository, "/", 2)[1]
		wantFork := *envelope.Routing.ForkOwner + "/" + repositoryName
		if *action.Fork != wantFork {
			return "fork_mismatch"
		}
	} else if envelope.Routing.ForkOwner != nil || action.Fork != nil {
		return "fork_mismatch"
	}
	if repositoryPolicy.RepositoryClass == "external" &&
		(governance.PushTarget != "operator_owned_fork" ||
			governance.PullRequestMode != "upstream_draft_only") {
		return "external_draft_only"
	}
	return ""
}

func validateArchitectureChecks(
	expected []string,
	governance *ArchitectureGovernanceDecision,
	action *ArchitectureGitHubActionDigest,
) string {
	if len(expected) == 0 ||
		len(governance.RequiredChecks) != len(expected) ||
		len(action.RequiredChecks) != len(expected) {
		return "required_checks_mismatch"
	}
	governanceNames := make([]string, 0, len(governance.RequiredChecks))
	actionNames := make([]string, 0, len(action.RequiredChecks))
	for _, check := range governance.RequiredChecks {
		governanceNames = append(governanceNames, check.Name)
		if check.Conclusion != "success" || check.HeadSHA != action.HeadSHA {
			return "required_check_not_green"
		}
	}
	for _, check := range action.RequiredChecks {
		actionNames = append(actionNames, check.Name)
		if check.Conclusion != "success" || check.HeadSHA != action.HeadSHA {
			return "required_check_not_green"
		}
	}
	if !sameUniqueStrings(governanceNames, expected) ||
		!sameUniqueStrings(actionNames, expected) {
		return "required_checks_mismatch"
	}
	return ""
}

func validateArchitectureChronology(
	envelope *ArchitectureRunEnvelope,
	candidate *ArchitectureCandidateDecision,
	governance *ArchitectureGovernanceDecision,
	reviewer *ArchitectureReviewerIndependence,
	action *ArchitectureGitHubActionDigest,
	now time.Time,
) string {
	createdAt, createdErr := time.Parse(time.RFC3339, envelope.CreatedAt)
	envelopeExpiresAt, envelopeExpiresErr := time.Parse(time.RFC3339, envelope.ExpiresAt)
	candidateAt, candidateErr := time.Parse(time.RFC3339, candidate.DecidedAt)
	governanceAt, governanceErr := time.Parse(time.RFC3339, governance.DecidedAt)
	reviewerAt, reviewerErr := time.Parse(time.RFC3339, reviewer.ReviewedAt)
	approvedAt, approvedErr := time.Parse(time.RFC3339, action.ApprovedAt)
	actionExpiresAt, actionExpiresErr := time.Parse(time.RFC3339, action.ExpiresAt)
	if createdErr != nil || envelopeExpiresErr != nil ||
		candidateErr != nil || governanceErr != nil || reviewerErr != nil ||
		approvedErr != nil || actionExpiresErr != nil {
		return "invalid_authority_timestamp"
	}
	now = now.UTC()
	if createdAt.After(now) ||
		!now.Before(envelopeExpiresAt) ||
		!now.Before(actionExpiresAt) ||
		!createdAt.Before(envelopeExpiresAt) ||
		!approvedAt.Before(actionExpiresAt) ||
		actionExpiresAt.Sub(approvedAt) > 24*time.Hour ||
		actionExpiresAt.After(envelopeExpiresAt) ||
		candidateAt.Before(createdAt) ||
		governanceAt.Before(createdAt) ||
		reviewerAt.Before(createdAt) ||
		approvedAt.Before(candidateAt) ||
		approvedAt.Before(governanceAt) ||
		approvedAt.Before(reviewerAt) ||
		approvedAt.After(now) {
		return "authority_chronology_invalid"
	}
	if envelope.Budgets.WallClockSeconds < 1 ||
		envelopeExpiresAt.Sub(createdAt) > time.Duration(envelope.Budgets.WallClockSeconds)*time.Second {
		return "envelope_lifetime_invalid"
	}
	return ""
}

func validateArchitectureActionClass(
	repositoryPolicy AutonomousRepairRepositoryPolicy,
	governance *ArchitectureGovernanceDecision,
	reviewer *ArchitectureReviewerIndependence,
	action *ArchitectureGitHubActionDigest,
) string {
	merge := governance.Merge
	if action.Action != "request_merge_queue" && action.Action != "auto_merge" &&
		(merge.Authorized || merge.Mode != "never" ||
			merge.ApprovalKind != "none" || merge.ApprovalHeadSHA != nil ||
			merge.AutoMergeOptIn) {
		return "contradictory_merge_authority"
	}
	switch repositoryPolicy.RepositoryClass {
	case "external":
		if action.Action != "push_operator_fork" && action.Action != "open_upstream_draft_pr" {
			return "external_draft_only"
		}
		if merge.Authorized || merge.Mode != "never" ||
			merge.ApprovalKind != "none" || merge.ApprovalHeadSHA != nil ||
			merge.AutoMergeOptIn {
			return "external_draft_only"
		}
	case "team":
		if action.Action == "auto_merge" {
			return "team_auto_merge_denied"
		}
		if action.Action == "request_merge_queue" {
			if !merge.Authorized || merge.Mode != "merge_queue" ||
				(merge.ApprovalKind != "independent_human" && merge.ApprovalKind != "codeowner") ||
				merge.ApprovalHeadSHA == nil || *merge.ApprovalHeadSHA != action.HeadSHA ||
				reviewer.Status != "independent" ||
				!reviewer.SatisfiesTeamMergeGate ||
				automatedReviewer(reviewer.ReviewerID) {
				return "independent_human_approval_required"
			}
		}
	case "sole_control":
		if action.Action == "auto_merge" &&
			(!repositoryPolicy.SoleAutoMergeOptIn ||
				!merge.Authorized ||
				merge.Mode != "auto_merge" ||
				!merge.AutoMergeOptIn) {
			return "sole_control_auto_merge_not_opted_in"
		}
	}
	return ""
}

func automatedReviewer(reviewerID string) bool {
	normalized := strings.ToLower(reviewerID)
	return strings.Contains(normalized, "automated") ||
		strings.Contains(normalized, "[bot]") ||
		strings.HasPrefix(normalized, "ao-") ||
		strings.HasPrefix(normalized, "codex")
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func architectureCanonicalDigest(document any, excludedField string) (string, error) {
	data, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", fmt.Errorf("canonical document must be an object")
	}
	delete(object, excludedField)
	var canonical bytes.Buffer
	if err := writeArchitectureCanonicalJSON(&canonical, object); err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func writeArchitectureCanonicalJSON(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case json.Number:
		buffer.WriteString(typed.String())
	case string:
		writeArchitectureJSONString(buffer, typed)
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := writeArchitectureCanonicalJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			writeArchitectureJSONString(buffer, key)
			buffer.WriteByte(':')
			if err := writeArchitectureCanonicalJSON(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func writeArchitectureJSONString(buffer *bytes.Buffer, value string) {
	buffer.WriteByte('"')
	for _, current := range value {
		switch current {
		case '"', '\\':
			buffer.WriteByte('\\')
			buffer.WriteRune(current)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		default:
			switch {
			case current < 0x20:
				fmt.Fprintf(buffer, `\u%04x`, current)
			case current <= 0x7f:
				buffer.WriteRune(current)
			case current <= 0xffff:
				fmt.Fprintf(buffer, `\u%04x`, current)
			default:
				first, second := utf16.EncodeRune(current)
				fmt.Fprintf(buffer, `\u%04x\u%04x`, first, second)
			}
		}
	}
	buffer.WriteByte('"')
}
