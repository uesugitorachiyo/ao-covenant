package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

func ValidateMutationClassAuthorityTicket(request map[string]any, ticket map[string]any, now time.Time) error {
	if governanceStringField(request, "schema_version") != "ao.foundry.mutation-class-authority-request.v0.1" {
		return fmt.Errorf("request schema_version must be ao.foundry.mutation-class-authority-request.v0.1")
	}
	if governanceStringField(request, "status") != "pending_covenant_authority" {
		return fmt.Errorf("request status must be pending_covenant_authority")
	}
	requestClass := governanceStringField(request, "mutation_class")
	if !validMutationClass(requestClass) {
		return fmt.Errorf("request mutation_class is not supported")
	}
	if governanceBoolField(request, "safe_to_request") != true || governanceBoolField(request, "safe_to_execute") != false {
		return fmt.Errorf("request must be safe_to_request=true and safe_to_execute=false")
	}
	if governanceStringField(ticket, "request_id") != governanceStringField(request, "request_id") {
		return fmt.Errorf("ticket request_id does not match request")
	}
	if governanceStringField(ticket, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if governanceStringField(ticket, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if governanceBoolField(ticket, "consumed") {
		return fmt.Errorf("authority ticket has already been consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339, governanceStringField(ticket, "expires_at"))
	if err != nil {
		return fmt.Errorf("authority ticket expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("authority ticket expired")
	}
	if governanceStringField(ticket, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	ticketScope, ok := ticket["approved_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("approved_scope is required")
	}
	if governanceStringField(ticketScope, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	if !governanceJSONEquivalent(ticketScope["allowed_paths"], request["allowed_paths"]) {
		return fmt.Errorf("ticket path scope is broader than request")
	}
	if !governanceJSONEquivalent(ticketScope["max_changed_files"], request["max_changed_files"]) {
		return fmt.Errorf("ticket diff limit does not exactly match request")
	}
	for _, field := range []string{"repo", "branch_policy", "forbidden_paths", "required_gates", "authority_boundary"} {
		if !governanceJSONEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match request")
		}
	}
	if governanceBoolField(request, "rollback_required") != true || governanceBoolField(ticketScope, "rollback_required") != true {
		return fmt.Errorf("rollback is required for mutation-class authority tickets")
	}
	for _, field := range []string{"rollback_scope", "rollback_evidence"} {
		if !governanceJSONEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket rollback scope does not exactly match request")
		}
	}
	if requestClass == "multi_repo_low_risk" {
		if err := validateMultiRepoLowRiskAuthorityScope(request, ticketScope, now); err != nil {
			return err
		}
	}
	digest, ok := ticket["scope_digest"].(map[string]any)
	if !ok {
		return fmt.Errorf("scope_digest is required")
	}
	if governanceStringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "approved_scope") {
		return fmt.Errorf("scope_digest must cover approved_scope")
	}
	expected, err := digestApprovedScope(ticketScope)
	if err != nil {
		return err
	}
	if governanceStringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match approved_scope")
	}
	boundaries, ok := ticket["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use"} {
		if !governanceBoolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "provider_calls_allowed", "release_or_publish_allowed"} {
		if governanceBoolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be false", field)
		}
	}
	return nil
}

func ValidateLowRiskCodeLivePolicy(policy map[string]any, now time.Time, expectedSchemaVersion string) error {
	if governanceStringField(policy, "schema_version") != expectedSchemaVersion {
		return fmt.Errorf("schema_version must be %s", expectedSchemaVersion)
	}
	if governanceStringField(policy, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if governanceStringField(policy, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if governanceBoolField(policy, "consumed") {
		return fmt.Errorf("low_risk_code live policy has already been consumed")
	}
	if governanceStringField(policy, "mutation_class") != "low_risk_code" {
		return fmt.Errorf("mutation_class must be low_risk_code")
	}
	if governanceBoolField(policy, "safe_to_request") != true || governanceBoolField(policy, "safe_to_execute") != false {
		return fmt.Errorf("policy must be safe_to_request=true and safe_to_execute=false")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, governanceStringField(policy, "issued_at"))
	expiresAt, expiresErr := time.Parse(time.RFC3339, governanceStringField(policy, "expires_at"))
	if issuedErr != nil || expiresErr != nil {
		return fmt.Errorf("policy issued_at and expires_at must be RFC3339")
	}
	if issuedAt.After(now) || !expiresAt.After(now) {
		return fmt.Errorf("low_risk_code live policy is stale or not yet valid")
	}
	candidateScope, ok := policy["candidate_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("candidate_scope is required")
	}
	if err := validateLowRiskCodeLiveCandidateScope(candidateScope); err != nil {
		return err
	}
	digest, ok := policy["scope_digest"].(map[string]any)
	if !ok {
		return fmt.Errorf("scope_digest is required")
	}
	if governanceStringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "candidate_scope") {
		return fmt.Errorf("scope_digest must cover candidate_scope")
	}
	expected, err := digestApprovedScope(candidateScope)
	if err != nil {
		return err
	}
	if governanceStringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match candidate_scope")
	}
	boundaries, ok := policy["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use", "single_repo", "single_branch"} {
		if !governanceBoolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "multi_repo_mutation_allowed", "complex_repo_mutation_allowed", "fully_unsupervised_complex_mutation_allowed", "provider_calls_allowed", "release_or_publish_allowed"} {
		if governanceBoolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be false", field)
		}
	}
	return nil
}

func validateLowRiskCodeLiveCandidateScope(scope map[string]any) error {
	chain, ok := scope["dry_run_chain"].(map[string]any)
	if !ok {
		return fmt.Errorf("dry_run_chain is required")
	}
	if governanceStringField(chain, "path") != "tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json" {
		return fmt.Errorf("dry_run_chain path must be tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json")
	}
	if governanceStringField(chain, "sha256") != "046dcdc9a17fcfd60877c8e61d1a15c722f7c34cacdeeb139651f153c6e1196e" {
		return fmt.Errorf("dry_run_chain sha256 must match current held rehearsal chain")
	}
	repo, ok := scope["repo"].(map[string]any)
	if !ok {
		return fmt.Errorf("repo is required")
	}
	if governanceStringField(repo, "id") != "ao-atlas" {
		return fmt.Errorf("repo id must be ao-atlas")
	}
	if governanceStringField(repo, "remote") != "uesugitorachiyo/ao-atlas" {
		return fmt.Errorf("repo remote must be uesugitorachiyo/ao-atlas")
	}
	if governanceStringField(scope, "base_branch") != "main" {
		return fmt.Errorf("base_branch must be main")
	}
	if governanceStringField(scope, "proposed_branch") != "codex/low-risk-code-rehearsal-one" {
		return fmt.Errorf("proposed_branch must be codex/low-risk-code-rehearsal-one")
	}
	if governanceStringField(scope, "intent") != "behavior-preserving cleanup in internal uniqueStrings helper" {
		return fmt.Errorf("intent must match selected held candidate")
	}
	if err := requireExactStringSlice(scope["file_allowlist"], []string{"internal/atlas/validate.go"}, "file_allowlist"); err != nil {
		return err
	}
	if err := requireExactStringSlice(scope["command_allowlist"], []string{"git diff --check", "go test ./..."}, "command_allowlist"); err != nil {
		return err
	}
	rollbackPlan, ok := scope["rollback_plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("rollback_plan is required")
	}
	if !governanceBoolField(rollbackPlan, "required") {
		return fmt.Errorf("rollback_plan required must be true")
	}
	if governanceStringField(rollbackPlan, "strategy") == "" {
		return fmt.Errorf("rollback_plan strategy is required")
	}
	if err := requireExactStringSlice(rollbackPlan["scope"], []string{"internal/atlas/validate.go"}, "rollback_plan scope"); err != nil {
		return err
	}
	return nil
}

func validateMultiRepoLowRiskAuthorityScope(request map[string]any, ticketScope map[string]any, now time.Time) error {
	for _, field := range []string{"multi_repo_plan", "per_repo_rollback", "ci_by_repo", "repo_state_evidence", "kill_switch"} {
		if !governanceJSONEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match multi_repo_low_risk request")
		}
	}
	plan, ok := ticketScope["multi_repo_plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("multi_repo_low_risk ordered merge plan is required")
	}
	if governanceStringField(plan, "status") != "ready" {
		return fmt.Errorf("multi_repo_low_risk ordered merge plan is not ready")
	}
	plannedRepos, err := validateOrderedMultiRepoPlan(plan)
	if err != nil {
		return err
	}
	if err := validatePerRepoRollback(plannedRepos, ticketScope["per_repo_rollback"]); err != nil {
		return err
	}
	if err := validatePerRepoCI(plannedRepos, ticketScope["ci_by_repo"]); err != nil {
		return err
	}
	if err := validateFreshRepoState(plannedRepos, ticketScope["repo_state_evidence"], now); err != nil {
		return err
	}
	killSwitch, ok := ticketScope["kill_switch"].(map[string]any)
	if !ok || !governanceBoolField(killSwitch, "required") || governanceStringField(killSwitch, "status") != "armed" {
		return fmt.Errorf("operator kill-switch must be armed for multi_repo_low_risk")
	}
	return nil
}

func validateOrderedMultiRepoPlan(plan map[string]any) ([]string, error) {
	order, ok := governanceStringSlice(plan["order"])
	if !ok || len(order) == 0 {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	entries, ok := governanceMapSlice(plan["ordered_merge_plan"])
	if !ok || len(entries) != len(order) {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	seen := map[string]bool{}
	repos := make([]string, 0, len(entries))
	for index, entry := range entries {
		repo := governanceStringField(entry, "repo")
		if repo == "" || repo != order[index] || governanceIntField(entry, "order") != index+1 || governanceStringField(entry, "planned_pr") == "" {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		dependencies, ok := governanceStringSlice(entry["depends_on"])
		if !ok {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		mergeAfter, ok := governanceStringSlice(entry["merge_after"])
		if !ok || !governanceJSONEquivalent(entry["depends_on"], entry["merge_after"]) {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		for _, dependency := range dependencies {
			if !seen[dependency] {
				return nil, fmt.Errorf("ordered dependency is missing or not earlier")
			}
		}
		for _, dependency := range mergeAfter {
			if !seen[dependency] {
				return nil, fmt.Errorf("ordered dependency is missing or not earlier")
			}
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	return repos, nil
}

func validatePerRepoRollback(repos []string, value any) error {
	entries, ok := governanceMapSlice(value)
	if !ok {
		return fmt.Errorf("per-repo rollback is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[governanceStringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		scope, _ := governanceStringSlice(entry["rollback_scope"])
		if entry == nil || governanceStringField(entry, "status") != "ready" || len(scope) == 0 {
			return fmt.Errorf("per-repo rollback is incomplete")
		}
	}
	return nil
}

func validatePerRepoCI(repos []string, value any) error {
	entries, ok := governanceMapSlice(value)
	if !ok {
		return fmt.Errorf("per-repo CI is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[governanceStringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		status := governanceStringField(entry, "status")
		if entry == nil || !governanceBoolField(entry, "required") || (status != "passed" && status != "success") {
			return fmt.Errorf("per-repo CI is incomplete")
		}
	}
	return nil
}

func validateFreshRepoState(repos []string, value any, now time.Time) error {
	entries, ok := governanceMapSlice(value)
	if !ok {
		return fmt.Errorf("repo state evidence is stale")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[governanceStringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		if entry == nil || governanceStringField(entry, "status") != "clean_synced" || governanceStringField(entry, "branch") != "main" {
			return fmt.Errorf("repo state evidence is stale")
		}
		observedAt, observedErr := time.Parse(time.RFC3339, governanceStringField(entry, "observed_at_utc"))
		expiresAt, expiresErr := time.Parse(time.RFC3339, governanceStringField(entry, "expires_at_utc"))
		if observedErr != nil || expiresErr != nil || observedAt.After(now) || !expiresAt.After(now) {
			return fmt.Errorf("repo state evidence is stale")
		}
	}
	return nil
}

func validMutationClass(value string) bool {
	switch value {
	case "docs_only_single_file",
		"docs_only_multi_file",
		"docs_config_only",
		"test_only",
		"low_risk_code",
		"multi_repo_low_risk",
		"complex_repo_mutation":
		return true
	default:
		return false
	}
}

func digestApprovedScope(scope map[string]any) (string, error) {
	bytes, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("encode approved_scope for digest: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func stringArrayContains(value any, want string) bool {
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, raw := range values {
		if raw == want {
			return true
		}
	}
	return false
}

func requireExactStringSlice(value any, want []string, label string) error {
	got, ok := governanceStringSlice(value)
	if !ok {
		return fmt.Errorf("%s must be a string array", label)
	}
	if len(got) != len(want) {
		return fmt.Errorf("%s must exactly match selected held candidate", label)
	}
	for index := range want {
		if got[index] != want[index] {
			return fmt.Errorf("%s must exactly match selected held candidate", label)
		}
	}
	return nil
}

func governanceStringField(document map[string]any, key string) string {
	value, _ := document[key].(string)
	return value
}

func governanceBoolField(document map[string]any, key string) bool {
	value, _ := document[key].(bool)
	return value
}

func governanceIntField(document map[string]any, key string) int {
	switch value := document[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func governanceStringSlice(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		values = append(values, text)
	}
	return values, true
}

func governanceMapSlice(value any) ([]map[string]any, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	values := make([]map[string]any, 0, len(items))
	for _, item := range items {
		document, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		values = append(values, document)
	}
	return values, true
}

func governanceJSONEquivalent(left any, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func StringField(document map[string]any, key string) string {
	return governanceStringField(document, key)
}

func BoolField(document map[string]any, key string) bool {
	return governanceBoolField(document, key)
}

func StringSliceField(value any) ([]string, bool) {
	return governanceStringSlice(value)
}

func JSONEquivalent(left any, right any) bool {
	return governanceJSONEquivalent(left, right)
}
