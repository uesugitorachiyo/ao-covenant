package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func runApprovalCreate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	taskID := flags.String("task", "", "task id")
	effectType := flags.String("effect", "", "side effect type")
	resource := flags.String("resource", "", "side effect resource")
	reason := flags.String("reason", "", "approval reason")
	outPath := flags.String("out", "", "path to write approval ticket JSON")
	ticketID := flags.String("ticket-id", "", "approval ticket id")
	approved := flags.Bool("approved", true, "whether the ticket approves the effect")
	operatorID := flags.String("operator", "", "operator identity approving the ticket")
	expiresAt := flags.String("expires-at", "", "RFC3339 timestamp when the approval expires")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *taskID == "" || *effectType == "" || *resource == "" || *reason == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--task, --effect, --resource, --reason, and --out are required")
		return 2
	}
	ticket, err := approval.Create(approval.CreateInput{
		TicketID:   *ticketID,
		TaskID:     *taskID,
		EffectType: *effectType,
		Resource:   *resource,
		Approved:   *approved,
		Reason:     *reason,
		OperatorID: *operatorID,
		ExpiresAt:  *expiresAt,
	})
	if err != nil {
		fmt.Fprintf(stderr, "create approval ticket: %v\n", err)
		return 1
	}
	ticketBytes, err := marshalSchemaJSONBytes(schema.ApprovalTicketSchemaID, ticket)
	if err != nil {
		fmt.Fprintf(stderr, "encode approval ticket: %v\n", err)
		return 1
	}
	if err := writeOutputFileBytes("approval create", *outPath, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "write approval ticket: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalCreateResult{
			SchemaVersion: schema.ApprovalCreateResultSchemaID,
			TicketPath:    *outPath,
			Ticket:        ticket,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalCreateResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval create result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "ticket=%s\n", *outPath)
	fmt.Fprintf(stdout, "ticket_id=%s\n", ticket.TicketID)
	if ticket.OperatorID != "" {
		fmt.Fprintf(stdout, "operator_id=%s\n", ticket.OperatorID)
	}
	if ticket.ExpiresAt != "" {
		fmt.Fprintf(stdout, "expires_at=%s\n", ticket.ExpiresAt)
	}
	return 0
}

func runApprovalInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.ApprovalTicketSchemaID, ticket); err != nil {
			fmt.Fprintf(stderr, "write approval ticket: %v\n", err)
			return 1
		}
		return 0
	}
	printTicket(stdout, ticket)
	return 0
}

func runApprovalValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	contractPath := flags.String("contract", "", "path to contract JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if *contractPath != "" {
		c, err := readContractFile(*contractPath)
		if err != nil {
			fmt.Fprintf(stderr, "read contract: %v\n", err)
			return 1
		}
		if err := approval.ValidateAgainstContract(c, ticket); err != nil {
			fmt.Fprintf(stderr, "validate approval ticket: %v\n", err)
			return 1
		}
	}
	if *jsonOutput {
		result := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      ticket.TicketID,
			ContractPath:  *contractPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", ticket.TicketID)
	return 0
}

func runApprovalLiveDocs(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalLiveDocsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalLiveDocsValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval live-docs command %q\n", args[0])
		printApprovalLiveDocsUsage(stderr)
		return 2
	}
}

func runApprovalLowRiskCodeLive(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalLowRiskCodeLiveUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalLowRiskCodeLiveValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval low-risk-code-live command %q\n", args[0])
		printApprovalLowRiskCodeLiveUsage(stderr)
		return 2
	}
}

func runApprovalMutationClass(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalMutationClassUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return runApprovalMutationClassValidate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval mutation-class command %q\n", args[0])
		printApprovalMutationClassUsage(stderr)
		return 2
	}
}

func runApprovalMutationClassValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval mutation-class validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "path to Foundry mutation-class authority request JSON")
	ticketPath := flags.String("ticket", "", "path to Covenant mutation-class authority ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *requestPath == "" {
		fmt.Fprintln(stderr, "--request is required")
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	request, err := readJSONObjectFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "read mutation-class authority request: %v\n", err)
		return 1
	}
	ticketBytes, err := os.ReadFile(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read mutation-class authority ticket: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.MutationClassAuthorityTicketSchemaID, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "validate mutation-class authority ticket schema: %v\n", err)
		return 1
	}
	var ticket map[string]any
	if err := json.Unmarshal(ticketBytes, &ticket); err != nil {
		fmt.Fprintf(stderr, "decode mutation-class authority ticket: %v\n", err)
		return 1
	}
	if err := validateMutationClassAuthorityTicket(request, ticket, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate mutation-class authority ticket: %v\n", err)
		return 1
	}
	result := mutationClassAuthorityValidateResult{
		SchemaVersion: schema.ApprovalValidateResultSchemaID,
		Valid:         true,
		TicketID:      stringField(ticket, "ticket_id"),
		RequestID:     stringField(ticket, "request_id"),
		MutationClass: stringField(ticket, "mutation_class"),
		SafeToRequest: boolField(request, "safe_to_request"),
		SafeToExecute: false,
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.TicketID,
			ContractPath:  *requestPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write mutation-class authority validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", result.TicketID)
	fmt.Fprintf(stdout, "request_id=%s\n", result.RequestID)
	fmt.Fprintf(stdout, "mutation_class=%s\n", result.MutationClass)
	fmt.Fprintf(stdout, "safe_to_request=%t\n", result.SafeToRequest)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	return 0
}

func runApprovalLowRiskCodeLiveValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval low-risk-code-live validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "path to Covenant low_risk_code live policy evidence JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "--policy is required")
		return 2
	}
	policyBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read low_risk_code live policy: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.LowRiskCodeLivePolicySchemaID, policyBytes); err != nil {
		fmt.Fprintf(stderr, "validate low_risk_code live policy schema: %v\n", err)
		return 1
	}
	var policy map[string]any
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		fmt.Fprintf(stderr, "decode low_risk_code live policy: %v\n", err)
		return 1
	}
	if err := validateLowRiskCodeLivePolicy(policy, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate low_risk_code live policy: %v\n", err)
		return 1
	}
	candidateScope, _ := policy["candidate_scope"].(map[string]any)
	repo, _ := candidateScope["repo"].(map[string]any)
	fileAllowlist, _ := stringSliceField(candidateScope["file_allowlist"])
	commandAllowlist, _ := stringSliceField(candidateScope["command_allowlist"])
	boundaries, _ := policy["authority_boundaries"].(map[string]any)
	result := lowRiskCodeLivePolicyValidateResult{
		SchemaVersion:     schema.ApprovalValidateResultSchemaID,
		Valid:             true,
		PolicyID:          stringField(policy, "policy_id"),
		MutationClass:     stringField(policy, "mutation_class"),
		CandidateRepo:     stringField(repo, "id"),
		BaseBranch:        stringField(candidateScope, "base_branch"),
		ProposedBranch:    stringField(candidateScope, "proposed_branch"),
		FileAllowlist:     fileAllowlist,
		CommandAllowlist:  commandAllowlist,
		SafeToRequest:     boolField(policy, "safe_to_request"),
		SafeToExecute:     boolField(policy, "safe_to_execute"),
		LiveMutationGrant: boolField(boundaries, "live_mutation_grant"),
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.PolicyID,
			ContractPath:  *policyPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write low_risk_code live policy validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "policy_id=%s\n", result.PolicyID)
	fmt.Fprintf(stdout, "mutation_class=%s\n", result.MutationClass)
	fmt.Fprintf(stdout, "candidate_repo=%s\n", result.CandidateRepo)
	fmt.Fprintf(stdout, "base_branch=%s\n", result.BaseBranch)
	fmt.Fprintf(stdout, "proposed_branch=%s\n", result.ProposedBranch)
	for _, path := range result.FileAllowlist {
		fmt.Fprintf(stdout, "file_allowlist=%s\n", path)
	}
	for _, command := range result.CommandAllowlist {
		fmt.Fprintf(stdout, "command_allowlist=%s\n", command)
	}
	fmt.Fprintf(stdout, "safe_to_request=%t\n", result.SafeToRequest)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	fmt.Fprintf(stdout, "live_mutation_grant=%t\n", result.LiveMutationGrant)
	return 0
}

func runApprovalLiveDocsValidate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval live-docs validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	requestPath := flags.String("request", "", "path to Foundry live docs approval request JSON")
	ticketPath := flags.String("ticket", "", "path to Covenant live docs approval ticket JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *requestPath == "" {
		fmt.Fprintln(stderr, "--request is required")
		return 2
	}
	if *ticketPath == "" {
		fmt.Fprintln(stderr, "--ticket is required")
		return 2
	}
	request, err := readJSONObjectFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval request: %v\n", err)
		return 1
	}
	ticketBytes, err := os.ReadFile(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	if err := schema.ValidateBytes(schema.LiveDocsApprovalTicketSchemaID, ticketBytes); err != nil {
		fmt.Fprintf(stderr, "validate approval ticket schema: %v\n", err)
		return 1
	}
	var ticket map[string]any
	if err := json.Unmarshal(ticketBytes, &ticket); err != nil {
		fmt.Fprintf(stderr, "decode approval ticket: %v\n", err)
		return 1
	}
	if err := validateLiveDocsApprovalTicket(request, ticket, time.Now().UTC()); err != nil {
		fmt.Fprintf(stderr, "validate live docs approval ticket: %v\n", err)
		return 1
	}
	result := liveDocsApprovalValidateResult{
		SchemaVersion: schema.ApprovalValidateResultSchemaID,
		Valid:         true,
		TicketID:      stringField(ticket, "ticket_id"),
		RequestID:     stringField(ticket, "request_id"),
		ApprovalState: stringField(ticket, "approval_state"),
		SafeToExecute: true,
	}
	if *jsonOutput {
		jsonResult := approvalValidateResult{
			SchemaVersion: schema.ApprovalValidateResultSchemaID,
			Valid:         true,
			TicketID:      result.TicketID,
			ContractPath:  *requestPath,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalValidateResultSchemaID, jsonResult); err != nil {
			fmt.Fprintf(stderr, "write approval validate result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, "valid=true")
	fmt.Fprintf(stdout, "ticket_id=%s\n", result.TicketID)
	fmt.Fprintf(stdout, "request_id=%s\n", result.RequestID)
	fmt.Fprintf(stdout, "approval_state=%s\n", result.ApprovalState)
	fmt.Fprintf(stdout, "safe_to_execute=%t\n", result.SafeToExecute)
	return 0
}

func validateLiveDocsApprovalTicket(request map[string]any, ticket map[string]any, now time.Time) error {
	if stringField(request, "schema_version") != "ao.foundry.live-mutation-approval-request.v0.1" {
		return fmt.Errorf("request schema_version must be ao.foundry.live-mutation-approval-request.v0.1")
	}
	if stringField(request, "status") != "pending_operator_approval" {
		return fmt.Errorf("request status must be pending_operator_approval")
	}
	if stringField(request, "first_live_class") != "docs_only" || boolField(request, "safe_to_request") != true || boolField(request, "safe_to_execute") != false {
		return fmt.Errorf("request must be safe_to_request=true, safe_to_execute=false, first_live_class=docs_only")
	}
	if stringField(ticket, "request_id") != stringField(request, "request_id") {
		return fmt.Errorf("ticket request_id does not match request")
	}
	if stringField(ticket, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(ticket, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(ticket, "consumed") {
		return fmt.Errorf("approval ticket has already been consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339, stringField(ticket, "expires_at"))
	if err != nil {
		return fmt.Errorf("approval ticket expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("approval ticket expired")
	}
	if stringField(ticket, "foundry_required_ticket_schema") != "ao.covenant.live-docs-approval-ticket.v0.1" {
		return fmt.Errorf("foundry_required_ticket_schema does not match request expectation")
	}
	ticketScope, ok := ticket["approved_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("approved_scope is required")
	}
	for _, field := range []string{"repo", "branch_policy", "docs_only_path_allowlist", "forbidden_paths", "max_changed_files"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match request")
		}
	}
	return nil
}

func validateMutationClassAuthorityTicket(request map[string]any, ticket map[string]any, now time.Time) error {
	if stringField(request, "schema_version") != "ao.foundry.mutation-class-authority-request.v0.1" {
		return fmt.Errorf("request schema_version must be ao.foundry.mutation-class-authority-request.v0.1")
	}
	if stringField(request, "status") != "pending_covenant_authority" {
		return fmt.Errorf("request status must be pending_covenant_authority")
	}
	requestClass := stringField(request, "mutation_class")
	if !validMutationClass(requestClass) {
		return fmt.Errorf("request mutation_class is not supported")
	}
	if boolField(request, "safe_to_request") != true || boolField(request, "safe_to_execute") != false {
		return fmt.Errorf("request must be safe_to_request=true and safe_to_execute=false")
	}
	if stringField(ticket, "request_id") != stringField(request, "request_id") {
		return fmt.Errorf("ticket request_id does not match request")
	}
	if stringField(ticket, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(ticket, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(ticket, "consumed") {
		return fmt.Errorf("authority ticket has already been consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339, stringField(ticket, "expires_at"))
	if err != nil {
		return fmt.Errorf("authority ticket expires_at must be RFC3339: %w", err)
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("authority ticket expired")
	}
	if stringField(ticket, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	ticketScope, ok := ticket["approved_scope"].(map[string]any)
	if !ok {
		return fmt.Errorf("approved_scope is required")
	}
	if stringField(ticketScope, "mutation_class") != requestClass {
		return fmt.Errorf("ticket mutation_class does not match request")
	}
	if !jsonEquivalent(ticketScope["allowed_paths"], request["allowed_paths"]) {
		return fmt.Errorf("ticket path scope is broader than request")
	}
	if !jsonEquivalent(ticketScope["max_changed_files"], request["max_changed_files"]) {
		return fmt.Errorf("ticket diff limit does not exactly match request")
	}
	for _, field := range []string{"repo", "branch_policy", "forbidden_paths", "required_gates", "authority_boundary"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match request")
		}
	}
	if boolField(request, "rollback_required") != true || boolField(ticketScope, "rollback_required") != true {
		return fmt.Errorf("rollback is required for mutation-class authority tickets")
	}
	for _, field := range []string{"rollback_scope", "rollback_evidence"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
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
	if stringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "approved_scope") {
		return fmt.Errorf("scope_digest must cover approved_scope")
	}
	expected, err := digestApprovedScope(ticketScope)
	if err != nil {
		return err
	}
	if stringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match approved_scope")
	}
	boundaries, ok := ticket["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use"} {
		if !boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "provider_calls_allowed", "release_or_publish_allowed"} {
		if boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be false", field)
		}
	}
	return nil
}

func validateLowRiskCodeLivePolicy(policy map[string]any, now time.Time) error {
	if stringField(policy, "schema_version") != schema.LowRiskCodeLivePolicySchemaID {
		return fmt.Errorf("schema_version must be %s", schema.LowRiskCodeLivePolicySchemaID)
	}
	if stringField(policy, "approval_state") != "approved" {
		return fmt.Errorf("approval_state must be approved")
	}
	if stringField(policy, "approver_identity") == "" {
		return fmt.Errorf("approver_identity is required")
	}
	if boolField(policy, "consumed") {
		return fmt.Errorf("low_risk_code live policy has already been consumed")
	}
	if stringField(policy, "mutation_class") != "low_risk_code" {
		return fmt.Errorf("mutation_class must be low_risk_code")
	}
	if boolField(policy, "safe_to_request") != true || boolField(policy, "safe_to_execute") != false {
		return fmt.Errorf("policy must be safe_to_request=true and safe_to_execute=false")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339, stringField(policy, "issued_at"))
	expiresAt, expiresErr := time.Parse(time.RFC3339, stringField(policy, "expires_at"))
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
	if stringField(digest, "algorithm") != "sha256" {
		return fmt.Errorf("scope_digest algorithm must be sha256")
	}
	if !stringArrayContains(digest["covers"], "candidate_scope") {
		return fmt.Errorf("scope_digest must cover candidate_scope")
	}
	expected, err := digestApprovedScope(candidateScope)
	if err != nil {
		return err
	}
	if stringField(digest, "value") != expected {
		return fmt.Errorf("scope_digest does not match candidate_scope")
	}
	boundaries, ok := policy["authority_boundaries"].(map[string]any)
	if !ok {
		return fmt.Errorf("authority_boundaries are required")
	}
	for _, field := range []string{"exact_scope", "class_bound", "digest_bound", "single_use", "single_repo", "single_branch"} {
		if !boolField(boundaries, field) {
			return fmt.Errorf("authority boundary %s must be true", field)
		}
	}
	for _, field := range []string{"live_mutation_grant", "multi_repo_mutation_allowed", "complex_repo_mutation_allowed", "fully_unsupervised_complex_mutation_allowed", "provider_calls_allowed", "release_or_publish_allowed"} {
		if boolField(boundaries, field) {
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
	if stringField(chain, "path") != "tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json" {
		return fmt.Errorf("dry_run_chain path must be tmp/low-risk-code-live-rehearsal-20260630/chain/summary.json")
	}
	if stringField(chain, "sha256") != "046dcdc9a17fcfd60877c8e61d1a15c722f7c34cacdeeb139651f153c6e1196e" {
		return fmt.Errorf("dry_run_chain sha256 must match current held rehearsal chain")
	}
	repo, ok := scope["repo"].(map[string]any)
	if !ok {
		return fmt.Errorf("repo is required")
	}
	if stringField(repo, "id") != "ao-atlas" {
		return fmt.Errorf("repo id must be ao-atlas")
	}
	if stringField(repo, "remote") != "uesugitorachiyo/ao-atlas" {
		return fmt.Errorf("repo remote must be uesugitorachiyo/ao-atlas")
	}
	if stringField(scope, "base_branch") != "main" {
		return fmt.Errorf("base_branch must be main")
	}
	if stringField(scope, "proposed_branch") != "codex/low-risk-code-rehearsal-one" {
		return fmt.Errorf("proposed_branch must be codex/low-risk-code-rehearsal-one")
	}
	if stringField(scope, "intent") != "behavior-preserving cleanup in internal uniqueStrings helper" {
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
	if !boolField(rollbackPlan, "required") {
		return fmt.Errorf("rollback_plan required must be true")
	}
	if stringField(rollbackPlan, "strategy") == "" {
		return fmt.Errorf("rollback_plan strategy is required")
	}
	if err := requireExactStringSlice(rollbackPlan["scope"], []string{"internal/atlas/validate.go"}, "rollback_plan scope"); err != nil {
		return err
	}
	return nil
}

func validateMultiRepoLowRiskAuthorityScope(request map[string]any, ticketScope map[string]any, now time.Time) error {
	for _, field := range []string{"multi_repo_plan", "per_repo_rollback", "ci_by_repo", "repo_state_evidence", "kill_switch"} {
		if !jsonEquivalent(ticketScope[field], request[field]) {
			return fmt.Errorf("ticket scope does not exactly match multi_repo_low_risk request")
		}
	}
	plan, ok := ticketScope["multi_repo_plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("multi_repo_low_risk ordered merge plan is required")
	}
	if stringField(plan, "status") != "ready" {
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
	if !ok || !boolField(killSwitch, "required") || stringField(killSwitch, "status") != "armed" {
		return fmt.Errorf("operator kill-switch must be armed for multi_repo_low_risk")
	}
	return nil
}

func validateOrderedMultiRepoPlan(plan map[string]any) ([]string, error) {
	order, ok := stringSliceField(plan["order"])
	if !ok || len(order) == 0 {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	entries, ok := mapSliceField(plan["ordered_merge_plan"])
	if !ok || len(entries) != len(order) {
		return nil, fmt.Errorf("ordered dependency is missing or not earlier")
	}
	seen := map[string]bool{}
	repos := make([]string, 0, len(entries))
	for index, entry := range entries {
		repo := stringField(entry, "repo")
		if repo == "" || repo != order[index] || intField(entry, "order") != index+1 || stringField(entry, "planned_pr") == "" {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		dependencies, ok := stringSliceField(entry["depends_on"])
		if !ok {
			return nil, fmt.Errorf("ordered dependency is missing or not earlier")
		}
		mergeAfter, ok := stringSliceField(entry["merge_after"])
		if !ok || !jsonEquivalent(entry["depends_on"], entry["merge_after"]) {
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
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("per-repo rollback is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		scope, _ := stringSliceField(entry["rollback_scope"])
		if entry == nil || stringField(entry, "status") != "ready" || len(scope) == 0 {
			return fmt.Errorf("per-repo rollback is incomplete")
		}
	}
	return nil
}

func validatePerRepoCI(repos []string, value any) error {
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("per-repo CI is incomplete")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		status := stringField(entry, "status")
		if entry == nil || !boolField(entry, "required") || (status != "passed" && status != "success") {
			return fmt.Errorf("per-repo CI is incomplete")
		}
	}
	return nil
}

func validateFreshRepoState(repos []string, value any, now time.Time) error {
	entries, ok := mapSliceField(value)
	if !ok {
		return fmt.Errorf("repo state evidence is stale")
	}
	byRepo := map[string]map[string]any{}
	for _, entry := range entries {
		byRepo[stringField(entry, "repo")] = entry
	}
	for _, repo := range repos {
		entry := byRepo[repo]
		if entry == nil || stringField(entry, "status") != "clean_synced" || stringField(entry, "branch") != "main" {
			return fmt.Errorf("repo state evidence is stale")
		}
		observedAt, observedErr := time.Parse(time.RFC3339, stringField(entry, "observed_at_utc"))
		expiresAt, expiresErr := time.Parse(time.RFC3339, stringField(entry, "expires_at_utc"))
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
	got, ok := stringSliceField(value)
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

func stringField(document map[string]any, key string) string {
	value, _ := document[key].(string)
	return value
}

func boolField(document map[string]any, key string) bool {
	value, _ := document[key].(bool)
	return value
}

func intField(document map[string]any, key string) int {
	switch value := document[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func stringSliceField(value any) ([]string, bool) {
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

func mapSliceField(value any) ([]map[string]any, bool) {
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

func jsonEquivalent(left any, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func runApprovalAttach(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval attach", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to contract JSON")
	ticketPath := flags.String("ticket", "", "path to approval ticket JSON")
	outPath := flags.String("out", "", "path to write approved contract JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *contractPath == "" || *ticketPath == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--contract, --ticket, and --out are required")
		return 2
	}
	c, err := readContractFile(*contractPath)
	if err != nil {
		fmt.Fprintf(stderr, "read contract: %v\n", err)
		return 1
	}
	ticket, err := approval.ReadTicket(*ticketPath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval ticket: %v\n", err)
		return 1
	}
	approvedContract, err := approval.Attach(c, ticket)
	if err != nil {
		fmt.Fprintf(stderr, "attach approval ticket: %v\n", err)
		return 1
	}
	contractBytes, err := marshalSchemaJSONBytes(schema.ContractSchemaID, approvedContract)
	if err != nil {
		fmt.Fprintf(stderr, "encode contract: %v\n", err)
		return 1
	}
	digest, err := contract.Digest(approvedContract)
	if err != nil {
		fmt.Fprintf(stderr, "digest contract: %v\n", err)
		return 1
	}
	if err := writeOutputPairWithRollback("approval attach", *outPath, contractBytes, *outPath+".sha256", []byte(digest+"\n")); err != nil {
		if outputPairErrorStage(err) == outputPairStageSidecar {
			fmt.Fprintf(stderr, "write digest: %v\n", err)
			return 1
		}
		fmt.Fprintf(stderr, "write contract: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalAttachResult{
			SchemaVersion:  schema.ApprovalAttachResultSchemaID,
			ContractPath:   *outPath,
			ContractDigest: digest,
			ApprovalCount:  len(approvedContract.Approvals),
			TicketID:       ticket.TicketID,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalAttachResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval attach result: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "contract=%s\n", *outPath)
	fmt.Fprintf(stdout, "contract_digest=%s\n", digest)
	fmt.Fprintf(stdout, "approvals=%d\n", len(approvedContract.Approvals))
	return 0
}

func runApprovalRevoke(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ticketID := flags.String("ticket-id", "", "approval ticket id to revoke")
	reason := flags.String("reason", "", "revocation reason")
	outPath := flags.String("out", "", "path to write approval revocation list JSON")
	appendToExisting := flags.Bool("append", false, "append to an existing revocation list")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *ticketID == "" || *reason == "" || *outPath == "" {
		fmt.Fprintln(stderr, "--ticket-id, --reason, and --out are required")
		return 2
	}

	list := approval.RevocationList{
		SchemaVersion: schema.ApprovalRevocationsSchemaID,
		RevokedTickets: []approval.RevokedTicket{
			{
				TicketID: *ticketID,
				Reason:   *reason,
			},
		},
	}
	if *appendToExisting {
		existing, err := approval.ReadRevocationList(*outPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "read approval revocation list: %v\n", err)
			return 1
		}
		if err == nil {
			list = existing
			list.RevokedTickets = append(list.RevokedTickets, approval.RevokedTicket{
				TicketID: *ticketID,
				Reason:   *reason,
			})
		}
	}
	if err := approval.ValidateRevocationList(list); err != nil {
		fmt.Fprintf(stderr, "validate approval revocation list: %v\n", err)
		return 1
	}
	revocationBytes, err := marshalSchemaJSONBytes(schema.ApprovalRevocationsSchemaID, list)
	if err != nil {
		fmt.Fprintf(stderr, "encode approval revocation list: %v\n", err)
		return 1
	}
	if err := writeOutputFileBytes("approval revoke", *outPath, revocationBytes); err != nil {
		fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalRevokeResult{
			SchemaVersion:      schema.ApprovalRevokeResultSchemaID,
			RevocationsPath:    *outPath,
			RevokedTicketCount: len(list.RevokedTickets),
			TicketID:           *ticketID,
			Revocations:        list,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalRevokeResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "revocations=%s\n", *outPath)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", len(list.RevokedTickets))
	fmt.Fprintf(stdout, "ticket_id=%s\n", *ticketID)
	return 0
}

func runApprovalRevocations(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalRevocationsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "inspect":
		return runApprovalRevocationsInspect(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval revocations command %q\n", args[0])
		printApprovalRevocationsUsage(stderr)
		return 2
	}
}

func runApprovalRevocationsInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("approval revocations inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "path to approval revocation list JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *filePath == "" {
		fmt.Fprintln(stderr, "--file is required")
		return 2
	}
	list, err := approval.ReadRevocationList(*filePath)
	if err != nil {
		fmt.Fprintf(stderr, "read approval revocation list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		result := approvalRevocationsInspectResult{
			SchemaVersion:      schema.ApprovalRevocationsInspectResultSchemaID,
			RevocationsPath:    *filePath,
			RevokedTicketCount: len(list.RevokedTickets),
			Revocations:        list,
		}
		if err := writeSchemaJSON(stdout, schema.ApprovalRevocationsInspectResultSchemaID, result); err != nil {
			fmt.Fprintf(stderr, "write approval revocation list: %v\n", err)
			return 1
		}
		return 0
	}
	printRevocationListSummary(stdout, list)
	return 0
}

func printRevocationListSummary(stdout io.Writer, list approval.RevocationList) {
	fmt.Fprintf(stdout, "schema_version=%s\n", list.SchemaVersion)
	fmt.Fprintf(stdout, "revoked_ticket_count=%d\n", len(list.RevokedTickets))
	for _, revoked := range list.RevokedTickets {
		fmt.Fprintf(stdout, "ticket_id=%s reason=%s\n", revoked.TicketID, revoked.Reason)
	}
}
