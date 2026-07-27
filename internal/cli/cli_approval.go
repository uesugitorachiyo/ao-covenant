package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
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
	if err := policy.ValidateMutationClassAuthorityTicket(request, ticket, time.Now().UTC()); err != nil {
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
	var policyDocument map[string]any
	if err := json.Unmarshal(policyBytes, &policyDocument); err != nil {
		fmt.Fprintf(stderr, "decode low_risk_code live policy: %v\n", err)
		return 1
	}
	if err := policy.ValidateLowRiskCodeLivePolicy(policyDocument, time.Now().UTC(), schema.LowRiskCodeLivePolicySchemaID); err != nil {
		fmt.Fprintf(stderr, "validate low_risk_code live policy: %v\n", err)
		return 1
	}
	candidateScope, _ := policyDocument["candidate_scope"].(map[string]any)
	repo, _ := candidateScope["repo"].(map[string]any)
	fileAllowlist, _ := stringSliceField(candidateScope["file_allowlist"])
	commandAllowlist, _ := stringSliceField(candidateScope["command_allowlist"])
	boundaries, _ := policyDocument["authority_boundaries"].(map[string]any)
	result := lowRiskCodeLivePolicyValidateResult{
		SchemaVersion:     schema.ApprovalValidateResultSchemaID,
		Valid:             true,
		PolicyID:          stringField(policyDocument, "policy_id"),
		MutationClass:     stringField(policyDocument, "mutation_class"),
		CandidateRepo:     stringField(repo, "id"),
		BaseBranch:        stringField(candidateScope, "base_branch"),
		ProposedBranch:    stringField(candidateScope, "proposed_branch"),
		FileAllowlist:     fileAllowlist,
		CommandAllowlist:  commandAllowlist,
		SafeToRequest:     boolField(policyDocument, "safe_to_request"),
		SafeToExecute:     boolField(policyDocument, "safe_to_execute"),
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

func stringField(document map[string]any, key string) string {
	return policy.StringField(document, key)
}

func boolField(document map[string]any, key string) bool {
	return policy.BoolField(document, key)
}

func stringSliceField(value any) ([]string, bool) {
	return policy.StringSliceField(value)
}

func jsonEquivalent(left any, right any) bool {
	return policy.JSONEquivalent(left, right)
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
