package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func runPolicyExplain(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *evidencePath == "" {
		fmt.Fprintln(stderr, "--evidence is required")
		return 2
	}
	evidence, err := readEvidencePackFile(*evidencePath)
	if err != nil {
		fmt.Fprintf(stderr, "read evidence: %v\n", err)
		return 1
	}
	report := policyExplainReport{
		SchemaVersion:      schema.PolicyExplainResultSchemaID,
		PolicyExplanations: policy.ExplainDecisions(evidence.PolicyDecisions),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicyExplainResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy explanations: %v\n", err)
			return 1
		}
		return 0
	}
	printPolicyExplanations(stdout, report.PolicyExplanations)
	return 0
}

func runPolicyIndex(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy index", flag.ContinueOnError)
	flags.SetOutput(stderr)
	evidencePath := flags.String("evidence", "", "path to evidence-pack.json")
	bundlePath := flags.String("bundle", "", "path to evidence bundle zip")
	publicKeyPath := flags.String("public-key", "", "path to public key for signed bundles")
	taskID := flags.String("task", "", "filter by task id")
	effectType := flags.String("effect", "", "filter by side effect type")
	resource := flags.String("resource", "", "filter by side effect resource")
	decision := flags.String("decision", "", "filter by decision allow or deny")
	approvalState := flags.String("approval", "", "filter by approval state: with-ticket or without-ticket")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if (*evidencePath == "" && *bundlePath == "") || (*evidencePath != "" && *bundlePath != "") {
		fmt.Fprintln(stderr, "provide exactly one of --evidence or --bundle")
		return 2
	}
	if *approvalState != "" && *approvalState != policy.ApprovalStateWithTicket && *approvalState != policy.ApprovalStateWithoutTicket {
		fmt.Fprintf(stderr, "--approval must be %q or %q\n", policy.ApprovalStateWithTicket, policy.ApprovalStateWithoutTicket)
		return 2
	}
	decisions, err := readPolicyIndexDecisions(*evidencePath, *bundlePath, *publicKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "read policy source: %v\n", err)
		return 1
	}
	decisions = policy.FilterDecisions(decisions, policy.DecisionFilters{
		TaskID:        *taskID,
		EffectType:    *effectType,
		Resource:      *resource,
		Decision:      *decision,
		ApprovalState: *approvalState,
	})
	report := policyIndexReport{
		SchemaVersion:      schema.PolicyIndexResultSchemaID,
		PolicyCount:        len(decisions),
		PolicyDecisions:    decisions,
		PolicyExplanations: policy.ExplainDecisions(decisions),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicyIndexResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy index: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "policy_count=%d\n", report.PolicyCount)
	printPolicyExplanations(stdout, report.PolicyExplanations)
	return 0
}

func readPolicyIndexDecisions(evidencePath string, bundlePath string, publicKeyPath string) ([]policy.Decision, error) {
	if evidencePath != "" {
		evidence, err := readEvidencePackFile(evidencePath)
		if err != nil {
			return nil, fmt.Errorf("read evidence: %w", err)
		}
		return evidence.PolicyDecisions, nil
	}
	report, err := bundlepkg.Report(bundlepkg.ReportOptions{
		BundlePath:    bundlePath,
		PublicKeyPath: publicKeyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	return report.PolicyDecisions, nil
}

func runPolicySpine(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy spine", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := policy.AO2FirstSpine(schema.PolicySpineResultSchemaID)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.PolicySpineResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy spine: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "stack=%s\n", report.Stack)
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "active_repositories=%s\n", strings.Join(report.Scope.ActiveRepositories, ","))
	for _, responsibility := range report.Responsibilities {
		fmt.Fprintf(stdout, "responsibility=%s owner=%s gates=%s\n", responsibility.Name, responsibility.Owner, strings.Join(responsibility.Gates, ";"))
	}
	for _, boundary := range report.OutOfBounds {
		fmt.Fprintf(stdout, "out_of_bounds=%s\n", boundary)
	}
	return 0
}

func runPolicyCredentialChecklist(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy credential-checklist", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := policy.ScopedCredentialPolicyChecklist(schema.ScopedCredentialPolicyChecklistSchemaID)
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.ScopedCredentialPolicyChecklistSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write credential checklist: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "scope=%s\n", report.Scope)
	fmt.Fprintf(stdout, "credential_values_inspected=%t\n", report.CredentialValuesInspected)
	fmt.Fprintf(stdout, "requires_credential_material=%t\n", report.RequiresCredentialMaterial)
	for _, check := range report.Checks {
		fmt.Fprintf(stdout, "check=%s status=%s requires_credential_value=%t\n", check.ID, check.Status, check.RequiresCredentialValue)
	}
	return 0
}

func runPolicyClaimPublishGate(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("policy claim-publish-gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	claimReadinessPath := flags.String("claim-readiness", "", "path to AO2 RSI claim-readiness summary JSON")
	readbackIndexPath := flags.String("readback-index", "", "path to AO2 live self-change readback index summary JSON")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *claimReadinessPath == "" {
		fmt.Fprintln(stderr, "--claim-readiness is required")
		return 2
	}
	if *readbackIndexPath == "" {
		fmt.Fprintln(stderr, "--readback-index is required")
		return 2
	}
	claimReadiness, err := readJSONObjectFile(*claimReadinessPath)
	if err != nil {
		fmt.Fprintf(stderr, "read claim readiness: %v\n", err)
		return 1
	}
	readbackIndex, err := readJSONObjectFile(*readbackIndexPath)
	if err != nil {
		fmt.Fprintf(stderr, "read readback index: %v\n", err)
		return 1
	}
	report := policy.EvaluateRSIClaimPublishGate(policy.ClaimPublishGateInput{
		ClaimReadiness: claimReadiness,
		ReadbackIndex:  readbackIndex,
	})
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.RSIClaimPublishGateSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write policy claim-publish gate: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "status=%s\n", report.Status)
	fmt.Fprintf(stdout, "decision=%s\n", report.Decision)
	fmt.Fprintf(stdout, "publish_authority=%t\n", report.PublishAuthority)
	fmt.Fprintf(stdout, "claim_level=%s\n", report.ClaimLevel)
	fmt.Fprintf(stdout, "claim_publish_resource=%s\n", report.ClaimPublishResource)
	for _, blocker := range report.Blockers {
		fmt.Fprintf(stdout, "blocker=%s evidence_state=%s required_evidence=%s\n", blocker.ID, blocker.EvidenceState, blocker.RequiredEvidence)
	}
	return 0
}

func readJSONObjectFile(path string) (map[string]any, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func printPolicyExplanations(stdout io.Writer, explanations []policy.Explanation) {
	for _, explanation := range explanations {
		fmt.Fprintf(stdout, "policy=%s task=%s decision=%s effect=%s resource=%s summary=%s\n", explanation.DecisionID, explanation.TaskID, explanation.Decision, explanation.EffectType, explanation.Resource, explanation.Summary)
		if explanation.OperatorAction != "" {
			fmt.Fprintf(stdout, "policy_action=%s action=%s\n", explanation.DecisionID, explanation.OperatorAction)
		}
	}
}
