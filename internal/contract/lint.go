package contract

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

type LintDiagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Line     int    `json:"line,omitempty"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`
	Hint     string `json:"hint,omitempty"`
}

type LintResult struct {
	SchemaVersion string           `json:"schema_version,omitempty"`
	Valid         bool             `json:"valid"`
	Diagnostics   []LintDiagnostic `json:"diagnostics"`
}

type LintSARIFOptions struct {
	SourceURI string
	Baseline  LintSARIFBaseline
}

const LintSARIFBaselineSchemaVersion = "covenant.lint-sarif-baseline.v1"

type LintSARIFBaseline struct {
	SchemaVersion string                   `json:"schema_version"`
	Accepted      []LintSARIFBaselineEntry `json:"accepted"`
}

type LintSARIFBaselineEntry struct {
	RuleID        string `json:"rule_id"`
	SourceURI     string `json:"source_uri"`
	Line          int    `json:"line,omitempty"`
	Field         string `json:"field,omitempty"`
	Justification string `json:"justification"`
}

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription SARIFMessage `json:"shortDescription,omitempty"`
	Help             SARIFMessage `json:"help,omitempty"`
}

type SARIFResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      SARIFMessage       `json:"message"`
	Locations    []SARIFLocation    `json:"locations,omitempty"`
	Suppressions []SARIFSuppression `json:"suppressions,omitempty"`
	Properties   map[string]string  `json:"properties,omitempty"`
}

type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

func LintSARIF(result LintResult, opts LintSARIFOptions) SARIFLog {
	rules := []SARIFRule{}
	ruleSeen := map[string]bool{}
	results := make([]SARIFResult, 0, len(result.Diagnostics))
	for _, diagnostic := range result.Diagnostics {
		if !ruleSeen[diagnostic.Code] {
			rules = append(rules, SARIFRule{
				ID:               diagnostic.Code,
				Name:             diagnostic.Code,
				ShortDescription: SARIFMessage{Text: diagnostic.Message},
				Help:             SARIFMessage{Text: diagnostic.Hint},
			})
			ruleSeen[diagnostic.Code] = true
		}
		sarifResult := SARIFResult{
			RuleID:       diagnostic.Code,
			Level:        sarifLevel(diagnostic.Severity),
			Message:      SARIFMessage{Text: diagnostic.Message},
			Suppressions: sarifSuppressionsForDiagnostic(diagnostic, opts),
			Properties:   lintDiagnosticProperties(diagnostic),
		}
		if opts.SourceURI != "" {
			location := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: opts.SourceURI},
				},
			}
			if diagnostic.Line > 0 {
				location.PhysicalLocation.Region = SARIFRegion{StartLine: diagnostic.Line}
			}
			sarifResult.Locations = []SARIFLocation{location}
		}
		results = append(results, sarifResult)
	}
	return SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "AO Covenant",
						InformationURI: "https://github.com/uesugitorachiyo/ao-covenant",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

func LintDiagnosticsAllSuppressed(result LintResult, opts LintSARIFOptions) bool {
	if len(result.Diagnostics) == 0 {
		return false
	}
	for _, diagnostic := range result.Diagnostics {
		if len(sarifSuppressionsForDiagnostic(diagnostic, opts)) == 0 {
			return false
		}
	}
	return true
}

func sarifSuppressionsForDiagnostic(diagnostic LintDiagnostic, opts LintSARIFOptions) []SARIFSuppression {
	entry, ok := matchingSARIFBaselineEntry(diagnostic, opts)
	if !ok {
		return nil
	}
	return []SARIFSuppression{
		{
			Kind:          "external",
			Justification: entry.Justification,
		},
	}
}

func matchingSARIFBaselineEntry(diagnostic LintDiagnostic, opts LintSARIFOptions) (LintSARIFBaselineEntry, bool) {
	for _, entry := range opts.Baseline.Accepted {
		if entry.RuleID != diagnostic.Code {
			continue
		}
		if entry.SourceURI != "" && entry.SourceURI != opts.SourceURI {
			continue
		}
		if entry.Line != 0 && entry.Line != diagnostic.Line {
			continue
		}
		if entry.Field != "" && entry.Field != diagnostic.Field {
			continue
		}
		return entry, true
	}
	return LintSARIFBaselineEntry{}, false
}

func LintBrief(brief string, opts CompileOptions) LintResult {
	if strings.TrimSpace(brief) == "" {
		return lintError(fmt.Errorf("brief is required"))
	}
	normalizedSourcePath := path.Clean(strings.ReplaceAll(opts.SourcePath, "\\", "/"))
	if normalizedSourcePath == "." {
		return lintError(fmt.Errorf("brief path is required"))
	}
	if err := validateRelativePath(normalizedSourcePath, "brief path"); err != nil {
		return lintError(err)
	}
	structured, ok, err := parseStructuredBrief(brief)
	if err != nil {
		return lintError(err)
	}
	if ok {
		return lintStructuredBrief(brief, normalizedSourcePath, opts.WorkspaceWrites, structured)
	}
	if _, err := CompileBriefWithOptions(brief, opts); err != nil {
		return lintError(err)
	}
	return LintResult{Valid: true, Diagnostics: []LintDiagnostic{}}
}

func LintContract(c Contract) LintResult {
	diagnostics := lintContractDiagnostics(c)
	if len(diagnostics) > 0 {
		return LintResult{Valid: false, Diagnostics: diagnostics}
	}
	return LintResult{Valid: true, Diagnostics: []LintDiagnostic{}}
}

func sarifLevel(severity string) string {
	switch severity {
	case "error":
		return "error"
	case "warning":
		return "warning"
	case "note":
		return "note"
	default:
		return "none"
	}
}

func lintDiagnosticProperties(diagnostic LintDiagnostic) map[string]string {
	properties := map[string]string{}
	if diagnostic.Field != "" {
		properties["field"] = diagnostic.Field
	}
	if diagnostic.Hint != "" {
		properties["hint"] = diagnostic.Hint
	}
	if len(properties) == 0 {
		return nil
	}
	return properties
}

func lintStructuredBrief(brief string, sourcePath string, rawWriteOverrides []string, parsed structuredBrief) LintResult {
	diagnostics := []LintDiagnostic{}
	if _, err := normalizeAuthoredPaths(parsed.reads, "workspace read"); err != nil {
		diagnostics = append(diagnostics, diagnosticForError(err))
	}
	writes, err := structuredWorkspaceWrites(rawWriteOverrides, parsed)
	if err != nil {
		diagnostics = append(diagnostics, diagnosticForError(err))
	}
	if err == nil {
		diagnostics = append(diagnostics, lintStructuredAuthoringDiagnostics(parsed, writes)...)
	}
	if len(diagnostics) > 0 {
		return LintResult{Valid: false, Diagnostics: diagnostics}
	}
	if _, err := buildStructuredContract(brief, sourcePath, rawWriteOverrides, parsed); err != nil {
		return lintError(err)
	}
	return LintResult{Valid: true, Diagnostics: []LintDiagnostic{}}
}

func lintStructuredAuthoringDiagnostics(parsed structuredBrief, workspaceWrites []string) []LintDiagnostic {
	diagnostics := []LintDiagnostic{}
	obligationIDs := map[string]int{}
	for i, obligation := range parsed.obligations {
		line := lineAt(parsed.obligationLines, i, 0)
		if err := validatePublicID(obligation.ID, "obligation id"); err != nil {
			diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_OBLIGATION_ID_INVALID", line, "%v", err))
			continue
		}
		if firstLine, exists := obligationIDs[obligation.ID]; exists {
			diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_OBLIGATION_ID_DUPLICATE", line, "duplicate obligation id %q; first defined at line %d", obligation.ID, firstLine))
			continue
		}
		obligationIDs[obligation.ID] = line
	}

	taskIDs := map[string]int{}
	for _, task := range parsed.tasks {
		if err := validatePublicID(task.id, "task id"); err != nil {
			diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_ID_INVALID", task.line, "%v", err))
			continue
		}
		if firstLine, exists := taskIDs[task.id]; exists {
			diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_ID_DUPLICATE", task.line, "duplicate task id %q; first defined at line %d", task.id, firstLine))
			continue
		}
		taskIDs[task.id] = task.line
	}

	workspaceWriteSet := map[string]bool{}
	for _, writePath := range workspaceWrites {
		workspaceWriteSet[writePath] = true
	}
	for _, task := range parsed.tasks {
		for i, dep := range task.dependsOn {
			if _, exists := taskIDs[dep]; !exists {
				diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_DEP_UNKNOWN", lineAt(task.dependsOnLines, i, task.line), "task %q depends on unknown task %q", task.id, dep))
			}
		}
		for i, obligationID := range task.obligations {
			if _, exists := obligationIDs[obligationID]; !exists {
				diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_OBLIGATION_UNKNOWN", lineAt(task.obligationLines, i, task.line), "task %q references unknown obligation %q", task.id, obligationID))
			}
		}
		for i, writePath := range task.writes {
			normalized := path.Clean(strings.ReplaceAll(writePath, "\\", "/"))
			if err := validateRelativePath(normalized, "side effect resource"); err != nil {
				diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_WRITE_INVALID", lineAt(task.writeLines, i, task.line), "%v", err))
				continue
			}
			if !workspaceWriteSet[normalized] {
				diagnostics = append(diagnostics, authoringDiagnostic("STRUCTURED_TASK_WRITE_UNDECLARED", lineAt(task.writeLines, i, task.line), "task %q writes %q outside workspace writes; add it under # Writes or pass --write %s", task.id, normalized, normalized))
			}
		}
	}
	return diagnostics
}

func lintContractDiagnostics(c Contract) []LintDiagnostic {
	diagnostics := []LintDiagnostic{}
	if c.SchemaVersion != ContractSchemaVersion {
		diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("unsupported schema_version %q", c.SchemaVersion)))
	}
	if strings.TrimSpace(c.Objective) == "" {
		diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("objective is required")))
	}
	if err := validateRelativePath(c.Workspace.Root, "workspace root"); err != nil {
		diagnostics = append(diagnostics, diagnosticForError(err))
	}
	for _, readPath := range c.Workspace.Reads {
		if err := validateRelativePath(readPath, "read path"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
		}
	}
	for _, writePath := range c.Workspace.Writes {
		if err := validateRelativePath(writePath, "write path"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
		}
	}

	obligationIDs := map[string]bool{}
	requiredObligationIDs := map[string]bool{}
	requiredCount := 0
	for _, obligation := range c.Obligations {
		if err := validatePublicID(obligation.ID, "obligation id"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
			continue
		}
		if obligationIDs[obligation.ID] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("duplicate obligation id %q", obligation.ID)))
			continue
		}
		obligationIDs[obligation.ID] = true
		if obligation.Required {
			requiredCount++
			requiredObligationIDs[obligation.ID] = true
		}
	}
	if requiredCount == 0 {
		diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("at least one required obligation is required")))
	}

	taskIDs := map[string]Task{}
	for _, task := range c.Tasks {
		if err := validatePublicID(task.ID, "task id"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
			continue
		}
		if _, exists := taskIDs[task.ID]; exists {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("duplicate task id %q", task.ID)))
			continue
		}
		if !allowedTaskKinds[task.Kind] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("unsupported task kind %q for task %q", task.Kind, task.ID)))
		}
		if strings.TrimSpace(task.Adapter) == "" {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("adapter is required for task %q", task.ID)))
		}
		if task.TimeoutSecs <= 0 {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("timeout_seconds must be positive for task %q", task.ID)))
		}
		for _, obligationID := range task.Obligations {
			if !obligationIDs[obligationID] {
				diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("task %q references unknown obligation %q", task.ID, obligationID)))
			}
		}
		for _, action := range task.DeclaredSideEffects {
			if !allowedSideEffectTypes[action.Type] {
				diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("unsupported side effect type %q for task %q", action.Type, task.ID)))
			}
			if err := validateRelativePath(action.Resource, "side effect resource"); err != nil {
				diagnostics = append(diagnostics, diagnosticForError(err))
			}
		}
		taskIDs[task.ID] = task
	}
	if len(taskIDs) == 0 {
		diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("at least one task is required")))
	}
	diagnostics = append(diagnostics, lintApprovalDiagnostics(c, taskIDs)...)
	for _, task := range c.Tasks {
		for _, dep := range task.DependsOn {
			if _, exists := taskIDs[dep]; !exists {
				diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("task %q depends on unknown task %q", task.ID, dep)))
			}
		}
	}
	if hasCycle(c.Tasks) {
		diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("task graph contains a cycle")))
	}
	evaluatorObligationIDs := map[string]bool{}
	for _, obligationID := range c.Evaluator.RequiredObligations {
		if !obligationIDs[obligationID] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("evaluator references unknown obligation %q", obligationID)))
		}
		evaluatorObligationIDs[obligationID] = true
	}
	for obligationID := range requiredObligationIDs {
		if !evaluatorObligationIDs[obligationID] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("required obligation %q is missing from evaluator required_obligations", obligationID)))
		}
	}
	return diagnostics
}

func lintApprovalDiagnostics(c Contract, taskIDs map[string]Task) []LintDiagnostic {
	diagnostics := []LintDiagnostic{}
	ticketIDs := map[string]bool{}
	declaredEffects := map[string]bool{}
	for _, task := range taskIDs {
		for _, action := range task.DeclaredSideEffects {
			declaredEffects[sideEffectKey(task.ID, action.Type, action.Resource)] = true
		}
	}
	for _, approval := range c.Approvals {
		if approval.SchemaVersion != policy.ApprovalTicketSchemaVersion {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("unsupported approval ticket schema_version %q", approval.SchemaVersion)))
		}
		if err := validatePublicID(approval.TicketID, "approval ticket id"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
		}
		if ticketIDs[approval.TicketID] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("duplicate approval ticket id %q", approval.TicketID)))
		}
		ticketIDs[approval.TicketID] = true
		if _, exists := taskIDs[approval.TaskID]; !exists {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("approval ticket %q references unknown task %q", approval.TicketID, approval.TaskID)))
		}
		if !allowedSideEffectTypes[approval.EffectType] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("approval ticket %q references unsupported side effect type %q", approval.TicketID, approval.EffectType)))
		}
		if err := validateRelativePath(approval.Resource, "approval ticket resource"); err != nil {
			diagnostics = append(diagnostics, diagnosticForError(err))
		}
		if strings.TrimSpace(approval.Reason) == "" {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("approval ticket %q reason is required", approval.TicketID)))
		}
		if strings.TrimSpace(approval.ExpiresAt) != "" {
			if _, err := time.Parse(time.RFC3339, approval.ExpiresAt); err != nil {
				diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("approval ticket %q expires_at must be RFC3339: %w", approval.TicketID, err)))
			}
		}
		if !declaredEffects[sideEffectKey(approval.TaskID, approval.EffectType, approval.Resource)] {
			diagnostics = append(diagnostics, diagnosticForError(fmt.Errorf("approval ticket %q does not match a declared side effect", approval.TicketID)))
		}
	}
	return diagnostics
}

func lintError(err error) LintResult {
	return LintResult{
		Valid:       false,
		Diagnostics: []LintDiagnostic{diagnosticForError(err)},
	}
}

func authoringDiagnostic(code string, line int, format string, args ...any) LintDiagnostic {
	return diagnosticForError(newAuthoringDiagnostic(code, line, format, args...))
}

func diagnosticForError(err error) LintDiagnostic {
	var authoring *AuthoringDiagnosticError
	if errors.As(err, &authoring) {
		code := authoring.Diagnostic.Code
		message := authoring.Diagnostic.Message
		return LintDiagnostic{
			Code:     code,
			Severity: "error",
			Line:     authoring.Diagnostic.Line,
			Message:  message,
			Hint:     diagnosticHint(code, message),
		}
	}
	message := err.Error()
	code, field := contractDiagnosticCode(message)
	return LintDiagnostic{
		Code:     code,
		Severity: "error",
		Field:    field,
		Message:  message,
		Hint:     diagnosticHint(code, message),
	}
}

func contractDiagnosticCode(message string) (string, string) {
	switch {
	case strings.Contains(message, "schema_version"):
		return "CONTRACT_SCHEMA_UNSUPPORTED", "schema_version"
	case message == "objective is required":
		return "CONTRACT_OBJECTIVE_REQUIRED", "objective"
	case strings.Contains(message, "workspace root"):
		return "CONTRACT_WORKSPACE_ROOT_INVALID", "workspace.root"
	case strings.Contains(message, "read path"):
		return "CONTRACT_WORKSPACE_READ_INVALID", "workspace.reads"
	case strings.Contains(message, "write path"):
		return "CONTRACT_WORKSPACE_WRITE_INVALID", "workspace.writes"
	case strings.Contains(message, "duplicate obligation id"):
		return "CONTRACT_OBLIGATION_DUPLICATE", "obligations"
	case strings.Contains(message, "obligation id"):
		return "CONTRACT_OBLIGATION_ID_INVALID", "obligations"
	case strings.Contains(message, "at least one required obligation"):
		return "CONTRACT_REQUIRED_OBLIGATION_MISSING", "obligations"
	case strings.Contains(message, "duplicate task id"):
		return "CONTRACT_TASK_DUPLICATE", "tasks"
	case strings.Contains(message, "task id"):
		return "CONTRACT_TASK_ID_INVALID", "tasks"
	case strings.Contains(message, "unsupported task kind"):
		return "CONTRACT_TASK_KIND_UNSUPPORTED", "tasks.kind"
	case strings.Contains(message, "adapter is required"):
		return "CONTRACT_TASK_ADAPTER_REQUIRED", "tasks.adapter"
	case strings.Contains(message, "timeout_seconds"):
		return "CONTRACT_TASK_TIMEOUT_INVALID", "tasks.timeout_seconds"
	case strings.Contains(message, "unknown obligation"):
		return "CONTRACT_TASK_OBLIGATION_UNKNOWN", "tasks.obligations"
	case strings.Contains(message, "unsupported side effect type"):
		return "CONTRACT_SIDE_EFFECT_UNSUPPORTED", "tasks.declared_side_effects"
	case strings.Contains(message, "side effect resource"):
		return "CONTRACT_SIDE_EFFECT_RESOURCE_INVALID", "tasks.declared_side_effects"
	case strings.Contains(message, "approval ticket"):
		return "CONTRACT_APPROVAL_INVALID", "approvals"
	case strings.Contains(message, "unknown task"):
		return "CONTRACT_TASK_DEPENDENCY_UNKNOWN", "tasks.depends_on"
	case strings.Contains(message, "task graph contains a cycle"):
		return "CONTRACT_TASK_GRAPH_CYCLE", "tasks.depends_on"
	case strings.Contains(message, "evaluator references unknown obligation"):
		return "CONTRACT_EVALUATOR_OBLIGATION_UNKNOWN", "evaluator.required_obligations"
	case strings.Contains(message, "missing from evaluator required_obligations"):
		return "CONTRACT_EVALUATOR_REQUIRED_OBLIGATION_MISSING", "evaluator.required_obligations"
	case message == "brief is required":
		return "BRIEF_REQUIRED", "brief"
	case strings.Contains(message, "brief path"):
		return "BRIEF_PATH_INVALID", "brief"
	case strings.Contains(message, "workspace write"):
		return "WORKSPACE_WRITE_INVALID", "workspace.writes"
	default:
		return "CONTRACT_INVALID", ""
	}
}

func diagnosticHint(code string, message string) string {
	quoted := quotedStrings(message)
	switch code {
	case "BRIEF_REQUIRED":
		return "Provide a non-empty brief before running compile or lint."
	case "BRIEF_PATH_INVALID":
		return "Use a workspace-relative brief path that does not escape the workspace."
	case "WORKSPACE_WRITE_INVALID", "CONTRACT_WORKSPACE_WRITE_INVALID":
		return "Use workspace-relative write paths and remove any absolute or parent-directory segments."
	case "CONTRACT_SCHEMA_UNSUPPORTED":
		return fmt.Sprintf("Regenerate the contract with schema_version %q.", ContractSchemaVersion)
	case "CONTRACT_OBJECTIVE_REQUIRED":
		return "Add a non-empty objective to the contract."
	case "CONTRACT_WORKSPACE_ROOT_INVALID":
		return "Set workspace.root to a relative workspace path, usually \".\"."
	case "CONTRACT_WORKSPACE_READ_INVALID":
		return "Use workspace-relative read paths and remove any absolute or parent-directory segments."
	case "CONTRACT_OBLIGATION_DUPLICATE":
		return "Rename or remove the duplicate obligation id."
	case "CONTRACT_OBLIGATION_ID_INVALID", "STRUCTURED_OBLIGATION_ID_INVALID":
		return "Use portable ids with letters, numbers, underscores, or hyphens."
	case "CONTRACT_REQUIRED_OBLIGATION_MISSING":
		return "Mark at least one obligation as required."
	case "CONTRACT_TASK_DUPLICATE":
		return "Rename or remove the duplicate task id."
	case "CONTRACT_TASK_ID_INVALID", "STRUCTURED_TASK_ID_INVALID":
		return "Use portable task ids with letters, numbers, underscores, or hyphens."
	case "CONTRACT_TASK_KIND_UNSUPPORTED":
		return "Use one of the supported task kinds: scripted, verify, or review."
	case "CONTRACT_TASK_ADAPTER_REQUIRED":
		return "Set adapter for the task, usually \"scripted\" for file-writing tasks."
	case "CONTRACT_TASK_TIMEOUT_INVALID", "STRUCTURED_TASK_TIMEOUT_INVALID":
		return "Set timeout_seconds to a positive integer."
	case "CONTRACT_TASK_OBLIGATION_UNKNOWN", "STRUCTURED_TASK_OBLIGATION_UNKNOWN":
		if len(quoted) >= 2 {
			return fmt.Sprintf("Define obligation %q or remove it from the task.", quoted[1])
		}
		return "Define the referenced obligation or remove it from the task."
	case "CONTRACT_SIDE_EFFECT_UNSUPPORTED":
		return "Use a supported side effect type such as file.write or file.read."
	case "CONTRACT_SIDE_EFFECT_RESOURCE_INVALID", "STRUCTURED_TASK_WRITE_INVALID":
		return "Use workspace-relative side effect resources and remove any absolute or parent-directory segments."
	case "CONTRACT_APPROVAL_INVALID":
		return "Update the approval ticket so its schema, task, effect, resource, reason, expiry, and declared side effect match the contract."
	case "CONTRACT_TASK_DEPENDENCY_UNKNOWN", "STRUCTURED_TASK_DEP_UNKNOWN":
		if len(quoted) >= 2 {
			return fmt.Sprintf("Define task %q or remove it from depends_on.", quoted[1])
		}
		return "Define the referenced task or remove it from depends_on."
	case "CONTRACT_TASK_GRAPH_CYCLE":
		return "Remove at least one depends_on edge so the task graph is acyclic."
	case "CONTRACT_EVALUATOR_OBLIGATION_UNKNOWN":
		if len(quoted) >= 1 {
			return fmt.Sprintf("Define obligation %q or remove it from evaluator.required_obligations.", quoted[0])
		}
		return "Define the referenced obligation or remove it from evaluator.required_obligations."
	case "CONTRACT_EVALUATOR_REQUIRED_OBLIGATION_MISSING":
		if len(quoted) >= 1 {
			return fmt.Sprintf("Add %q to evaluator.required_obligations.", quoted[0])
		}
		return "Add every required obligation to evaluator.required_obligations."
	case "STRUCTURED_OBLIGATION_ID_DUPLICATE":
		return "Rename one of the duplicate obligation headings."
	case "STRUCTURED_TASK_ID_DUPLICATE":
		return "Rename one of the duplicate task headings."
	case "STRUCTURED_TASK_WRITE_UNDECLARED":
		if len(quoted) >= 2 {
			return fmt.Sprintf("Add %q under # Writes or pass --write %s.", quoted[1], quoted[1])
		}
		return "Add the task write under # Writes or pass it with --write."
	case "STRUCTURED_TASK_FIELD_UNKNOWN":
		return "Use supported task fields: kind, adapter, timeout_seconds, depends_on, obligations, writes, or reads."
	case "STRUCTURED_OBLIGATION_FIELD_UNKNOWN":
		return "Use supported obligation fields: required or text."
	case "STRUCTURED_HEADING_UNSUPPORTED":
		return "Use top-level sections and supported headings such as ## Task: <id> or ## Obligation: <id>."
	case "STRUCTURED_TASK_ID_MISSING":
		return "Add an id after the task heading, for example ## Task: draft_report."
	case "STRUCTURED_OBLIGATION_ID_MISSING":
		return "Add an id after the obligation heading, for example ## Obligation: obl_report_exists."
	case "STRUCTURED_READ_BULLET_REQUIRED":
		return "Format each read as a markdown bullet under # Reads."
	case "STRUCTURED_WRITE_BULLET_REQUIRED":
		return "Format each write as a markdown bullet under # Writes."
	case "STRUCTURED_OBLIGATION_HEADING_REQUIRED":
		return "Start each obligation with ## Obligation: <id> before its fields."
	case "STRUCTURED_TASK_HEADING_REQUIRED":
		return "Start each task with ## Task: <id> before its fields."
	case "STRUCTURED_OBLIGATION_LINE_INVALID":
		return "Write obligation fields as key: value lines."
	case "STRUCTURED_OBLIGATION_REQUIRED_INVALID":
		return "Set required to true or false."
	case "STRUCTURED_TASK_LIST_FIELD_REQUIRED":
		return "Place task bullets under depends_on, obligations, writes, or reads."
	case "STRUCTURED_TASK_LINE_INVALID":
		return "Write task fields as key: value lines or list bullets."
	case "STRUCTURED_TASK_LIST_FIELD_UNKNOWN":
		return "Use supported task list fields: depends_on, obligations, writes, or reads."
	default:
		return "Review the diagnostic message and update the input before rerunning lint."
	}
}

func quotedStrings(message string) []string {
	values := []string{}
	remaining := message
	for {
		start := strings.IndexByte(remaining, '"')
		if start < 0 {
			return values
		}
		remaining = remaining[start+1:]
		end := strings.IndexByte(remaining, '"')
		if end < 0 {
			return values
		}
		values = append(values, remaining[:end])
		remaining = remaining[end+1:]
	}
}
