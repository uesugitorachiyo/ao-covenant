package contract

import (
	"fmt"
	"path"
	"strconv"
	"strings"
)

type structuredBrief struct {
	objective       string
	reads           []string
	writes          []string
	obligations     []Obligation
	obligationLines []int
	tasks           []taskDraft
}

type taskDraft struct {
	id              string
	line            int
	kind            string
	adapter         string
	dependsOn       []string
	dependsOnLines  []int
	obligations     []string
	obligationLines []int
	writes          []string
	writeLines      []int
	reads           []string
	readLines       []int
	timeoutSecs     int
}

type AuthoringDiagnostic struct {
	Code    string
	Line    int
	Message string
}

type AuthoringDiagnosticError struct {
	Diagnostic AuthoringDiagnostic
}

func (e *AuthoringDiagnosticError) Error() string {
	if e.Diagnostic.Line > 0 {
		return fmt.Sprintf("%s line %d: %s", e.Diagnostic.Code, e.Diagnostic.Line, e.Diagnostic.Message)
	}
	return fmt.Sprintf("%s: %s", e.Diagnostic.Code, e.Diagnostic.Message)
}

func newAuthoringDiagnostic(code string, line int, format string, args ...any) *AuthoringDiagnosticError {
	return &AuthoringDiagnosticError{
		Diagnostic: AuthoringDiagnostic{
			Code:    code,
			Line:    line,
			Message: fmt.Sprintf(format, args...),
		},
	}
}

func parseStructuredBrief(brief string) (structuredBrief, bool, error) {
	var parsed structuredBrief
	lines := strings.Split(strings.ReplaceAll(brief, "\r\n", "\n"), "\n")
	section := ""
	listField := ""
	var objectiveLines []string
	var currentTask *taskDraft
	var currentObligation *Obligation
	currentObligationLine := 0

	finishTask := func() {
		if currentTask == nil {
			return
		}
		parsed.tasks = append(parsed.tasks, *currentTask)
		currentTask = nil
	}
	finishObligation := func() {
		if currentObligation == nil {
			return
		}
		parsed.obligations = append(parsed.obligations, *currentObligation)
		parsed.obligationLines = append(parsed.obligationLines, currentObligationLine)
		currentObligation = nil
		currentObligationLine = 0
	}

	for lineNumber, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			finishTask()
			finishObligation()
			section = normalizeHeading(strings.TrimSpace(strings.TrimPrefix(line, "# ")))
			listField = ""
			continue
		}
		if strings.HasPrefix(line, "## ") {
			heading := strings.TrimSpace(strings.TrimPrefix(line, "## "))
			switch {
			case section == "tasks" && strings.HasPrefix(strings.ToLower(heading), "task:"):
				finishTask()
				id := strings.TrimSpace(heading[len("task:"):])
				if id == "" {
					return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_TASK_ID_MISSING", lineNumber+1, "task heading is missing an id")
				}
				currentTask = &taskDraft{id: id, line: lineNumber + 1, kind: "scripted", adapter: "scripted", timeoutSecs: 30}
				listField = ""
				continue
			case section == "obligations" && strings.HasPrefix(strings.ToLower(heading), "obligation:"):
				finishObligation()
				id := strings.TrimSpace(heading[len("obligation:"):])
				if id == "" {
					return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_OBLIGATION_ID_MISSING", lineNumber+1, "obligation heading is missing an id")
				}
				currentObligation = &Obligation{ID: id, Required: true}
				currentObligationLine = lineNumber + 1
				listField = ""
				continue
			default:
				return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_HEADING_UNSUPPORTED", lineNumber+1, "unsupported heading %q", heading)
			}
		}

		switch section {
		case "objective":
			objectiveLines = append(objectiveLines, line)
		case "reads":
			value, ok := parseBullet(line)
			if !ok {
				return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_READ_BULLET_REQUIRED", lineNumber+1, "read must be a bullet")
			}
			parsed.reads = append(parsed.reads, value)
		case "writes":
			value, ok := parseBullet(line)
			if !ok {
				return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_WRITE_BULLET_REQUIRED", lineNumber+1, "write must be a bullet")
			}
			parsed.writes = append(parsed.writes, value)
		case "obligations":
			if currentObligation == nil {
				return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_OBLIGATION_HEADING_REQUIRED", lineNumber+1, "obligation field appears before an obligation heading")
			}
			if err := parseObligationLine(currentObligation, line, lineNumber+1); err != nil {
				return structuredBrief{}, false, err
			}
		case "tasks":
			if currentTask == nil {
				return structuredBrief{}, false, newAuthoringDiagnostic("STRUCTURED_TASK_HEADING_REQUIRED", lineNumber+1, "task field appears before a task heading")
			}
			nextListField, err := parseTaskLine(currentTask, listField, line, lineNumber+1)
			if err != nil {
				return structuredBrief{}, false, err
			}
			listField = nextListField
		default:
			continue
		}
	}
	finishTask()
	finishObligation()
	parsed.objective = strings.TrimSpace(strings.Join(objectiveLines, "\n"))
	return parsed, len(parsed.tasks) > 0, nil
}

func buildStructuredContract(brief string, sourcePath string, rawWriteOverrides []string, parsed structuredBrief) (Contract, error) {
	reads, err := normalizeAuthoredPaths(parsed.reads, "workspace read")
	if err != nil {
		return Contract{}, err
	}
	reads = uniqueStrings(append([]string{sourcePath}, reads...))

	writes, err := structuredWorkspaceWrites(rawWriteOverrides, parsed)
	if err != nil {
		return Contract{}, err
	}
	if err := validateStructuredAuthoring(parsed, writes); err != nil {
		return Contract{}, err
	}
	obligations := nonNilObligations(parsed.obligations)
	requiredObligations := requiredObligationIDs(obligations)
	tasks, err := structuredTasks(parsed.tasks)
	if err != nil {
		return Contract{}, err
	}
	objective := parsed.objective
	if objective == "" {
		objective = strings.TrimSpace(brief)
	}
	c := Contract{
		SchemaVersion: ContractSchemaVersion,
		Objective:     objective,
		Workspace: WorkspaceScope{
			Root:   ".",
			Reads:  reads,
			Writes: writes,
		},
		Obligations: obligations,
		Tasks:       tasks,
		Policy:      PolicyProfile{Mode: "strict"},
		Evaluator: EvaluatorRules{
			RequiredObligations: requiredObligations,
		},
	}
	if err := Validate(c); err != nil {
		return Contract{}, err
	}
	return c, nil
}

func structuredWorkspaceWrites(rawWriteOverrides []string, parsed structuredBrief) ([]string, error) {
	if len(rawWriteOverrides) > 0 {
		return normalizeAuthoredPaths(rawWriteOverrides, "workspace write")
	}
	writes := append([]string{}, parsed.writes...)
	if len(writes) == 0 {
		for _, task := range parsed.tasks {
			writes = append(writes, task.writes...)
		}
	}
	return uniqueNormalizedPaths(writes, "workspace write")
}

func structuredTasks(drafts []taskDraft) ([]Task, error) {
	tasks := make([]Task, 0, len(drafts))
	for _, draft := range drafts {
		writes, err := normalizeAuthoredPaths(draft.writes, "side effect resource")
		if err != nil {
			return nil, err
		}
		reads, err := normalizeAuthoredPaths(draft.reads, "side effect resource")
		if err != nil {
			return nil, err
		}
		actions := append(fileWriteActions(writes), fileReadActions(reads)...)
		timeoutSecs := draft.timeoutSecs
		if timeoutSecs == 0 {
			timeoutSecs = 30
		}
		kind := strings.TrimSpace(draft.kind)
		if kind == "" {
			kind = "scripted"
		}
		adapter := strings.TrimSpace(draft.adapter)
		if adapter == "" {
			adapter = "scripted"
		}
		tasks = append(tasks, Task{
			ID:                  strings.TrimSpace(draft.id),
			Kind:                kind,
			Adapter:             adapter,
			DependsOn:           nonNilStrings(draft.dependsOn),
			Obligations:         nonNilStrings(draft.obligations),
			TimeoutSecs:         timeoutSecs,
			DeclaredSideEffects: actions,
		})
	}
	return tasks, nil
}

func validateStructuredAuthoring(parsed structuredBrief, workspaceWrites []string) error {
	obligationIDs := map[string]int{}
	for i, obligation := range parsed.obligations {
		line := lineAt(parsed.obligationLines, i, 0)
		if err := validatePublicID(obligation.ID, "obligation id"); err != nil {
			return newAuthoringDiagnostic("STRUCTURED_OBLIGATION_ID_INVALID", line, "%v", err)
		}
		if firstLine, exists := obligationIDs[obligation.ID]; exists {
			return newAuthoringDiagnostic("STRUCTURED_OBLIGATION_ID_DUPLICATE", line, "duplicate obligation id %q; first defined at line %d", obligation.ID, firstLine)
		}
		obligationIDs[obligation.ID] = line
	}

	taskIDs := map[string]int{}
	for _, task := range parsed.tasks {
		if err := validatePublicID(task.id, "task id"); err != nil {
			return newAuthoringDiagnostic("STRUCTURED_TASK_ID_INVALID", task.line, "%v", err)
		}
		if firstLine, exists := taskIDs[task.id]; exists {
			return newAuthoringDiagnostic("STRUCTURED_TASK_ID_DUPLICATE", task.line, "duplicate task id %q; first defined at line %d", task.id, firstLine)
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
				return newAuthoringDiagnostic("STRUCTURED_TASK_DEP_UNKNOWN", lineAt(task.dependsOnLines, i, task.line), "task %q depends on unknown task %q", task.id, dep)
			}
		}
		for i, obligationID := range task.obligations {
			if _, exists := obligationIDs[obligationID]; !exists {
				return newAuthoringDiagnostic("STRUCTURED_TASK_OBLIGATION_UNKNOWN", lineAt(task.obligationLines, i, task.line), "task %q references unknown obligation %q", task.id, obligationID)
			}
		}
		for i, writePath := range task.writes {
			normalized := path.Clean(strings.ReplaceAll(writePath, "\\", "/"))
			if err := validateRelativePath(normalized, "side effect resource"); err != nil {
				return newAuthoringDiagnostic("STRUCTURED_TASK_WRITE_INVALID", lineAt(task.writeLines, i, task.line), "%v", err)
			}
			if !workspaceWriteSet[normalized] {
				return newAuthoringDiagnostic("STRUCTURED_TASK_WRITE_UNDECLARED", lineAt(task.writeLines, i, task.line), "task %q writes %q outside workspace writes; add it under # Writes or pass --write %s", task.id, normalized, normalized)
			}
		}
	}
	return nil
}

func lineAt(lines []int, index int, fallback int) int {
	if index >= 0 && index < len(lines) && lines[index] > 0 {
		return lines[index]
	}
	return fallback
}

func parseObligationLine(obligation *Obligation, line string, lineNumber int) error {
	key, value, ok := parseKeyValue(line)
	if !ok {
		return newAuthoringDiagnostic("STRUCTURED_OBLIGATION_LINE_INVALID", lineNumber, "obligation line must be key: value")
	}
	switch key {
	case "required":
		required, err := strconv.ParseBool(strings.ToLower(value))
		if err != nil {
			return newAuthoringDiagnostic("STRUCTURED_OBLIGATION_REQUIRED_INVALID", lineNumber, "obligation required must be true or false")
		}
		obligation.Required = required
	case "text":
		obligation.Text = value
	default:
		return newAuthoringDiagnostic("STRUCTURED_OBLIGATION_FIELD_UNKNOWN", lineNumber, "unsupported obligation field %q", key)
	}
	return nil
}

func parseTaskLine(task *taskDraft, currentListField string, line string, lineNumber int) (string, error) {
	if value, ok := parseBullet(line); ok {
		if currentListField == "" {
			return "", newAuthoringDiagnostic("STRUCTURED_TASK_LIST_FIELD_REQUIRED", lineNumber, "task bullet appears before a list field")
		}
		if err := appendTaskListValue(task, currentListField, value, lineNumber); err != nil {
			return "", err
		}
		return currentListField, nil
	}
	key, value, ok := parseKeyValue(line)
	if !ok {
		return "", newAuthoringDiagnostic("STRUCTURED_TASK_LINE_INVALID", lineNumber, "task line must be key: value or list bullet")
	}
	switch key {
	case "kind":
		task.kind = value
	case "adapter":
		task.adapter = value
	case "timeout_seconds":
		timeoutSecs, err := strconv.Atoi(value)
		if err != nil {
			return "", newAuthoringDiagnostic("STRUCTURED_TASK_TIMEOUT_INVALID", lineNumber, "timeout_seconds must be an integer")
		}
		task.timeoutSecs = timeoutSecs
	case "depends_on", "obligations", "writes", "reads":
		if value != "" {
			for _, item := range splitInlineList(value) {
				if err := appendTaskListValue(task, key, item, lineNumber); err != nil {
					return "", err
				}
			}
		}
		return key, nil
	default:
		return "", newAuthoringDiagnostic("STRUCTURED_TASK_FIELD_UNKNOWN", lineNumber, "unsupported task field %q; expected kind, adapter, timeout_seconds, depends_on, obligations, writes, or reads", key)
	}
	return "", nil
}

func appendTaskListValue(task *taskDraft, field string, value string, lineNumber int) error {
	switch field {
	case "depends_on":
		task.dependsOn = append(task.dependsOn, value)
		task.dependsOnLines = append(task.dependsOnLines, lineNumber)
	case "obligations":
		task.obligations = append(task.obligations, value)
		task.obligationLines = append(task.obligationLines, lineNumber)
	case "writes":
		task.writes = append(task.writes, value)
		task.writeLines = append(task.writeLines, lineNumber)
	case "reads":
		task.reads = append(task.reads, value)
		task.readLines = append(task.readLines, lineNumber)
	default:
		return newAuthoringDiagnostic("STRUCTURED_TASK_LIST_FIELD_UNKNOWN", lineNumber, "unsupported task list field %q", field)
	}
	return nil
}

func parseKeyValue(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return normalizeHeading(key), strings.TrimSpace(value), true
}

func parseBullet(line string) (string, bool) {
	if !strings.HasPrefix(line, "- ") {
		return "", false
	}
	value := strings.TrimSpace(strings.TrimPrefix(line, "- "))
	return value, value != ""
}

func normalizeHeading(raw string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(raw, " ", "_")))
}

func splitInlineList(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func normalizeAuthoredPaths(raw []string, label string) ([]string, error) {
	paths := make([]string, 0, len(raw))
	for _, p := range raw {
		normalized := path.Clean(strings.ReplaceAll(p, "\\", "/"))
		if err := validateRelativePath(normalized, label); err != nil {
			return nil, err
		}
		paths = append(paths, normalized)
	}
	return paths, nil
}

func uniqueNormalizedPaths(raw []string, label string) ([]string, error) {
	paths, err := normalizeAuthoredPaths(raw, label)
	if err != nil {
		return nil, err
	}
	return uniqueStrings(paths), nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

func nonNilObligations(obligations []Obligation) []Obligation {
	if obligations == nil {
		return []Obligation{}
	}
	return obligations
}

func requiredObligationIDs(obligations []Obligation) []string {
	ids := make([]string, 0, len(obligations))
	for _, obligation := range obligations {
		if obligation.Required {
			ids = append(ids, obligation.ID)
		}
	}
	return ids
}
