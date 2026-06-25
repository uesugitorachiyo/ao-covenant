package contract

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

var allowedTaskKinds = map[string]bool{
	"scripted": true,
	"shell":    true,
	"agent":    true,
	"verify":   true,
	"review":   true,
	"evaluate": true,
}

var allowedSideEffectTypes = map[string]bool{
	"file.write":      true,
	"file.read":       true,
	"process.spawn":   true,
	"network.request": true,
	"claim.publish":   true,
}

func Validate(c Contract) error {
	if c.SchemaVersion != ContractSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", c.SchemaVersion)
	}
	if strings.TrimSpace(c.Objective) == "" {
		return fmt.Errorf("objective is required")
	}
	if err := validateRelativePath(c.Workspace.Root, "workspace root"); err != nil {
		return err
	}
	if err := validatePaths(c.Workspace.Reads, "read"); err != nil {
		return err
	}
	if err := validatePaths(c.Workspace.Writes, "write"); err != nil {
		return err
	}

	obligationIDs := map[string]bool{}
	requiredObligationIDs := map[string]bool{}
	requiredCount := 0
	for _, obligation := range c.Obligations {
		if err := validatePublicID(obligation.ID, "obligation id"); err != nil {
			return err
		}
		if obligationIDs[obligation.ID] {
			return fmt.Errorf("duplicate obligation id %q", obligation.ID)
		}
		obligationIDs[obligation.ID] = true
		if obligation.Required {
			requiredCount++
			requiredObligationIDs[obligation.ID] = true
		}
	}
	if requiredCount == 0 {
		return fmt.Errorf("at least one required obligation is required")
	}

	taskIDs := map[string]Task{}
	for _, task := range c.Tasks {
		if err := validatePublicID(task.ID, "task id"); err != nil {
			return err
		}
		if _, exists := taskIDs[task.ID]; exists {
			return fmt.Errorf("duplicate task id %q", task.ID)
		}
		if !allowedTaskKinds[task.Kind] {
			return fmt.Errorf("unsupported task kind %q for task %q", task.Kind, task.ID)
		}
		if strings.TrimSpace(task.Adapter) == "" {
			return fmt.Errorf("adapter is required for task %q", task.ID)
		}
		if task.TimeoutSecs <= 0 {
			return fmt.Errorf("timeout_seconds must be positive for task %q", task.ID)
		}
		for _, obligationID := range task.Obligations {
			if !obligationIDs[obligationID] {
				return fmt.Errorf("task %q references unknown obligation %q", task.ID, obligationID)
			}
		}
		for _, action := range task.DeclaredSideEffects {
			if !allowedSideEffectTypes[action.Type] {
				return fmt.Errorf("unsupported side effect type %q for task %q", action.Type, task.ID)
			}
			if err := validateRelativePath(action.Resource, "side effect resource"); err != nil {
				return err
			}
		}
		if err := schema.ValidateValue(schema.TaskSchemaID, task); err != nil {
			return fmt.Errorf("task %q schema invalid: %w", task.ID, err)
		}
		taskIDs[task.ID] = task
	}
	if len(taskIDs) == 0 {
		return fmt.Errorf("at least one task is required")
	}
	if err := validateApprovals(c.Approvals, taskIDs); err != nil {
		return err
	}
	for _, task := range c.Tasks {
		for _, dep := range task.DependsOn {
			if _, exists := taskIDs[dep]; !exists {
				return fmt.Errorf("task %q depends on unknown task %q", task.ID, dep)
			}
		}
	}
	if hasCycle(c.Tasks) {
		return fmt.Errorf("task graph contains a cycle")
	}
	evaluatorObligationIDs := map[string]bool{}
	for _, obligationID := range c.Evaluator.RequiredObligations {
		if !obligationIDs[obligationID] {
			return fmt.Errorf("evaluator references unknown obligation %q", obligationID)
		}
		evaluatorObligationIDs[obligationID] = true
	}
	for obligationID := range requiredObligationIDs {
		if !evaluatorObligationIDs[obligationID] {
			return fmt.Errorf("required obligation %q is missing from evaluator required_obligations", obligationID)
		}
	}
	return nil
}

func validateApprovals(approvals []policy.ApprovalTicket, taskIDs map[string]Task) error {
	ticketIDs := map[string]bool{}
	declaredEffects := map[string]bool{}
	for _, task := range taskIDs {
		for _, action := range task.DeclaredSideEffects {
			declaredEffects[sideEffectKey(task.ID, action.Type, action.Resource)] = true
		}
	}
	for _, approval := range approvals {
		if approval.SchemaVersion != policy.ApprovalTicketSchemaVersion {
			return fmt.Errorf("unsupported approval ticket schema_version %q", approval.SchemaVersion)
		}
		if err := validatePublicID(approval.TicketID, "approval ticket id"); err != nil {
			return err
		}
		if ticketIDs[approval.TicketID] {
			return fmt.Errorf("duplicate approval ticket id %q", approval.TicketID)
		}
		ticketIDs[approval.TicketID] = true
		if _, exists := taskIDs[approval.TaskID]; !exists {
			return fmt.Errorf("approval ticket %q references unknown task %q", approval.TicketID, approval.TaskID)
		}
		if !allowedSideEffectTypes[approval.EffectType] {
			return fmt.Errorf("approval ticket %q references unsupported side effect type %q", approval.TicketID, approval.EffectType)
		}
		if err := validateRelativePath(approval.Resource, "approval ticket resource"); err != nil {
			return err
		}
		if strings.TrimSpace(approval.Reason) == "" {
			return fmt.Errorf("approval ticket %q reason is required", approval.TicketID)
		}
		if strings.TrimSpace(approval.ExpiresAt) != "" {
			if _, err := time.Parse(time.RFC3339, approval.ExpiresAt); err != nil {
				return fmt.Errorf("approval ticket %q expires_at must be RFC3339: %w", approval.TicketID, err)
			}
		}
		if !declaredEffects[sideEffectKey(approval.TaskID, approval.EffectType, approval.Resource)] {
			return fmt.Errorf("approval ticket %q does not match a declared side effect", approval.TicketID)
		}
	}
	return nil
}

func sideEffectKey(taskID string, effectType string, resource string) string {
	normalized := path.Clean(strings.ReplaceAll(resource, "\\", "/"))
	return taskID + "\x00" + effectType + "\x00" + normalized
}

func validatePublicID(raw string, label string) error {
	id := strings.TrimSpace(raw)
	if id == "" {
		return fmt.Errorf("%s is required", label)
	}
	if id != raw {
		return fmt.Errorf("%s %q contains surrounding whitespace", label, raw)
	}
	if id != strings.ToLower(id) {
		return fmt.Errorf("%s %q must be lowercase", label, raw)
	}
	if isReservedWindowsName(id) {
		return fmt.Errorf("%s %q is reserved on Windows", label, raw)
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("%s %q contains invalid character %q", label, raw, r)
	}
	return nil
}

func isReservedWindowsName(id string) bool {
	switch id {
	case "con", "prn", "aux", "nul":
		return true
	}
	if len(id) == 4 && (strings.HasPrefix(id, "com") || strings.HasPrefix(id, "lpt")) {
		return id[3] >= '1' && id[3] <= '9'
	}
	return false
}

func validatePaths(paths []string, label string) error {
	for _, p := range paths {
		if err := validateRelativePath(p, label+" path"); err != nil {
			return err
		}
	}
	return nil
}

func validateRelativePath(raw string, label string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", label)
	}
	normalized := path.Clean(strings.ReplaceAll(raw, "\\", "/"))
	if path.IsAbs(normalized) || hasWindowsDrivePrefix(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return fmt.Errorf("%s %q escapes workspace", label, raw)
	}
	return nil
}

func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 {
		return false
	}
	drive := p[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) && p[1] == ':'
}

func hasCycle(tasks []Task) bool {
	byID := map[string]Task{}
	for _, task := range tasks {
		byID[task.ID] = task
	}
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] {
			return true
		}
		if visited[id] {
			return false
		}
		visiting[id] = true
		for _, dep := range byID[id].DependsOn {
			if visit(dep) {
				return true
			}
		}
		visiting[id] = false
		visited[id] = true
		return false
	}
	for _, task := range tasks {
		if visit(task.ID) {
			return true
		}
	}
	return false
}
