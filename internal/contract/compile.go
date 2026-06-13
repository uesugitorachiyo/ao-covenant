package contract

import (
	"fmt"
	"path"
	"strings"
)

var defaultWorkspaceWrites = []string{"demo-output/report.txt"}

type CompileOptions struct {
	SourcePath      string
	WorkspaceWrites []string
}

func CompileBrief(brief string) (Contract, error) {
	return CompileBriefWithSource(brief, "examples/risky-change/brief.md")
}

func CompileBriefWithSource(brief string, sourcePath string) (Contract, error) {
	return CompileBriefWithOptions(brief, CompileOptions{SourcePath: sourcePath})
}

func CompileBriefWithOptions(brief string, opts CompileOptions) (Contract, error) {
	if strings.TrimSpace(brief) == "" {
		return Contract{}, fmt.Errorf("brief is required")
	}
	normalizedSourcePath := path.Clean(strings.ReplaceAll(opts.SourcePath, "\\", "/"))
	if normalizedSourcePath == "." {
		return Contract{}, fmt.Errorf("brief path is required")
	}
	if err := validateRelativePath(normalizedSourcePath, "brief path"); err != nil {
		return Contract{}, err
	}
	structured, ok, err := parseStructuredBrief(brief)
	if err != nil {
		return Contract{}, err
	}
	if ok {
		return buildStructuredContract(brief, normalizedSourcePath, opts.WorkspaceWrites, structured)
	}
	workspaceWrites, err := normalizeWorkspaceWrites(opts.WorkspaceWrites)
	if err != nil {
		return Contract{}, err
	}
	c := Contract{
		SchemaVersion: ContractSchemaVersion,
		Objective:     strings.TrimSpace(brief),
		Workspace: WorkspaceScope{
			Root:   ".",
			Reads:  []string{normalizedSourcePath},
			Writes: workspaceWrites,
		},
		Obligations: []Obligation{
			{ID: "obl_requested_file", Text: "The requested file is created.", Required: true},
			{ID: "obl_verify_passes", Text: "The verifier passes.", Required: true},
			{ID: "obl_review_clear", Text: "The reviewer has no unresolved high concern.", Required: true},
		},
		Tasks: []Task{
			{
				ID:                  "scripted_change",
				Kind:                "scripted",
				Adapter:             "scripted",
				DependsOn:           []string{},
				Obligations:         []string{"obl_requested_file"},
				TimeoutSecs:         30,
				DeclaredSideEffects: fileWriteActions(workspaceWrites),
			},
			{
				ID:          "verify_change",
				Kind:        "verify",
				Adapter:     "scripted",
				DependsOn:   []string{"scripted_change"},
				Obligations: []string{"obl_verify_passes"},
				TimeoutSecs: 30,
			},
			{
				ID:          "review_change",
				Kind:        "review",
				Adapter:     "scripted",
				DependsOn:   []string{"verify_change"},
				Obligations: []string{"obl_review_clear"},
				TimeoutSecs: 30,
			},
		},
		Policy: PolicyProfile{Mode: "strict"},
		Evaluator: EvaluatorRules{
			RequiredObligations: []string{"obl_requested_file", "obl_verify_passes", "obl_review_clear"},
		},
	}
	if err := Validate(c); err != nil {
		return Contract{}, err
	}
	return c, nil
}

func normalizeWorkspaceWrites(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return append([]string{}, defaultWorkspaceWrites...), nil
	}
	writes := make([]string, 0, len(raw))
	for _, writePath := range raw {
		normalized := path.Clean(strings.ReplaceAll(writePath, "\\", "/"))
		if err := validateRelativePath(normalized, "workspace write"); err != nil {
			return nil, err
		}
		writes = append(writes, normalized)
	}
	return writes, nil
}

func fileWriteActions(writes []string) []ActionRef {
	actions := make([]ActionRef, 0, len(writes))
	for _, writePath := range writes {
		actions = append(actions, ActionRef{Type: "file.write", Resource: writePath})
	}
	return actions
}

func fileReadActions(reads []string) []ActionRef {
	actions := make([]ActionRef, 0, len(reads))
	for _, readPath := range reads {
		actions = append(actions, ActionRef{Type: "file.read", Resource: readPath})
	}
	return actions
}
