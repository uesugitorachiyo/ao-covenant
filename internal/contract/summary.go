package contract

const CompileSummarySchemaVersion = "covenant.compile-summary.v1"

type Summary struct {
	SchemaVersion  string              `json:"schema_version"`
	Contract       string              `json:"contract"`
	ContractDigest string              `json:"contract_digest"`
	Reads          []string            `json:"reads"`
	Writes         []string            `json:"writes"`
	Tasks          []TaskSummary       `json:"tasks"`
	Obligations    []ObligationSummary `json:"obligations"`
}

type TaskSummary struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	DependsOn   []string `json:"depends_on"`
	Obligations []string `json:"obligations"`
}

type ObligationSummary struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
	Text     string `json:"text"`
}

func NewSummary(c Contract, contractPath string, digest string) Summary {
	tasks := make([]TaskSummary, 0, len(c.Tasks))
	for _, task := range c.Tasks {
		tasks = append(tasks, TaskSummary{
			ID:          task.ID,
			Kind:        task.Kind,
			DependsOn:   nonNilStrings(task.DependsOn),
			Obligations: nonNilStrings(task.Obligations),
		})
	}
	obligations := make([]ObligationSummary, 0, len(c.Obligations))
	for _, obligation := range c.Obligations {
		obligations = append(obligations, ObligationSummary{
			ID:       obligation.ID,
			Required: obligation.Required,
			Text:     obligation.Text,
		})
	}
	return Summary{
		SchemaVersion:  CompileSummarySchemaVersion,
		Contract:       contractPath,
		ContractDigest: digest,
		Reads:          nonNilStrings(c.Workspace.Reads),
		Writes:         nonNilStrings(c.Workspace.Writes),
		Tasks:          tasks,
		Obligations:    obligations,
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string{}, values...)
}
