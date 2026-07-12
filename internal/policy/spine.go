package policy

type SpineResult struct {
	SchemaVersion    string                `json:"schema_version"`
	Stack            string                `json:"stack"`
	Status           string                `json:"status"`
	Scope            SpineScope            `json:"scope"`
	Responsibilities []SpineResponsibility `json:"responsibilities"`
	OutOfBounds      []string              `json:"out_of_bounds"`
}

type SpineScope struct {
	ActiveRepositories []string `json:"active_repositories"`
	ReplacedBy         []string `json:"replaced_by"`
}

type SpineResponsibility struct {
	Name  string   `json:"name"`
	Owner string   `json:"owner"`
	Gates []string `json:"gates"`
}

func AO2FirstSpine(schemaVersion string) SpineResult {
	return SpineResult{
		SchemaVersion: schemaVersion,
		Stack:         "ao2-first",
		Status:        "ready",
		Scope: SpineScope{
			ActiveRepositories: []string{
				"ao2",
				"ao2-control-plane",
				"ao-foundry",
				"ao-forge",
				"ao-command",
				"ao-covenant",
				"ao-atlas",
			},
			ReplacedBy: []string{
				"ao2",
				"ao2-control-plane",
			},
		},
		Responsibilities: []SpineResponsibility{
			{
				Name:  "policy-decision",
				Owner: "ao-covenant",
				Gates: []string{
					"contract schema validation",
					"strict side-effect decisions",
					"approval ticket validation",
				},
			},
			{
				Name:  "rsi-claim-boundary",
				Owner: "ao-covenant",
				Gates: []string{
					"claim.publish side-effect policy",
					"bounded_governed_rsi claim level",
					"full_autonomous_self_mutating_rsi claim level",
					"mutation authority evidence",
					"rollback evidence",
					"live self-change evidence",
				},
			},
			{
				Name:  "execution",
				Owner: "ao2",
				Gates: []string{
					"policy decision input",
					"evidence pack output",
				},
			},
			{
				Name:  "control-plane-evidence",
				Owner: "ao2-control-plane",
				Gates: []string{
					"schema-backed publication",
					"readiness status exposure",
				},
			},
			{
				Name:  "release-orchestration",
				Owner: "ao-forge",
				Gates: []string{
					"release candidate validation",
					"handoff contract validation",
				},
			},
			{
				Name:  "operator-status",
				Owner: "ao-command",
				Gates: []string{
					"read-only status",
					"active-stack routing",
				},
			},
		},
		OutOfBounds: []string{
			"does not execute governed work",
			"does not publish or store control-plane evidence",
			"does not replace release orchestration",
			"does not provide operator dashboard workflows",
		},
	}
}
