package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const autonomousRepairPolicyFixture = "../../examples/autonomous-repair-governance/policy.json"

func TestHistoricalGitHubIssuePoliciesRemainUnchanged(t *testing.T) {
	tests := []struct {
		path          string
		schemaVersion string
		policyID      string
	}{
		{
			path:          "../../examples/operator/github-issue-action-policy.json",
			schemaVersion: "ao.covenant.github-issue-action-policy.v0.1",
			policyID:      "github-issue-to-draft-pr-month1-policy",
		},
		{
			path:          "../../examples/operator/github-issue-reproduction-policy.json",
			schemaVersion: "ao.covenant.github-issue-reproduction-policy.v0.1",
			policyID:      "github-issue-month2-reproduction-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.policyID, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				SchemaVersion string `json:"schema_version"`
				PolicyID      string `json:"policy_id"`
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.SchemaVersion != tt.schemaVersion || fixture.PolicyID != tt.policyID {
				t.Fatalf("historical fixture identity changed: %+v", fixture)
			}
		})
	}
}

func TestAutonomousRepairGovernancePolicyFixtureIsStrictAndRegistered(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernancePolicySchemaID, data); err != nil {
		t.Fatalf("valid policy fixture rejected: %v", err)
	}

	var policyDocument map[string]any
	if err := json.Unmarshal(data, &policyDocument); err != nil {
		t.Fatal(err)
	}
	policyDocument["unexpected"] = true
	invalid, err := json.Marshal(policyDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernancePolicySchemaID, invalid); err == nil {
		t.Fatal("policy schema accepted an unknown field")
	}
}

func TestAutonomousRepairGovernanceScenarios(t *testing.T) {
	policyDocument, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy, err := DecodeAutonomousRepairGovernancePolicy(policyDocument)
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("testdata", "autonomous_repair_governance_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		ReferenceTime string         `json:"reference_time"`
		BaseRequest   map[string]any `json:"base_request"`
		Cases         []struct {
			Name                string         `json:"name"`
			Override            map[string]any `json:"override"`
			WantAuthorized      bool           `json:"want_authorized"`
			WantMutation        bool           `json:"want_mutation_authorized"`
			WantReasonCode      string         `json:"want_reason_code"`
			WantRepositoryClass string         `json:"want_repository_class"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&suite); err != nil {
		t.Fatalf("decode scenario suite: %v", err)
	}
	referenceTime, err := time.Parse(time.RFC3339, suite.ReferenceTime)
	if err != nil {
		t.Fatal(err)
	}

	if len(suite.Cases) < 16 {
		t.Fatalf("scenario count = %d, want at least 16", len(suite.Cases))
	}
	for _, tt := range suite.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			requestDocument := mergeAutonomousRepairFixture(suite.BaseRequest, tt.Override)
			requestBytes, err := json.Marshal(requestDocument)
			if err != nil {
				t.Fatal(err)
			}
			request, err := DecodeAutonomousRepairGovernanceRequest(requestBytes)
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			decision := EvaluateAutonomousRepairGovernance(governancePolicy, request, referenceTime)
			if decision.Authorized != tt.WantAuthorized ||
				decision.MutationAuthorized != tt.WantMutation ||
				decision.ReasonCode != tt.WantReasonCode ||
				decision.RepositoryClass != tt.WantRepositoryClass {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}
}

func mergeAutonomousRepairFixture(base map[string]any, override map[string]any) map[string]any {
	merged := make(map[string]any, len(base))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		baseMap, baseOK := merged[key].(map[string]any)
		overrideMap, overrideOK := value.(map[string]any)
		if baseOK && overrideOK {
			merged[key] = mergeAutonomousRepairFixture(baseMap, overrideMap)
			continue
		}
		merged[key] = value
	}
	return merged
}

func TestAutonomousRepairGovernanceRequestRejectsUnknownFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "autonomous_repair_governance_unknown_field.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAutonomousRepairGovernanceRequest(data); err == nil {
		t.Fatal("request decoder accepted an unknown field")
	}
}

func TestAutonomousRepairGovernanceRejectsWidenedPolicyAtRuntime(t *testing.T) {
	policyDocument, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy, err := DecodeAutonomousRepairGovernancePolicy(policyDocument)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy.Defaults.IssueTextCanAuthorize = true

	decision := EvaluateAutonomousRepairGovernance(governancePolicy, AutonomousRepairGovernanceRequest{
		SchemaVersion: AutonomousRepairGovernanceRequestVersion,
		Repository:    "uesugitorachiyo/ao2",
		Action:        "discover",
		Ownership: AutonomousRepairOwnership{
			Source:          "explicit_policy",
			RepositoryClass: "unknown",
			Repository:      "uesugitorachiyo/ao2",
		},
	}, time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC))
	if decision.Authorized || decision.ReasonCode != "invalid_policy" {
		t.Fatalf("widened policy was consumed: %+v", decision)
	}
}

func TestAutonomousRepairGovernanceRejectsInvalidDirectRequest(t *testing.T) {
	policyDocument, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy, err := DecodeAutonomousRepairGovernancePolicy(policyDocument)
	if err != nil {
		t.Fatal(err)
	}

	decision := EvaluateAutonomousRepairGovernance(governancePolicy, AutonomousRepairGovernanceRequest{
		SchemaVersion: "wrong.request.v1",
		RequestID:     "repair-invalid",
		Repository:    "uesugitorachiyo/ao2",
		IssueNumber:   42,
		Action:        "discover",
		Ownership: AutonomousRepairOwnership{
			Source:          "explicit_policy",
			RepositoryClass: "unknown",
			Repository:      "uesugitorachiyo/ao2",
		},
	}, time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC))
	if decision.Authorized || decision.ReasonCode != "invalid_request" {
		t.Fatalf("invalid direct request was consumed: %+v", decision)
	}
}
