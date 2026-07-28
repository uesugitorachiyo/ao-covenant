package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const autonomousRepairGitHubExecutionPolicyFixture = "../../examples/autonomous-repair-github-execution/policy.json"

func TestAutonomousRepairGitHubExecutionPolicyFixtureIsStrictAndRegistered(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairGitHubExecutionPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !schema.KnownSchemaID(schema.AutonomousRepairGitHubExecutionPolicySchemaID) {
		t.Fatalf("schema %q is not registered", schema.AutonomousRepairGitHubExecutionPolicySchemaID)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGitHubExecutionPolicySchemaID, data); err != nil {
		t.Fatalf("fixture schema validation: %v", err)
	}
	policy, err := DecodeAutonomousRepairGitHubExecutionPolicy(data)
	if err != nil {
		t.Fatalf("fixture strict decode: %v", err)
	}
	if policy.ArchitectureWorkflowContract.Commit != "8e6f247b800b60c520b4e967f7553974a20ec2f8" {
		t.Fatalf("architecture commit = %q", policy.ArchitectureWorkflowContract.Commit)
	}
}

func TestAutonomousRepairGitHubExecutionPolicyRejectsEveryAuthorityWidening(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairGitHubExecutionPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"architecture repository", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["repository"] = "attacker/repo"
		}},
		{"architecture commit", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["commit"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"architecture path", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["path"] = "other.json"
		}},
		{"architecture schema", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["schema"] = "other.v1"
		}},
		{"architecture source digest", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["source_sha256"] = fmt.Sprintf("%064d", 0)
		}},
		{"architecture semantics digest", func(p map[string]any) {
			p["architecture_workflow_contract"].(map[string]any)["semantics_sha256"] = fmt.Sprintf("%064d", 0)
		}},
		{"fork lookup", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["fork_lookup"] = "optional"
		}},
		{"fork absent", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["fork_absent"] = "create_without_readback"
		}},
		{"fork present", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["fork_present"] = "reuse_any"
		}},
		{"branch absent", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["branch_absent"] = "create_at_latest"
		}},
		{"branch present", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["branch_present"] = "update"
		}},
		{"force update", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["force_update_allowed"] = true
		}},
		{"upstream push", func(p map[string]any) {
			p["push_operator_fork"].(map[string]any)["upstream_push_allowed"] = true
		}},
		{"draft lookup", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["lookup"] = "title_only"
		}},
		{"draft absent", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["absent"] = "create_many"
		}},
		{"draft present", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["present"] = "reuse_any"
		}},
		{"draft update", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["update_allowed"] = true
		}},
		{"ready for review", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["ready_for_review_allowed"] = true
		}},
		{"review", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["review_allowed"] = true
		}},
		{"merge", func(p map[string]any) {
			p["open_upstream_draft_pr"].(map[string]any)["merge_allowed"] = true
		}},
		{"fork create budget", func(p map[string]any) {
			p["write_budget"].(map[string]any)["fork_creates"] = float64(2)
		}},
		{"branch create budget", func(p map[string]any) {
			p["write_budget"].(map[string]any)["branch_creates"] = float64(2)
		}},
		{"draft create budget", func(p map[string]any) {
			p["write_budget"].(map[string]any)["draft_pr_creates"] = float64(2)
		}},
		{"ambient only", func(p map[string]any) {
			p["credentials"].(map[string]any)["ambient_only"] = false
		}},
		{"credential serialization", func(p map[string]any) {
			p["credentials"].(map[string]any)["serialized"] = true
		}},
		{"issue list authority", func(p map[string]any) {
			p["safety"].(map[string]any)["issue_list_grants_mutation_authority"] = true
		}},
		{"successor widening", func(p map[string]any) {
			p["safety"].(map[string]any)["successor_may_widen_authority"] = true
		}},
		{"unknown default", func(p map[string]any) {
			p["safety"].(map[string]any)["unknown_governance_defaults_to_external_draft_only"] = false
		}},
		{"external merge", func(p map[string]any) {
			p["safety"].(map[string]any)["external_merge_authorized"] = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			tt.mutate(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.ValidateBytes(schema.AutonomousRepairGitHubExecutionPolicySchemaID, mutated); err == nil {
				t.Fatal("public schema accepted authority widening")
			}
			if _, err := DecodeAutonomousRepairGitHubExecutionPolicy(mutated); err == nil {
				t.Fatal("runtime accepted authority widening")
			}
		})
	}
}

func TestAutonomousRepairGitHubExecutionRuntimeRejectsEveryAuthorityWidening(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairGitHubExecutionPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeAutonomousRepairGitHubExecutionPolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*AutonomousRepairGitHubExecutionPolicy)
	}{
		{"schema version", func(p *AutonomousRepairGitHubExecutionPolicy) { p.SchemaVersion = "other.v1" }},
		{"policy id", func(p *AutonomousRepairGitHubExecutionPolicy) { p.PolicyID = "other" }},
		{"architecture repository", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.Repository = "attacker/repo"
		}},
		{"architecture commit", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.Commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"architecture path", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.Path = "other.json"
		}},
		{"architecture schema", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.Schema = "other.v1"
		}},
		{"architecture source digest", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.SourceSHA256 = stringsOf('0', 64)
		}},
		{"architecture semantics digest", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.ArchitectureWorkflowContract.SemanticsSHA256 = stringsOf('0', 64)
		}},
		{"fork lookup", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.ForkLookup = "optional"
		}},
		{"fork absent", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.ForkAbsent = "create_without_readback"
		}},
		{"fork present", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.ForkPresent = "reuse_any"
		}},
		{"branch absent", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.BranchAbsent = "create_at_latest"
		}},
		{"branch present", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.BranchPresent = "update"
		}},
		{"force update", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.ForceUpdateAllowed = true
		}},
		{"upstream push", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.PushOperatorFork.UpstreamPushAllowed = true
		}},
		{"draft lookup", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.Lookup = "title_only"
		}},
		{"draft absent", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.Absent = "create_many"
		}},
		{"draft present", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.Present = "reuse_any"
		}},
		{"draft update", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.UpdateAllowed = true
		}},
		{"ready for review", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.ReadyForReviewAllowed = true
		}},
		{"review", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.ReviewAllowed = true
		}},
		{"merge", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.OpenUpstreamDraftPR.MergeAllowed = true
		}},
		{"fork create budget", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.WriteBudget.ForkCreates = 2
		}},
		{"branch create budget", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.WriteBudget.BranchCreates = 2
		}},
		{"draft create budget", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.WriteBudget.DraftPRCreates = 2
		}},
		{"ambient only", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Credentials.AmbientOnly = false
		}},
		{"credential serialization", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Credentials.Serialized = true
		}},
		{"issue list authority", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Safety.IssueListGrantsMutationAuthority = true
		}},
		{"successor widening", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Safety.SuccessorMayWidenAuthority = true
		}},
		{"unknown default", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Safety.UnknownGovernanceDefaultsToExternalDraftOnly = false
		}},
		{"external merge", func(p *AutonomousRepairGitHubExecutionPolicy) {
			p.Safety.ExternalMergeAuthorized = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := policy
			tt.mutate(&mutated)
			if validAutonomousRepairGitHubExecutionPolicy(mutated) {
				t.Fatal("runtime predicate accepted authority widening")
			}
		})
	}
}

func TestAutonomousRepairGitHubExecutionPolicyRejectsUnknownAndMissingFields(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairGitHubExecutionPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	document["unexpected"] = true
	withUnknown, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAutonomousRepairGitHubExecutionPolicy(withUnknown); err == nil {
		t.Fatal("runtime accepted unknown field")
	}

	delete(document, "unexpected")
	delete(document, "write_budget")
	missing, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAutonomousRepairGitHubExecutionPolicy(missing); err == nil {
		t.Fatal("runtime accepted missing write budget")
	}
}

func TestAutonomousRepairGitHubExecutionPolicySemanticsDigestMatchesFixture(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairGitHubExecutionPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	semantics := map[string]any{
		"github_action_execution": map[string]any{
			"push_operator_fork":     document["push_operator_fork"],
			"open_upstream_draft_pr": document["open_upstream_draft_pr"],
			"write_budget":           document["write_budget"],
			"credentials":            document["credentials"],
		},
		"safety": document["safety"],
	}
	canonical, err := json.Marshal(semantics)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprintf("%x", sha256.Sum256(canonical))
	source := document["architecture_workflow_contract"].(map[string]any)
	if want := source["semantics_sha256"]; got != want {
		t.Fatalf("semantics digest = %s, want %s", got, want)
	}
}

func TestAutonomousRepairGitHubExecutionPolicyPublishedFixturePathIsStable(t *testing.T) {
	if filepath.Clean(autonomousRepairGitHubExecutionPolicyFixture) !=
		filepath.Join("..", "..", "examples", "autonomous-repair-github-execution", "policy.json") {
		t.Fatal("published fixture path changed")
	}
}
