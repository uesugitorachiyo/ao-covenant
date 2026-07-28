package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestAutonomousRepairPolicyOwnsRepositoryAuthority(t *testing.T) {
	data, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy, err := DecodeAutonomousRepairGovernancePolicy(data)
	if err != nil {
		t.Fatal(err)
	}

	sole, ok := governancePolicy.RepositoryPolicies["fixture/sole-repair"]
	if !ok || sole.RepositoryClass != "sole_control" || !sole.SoleAutoMergeOptIn {
		t.Fatalf("sole-control fixture policy = %+v, found=%v", sole, ok)
	}
	if _, ok := governancePolicy.RepositoryPolicies["uesugitorachiyo/ao2"]; ok {
		t.Fatal("production AO repository was silently granted autonomous authority")
	}
	livekit, ok := governancePolicy.RepositoryPolicies["livekit/livekit"]
	if !ok || livekit.RepositoryClass != "external" || livekit.SoleAutoMergeOptIn {
		t.Fatalf("LiveKit policy = %+v, found=%v", livekit, ok)
	}
}

func TestAutonomousRepairGovernanceRequestSchemaIsRegistered(t *testing.T) {
	if !schema.KnownSchemaID(schema.AutonomousRepairGovernanceRequestSchemaID) {
		t.Fatalf("request schema %q is not registered", schema.AutonomousRepairGovernanceRequestSchemaID)
	}
}

func TestAutonomousRepairGovernanceSchemasRejectUnknownFields(t *testing.T) {
	policyBytes, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernancePolicySchemaID, policyBytes); err != nil {
		t.Fatalf("policy fixture rejected: %v", err)
	}
	var policyDocument map[string]any
	if err := json.Unmarshal(policyBytes, &policyDocument); err != nil {
		t.Fatal(err)
	}
	policyDocument["unexpected"] = true
	invalidPolicy, err := json.Marshal(policyDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernancePolicySchemaID, invalidPolicy); err == nil {
		t.Fatal("policy schema accepted unknown field")
	}

	request := canonicalRepairRequest(t, "external", "open_upstream_draft_pr")
	requestBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernanceRequestSchemaID, requestBytes); err != nil {
		t.Fatalf("write request rejected: %v", err)
	}
	var requestDocument map[string]any
	if err := json.Unmarshal(requestBytes, &requestDocument); err != nil {
		t.Fatal(err)
	}
	requestDocument["candidate_decision"].(map[string]any)["unexpected"] = true
	invalidRequest, err := json.Marshal(requestDocument)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAutonomousRepairGovernanceRequest(invalidRequest); err == nil {
		t.Fatal("strict request decoder accepted nested unknown field")
	}
}

func TestAutonomousRepairGovernancePublishedFixtures(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	now := time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)
	fixtures := map[string]AutonomousRepairGovernanceRequest{
		"discovery-request.json": {
			SchemaVersion: AutonomousRepairGovernanceRequestVersion,
			RequestID:     "discovery-livekit",
			Mode:          "discovery",
			Repository:    "livekit/livekit",
		},
	}
	for _, item := range []struct {
		file       string
		class      string
		action     string
		repository string
	}{
		{"write-request-sole.json", "sole_control", "auto_merge", "fixture/sole-repair"},
		{"write-request-team.json", "team", "request_merge_queue", "fixture/team-repair"},
		{"write-request-external.json", "external", "open_upstream_draft_pr", "fixture/external-repair"},
		{"write-request-unknown.json", "unknown", "open_upstream_draft_pr", "fixture/unknown-repair"},
	} {
		request := canonicalRepairRequest(t, item.class, item.action)
		request.Repository = item.repository
		setCanonicalRepository(t, &request, item.repository)
		fixtures[item.file] = request
	}

	for file, request := range fixtures {
		file := file
		request := request
		t.Run(file, func(t *testing.T) {
			path := filepath.Join("..", "..", "examples", "autonomous-repair-governance", file)
			if os.Getenv("COVENANT_UPDATE_AUTONOMOUS_REPAIR_FIXTURES") == "1" {
				data, err := json.MarshalIndent(request, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, '\n')
				if err := os.WriteFile(path, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.ValidateBytes(schema.AutonomousRepairGovernanceRequestSchemaID, data); err != nil {
				t.Fatalf("fixture schema validation: %v", err)
			}
			decoded, err := DecodeAutonomousRepairGovernanceRequest(data)
			if err != nil {
				t.Fatalf("fixture strict decode: %v", err)
			}
			decision := EvaluateAutonomousRepairGovernance(governancePolicy, decoded, now)
			if !decision.Authorized {
				t.Fatalf("fixture decision = %+v", decision)
			}
		})
	}
}

func TestDiscoveryRequestHasNoWriteAuthoritySurface(t *testing.T) {
	valid := []byte(`{
	  "schema_version": "covenant.autonomous-repair-governance-request.v1",
	  "request_id": "discovery-livekit",
	  "mode": "discovery",
	  "repository": "livekit/livekit"
	}`)
	if _, err := DecodeAutonomousRepairGovernanceRequest(valid); err != nil {
		t.Fatalf("valid discovery rejected: %v", err)
	}

	contradictory := []byte(`{
	  "schema_version": "covenant.autonomous-repair-governance-request.v1",
	  "request_id": "discovery-livekit",
	  "mode": "discovery",
	  "repository": "livekit/livekit",
	  "approved_action_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}`)
	if _, err := DecodeAutonomousRepairGovernanceRequest(contradictory); err == nil {
		t.Fatal("discovery accepted write authority evidence")
	}
	if err := schema.ValidateBytes(schema.AutonomousRepairGovernanceRequestSchemaID, contradictory); err == nil {
		t.Fatal("request schema accepted discovery write authority evidence")
	}
}

func TestAutonomousRepairGovernanceFourClassOutcomes(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	now := time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		class      string
		action     string
		repository string
		reason     string
	}{
		{"sole auto merge", "sole_control", "auto_merge", "fixture/sole-repair", "sole_control_auto_merge"},
		{"team merge queue", "team", "request_merge_queue", "fixture/team-repair", "team_merge_queue"},
		{"external upstream draft", "external", "open_upstream_draft_pr", "fixture/external-repair", "external_draft_only"},
		{"unknown defaults external", "unknown", "open_upstream_draft_pr", "fixture/unknown-repair", "external_draft_only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := canonicalRepairRequest(t, tt.class, tt.action)
			request.Repository = tt.repository
			setCanonicalRepository(t, &request, tt.repository)
			decision := EvaluateAutonomousRepairGovernance(governancePolicy, request, now)
			if !decision.Authorized || !decision.MutationAuthorized ||
				decision.RepositoryClass != mapUnknownClass(tt.class) ||
				decision.ReasonCode != tt.reason {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}
}

func TestAutonomousRepairGovernanceRejectsClassEscalationAndUnsafeActions(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	now := time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)

	external := canonicalRepairRequest(t, "external", "open_upstream_draft_pr")
	claimedSole := "sole_control"
	external.OwnershipClassAssertion = &claimedSole
	if decision := EvaluateAutonomousRepairGovernance(governancePolicy, external, now); decision.ReasonCode != "ownership_assertion_mismatch" {
		t.Fatalf("external class escalation = %+v", decision)
	}

	team := canonicalRepairRequest(t, "team", "auto_merge")
	if decision := EvaluateAutonomousRepairGovernance(governancePolicy, team, now); decision.Authorized ||
		(decision.ReasonCode != "action_not_allowed_by_repository_policy" &&
			decision.ReasonCode != "team_auto_merge_denied" &&
			decision.ReasonCode != "repository_policy_mismatch") {
		t.Fatalf("team auto-merge = %+v", decision)
	}

	productionAO := canonicalRepairRequest(t, "external", "open_upstream_draft_pr")
	productionAO.Repository = "uesugitorachiyo/ao2"
	setCanonicalRepository(t, &productionAO, productionAO.Repository)
	productionAO.OwnershipClassAssertion = &claimedSole
	if decision := EvaluateAutonomousRepairGovernance(governancePolicy, productionAO, now); decision.ReasonCode != "ownership_assertion_mismatch" {
		t.Fatalf("production AO auto authority = %+v", decision)
	}

	for _, action := range []string{"open_ready_pr", "request_merge_queue", "auto_merge"} {
		request := canonicalRepairRequest(t, "external", action)
		decision := EvaluateAutonomousRepairGovernance(governancePolicy, request, now)
		if decision.Authorized {
			t.Fatalf("external action %s authorized: %+v", action, decision)
		}
	}

	for _, action := range []string{"approve_review", "mutate_issue"} {
		document := []byte(`{
		  "schema_version": "covenant.autonomous-repair-governance-request.v1",
		  "request_id": "repair-denied-action",
		  "mode": "write",
		  "repository": "fixture/external-repair",
		  "issue_number": 101,
		  "action": "` + action + `"
		}`)
		if _, err := DecodeAutonomousRepairGovernanceRequest(document); err == nil {
			t.Fatalf("permanently denied action %s decoded", action)
		}
		if err := schema.ValidateBytes(schema.AutonomousRepairGovernanceRequestSchemaID, document); err == nil {
			t.Fatalf("permanently denied action %s passed schema", action)
		}
	}

	soleWithoutOptIn := governancePolicy
	soleWithoutOptIn.RepositoryPolicies = cloneRepositoryPolicies(governancePolicy.RepositoryPolicies)
	solePolicy := soleWithoutOptIn.RepositoryPolicies["fixture/sole-repair"]
	solePolicy.SoleAutoMergeOptIn = false
	soleWithoutOptIn.RepositoryPolicies["fixture/sole-repair"] = solePolicy
	soleRequest := canonicalRepairRequest(t, "sole_control", "auto_merge")
	if decision := EvaluateAutonomousRepairGovernance(soleWithoutOptIn, soleRequest, now); decision.Authorized {
		t.Fatalf("sole auto-merge survived revoked policy opt-in: %+v", decision)
	}
}

func TestAutonomousRepairGovernanceRejectsEveryPreviouslyUnboundFieldWithoutRedigest(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	now := time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*AutonomousRepairGovernanceRequest)
	}{
		{"envelope default branch", func(r *AutonomousRepairGovernanceRequest) { r.RunEnvelope.Trigger.DefaultBranch = "other" }},
		{"envelope routing branch", func(r *AutonomousRepairGovernanceRequest) { r.RunEnvelope.Routing.RepairBranch = "codex/other" }},
		{"envelope fork owner", func(r *AutonomousRepairGovernanceRequest) {
			value := "attacker"
			r.RunEnvelope.Routing.ForkOwner = &value
		}},
		{"envelope protected classes", func(r *AutonomousRepairGovernanceRequest) {
			r.RunEnvelope.Routing.ProtectedPathClasses = []string{"workflow"}
		}},
		{"envelope checks", func(r *AutonomousRepairGovernanceRequest) { r.RunEnvelope.Routing.RequiredChecks = []string{"fake"} }},
		{"envelope ownership", func(r *AutonomousRepairGovernanceRequest) { r.RunEnvelope.Governance.OwnershipClass = "sole_control" }},
		{"envelope opt in", func(r *AutonomousRepairGovernanceRequest) { r.RunEnvelope.Governance.SoleControlAutoMergeOptIn = true }},
		{"candidate security", func(r *AutonomousRepairGovernanceRequest) { r.CandidateDecision.Eligibility.SecuritySensitive = true }},
		{"candidate repository", func(r *AutonomousRepairGovernanceRequest) { r.CandidateDecision.Repository = "attacker/repo" }},
		{"candidate issue", func(r *AutonomousRepairGovernanceRequest) { r.CandidateDecision.IssueNumber++ }},
		{"governance class", func(r *AutonomousRepairGovernanceRequest) { r.GovernanceDecision.GovernanceClass = "sole_control" }},
		{"governance push target", func(r *AutonomousRepairGovernanceRequest) {
			r.GovernanceDecision.PushTarget = "policy_authorized_branch"
		}},
		{"governance pr mode", func(r *AutonomousRepairGovernanceRequest) {
			r.GovernanceDecision.PullRequestMode = "draft_or_ready_by_policy"
		}},
		{"governance merge", func(r *AutonomousRepairGovernanceRequest) { r.GovernanceDecision.Merge.Authorized = true }},
		{"governance protected result", func(r *AutonomousRepairGovernanceRequest) { r.GovernanceDecision.ProtectedPathTouched = true }},
		{"governance checks", func(r *AutonomousRepairGovernanceRequest) { r.GovernanceDecision.RequiredChecks[0].Name = "fake" }},
		{"reviewer id", func(r *AutonomousRepairGovernanceRequest) { r.ReviewerIndependence.ReviewerID = "ao-reviewer" }},
		{"reviewer status", func(r *AutonomousRepairGovernanceRequest) { r.ReviewerIndependence.Status = "unverified" }},
		{"reviewer gate", func(r *AutonomousRepairGovernanceRequest) { r.ReviewerIndependence.SatisfiesTeamMergeGate = true }},
		{"reviewer subject", func(r *AutonomousRepairGovernanceRequest) { r.ReviewerIndependence.SubjectDigest = digestOf("other") }},
		{"action fork", func(r *AutonomousRepairGovernanceRequest) {
			value := "attacker/repo"
			r.GitHubActionDigest.Fork = &value
		}},
		{"action branch", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.Branch = "codex/other" }},
		{"action title", func(r *AutonomousRepairGovernanceRequest) {
			r.GitHubActionDigest.PRTitleDigest = digestOf("other title")
		}},
		{"action body", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.PRBodyDigest = digestOf("other body") }},
		{"action diff", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.DiffDigest = digestOf("other diff") }},
		{"action checks", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.RequiredChecks[0].Name = "fake" }},
		{"action name", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.Action = "auto_merge" }},
		{"action base", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.BaseSHA = stringsOf('c', 40) }},
		{"action head", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.HeadSHA = stringsOf('c', 40) }},
		{"action repository", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.Repository = "attacker/repo" }},
		{"action issue", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.IssueNumber++ }},
		{"action envelope digest", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.RunEnvelopeDigest = digestOf("other") }},
		{"action candidate digest", func(r *AutonomousRepairGovernanceRequest) {
			r.GitHubActionDigest.CandidateDecisionDigest = digestOf("other")
		}},
		{"action governance digest", func(r *AutonomousRepairGovernanceRequest) {
			r.GitHubActionDigest.GovernanceDecisionDigest = digestOf("other")
		}},
		{"action reviewer digest", func(r *AutonomousRepairGovernanceRequest) {
			r.GitHubActionDigest.ReviewerIndependenceDigest = digestOf("other")
		}},
		{"action approval", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.ApprovedAt = "2026-07-27T23:21:00Z" }},
		{"action expiry", func(r *AutonomousRepairGovernanceRequest) { r.GitHubActionDigest.ExpiresAt = "2026-07-28T00:01:00Z" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := canonicalRepairRequest(t, "external", "open_upstream_draft_pr")
			tt.mutate(&request)
			decision := EvaluateAutonomousRepairGovernance(governancePolicy, request, now)
			if decision.Authorized || decision.MutationAuthorized {
				t.Fatalf("tampered request authorized: %+v", decision)
			}
		})
	}
}

func TestAutonomousRepairGovernanceRejectsRedigestedContradictions(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	now := time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*AutonomousRepairGovernanceRequest)
		reason string
	}{
		{
			name: "security sensitive candidate",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.CandidateDecision.Eligibility.SecuritySensitive = true
			},
			reason: "security_sensitive",
		},
		{
			name: "protected path result contradiction",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.ChangedPathClasses = []string{"workflow"}
			},
			reason: "protected_path_classification_mismatch",
		},
		{
			name: "protected path confirmed",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.ChangedPathClasses = []string{"workflow"}
				r.GovernanceDecision.ProtectedPathTouched = true
			},
			reason: "protected_path",
		},
		{
			name: "external claims sole in authority documents",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.RunEnvelope.Governance.OwnershipClass = "sole_control"
				r.GovernanceDecision.GovernanceClass = "sole_control"
			},
			reason: "repository_policy_mismatch",
		},
		{
			name: "approval exceeds twenty four hours",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.RunEnvelope.ExpiresAt = "2026-07-29T00:00:00Z"
				r.RunEnvelope.Budgets.WallClockSeconds = 115200
				r.GitHubActionDigest.ExpiresAt = "2026-07-29T00:00:00Z"
			},
			reason: "authority_chronology_invalid",
		},
		{
			name: "future reviewer evidence",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.ReviewerIndependence.ReviewedAt = "2026-07-27T23:40:00Z"
			},
			reason: "authority_chronology_invalid",
		},
		{
			name: "failed exact-head check",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.GovernanceDecision.RequiredChecks[0].Conclusion = "failure"
				r.GitHubActionDigest.RequiredChecks[0].Conclusion = "failure"
			},
			reason: "required_check_not_green",
		},
		{
			name: "missing required check",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.GovernanceDecision.RequiredChecks = r.GovernanceDecision.RequiredChecks[1:]
				r.GitHubActionDigest.RequiredChecks = r.GitHubActionDigest.RequiredChecks[1:]
			},
			reason: "required_checks_mismatch",
		},
		{
			name: "envelope action widening",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.RunEnvelope.Governance.AllowedActions = append(
					r.RunEnvelope.Governance.AllowedActions,
					"auto_merge",
				)
			},
			reason: "repository_policy_mismatch",
		},
		{
			name: "stale reviewer head",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.GovernanceDecision.Merge.ApprovalHeadSHA = pointerTo(stringsOf('c', 40))
			},
			reason: "independent_human_approval_required",
		},
		{
			name: "automated reviewer",
			mutate: func(r *AutonomousRepairGovernanceRequest) {
				r.ReviewerIndependence.ReviewerID = "ao-reviewer"
			},
			reason: "independent_human_approval_required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class := "external"
			action := "open_upstream_draft_pr"
			if tt.name == "stale reviewer head" || tt.name == "automated reviewer" {
				class = "team"
				action = "request_merge_queue"
			}
			request := canonicalRepairRequest(t, class, action)
			tt.mutate(&request)
			redigestCanonicalRequest(t, &request)
			decision := EvaluateAutonomousRepairGovernance(governancePolicy, request, now)
			if decision.Authorized || decision.ReasonCode != tt.reason {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}
}

func TestApprovedActionDigestMustBeDistinctExactAuthority(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	request := canonicalRepairRequest(t, "external", "open_upstream_draft_pr")
	request.ApprovedActionDigest = digestOf("different approval")
	decision := EvaluateAutonomousRepairGovernance(
		governancePolicy,
		request,
		time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC),
	)
	if decision.Authorized || decision.ReasonCode != "approved_action_digest_mismatch" {
		t.Fatalf("mismatched approved action digest = %+v", decision)
	}
}

func TestMalformedCanonicalEvidenceFailsClosedWithoutPanic(t *testing.T) {
	governancePolicy := loadAutonomousRepairPolicy(t)
	request := AutonomousRepairGovernanceRequest{
		SchemaVersion:        AutonomousRepairGovernanceRequestVersion,
		RequestID:            "repair-malformed",
		Mode:                 "write",
		Repository:           "fixture/external-repair",
		IssueNumber:          pointerTo(101),
		Action:               "open_upstream_draft_pr",
		CurrentBaseSHA:       stringsOf('1', 40),
		ApprovedActionDigest: stringsOf('a', 64),
		RunEnvelope:          &ArchitectureRunEnvelope{},
		CandidateDecision:    &ArchitectureCandidateDecision{},
		GovernanceDecision:   &ArchitectureGovernanceDecision{},
		ReviewerIndependence: &ArchitectureReviewerIndependence{},
		GitHubActionDigest:   &ArchitectureGitHubActionDigest{},
	}
	decision := EvaluateAutonomousRepairGovernance(
		governancePolicy,
		request,
		time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC),
	)
	if decision.Authorized || decision.ReasonCode != "malformed_canonical_authority" {
		t.Fatalf("malformed evidence decision = %+v", decision)
	}
}

func loadAutonomousRepairPolicy(t *testing.T) AutonomousRepairGovernancePolicy {
	t.Helper()
	data, err := os.ReadFile(autonomousRepairPolicyFixture)
	if err != nil {
		t.Fatal(err)
	}
	governancePolicy, err := DecodeAutonomousRepairGovernancePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	return governancePolicy
}

func canonicalRepairRequest(t *testing.T, class string, actionName string) AutonomousRepairGovernanceRequest {
	t.Helper()
	repository := "fixture/" + class + "-repair"
	if class == "unknown" {
		repository = "fixture/unknown-repair"
		class = "external"
	}
	baseSHA := stringsOf('1', 40)
	headSHA := stringsOf('b', 40)
	diffDigest := stringsOf('f', 64)
	requiredChecks := []string{"test", "lint"}
	checks := []ArchitectureRequiredCheck{
		{Name: "test", Conclusion: "success", HeadSHA: headSHA},
		{Name: "lint", Conclusion: "success", HeadSHA: headSHA},
	}
	forkOwner := "operator"
	var envelopeForkOwner *string
	var actionFork *string
	pushTarget := "policy_authorized_branch"
	prMode := "draft_or_ready_by_policy"
	allowedActions := []string{"open_ready_pr", actionName}
	merge := ArchitectureMergeDecision{Mode: "never", ApprovalKind: "none"}
	reviewerID := "independent-reviewer"
	reviewerGate := false
	autoMergeOptIn := false
	if class == "external" {
		envelopeForkOwner = &forkOwner
		fork := forkOwner + "/" + strings.SplitN(repository, "/", 2)[1]
		actionFork = &fork
		pushTarget = "operator_owned_fork"
		prMode = "upstream_draft_only"
		allowedActions = []string{"push_operator_fork", "open_upstream_draft_pr"}
	} else if class == "team" && actionName == "request_merge_queue" {
		merge.Authorized = true
		merge.Mode = "merge_queue"
		merge.ApprovalKind = "independent_human"
		merge.ApprovalHeadSHA = &headSHA
		reviewerID = "human-reviewer"
		reviewerGate = true
	} else if class == "sole_control" && actionName == "auto_merge" {
		merge.Authorized = true
		merge.Mode = "auto_merge"
		merge.AutoMergeOptIn = true
		autoMergeOptIn = true
	}

	issueNumber := 101
	classAssertion := class
	request := AutonomousRepairGovernanceRequest{
		SchemaVersion:           AutonomousRepairGovernanceRequestVersion,
		RequestID:               "repair-run-20260728",
		Mode:                    "write",
		Repository:              repository,
		OwnershipClassAssertion: &classAssertion,
		IssueNumber:             &issueNumber,
		Action:                  actionName,
		CurrentBaseSHA:          baseSHA,
		ChangedPathClasses:      []string{"source"},
		RunEnvelope: &ArchitectureRunEnvelope{
			Schema: architectureRunEnvelopeSchema,
			RunID:  "repair-run-20260728",
			Loop: ArchitectureRepairLoop{
				Goal:         "Repair one controlled fixture.",
				Trigger:      "Use an exact repository policy.",
				Discovery:    "Use bounded discovery.",
				Action:       "Perform one bounded action.",
				Verification: "Require deterministic checks.",
				State:        "Persist canonical evidence.",
				HumanGates:   "Apply repository governance.",
			},
			Trigger: ArchitectureRepairTrigger{
				Mode:             "explicit_issue",
				CanonicalURL:     "https://github.com/" + repository + "/issues/101",
				Repository:       repository,
				DefaultBranch:    "main",
				PinnedBaseCommit: baseSHA,
			},
			Discovery: ArchitectureRepairDiscovery{SnapshotLimit: 50, CandidateLimit: 10, SelectedLimit: 1},
			Budgets: ArchitectureRepairBudgets{
				WallClockSeconds: 28800,
				CloneCount:       1,
				TestRuns:         20,
				RetryCount:       3,
				RepairCount:      1,
				PublicationCount: 1,
			},
			Governance: ArchitectureEnvelopeGovernance{
				OwnershipClass:            class,
				AllowedActions:            allowedActions,
				DeniedActions:             []string{"push_upstream", "open_ready_pr", "mark_ready", "approve_review", "merge", "mutate_issue", "publish_release"},
				SoleControlAutoMergeOptIn: autoMergeOptIn,
			},
			Routing: ArchitectureRepairRouting{
				DefaultBranch:        "main",
				PinnedBaseCommit:     baseSHA,
				ForkOwner:            envelopeForkOwner,
				RepairBranch:         "codex/repair-issue",
				ProtectedPathClasses: append([]string(nil), autonomousRepairRiskyPathClasses...),
				RequiredChecks:       requiredChecks,
			},
			CreatedAt:        "2026-07-27T16:00:00Z",
			ExpiresAt:        "2026-07-28T00:00:00Z",
			Lineage:          ArchitectureRepairLineage{Kind: "origin"},
			StopConditions:   []string{"policy_ambiguity", "security_sensitive", "digest_mismatch", "required_check_conflict"},
			TerminalStatuses: []string{"completed", "blocked", "expired"},
		},
		CandidateDecision: &ArchitectureCandidateDecision{
			Schema:      architectureCandidateSchema,
			RunID:       "repair-run-20260728",
			Repository:  repository,
			BaseSHA:     baseSHA,
			IssueNumber: issueNumber,
			Rank:        1,
			Decision:    "selected",
			Eligibility: ArchitectureCandidateEligibility{
				OpenBug:                        true,
				TargetInRepository:             true,
				NoExistingFix:                  true,
				CurrentHeadUnfixed:             true,
				PublicReproductionFeasible:     true,
				DeterministicLocalReproduction: true,
				ExpectedBehaviorGrounded:       true,
				BoundedPolicyCompatible:        true,
			},
			ReasonCodes:            []string{"eligible_all_predicates_passed"},
			EvidenceDigests:        []string{stringsOf('6', 64)},
			ExpectedBehaviorSource: "tests",
			DecidedAt:              "2026-07-27T22:00:00Z",
		},
		GovernanceDecision: &ArchitectureGovernanceDecision{
			Schema:                architectureGovernanceSchema,
			RunID:                 "repair-run-20260728",
			Repository:            repository,
			BaseSHA:               baseSHA,
			HeadSHA:               headSHA,
			GovernanceClass:       class,
			ClassificationSources: []string{"repository_policy", "operator_envelope"},
			PushTarget:            pushTarget,
			PullRequestMode:       prMode,
			Merge:                 merge,
			RequiredChecks:        append([]ArchitectureRequiredCheck(nil), checks...),
			ActionDigestRequired:  true,
			DecidedAt:             "2026-07-27T23:10:00Z",
		},
		ReviewerIndependence: &ArchitectureReviewerIndependence{
			Schema:                    architectureReviewerSchema,
			RunID:                     "repair-run-20260728",
			SubjectDigest:             diffDigest,
			ReviewerID:                reviewerID,
			Status:                    "independent",
			DeterministicTestsPrimary: true,
			SatisfiesTeamMergeGate:    reviewerGate,
			ReviewedAt:                "2026-07-27T23:15:00Z",
		},
		GitHubActionDigest: &ArchitectureGitHubActionDigest{
			Schema:         architectureGitHubActionDigestSchema,
			RunID:          "repair-run-20260728",
			Repository:     repository,
			IssueNumber:    issueNumber,
			BaseSHA:        baseSHA,
			HeadSHA:        headSHA,
			Fork:           actionFork,
			Branch:         "codex/repair-issue",
			PRTitleDigest:  stringsOf('d', 64),
			PRBodyDigest:   stringsOf('e', 64),
			DiffDigest:     diffDigest,
			RequiredChecks: append([]ArchitectureRequiredCheck(nil), checks...),
			Action:         actionName,
			ApprovedAt:     "2026-07-27T23:20:00Z",
			ExpiresAt:      "2026-07-28T00:00:00Z",
		},
	}
	redigestCanonicalRequest(t, &request)
	return request
}

func redigestCanonicalRequest(t *testing.T, request *AutonomousRepairGovernanceRequest) {
	t.Helper()
	var err error
	request.RunEnvelope.CanonicalDigest, err = architectureCanonicalDigest(*request.RunEnvelope, "canonical_digest")
	if err != nil {
		t.Fatal(err)
	}
	request.CandidateDecision.DecisionDigest, err = architectureCanonicalDigest(*request.CandidateDecision, "decision_digest")
	if err != nil {
		t.Fatal(err)
	}
	request.GovernanceDecision.DecisionDigest, err = architectureCanonicalDigest(*request.GovernanceDecision, "decision_digest")
	if err != nil {
		t.Fatal(err)
	}
	request.ReviewerIndependence.ReviewDigest, err = architectureCanonicalDigest(*request.ReviewerIndependence, "review_digest")
	if err != nil {
		t.Fatal(err)
	}
	request.GitHubActionDigest.RunEnvelopeDigest = request.RunEnvelope.CanonicalDigest
	request.GitHubActionDigest.CandidateDecisionDigest = request.CandidateDecision.DecisionDigest
	request.GitHubActionDigest.GovernanceDecisionDigest = request.GovernanceDecision.DecisionDigest
	request.GitHubActionDigest.ReviewerIndependenceDigest = request.ReviewerIndependence.ReviewDigest
	request.GitHubActionDigest.ActionDigest, err = architectureCanonicalDigest(*request.GitHubActionDigest, "action_digest")
	if err != nil {
		t.Fatal(err)
	}
	request.ApprovedActionDigest = request.GitHubActionDigest.ActionDigest
}

func setCanonicalRepository(t *testing.T, request *AutonomousRepairGovernanceRequest, repository string) {
	t.Helper()
	request.RunEnvelope.Trigger.Repository = repository
	request.RunEnvelope.Trigger.CanonicalURL = "https://github.com/" + repository + "/issues/101"
	request.CandidateDecision.Repository = repository
	request.GovernanceDecision.Repository = repository
	request.GitHubActionDigest.Repository = repository
	if request.GitHubActionDigest.Fork != nil {
		fork := "operator/" + strings.SplitN(repository, "/", 2)[1]
		request.GitHubActionDigest.Fork = &fork
	}
	redigestCanonicalRequest(t, request)
}

func mapUnknownClass(class string) string {
	if class == "unknown" {
		return "external"
	}
	return class
}

func cloneRepositoryPolicies(source map[string]AutonomousRepairRepositoryPolicy) map[string]AutonomousRepairRepositoryPolicy {
	cloned := make(map[string]AutonomousRepairRepositoryPolicy, len(source))
	for repository, repositoryPolicy := range source {
		cloned[repository] = repositoryPolicy
	}
	return cloned
}

func stringsOf(value byte, count int) string {
	return strings.Repeat(string(value), count)
}

func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func pointerTo[T any](value T) *T {
	return &value
}
