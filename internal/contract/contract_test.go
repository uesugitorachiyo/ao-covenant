package contract

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
)

type canonicalJSONVectorFixture struct {
	SchemaVersion string   `json:"schema_version"`
	Language      string   `json:"language"`
	Generator     string   `json:"generator"`
	Contract      Contract `json:"contract"`
	CanonicalJSON string   `json:"canonical_json"`
	SHA256        string   `json:"sha256"`
	FixtureOnly   bool     `json:"fixture_only"`
	ExecutesWork  bool     `json:"executes_work"`
	ApprovesWork  bool     `json:"approves_work"`
}

func validContract() Contract {
	return Contract{
		SchemaVersion: "covenant.contract.v1",
		Objective:     "Create a guarded risky-change demo contract.",
		Workspace: WorkspaceScope{
			Root:   ".",
			Reads:  []string{"examples/risky-change/brief.md"},
			Writes: []string{"demo-output/report.txt"},
		},
		Obligations: []Obligation{
			{ID: "obl_requested_file", Text: "The requested file is created.", Required: true},
			{ID: "obl_verify_passes", Text: "The verifier passes.", Required: true},
		},
		Tasks: []Task{
			{
				ID:          "scripted_change",
				Kind:        "scripted",
				Adapter:     "scripted",
				DependsOn:   []string{},
				Obligations: []string{"obl_requested_file"},
				TimeoutSecs: 30,
				DeclaredSideEffects: []ActionRef{
					{Type: "file.write", Resource: "demo-output/report.txt"},
				},
			},
			{
				ID:          "verify_change",
				Kind:        "verify",
				Adapter:     "scripted",
				DependsOn:   []string{"scripted_change"},
				Obligations: []string{"obl_verify_passes"},
				TimeoutSecs: 30,
			},
		},
		Policy: PolicyProfile{Mode: "strict"},
		Evaluator: EvaluatorRules{
			RequiredObligations: []string{"obl_requested_file", "obl_verify_passes"},
		},
	}
}

func TestValidateAcceptsValidContract(t *testing.T) {
	if err := Validate(validContract()); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestCanonicalJSONVectorExamplesBindGoAndRustBytes(t *testing.T) {
	root := filepath.Join("testdata", "canonical-json-vectors")
	goVector := readCanonicalJSONVectorFixture(t, filepath.Join(root, "go-contract-vector.json"))
	rustVector := readCanonicalJSONVectorFixture(t, filepath.Join(root, "rust-contract-vector.json"))

	if goVector.SchemaVersion != "covenant.canonical-json-vector.v1" ||
		rustVector.SchemaVersion != "covenant.canonical-json-vector.v1" ||
		goVector.Language != "go" ||
		rustVector.Language != "rust" ||
		!goVector.FixtureOnly ||
		!rustVector.FixtureOnly ||
		goVector.ExecutesWork ||
		rustVector.ExecutesWork ||
		goVector.ApprovesWork ||
		rustVector.ApprovesWork {
		t.Fatalf("canonical JSON vectors changed safety or identity: go=%+v rust=%+v", goVector, rustVector)
	}
	goCanonical, err := CanonicalJSON(goVector.Contract)
	if err != nil {
		t.Fatal(err)
	}
	goDigest, err := Digest(goVector.Contract)
	if err != nil {
		t.Fatal(err)
	}
	rustCanonical, err := CanonicalJSON(rustVector.Contract)
	if err != nil {
		t.Fatal(err)
	}
	rustDigest, err := Digest(rustVector.Contract)
	if err != nil {
		t.Fatal(err)
	}
	if string(goCanonical) != goVector.CanonicalJSON ||
		goDigest != goVector.SHA256 ||
		string(rustCanonical) != rustVector.CanonicalJSON ||
		rustDigest != rustVector.SHA256 {
		t.Fatalf("canonical vector digest mismatch")
	}
	if goVector.CanonicalJSON != rustVector.CanonicalJSON || goVector.SHA256 != rustVector.SHA256 {
		t.Fatalf("Go and Rust canonical vector examples diverged:\ngo=%s %s\nrust=%s %s", goVector.SHA256, goVector.CanonicalJSON, rustVector.SHA256, rustVector.CanonicalJSON)
	}
}

func readCanonicalJSONVectorFixture(t *testing.T, path string) canonicalJSONVectorFixture {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture canonicalJSONVectorFixture
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestValidateRejectsUnsupportedSchemaVersion(t *testing.T) {
	c := validContract()
	c.SchemaVersion = "covenant.contract.v2"
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema_version") {
		t.Fatalf("Validate error = %v, want unsupported schema_version", err)
	}
}

func TestValidateRejectsMissingDependency(t *testing.T) {
	c := validContract()
	c.Tasks[1].DependsOn = []string{"missing_task"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "depends on unknown task") {
		t.Fatalf("Validate error = %v, want missing dependency", err)
	}
}

func TestValidateRejectsCycle(t *testing.T) {
	c := validContract()
	c.Tasks[0].DependsOn = []string{"verify_change"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("Validate error = %v, want cycle", err)
	}
}

func TestValidateRejectsPathEscape(t *testing.T) {
	c := validContract()
	c.Workspace.Writes = []string{"../outside.txt"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("Validate error = %v, want path escape", err)
	}
}

func TestValidateRejectsWorkspaceRootEscape(t *testing.T) {
	tests := []string{
		"../outside",
		"/tmp/outside",
		`C:\outside`,
		"C:outside.txt",
		`\\server\share`,
	}
	for _, root := range tests {
		t.Run(root, func(t *testing.T) {
			c := validContract()
			c.Workspace.Root = root
			err := Validate(c)
			if err == nil || !strings.Contains(err.Error(), "workspace root") {
				t.Fatalf("Validate error = %v, want workspace root rejection", err)
			}
		})
	}
}

func TestValidateRejectsWindowsDrivePathEscape(t *testing.T) {
	c := validContract()
	c.Workspace.Writes = []string{`C:\outside.txt`}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("Validate error = %v, want Windows drive path escape", err)
	}
}

func TestValidateRejectsWindowsDriveRelativePathEscape(t *testing.T) {
	c := validContract()
	c.Workspace.Writes = []string{"C:outside.txt"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("Validate error = %v, want Windows drive-relative path escape", err)
	}
}

func TestValidateRejectsUnsupportedTaskKind(t *testing.T) {
	c := validContract()
	c.Tasks[0].Kind = "remote"
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "unsupported task kind") {
		t.Fatalf("Validate error = %v, want unsupported task kind", err)
	}
}

func TestValidateRejectsTaskMissingDependsOnWithSchemaContext(t *testing.T) {
	c := validContract()
	c.Tasks[0].DependsOn = nil

	err := Validate(c)
	if err == nil {
		t.Fatalf("Validate returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "task \"scripted_change\" schema invalid") {
		t.Fatalf("Validate error = %v, want task schema context", err)
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.task.v1") {
		t.Fatalf("Validate error = %v, want task schema validation context", err)
	}
}

func TestValidateRejectsTaskMissingObligationsWithSchemaContext(t *testing.T) {
	c := validContract()
	c.Tasks[0].Obligations = nil

	err := Validate(c)
	if err == nil {
		t.Fatalf("Validate returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "task \"scripted_change\" schema invalid") {
		t.Fatalf("Validate error = %v, want task schema context", err)
	}
	if !strings.Contains(err.Error(), "schema validation failed for covenant.task.v1") {
		t.Fatalf("Validate error = %v, want task schema validation context", err)
	}
}

func TestValidateRejectsMixedCaseTaskID(t *testing.T) {
	c := validContract()
	c.Tasks[0].ID = "Scripted_change"
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("Validate error = %v, want lowercase id rejection", err)
	}
}

func TestValidateRejectsReservedWindowsTaskID(t *testing.T) {
	c := validContract()
	c.Tasks[0].ID = "con"
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("Validate error = %v, want reserved id rejection", err)
	}
}

func TestValidateRejectsMissingRequiredObligation(t *testing.T) {
	c := validContract()
	c.Obligations = nil
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "at least one required obligation") {
		t.Fatalf("Validate error = %v, want missing obligation", err)
	}
}

func TestValidateRejectsMixedCaseObligationID(t *testing.T) {
	c := validContract()
	c.Obligations[0].ID = "Obl_requested_file"
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("Validate error = %v, want lowercase obligation id rejection", err)
	}
}

func TestValidateRejectsRequiredObligationMissingFromEvaluator(t *testing.T) {
	c := validContract()
	c.Evaluator.RequiredObligations = []string{"obl_requested_file"}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "required obligation") {
		t.Fatalf("Validate error = %v, want missing evaluator required obligation", err)
	}
}

func TestValidateAcceptsApprovalTicketForKnownTask(t *testing.T) {
	c := validContract()
	c.Tasks[0].DeclaredSideEffects = append(c.Tasks[0].DeclaredSideEffects, ActionRef{
		Type:     "network.request",
		Resource: "api.example.test",
	})
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "scripted_change",
			EffectType:    "network.request",
			Resource:      "api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
	}
	if err := Validate(c); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRejectsApprovalTicketForUnknownTask(t *testing.T) {
	c := validContract()
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "missing_task",
			EffectType:    "network.request",
			Resource:      "api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
	}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "unknown task") {
		t.Fatalf("Validate error = %v, want unknown task", err)
	}
}

func TestValidateRejectsDuplicateApprovalTicketID(t *testing.T) {
	c := validContract()
	c.Tasks[0].DeclaredSideEffects = append(c.Tasks[0].DeclaredSideEffects, ActionRef{
		Type:     "network.request",
		Resource: "api.example.test",
	})
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "scripted_change",
			EffectType:    "network.request",
			Resource:      "api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "scripted_change",
			EffectType:    "network.request",
			Resource:      "api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
	}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "duplicate approval ticket") {
		t.Fatalf("Validate error = %v, want duplicate approval ticket", err)
	}
}

func TestValidateRejectsApprovalTicketPathEscape(t *testing.T) {
	c := validContract()
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "scripted_change",
			EffectType:    "network.request",
			Resource:      "../api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
	}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("Validate error = %v, want approval path escape", err)
	}
}

func TestValidateRejectsApprovalTicketInvalidExpiration(t *testing.T) {
	c := validContract()
	c.Tasks[0].DeclaredSideEffects = append(c.Tasks[0].DeclaredSideEffects, ActionRef{
		Type:     "process.spawn",
		Resource: "make-test",
	})
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_process",
			TaskID:        "scripted_change",
			EffectType:    "process.spawn",
			Resource:      "make-test",
			Approved:      true,
			Reason:        "fixture approval",
			ExpiresAt:     "tomorrow",
		},
	}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "expires_at must be RFC3339") {
		t.Fatalf("Validate error = %v, want invalid expiration", err)
	}
}

func TestValidateRejectsApprovalTicketWithoutMatchingDeclaredSideEffect(t *testing.T) {
	c := validContract()
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "ticket_network",
			TaskID:        "scripted_change",
			EffectType:    "network.request",
			Resource:      "api.example.test",
			Approved:      true,
			Reason:        "fixture approval",
		},
	}
	err := Validate(c)
	if err == nil || !strings.Contains(err.Error(), "declared side effect") {
		t.Fatalf("Validate error = %v, want missing declared side effect", err)
	}
}

func TestCompileBriefWithSourceRecordsBriefPath(t *testing.T) {
	c, err := CompileBriefWithSource("Create a demo report.", "briefs/demo.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	if len(c.Workspace.Reads) != 1 || c.Workspace.Reads[0] != "briefs/demo.md" {
		t.Fatalf("workspace reads = %v, want briefs/demo.md", c.Workspace.Reads)
	}
}

func TestCompileBriefWithOptionsUsesWorkspaceWrites(t *testing.T) {
	c, err := CompileBriefWithOptions("Create authored reports.", CompileOptions{
		SourcePath:      "briefs/demo.md",
		WorkspaceWrites: []string{"reports/summary.txt", "reports/audit.txt"},
	})
	if err != nil {
		t.Fatalf("CompileBriefWithOptions error: %v", err)
	}
	if len(c.Workspace.Writes) != 2 || c.Workspace.Writes[0] != "reports/summary.txt" || c.Workspace.Writes[1] != "reports/audit.txt" {
		t.Fatalf("workspace writes = %v, want reports", c.Workspace.Writes)
	}
	if len(c.Tasks) == 0 {
		t.Fatalf("tasks empty")
	}
	sideEffects := c.Tasks[0].DeclaredSideEffects
	if len(sideEffects) != 2 {
		t.Fatalf("side effects len = %d, want 2", len(sideEffects))
	}
	for i, want := range c.Workspace.Writes {
		if sideEffects[i].Type != "file.write" || sideEffects[i].Resource != want {
			t.Fatalf("side effect %d = %+v, want file.write %s", i, sideEffects[i], want)
		}
	}
}

func TestCompileStructuredBriefBuildsAuthoredTaskDAG(t *testing.T) {
	c, err := CompileBriefWithSource(structuredReleaseBrief(), "briefs/release.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	if c.Objective != "Create a release report." {
		t.Fatalf("objective = %q, want structured objective", c.Objective)
	}
	if len(c.Workspace.Reads) != 2 || c.Workspace.Reads[0] != "briefs/release.md" || c.Workspace.Reads[1] != "docs/source.md" {
		t.Fatalf("workspace reads = %v, want source brief and authored read", c.Workspace.Reads)
	}
	if len(c.Workspace.Writes) != 2 || c.Workspace.Writes[0] != "reports/release.md" || c.Workspace.Writes[1] != "reports/checklist.md" {
		t.Fatalf("workspace writes = %v, want authored writes", c.Workspace.Writes)
	}
	if len(c.Tasks) != 3 {
		t.Fatalf("tasks len = %d, want 3", len(c.Tasks))
	}
	draft := c.Tasks[0]
	if draft.ID != "draft_release_report" || draft.Kind != "scripted" || len(draft.DependsOn) != 0 {
		t.Fatalf("draft task = %+v", draft)
	}
	if draft.TimeoutSecs != 45 {
		t.Fatalf("draft timeout = %d, want 45", draft.TimeoutSecs)
	}
	if len(draft.Obligations) != 1 || draft.Obligations[0] != "obl_release_report" {
		t.Fatalf("draft obligations = %v", draft.Obligations)
	}
	if len(draft.DeclaredSideEffects) != 2 {
		t.Fatalf("draft side effects len = %d, want write and read", len(draft.DeclaredSideEffects))
	}
	if draft.DeclaredSideEffects[0] != (ActionRef{Type: "file.write", Resource: "reports/release.md"}) {
		t.Fatalf("draft side effect 0 = %+v", draft.DeclaredSideEffects[0])
	}
	if draft.DeclaredSideEffects[1] != (ActionRef{Type: "file.read", Resource: "docs/source.md"}) {
		t.Fatalf("draft side effect 1 = %+v", draft.DeclaredSideEffects[1])
	}
	verify := c.Tasks[1]
	if verify.ID != "verify_release_report" || verify.Kind != "verify" {
		t.Fatalf("verify task = %+v", verify)
	}
	if len(verify.DependsOn) != 1 || verify.DependsOn[0] != "draft_release_report" {
		t.Fatalf("verify depends_on = %v", verify.DependsOn)
	}
	review := c.Tasks[2]
	if review.ID != "review_release_report" || review.Kind != "review" {
		t.Fatalf("review task = %+v", review)
	}
	if len(review.DependsOn) != 1 || review.DependsOn[0] != "verify_release_report" {
		t.Fatalf("review depends_on = %v", review.DependsOn)
	}
	if len(c.Obligations) != 3 {
		t.Fatalf("obligations len = %d, want 3", len(c.Obligations))
	}
	if c.Obligations[0].ID != "obl_release_report" || !c.Obligations[0].Required || c.Obligations[0].Text != "Release report exists." {
		t.Fatalf("obligation 0 = %+v", c.Obligations[0])
	}
	if len(c.Evaluator.RequiredObligations) != 3 || c.Evaluator.RequiredObligations[0] != "obl_release_report" || c.Evaluator.RequiredObligations[2] != "obl_review_clear" {
		t.Fatalf("required obligations = %v", c.Evaluator.RequiredObligations)
	}
	if err := Validate(c); err != nil {
		t.Fatalf("compiled contract did not validate: %v", err)
	}
}

func TestCompileStructuredBriefAllowsCLIWriteOverrideWhenItCoversTaskWrites(t *testing.T) {
	c, err := CompileBriefWithOptions(structuredReleaseBrief(), CompileOptions{
		SourcePath:      "briefs/release.md",
		WorkspaceWrites: []string{"reports/release.md", "reports/extra.md"},
	})
	if err != nil {
		t.Fatalf("CompileBriefWithOptions error: %v", err)
	}
	if len(c.Workspace.Writes) != 2 || c.Workspace.Writes[0] != "reports/release.md" || c.Workspace.Writes[1] != "reports/extra.md" {
		t.Fatalf("workspace writes = %v, want override", c.Workspace.Writes)
	}
}

func TestCompileStructuredBriefDiagnosesUnknownTaskField(t *testing.T) {
	_, err := CompileBriefWithSource(`# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`, "briefs/release.md")

	requireAuthoringDiagnostic(t, err, "STRUCTURED_TASK_FIELD_UNKNOWN", 8, `unsupported task field "writess"`)
}

func TestCompileStructuredBriefDiagnosesUnknownDependency(t *testing.T) {
	_, err := CompileBriefWithSource(`# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
obligations:
- obl_release_report

## Task: verify_release_report
depends_on:
- missing_task
obligations:
- obl_release_report
`, "briefs/release.md")

	requireAuthoringDiagnostic(t, err, "STRUCTURED_TASK_DEP_UNKNOWN", 13, `task "verify_release_report" depends on unknown task "missing_task"`)
}

func TestCompileStructuredBriefDiagnosesUnknownObligation(t *testing.T) {
	_, err := CompileBriefWithSource(`# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
obligations:
- obl_missing
`, "briefs/release.md")

	requireAuthoringDiagnostic(t, err, "STRUCTURED_TASK_OBLIGATION_UNKNOWN", 9, `task "draft_release_report" references unknown obligation "obl_missing"`)
}

func TestCompileStructuredBriefDiagnosesDuplicateTaskID(t *testing.T) {
	_, err := CompileBriefWithSource(`# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
obligations:
- obl_release_report

## Task: draft_release_report
obligations:
- obl_release_report
`, "briefs/release.md")

	requireAuthoringDiagnostic(t, err, "STRUCTURED_TASK_ID_DUPLICATE", 11, `duplicate task id "draft_release_report"`)
}

func TestCompileStructuredBriefDiagnosesUndeclaredTaskWrite(t *testing.T) {
	_, err := CompileBriefWithSource(`# Writes
- reports/allowed.md

# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writes:
- reports/not-declared.md
obligations:
- obl_release_report
`, "briefs/release.md")

	requireAuthoringDiagnostic(t, err, "STRUCTURED_TASK_WRITE_UNDECLARED", 12, `task "draft_release_report" writes "reports/not-declared.md" outside workspace writes`)
}

func TestCompileBriefWithOptionsRejectsEscapingWrite(t *testing.T) {
	_, err := CompileBriefWithOptions("Create authored reports.", CompileOptions{
		SourcePath:      "briefs/demo.md",
		WorkspaceWrites: []string{"../outside.txt"},
	})
	if err == nil || !strings.Contains(err.Error(), `workspace write "../outside.txt" escapes workspace`) {
		t.Fatalf("CompileBriefWithOptions error = %v, want escaping write rejection", err)
	}
}

func TestCompileBriefWithSourceRejectsEscapingBriefPath(t *testing.T) {
	_, err := CompileBriefWithSource("Create a demo report.", "../brief.md")
	if err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("CompileBriefWithSource error = %v, want path escape", err)
	}
}

func TestDigestIsStableForCanonicalContract(t *testing.T) {
	c := validContract()
	first, err := Digest(c)
	if err != nil {
		t.Fatalf("Digest first error: %v", err)
	}
	second, err := Digest(c)
	if err != nil {
		t.Fatalf("Digest second error: %v", err)
	}
	if first != second {
		t.Fatalf("digests differ: %s != %s", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("digest length = %d, want 64", len(first))
	}
}

func TestCompileRiskyChangeBrief(t *testing.T) {
	brief := "Create a demo report at demo-output/report.txt and verify it."
	c, err := CompileBrief(brief)
	if err != nil {
		t.Fatalf("CompileBrief error: %v", err)
	}
	if c.SchemaVersion != ContractSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", c.SchemaVersion, ContractSchemaVersion)
	}
	if len(c.Tasks) != 3 {
		t.Fatalf("tasks len = %d, want 3", len(c.Tasks))
	}
	if err := Validate(c); err != nil {
		t.Fatalf("compiled contract did not validate: %v", err)
	}
	digest, err := Digest(c)
	if err != nil {
		t.Fatalf("Digest error: %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("digest length = %d, want 64", len(digest))
	}
}

func TestCompileBriefRejectsEmptyBrief(t *testing.T) {
	_, err := CompileBrief("  \n")
	if err == nil || !strings.Contains(err.Error(), "brief is required") {
		t.Fatalf("CompileBrief error = %v, want brief is required", err)
	}
}

func TestLintBriefReportsStructuredAuthoringDiagnostic(t *testing.T) {
	result := LintBrief(`# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`, CompileOptions{SourcePath: "briefs/release.md"})

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics len = %d, want 1", len(result.Diagnostics))
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != "STRUCTURED_TASK_FIELD_UNKNOWN" || diagnostic.Line != 8 || diagnostic.Severity != "error" {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
	if !strings.Contains(diagnostic.Message, `unsupported task field "writess"`) {
		t.Fatalf("message = %q", diagnostic.Message)
	}
}

func TestLintBriefReportsMultipleStructuredSemanticDiagnostics(t *testing.T) {
	result := LintBrief(`# Writes
- reports/declared.md

# Obligations
## Obligation: obl_release_report
required: true

# Tasks
## Task: draft_release_report
depends_on:
- missing_task
obligations:
- obl_missing
writes:
- reports/not-declared.md
`, CompileOptions{SourcePath: "briefs/release.md"})

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	wantCodes := []string{
		"STRUCTURED_TASK_DEP_UNKNOWN",
		"STRUCTURED_TASK_OBLIGATION_UNKNOWN",
		"STRUCTURED_TASK_WRITE_UNDECLARED",
	}
	if got := lintDiagnosticCodes(result.Diagnostics); strings.Join(got, ",") != strings.Join(wantCodes, ",") {
		t.Fatalf("diagnostic codes = %v, want %v; diagnostics = %+v", got, wantCodes, result.Diagnostics)
	}
	if result.Diagnostics[0].Line != 11 || result.Diagnostics[1].Line != 13 || result.Diagnostics[2].Line != 15 {
		t.Fatalf("diagnostic lines = %+v, want 11, 13, 15", result.Diagnostics)
	}
}

func TestLintContractReportsStableValidationDiagnostic(t *testing.T) {
	c := validContract()
	c.Objective = ""

	result := LintContract(c)

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics len = %d, want 1", len(result.Diagnostics))
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != "CONTRACT_OBJECTIVE_REQUIRED" || diagnostic.Severity != "error" || diagnostic.Message != "objective is required" {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
}

func TestLintContractDiagnosticsIncludeRemediationHints(t *testing.T) {
	c := validContract()
	c.Tasks[0].DependsOn = []string{"missing_task"}

	result := LintContract(c)

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics len = %d, want 1", len(result.Diagnostics))
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != "CONTRACT_TASK_DEPENDENCY_UNKNOWN" {
		t.Fatalf("diagnostic code = %s, want CONTRACT_TASK_DEPENDENCY_UNKNOWN", diagnostic.Code)
	}
	if diagnostic.Hint != `Define task "missing_task" or remove it from depends_on.` {
		t.Fatalf("diagnostic hint = %q", diagnostic.Hint)
	}
}

func TestLintBriefDiagnosticsIncludeRemediationHints(t *testing.T) {
	brief := `# Writes
- reports/declared.md

# Obligations
## Obligation: obl_release_report
required: true

# Tasks
## Task: draft_release_report
writes:
- reports/not-declared.md
`

	result := LintBrief(brief, CompileOptions{SourcePath: "brief.md"})

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics len = %d, want 1", len(result.Diagnostics))
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Code != "STRUCTURED_TASK_WRITE_UNDECLARED" {
		t.Fatalf("diagnostic code = %s, want STRUCTURED_TASK_WRITE_UNDECLARED", diagnostic.Code)
	}
	if diagnostic.Hint != `Add "reports/not-declared.md" under # Writes or pass --write reports/not-declared.md.` {
		t.Fatalf("diagnostic hint = %q", diagnostic.Hint)
	}
}

func TestLintSARIFRendersDiagnosticsWithLocationsAndRules(t *testing.T) {
	result := LintResult{
		Valid: false,
		Diagnostics: []LintDiagnostic{
			{
				Code:     "STRUCTURED_TASK_WRITE_UNDECLARED",
				Severity: "error",
				Line:     12,
				Field:    "tasks.writes",
				Message:  `task "draft_release_report" writes "reports/not-declared.md" outside workspace writes`,
				Hint:     `Add "reports/not-declared.md" under # Writes or pass --write reports/not-declared.md.`,
			},
		},
	}

	sarif := LintSARIF(result, LintSARIFOptions{SourceURI: "brief.md"})

	if sarif.Version != "2.1.0" || sarif.Schema == "" {
		t.Fatalf("sarif header = %+v", sarif)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "AO Covenant" || run.Tool.Driver.InformationURI == "" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "STRUCTURED_TASK_WRITE_UNDECLARED" {
		t.Fatalf("rules = %+v", run.Tool.Driver.Rules)
	}
	if run.Tool.Driver.Rules[0].Help.Text != `Add "reports/not-declared.md" under # Writes or pass --write reports/not-declared.md.` {
		t.Fatalf("rule help = %+v", run.Tool.Driver.Rules[0].Help)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(run.Results))
	}
	sarifResult := run.Results[0]
	if sarifResult.RuleID != "STRUCTURED_TASK_WRITE_UNDECLARED" || sarifResult.Level != "error" {
		t.Fatalf("result = %+v", sarifResult)
	}
	if sarifResult.Message.Text != result.Diagnostics[0].Message {
		t.Fatalf("message = %q", sarifResult.Message.Text)
	}
	if len(sarifResult.Locations) != 1 {
		t.Fatalf("locations = %+v, want one", sarifResult.Locations)
	}
	location := sarifResult.Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "brief.md" || location.Region.StartLine != 12 {
		t.Fatalf("location = %+v", location)
	}
	if sarifResult.Properties["field"] != "tasks.writes" || sarifResult.Properties["hint"] == "" {
		t.Fatalf("properties = %+v", sarifResult.Properties)
	}
}

func TestLintSARIFDeduplicatesRules(t *testing.T) {
	result := LintResult{
		Valid: false,
		Diagnostics: []LintDiagnostic{
			{Code: "CONTRACT_OBJECTIVE_REQUIRED", Severity: "error", Message: "objective is required"},
			{Code: "CONTRACT_OBJECTIVE_REQUIRED", Severity: "error", Message: "objective is required again"},
		},
	}

	sarif := LintSARIF(result, LintSARIFOptions{SourceURI: "contract.json"})

	if len(sarif.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("rules = %+v, want one deduplicated rule", sarif.Runs[0].Tool.Driver.Rules)
	}
	if len(sarif.Runs[0].Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(sarif.Runs[0].Results))
	}
}

func TestLintSARIFAppliesBaselineSuppressions(t *testing.T) {
	result := LintResult{
		Valid: false,
		Diagnostics: []LintDiagnostic{
			{
				Code:     "STRUCTURED_TASK_WRITE_UNDECLARED",
				Severity: "error",
				Line:     12,
				Field:    "tasks.writes",
				Message:  "task writes outside workspace writes",
			},
		},
	}
	baseline := LintSARIFBaseline{
		SchemaVersion: LintSARIFBaselineSchemaVersion,
		Accepted: []LintSARIFBaselineEntry{
			{
				RuleID:        "STRUCTURED_TASK_WRITE_UNDECLARED",
				SourceURI:     "brief.md",
				Line:          12,
				Field:         "tasks.writes",
				Justification: "accepted for generated fixture",
			},
		},
	}

	sarif := LintSARIF(result, LintSARIFOptions{SourceURI: "brief.md", Baseline: baseline})

	suppression := sarif.Runs[0].Results[0].Suppressions[0]
	if suppression.Kind != "external" || suppression.Justification != "accepted for generated fixture" {
		t.Fatalf("suppression = %+v, want external justification", suppression)
	}
	if !LintDiagnosticsAllSuppressed(result, LintSARIFOptions{SourceURI: "brief.md", Baseline: baseline}) {
		t.Fatalf("all suppressed = false, want true")
	}
}

func TestLintSARIFBaselineDoesNotSuppressDifferentLine(t *testing.T) {
	result := LintResult{
		Valid: false,
		Diagnostics: []LintDiagnostic{
			{
				Code:     "STRUCTURED_TASK_WRITE_UNDECLARED",
				Severity: "error",
				Line:     13,
				Field:    "tasks.writes",
				Message:  "task writes outside workspace writes",
			},
		},
	}
	baseline := LintSARIFBaseline{
		SchemaVersion: LintSARIFBaselineSchemaVersion,
		Accepted: []LintSARIFBaselineEntry{
			{
				RuleID:        "STRUCTURED_TASK_WRITE_UNDECLARED",
				SourceURI:     "brief.md",
				Line:          12,
				Field:         "tasks.writes",
				Justification: "accepted for generated fixture",
			},
		},
	}

	sarif := LintSARIF(result, LintSARIFOptions{SourceURI: "brief.md", Baseline: baseline})

	if len(sarif.Runs[0].Results[0].Suppressions) != 0 {
		t.Fatalf("suppressions = %+v, want none", sarif.Runs[0].Results[0].Suppressions)
	}
	if LintDiagnosticsAllSuppressed(result, LintSARIFOptions{SourceURI: "brief.md", Baseline: baseline}) {
		t.Fatalf("all suppressed = true, want false")
	}
}

func TestLintContractReportsMultipleValidationDiagnostics(t *testing.T) {
	c := validContract()
	c.Objective = ""
	c.Workspace.Writes = []string{"../outside.txt"}

	result := LintContract(c)

	if result.Valid {
		t.Fatalf("valid = true, want false")
	}
	wantCodes := []string{
		"CONTRACT_OBJECTIVE_REQUIRED",
		"CONTRACT_WORKSPACE_WRITE_INVALID",
	}
	if got := lintDiagnosticCodes(result.Diagnostics); strings.Join(got, ",") != strings.Join(wantCodes, ",") {
		t.Fatalf("diagnostic codes = %v, want %v; diagnostics = %+v", got, wantCodes, result.Diagnostics)
	}
}

func structuredReleaseBrief() string {
	return `# Objective
Create a release report.

# Reads
- docs/source.md

# Writes
- reports/release.md
- reports/checklist.md

# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

## Obligation: obl_verify_passes
required: true
text: Verification passes.

## Obligation: obl_review_clear
required: true
text: Review is clear.

# Tasks
## Task: draft_release_report
kind: scripted
writes:
- reports/release.md
reads:
- docs/source.md
obligations:
- obl_release_report
timeout_seconds: 45

## Task: verify_release_report
kind: verify
depends_on:
- draft_release_report
obligations:
- obl_verify_passes

## Task: review_release_report
kind: review
depends_on:
- verify_release_report
obligations:
- obl_review_clear
`
}

func requireAuthoringDiagnostic(t *testing.T, err error, code string, line int, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("CompileBriefWithSource error is nil, want %s", code)
	}
	var diag *AuthoringDiagnosticError
	if !errors.As(err, &diag) {
		t.Fatalf("error = %T %[1]v, want AuthoringDiagnosticError", err)
	}
	if diag.Diagnostic.Code != code || diag.Diagnostic.Line != line {
		t.Fatalf("diagnostic = %+v, want code=%s line=%d", diag.Diagnostic, code, line)
	}
	if !strings.Contains(diag.Error(), contains) {
		t.Fatalf("diagnostic error = %q, want %q", diag.Error(), contains)
	}
}

func lintDiagnosticCodes(diagnostics []LintDiagnostic) []string {
	codes := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		codes = append(codes, diagnostic.Code)
	}
	return codes
}
