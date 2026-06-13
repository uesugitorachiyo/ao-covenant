package schema

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	embedded "github.com/uesugitorachiyo/ao-covenant/schemas"
)

const (
	publicSchemaDraft                        = "https://json-schema.org/draft/2020-12/schema"
	ContractSchemaID                         = "covenant.contract.v1"
	TaskSchemaID                             = "covenant.task.v1"
	EventSchemaID                            = "covenant.event.v1"
	ArtifactRefSchemaID                      = "covenant.artifact-ref.v1"
	InputSnapshotSchemaID                    = "covenant.input-snapshot.v1"
	PolicyDecisionSchemaID                   = "covenant.policy-decision.v1"
	ApprovalTicketSchemaID                   = "covenant.approval-ticket.v1"
	ApprovalRevocationsSchemaID              = "covenant.approval-revocations.v1"
	ApprovalCreateResultSchemaID             = "covenant.approval-create-result.v1"
	ApprovalValidateResultSchemaID           = "covenant.approval-validate-result.v1"
	ApprovalAttachResultSchemaID             = "covenant.approval-attach-result.v1"
	ApprovalRevokeResultSchemaID             = "covenant.approval-revoke-result.v1"
	ApprovalRevocationsInspectResultSchemaID = "covenant.approval-revocations-inspect-result.v1"
	ReportRedactionPolicySchemaID            = "covenant.report-redaction-policy.v1"
	LintSARIFBaselineSchemaID                = "covenant.lint-sarif-baseline.v1"
	LintResultSchemaID                       = "covenant.lint-result.v1"
	SchemaValidationReportSchemaID           = "covenant.schema-validation-report.v1"
	RunResultSchemaID                        = "covenant.run-result.v1"
	SelfRunResultSchemaID                    = "covenant.self-run-result.v1"
	CompileResultSchemaID                    = "covenant.compile-result.v1"
	CompileSummarySchemaID                   = "covenant.compile-summary.v1"
	VerifyResultSchemaID                     = "covenant.verify-result.v1"
	VersionResultSchemaID                    = "covenant.version-result.v1"
	ReleaseManifestSchemaID                  = "covenant.release-manifest.v1"
	ReleasePackageResultSchemaID             = "covenant.release-package-result.v1"
	ReleaseVerifyResultSchemaID              = "covenant.release-verify-result.v1"
	ReleaseDiffResultSchemaID                = "covenant.release-diff-result.v1"
	ReleaseSignatureSchemaID                 = "covenant.release-signature.v1"
	ReleaseInspectResultSchemaID             = "covenant.release-inspect-result.v1"
	ReleaseReportResultSchemaID              = "covenant.release-report-result.v1"
	ReleaseFixtureIndexSchemaID              = "covenant.release-fixture-index.v1"
	PolicyExplainResultSchemaID              = "covenant.policy-explain-result.v1"
	PolicyIndexResultSchemaID                = "covenant.policy-index-result.v1"
	SchemaCatalogResultSchemaID              = "covenant.schema-catalog-result.v1"
	SchemaExportResultSchemaID               = "covenant.schema-export-result.v1"
	BundleInspectResultSchemaID              = "covenant.bundle-inspect-result.v1"
	BundleReportResultSchemaID               = "covenant.bundle-report-result.v1"
	BundleExportResultSchemaID               = "covenant.bundle-export-result.v1"
	BundleKeygenResultSchemaID               = "covenant.bundle-keygen-result.v1"
	BundlePrivateKeySchemaID                 = "covenant.bundle-private-key.v1"
	BundlePublicKeySchemaID                  = "covenant.bundle-public-key.v1"
	BundleSignatureSchemaID                  = "covenant.bundle-signature.v1"
	ClosureMatrixSchemaID                    = "covenant.closure-matrix.v1"
	FailureSchemaID                          = "covenant.failure.v1"
	EvidenceBundleSchemaID                   = "covenant.evidence-bundle.v1"
	EvidencePackSchemaID                     = "covenant.evidence-pack.v1"
)

type RequiredSchema struct {
	FileName   string
	ID         string
	SchemaPath string
}

func requiredSchema(fileName string, id string) RequiredSchema {
	return RequiredSchema{
		FileName:   fileName,
		ID:         id,
		SchemaPath: "schemas/" + fileName,
	}
}

var requiredSchemas = []RequiredSchema{
	requiredSchema("covenant.contract.v1.schema.json", ContractSchemaID),
	requiredSchema("covenant.task.v1.schema.json", TaskSchemaID),
	requiredSchema("covenant.event.v1.schema.json", EventSchemaID),
	requiredSchema("covenant.artifact-ref.v1.schema.json", ArtifactRefSchemaID),
	requiredSchema("covenant.input-snapshot.v1.schema.json", InputSnapshotSchemaID),
	requiredSchema("covenant.policy-decision.v1.schema.json", PolicyDecisionSchemaID),
	requiredSchema("covenant.approval-ticket.v1.schema.json", ApprovalTicketSchemaID),
	requiredSchema("covenant.approval-revocations.v1.schema.json", ApprovalRevocationsSchemaID),
	requiredSchema("covenant.approval-create-result.v1.schema.json", ApprovalCreateResultSchemaID),
	requiredSchema("covenant.approval-validate-result.v1.schema.json", ApprovalValidateResultSchemaID),
	requiredSchema("covenant.approval-attach-result.v1.schema.json", ApprovalAttachResultSchemaID),
	requiredSchema("covenant.approval-revoke-result.v1.schema.json", ApprovalRevokeResultSchemaID),
	requiredSchema("covenant.approval-revocations-inspect-result.v1.schema.json", ApprovalRevocationsInspectResultSchemaID),
	requiredSchema("covenant.report-redaction-policy.v1.schema.json", ReportRedactionPolicySchemaID),
	requiredSchema("covenant.lint-sarif-baseline.v1.schema.json", LintSARIFBaselineSchemaID),
	requiredSchema("covenant.lint-result.v1.schema.json", LintResultSchemaID),
	requiredSchema("covenant.schema-validation-report.v1.schema.json", SchemaValidationReportSchemaID),
	requiredSchema("covenant.run-result.v1.schema.json", RunResultSchemaID),
	requiredSchema("covenant.self-run-result.v1.schema.json", SelfRunResultSchemaID),
	requiredSchema("covenant.compile-result.v1.schema.json", CompileResultSchemaID),
	requiredSchema("covenant.compile-summary.v1.schema.json", CompileSummarySchemaID),
	requiredSchema("covenant.verify-result.v1.schema.json", VerifyResultSchemaID),
	requiredSchema("covenant.version-result.v1.schema.json", VersionResultSchemaID),
	requiredSchema("covenant.release-manifest.v1.schema.json", ReleaseManifestSchemaID),
	requiredSchema("covenant.release-package-result.v1.schema.json", ReleasePackageResultSchemaID),
	requiredSchema("covenant.release-verify-result.v1.schema.json", ReleaseVerifyResultSchemaID),
	requiredSchema("covenant.release-diff-result.v1.schema.json", ReleaseDiffResultSchemaID),
	requiredSchema("covenant.release-signature.v1.schema.json", ReleaseSignatureSchemaID),
	requiredSchema("covenant.release-inspect-result.v1.schema.json", ReleaseInspectResultSchemaID),
	requiredSchema("covenant.release-report-result.v1.schema.json", ReleaseReportResultSchemaID),
	requiredSchema("covenant.release-fixture-index.v1.schema.json", ReleaseFixtureIndexSchemaID),
	requiredSchema("covenant.policy-explain-result.v1.schema.json", PolicyExplainResultSchemaID),
	requiredSchema("covenant.policy-index-result.v1.schema.json", PolicyIndexResultSchemaID),
	requiredSchema("covenant.schema-catalog-result.v1.schema.json", SchemaCatalogResultSchemaID),
	requiredSchema("covenant.schema-export-result.v1.schema.json", SchemaExportResultSchemaID),
	requiredSchema("covenant.bundle-inspect-result.v1.schema.json", BundleInspectResultSchemaID),
	requiredSchema("covenant.bundle-report-result.v1.schema.json", BundleReportResultSchemaID),
	requiredSchema("covenant.bundle-export-result.v1.schema.json", BundleExportResultSchemaID),
	requiredSchema("covenant.bundle-keygen-result.v1.schema.json", BundleKeygenResultSchemaID),
	requiredSchema("covenant.bundle-private-key.v1.schema.json", BundlePrivateKeySchemaID),
	requiredSchema("covenant.bundle-public-key.v1.schema.json", BundlePublicKeySchemaID),
	requiredSchema("covenant.bundle-signature.v1.schema.json", BundleSignatureSchemaID),
	requiredSchema("covenant.closure-matrix.v1.schema.json", ClosureMatrixSchemaID),
	requiredSchema("covenant.failure.v1.schema.json", FailureSchemaID),
	requiredSchema("covenant.evidence-bundle.v1.schema.json", EvidenceBundleSchemaID),
	requiredSchema("covenant.evidence-pack.v1.schema.json", EvidencePackSchemaID),
}

var requiredSchemasByID = func() map[string]RequiredSchema {
	byID := make(map[string]RequiredSchema, len(requiredSchemas))
	for _, entry := range requiredSchemas {
		byID[entry.ID] = entry
	}
	return byID
}()

var schemaIDPattern = regexp.MustCompile(`^covenant\.[a-z0-9][a-z0-9.-]*\.v[0-9]+$`)

type CatalogEntry struct {
	ID         string `json:"id"`
	FileName   string `json:"file_name"`
	SchemaPath string `json:"schema_path"`
}

type ExportedSchema struct {
	ID          string `json:"id"`
	FileName    string `json:"file_name"`
	SchemaPath  string `json:"schema_path"`
	WrittenPath string `json:"written_path"`
}

type ValidationReport struct {
	SchemaID string `json:"schema_id"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
	Location string `json:"location,omitempty"`
}

type ValidationSARIFReport struct {
	SchemaID string
	File     string
	Valid    bool
	Error    string
	Location string
}

type ValidationSARIFOptions struct {
	Baseline SARIFBaseline
}

type SARIFBaseline struct {
	Accepted []SARIFBaselineEntry
}

type SARIFBaselineEntry struct {
	RuleID        string
	SourceURI     string
	Field         string
	Justification string
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
	ShortDescription SARIFMessage `json:"shortDescription,omitempty"`
	Help             SARIFMessage `json:"help,omitempty"`
}

type SARIFResult struct {
	RuleID       string                `json:"ruleId"`
	Level        string                `json:"level"`
	Message      SARIFMessage          `json:"message"`
	Locations    []SARIFLocation       `json:"locations,omitempty"`
	Suppressions []SARIFSuppression    `json:"suppressions,omitempty"`
	Properties   SARIFResultProperties `json:"properties,omitempty"`
}

type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type SARIFResultProperties struct {
	SchemaID     string `json:"schema_id,omitempty"`
	Location     string `json:"location,omitempty"`
	Component    string `json:"component,omitempty"`
	Kind         string `json:"kind,omitempty"`
	Name         string `json:"name,omitempty"`
	ReleaseDir   string `json:"release_dir,omitempty"`
	ArtifactName string `json:"artifact_name,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type ValidationJUnitReport struct {
	SchemaID string
	File     string
	Valid    bool
	Error    string
	Location string
}

type JUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func ValidationSARIF(reports []ValidationSARIFReport) SARIFLog {
	return ValidationSARIFWithOptions(reports, ValidationSARIFOptions{})
}

func ValidationSARIFWithOptions(reports []ValidationSARIFReport, opts ValidationSARIFOptions) SARIFLog {
	results := make([]SARIFResult, 0)
	for _, report := range reports {
		if report.Valid {
			continue
		}
		result := SARIFResult{
			RuleID:       "SCHEMA_VALIDATION_FAILED",
			Level:        "error",
			Message:      SARIFMessage{Text: report.Error},
			Suppressions: validationSARIFSuppressionsForReport(report, opts),
			Properties: SARIFResultProperties{
				SchemaID: report.SchemaID,
				Location: report.Location,
			},
		}
		if strings.TrimSpace(report.File) != "" {
			result.Locations = []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: report.File},
				},
			}}
		}
		results = append(results, result)
	}

	rules := []SARIFRule{}
	if len(results) > 0 {
		rules = []SARIFRule{{
			ID:               "SCHEMA_VALIDATION_FAILED",
			ShortDescription: SARIFMessage{Text: "Schema validation failed"},
			Help:             SARIFMessage{Text: "Validate the JSON document against its AO Covenant public schema."},
		}}
	}
	return SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "AO Covenant Schema Validator",
					InformationURI: "https://github.com/uesugitorachiyo/ao-covenant",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func ValidationSARIFReportsAllSuppressed(reports []ValidationSARIFReport, opts ValidationSARIFOptions) bool {
	hasInvalid := false
	for _, report := range reports {
		if report.Valid {
			continue
		}
		hasInvalid = true
		if len(validationSARIFSuppressionsForReport(report, opts)) == 0 {
			return false
		}
	}
	return hasInvalid
}

func validationSARIFSuppressionsForReport(report ValidationSARIFReport, opts ValidationSARIFOptions) []SARIFSuppression {
	entry, ok := matchingValidationSARIFBaselineEntry(report, opts)
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

func matchingValidationSARIFBaselineEntry(report ValidationSARIFReport, opts ValidationSARIFOptions) (SARIFBaselineEntry, bool) {
	for _, entry := range opts.Baseline.Accepted {
		if entry.RuleID != "SCHEMA_VALIDATION_FAILED" {
			continue
		}
		if entry.SourceURI != "" && entry.SourceURI != report.File {
			continue
		}
		if entry.Field != "" && entry.Field != report.Location {
			continue
		}
		return entry, true
	}
	return SARIFBaselineEntry{}, false
}

func ValidationJUnit(reports []ValidationJUnitReport, suiteName string) JUnitTestSuites {
	suiteName = strings.TrimSpace(suiteName)
	if suiteName == "" {
		suiteName = "AO Covenant schema validation"
	}
	testCases := make([]JUnitTestCase, 0, len(reports))
	failures := 0
	for _, report := range reports {
		name := strings.TrimSpace(report.File)
		if name == "" {
			name = report.SchemaID
		}
		testCase := JUnitTestCase{
			ClassName: report.SchemaID,
			Name:      name,
		}
		if !report.Valid {
			failures++
			failureText := report.Error
			if report.Location != "" {
				failureText = "location=" + report.Location + " " + failureText
			}
			testCase.Failure = &JUnitFailure{
				Message: "schema validation failed",
				Text:    failureText,
			}
		}
		testCases = append(testCases, testCase)
	}
	suite := JUnitTestSuite{
		Name:      suiteName,
		Tests:     len(testCases),
		Failures:  failures,
		TestCases: testCases,
	}
	return JUnitTestSuites{
		Tests:      len(testCases),
		Failures:   failures,
		TestSuites: []JUnitTestSuite{suite},
	}
}

func RequiredSchemas() []RequiredSchema {
	required := make([]RequiredSchema, len(requiredSchemas))
	copy(required, requiredSchemas)
	return required
}

func RequiredFiles() []RequiredSchema {
	return RequiredSchemas()
}

func RequiredSchemaByID(schemaID string) (RequiredSchema, bool) {
	required, ok := requiredSchemasByID[schemaID]
	return required, ok
}

func ValidateRegistry() error {
	files, err := embeddedSchemaFileNames(embedded.Files)
	if err != nil {
		return err
	}
	return validateRequiredSchemas(RequiredSchemas(), files)
}

func embeddedSchemaFileNames(files fs.ReadDirFS) ([]string, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded schemas: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

func validateRequiredSchemas(required []RequiredSchema, schemaFiles []string) error {
	return validateRequiredSchemasWithFS(required, schemaFiles, embedded.Files)
}

func validateRequiredSchemasWithFS(required []RequiredSchema, schemaFiles []string, files fs.ReadFileFS) error {
	var problems []string
	seenIDs := map[string]struct{}{}
	seenFiles := map[string]struct{}{}
	seenPaths := map[string]struct{}{}
	registeredIDs := map[string]struct{}{}
	registeredFiles := map[string]RequiredSchema{}

	for _, entry := range required {
		if _, exists := seenIDs[entry.ID]; exists {
			problems = append(problems, fmt.Sprintf("duplicate schema id %q", entry.ID))
		}
		seenIDs[entry.ID] = struct{}{}

		if _, exists := seenFiles[entry.FileName]; exists {
			problems = append(problems, fmt.Sprintf("duplicate schema file %q", entry.FileName))
		}
		seenFiles[entry.FileName] = struct{}{}

		if _, exists := seenPaths[entry.SchemaPath]; exists {
			problems = append(problems, fmt.Sprintf("duplicate schema path %q", entry.SchemaPath))
		}
		seenPaths[entry.SchemaPath] = struct{}{}

		problems = append(problems, validateSchemaNaming(entry)...)

		registeredIDs[entry.ID] = struct{}{}
		registeredFiles[entry.FileName] = entry
	}

	embeddedFileSet := map[string]struct{}{}
	for _, fileName := range schemaFiles {
		embeddedFileSet[fileName] = struct{}{}
		entry, ok := registeredFiles[fileName]
		if !ok {
			problems = append(problems, fmt.Sprintf("unregistered embedded schema %q", fileName))
			continue
		}

		bytes, err := files.ReadFile(fileName)
		if err != nil {
			problems = append(problems, fmt.Sprintf("read embedded schema %q: %v", fileName, err))
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal(bytes, &parsed); err != nil {
			problems = append(problems, fmt.Sprintf("parse embedded schema %q: %v", fileName, err))
			continue
		}
		if got := parsed["$id"]; got != entry.ID {
			problems = append(problems, fmt.Sprintf("%s $id = %v, want %s", fileName, got, entry.ID))
		}
		if got := parsed["$schema"]; got != publicSchemaDraft {
			problems = append(problems, fmt.Sprintf("%s $schema = %v, want %s", fileName, got, publicSchemaDraft))
		}
		if got := parsed["type"]; got != "object" {
			problems = append(problems, fmt.Sprintf("%s type = %v, want object", fileName, got))
		}
		if got, ok := parsed["additionalProperties"]; ok {
			if got != false {
				problems = append(problems, fmt.Sprintf("%s additionalProperties = %v, want false", fileName, got))
			}
		} else if got := parsed["unevaluatedProperties"]; got != false {
			problems = append(problems, fmt.Sprintf("%s additionalProperties or unevaluatedProperties = %v, want false", fileName, got))
		}
		problems = append(problems, validateSchemaVersionDeclaration(fileName, entry.ID, parsed)...)
		problems = append(problems, validateSchemaRequiredProperties(fileName, parsed)...)
		problems = append(problems, validateSchemaRefs(fileName, parsed, registeredIDs)...)
	}

	for _, entry := range required {
		if _, ok := embeddedFileSet[entry.FileName]; !ok {
			problems = append(problems, fmt.Sprintf("registered schema %q missing embedded file %q", entry.ID, entry.FileName))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("schema registry invariant violations: %s", strings.Join(problems, "; "))
	}
	return nil
}

func validateSchemaNaming(entry RequiredSchema) []string {
	var problems []string
	if !schemaIDPattern.MatchString(entry.ID) {
		problems = append(problems, fmt.Sprintf("schema id %q must be lowercase covenant.<name>.vN", entry.ID))
	}
	wantFileName := entry.ID + ".schema.json"
	if entry.FileName != wantFileName {
		problems = append(problems, fmt.Sprintf("schema file for %q = %q, want %q", entry.ID, entry.FileName, wantFileName))
	}
	wantPath := "schemas/" + wantFileName
	if entry.SchemaPath != wantPath {
		problems = append(problems, fmt.Sprintf("schema path for %q = %q, want %q", entry.ID, entry.SchemaPath, wantPath))
	}
	return problems
}

func validateSchemaVersionDeclaration(fileName string, schemaID string, schema map[string]any) []string {
	if !schemaMentionsSchemaVersion(schema, schema, map[string]struct{}{}) {
		return nil
	}
	if schemaNodeRequiresSchemaVersion(schema, schemaID, schema, map[string]struct{}{}) {
		return nil
	}
	if got, ok := firstSchemaVersionConst(schema, schema, map[string]struct{}{}); ok && got != schemaID {
		return []string{fmt.Sprintf("%s schema_version const = %v, want %s", fileName, got, schemaID)}
	}
	return []string{fmt.Sprintf("%s required schema_version const %q is missing", fileName, schemaID)}
}

func schemaNodeRequiresSchemaVersion(node any, schemaID string, root any, seenRefs map[string]struct{}) bool {
	typed, ok := node.(map[string]any)
	if !ok {
		return false
	}
	if ref, ok := typed["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
		if _, seen := seenRefs[ref]; seen {
			return false
		}
		resolved, found := resolveJSONPointer(root, strings.TrimPrefix(ref, "#"))
		if !found {
			return false
		}
		nextSeenRefs := cloneStringSet(seenRefs)
		nextSeenRefs[ref] = struct{}{}
		return schemaNodeRequiresSchemaVersion(resolved, schemaID, root, nextSeenRefs)
	}
	if directSchemaVersionConst(typed, schemaID) {
		return true
	}
	if children, ok := typed["allOf"].([]any); ok && len(children) > 0 {
		requiresSchemaVersion := false
		hasMatchingConst := false
		for _, child := range children {
			if schemaNodeRequiresSchemaVersion(child, schemaID, root, cloneStringSet(seenRefs)) {
				return true
			}
			if schemaNodeRequiresSchemaVersionField(child, root, cloneStringSet(seenRefs)) {
				requiresSchemaVersion = true
			}
			if got, ok := firstSchemaVersionConst(child, root, cloneStringSet(seenRefs)); ok && got == schemaID {
				hasMatchingConst = true
			}
		}
		if requiresSchemaVersion && hasMatchingConst {
			return true
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		children, ok := typed[keyword].([]any)
		if !ok || len(children) == 0 {
			continue
		}
		allChildrenRequireSchemaVersion := true
		for _, child := range children {
			if !schemaNodeRequiresSchemaVersion(child, schemaID, root, cloneStringSet(seenRefs)) {
				allChildrenRequireSchemaVersion = false
				break
			}
		}
		if allChildrenRequireSchemaVersion {
			return true
		}
	}
	return false
}

func directSchemaVersionConst(schema map[string]any, schemaID string) bool {
	if !stringSliceContains(schema["required"], "schema_version") {
		return false
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return false
	}
	schemaVersion, ok := properties["schema_version"].(map[string]any)
	if !ok {
		return false
	}
	return schemaVersion["const"] == schemaID
}

func schemaMentionsSchemaVersion(node any, root any, seenRefs map[string]struct{}) bool {
	if _, ok := firstSchemaVersionConst(node, root, cloneStringSet(seenRefs)); ok {
		return true
	}
	return schemaNodeRequiresSchemaVersionField(node, root, seenRefs)
}

func schemaNodeRequiresSchemaVersionField(node any, root any, seenRefs map[string]struct{}) bool {
	typed, ok := node.(map[string]any)
	if !ok {
		return false
	}
	if ref, ok := typed["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
		if _, seen := seenRefs[ref]; seen {
			return false
		}
		resolved, found := resolveJSONPointer(root, strings.TrimPrefix(ref, "#"))
		if !found {
			return false
		}
		nextSeenRefs := cloneStringSet(seenRefs)
		nextSeenRefs[ref] = struct{}{}
		return schemaNodeRequiresSchemaVersionField(resolved, root, nextSeenRefs)
	}
	if stringSliceContains(typed["required"], "schema_version") {
		return true
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		children, ok := typed[keyword].([]any)
		if !ok || len(children) == 0 {
			continue
		}
		allChildrenRequireSchemaVersion := true
		for _, child := range children {
			if !schemaNodeRequiresSchemaVersionField(child, root, cloneStringSet(seenRefs)) {
				allChildrenRequireSchemaVersion = false
				break
			}
		}
		if allChildrenRequireSchemaVersion {
			return true
		}
	}
	if children, ok := typed["allOf"].([]any); ok {
		for _, child := range children {
			if schemaNodeRequiresSchemaVersionField(child, root, cloneStringSet(seenRefs)) {
				return true
			}
		}
	}
	return false
}

func firstSchemaVersionConst(node any, root any, seenRefs map[string]struct{}) (string, bool) {
	typed, ok := node.(map[string]any)
	if !ok {
		return "", false
	}
	if ref, ok := typed["$ref"].(string); ok && strings.HasPrefix(ref, "#") {
		if _, seen := seenRefs[ref]; seen {
			return "", false
		}
		resolved, found := resolveJSONPointer(root, strings.TrimPrefix(ref, "#"))
		if !found {
			return "", false
		}
		nextSeenRefs := cloneStringSet(seenRefs)
		nextSeenRefs[ref] = struct{}{}
		return firstSchemaVersionConst(resolved, root, nextSeenRefs)
	}
	if properties, ok := typed["properties"].(map[string]any); ok {
		if schemaVersion, ok := properties["schema_version"].(map[string]any); ok {
			if got, ok := schemaVersion["const"].(string); ok {
				return got, true
			}
		}
	}
	for _, keyword := range []string{"allOf", "oneOf", "anyOf"} {
		children, ok := typed[keyword].([]any)
		if !ok {
			continue
		}
		for _, child := range children {
			if got, ok := firstSchemaVersionConst(child, root, cloneStringSet(seenRefs)); ok {
				return got, true
			}
		}
	}
	return "", false
}

func validateSchemaRequiredProperties(fileName string, schema map[string]any) []string {
	var problems []string
	walkSchema(fileName, "#", schema, func(path string, node map[string]any) {
		problems = append(problems, validateRequiredKeyword(path, node)...)
		problems = append(problems, validatePropertiesKeyword(path, node)...)
		problems = append(problems, validatePatternPropertiesKeyword(path, node)...)
		problems = append(problems, validateSchemaBoundaryKeywords(path, node)...)
		problems = append(problems, validateArraySchemaKeywords(path, node)...)
		problems = append(problems, validateCompositionKeywords(path, node)...)
		problems = append(problems, validateConditionalKeywords(path, node)...)
		problems = append(problems, validateScalarKeywords(path, node)...)
	})
	return problems
}

func validateRequiredKeyword(path string, node map[string]any) []string {
	rawRequired, hasRequired := node["required"]
	if !hasRequired {
		return nil
	}
	required, ok := rawRequired.([]any)
	if !ok {
		return []string{fmt.Sprintf("%s required keyword must be an array of strings", path)}
	}
	properties, ok := node["properties"].(map[string]any)
	if !ok {
		if schemaRequiresPropertiesForRequired(node) {
			return []string{fmt.Sprintf("%s required keyword requires a properties object", path)}
		}
		return nil
	}
	var problems []string
	for index, raw := range required {
		field, ok := raw.(string)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s/required/%d required keyword must be an array of strings", path, index))
			continue
		}
		if _, ok := properties[field]; !ok {
			problems = append(problems, fmt.Sprintf("%s required field %q is missing from properties", path, field))
		}
	}
	return problems
}

func validatePropertiesKeyword(path string, node map[string]any) []string {
	rawProperties, ok := node["properties"]
	if !ok {
		return nil
	}
	properties, ok := rawProperties.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s/properties properties keyword must be an object", path)}
	}
	var problems []string
	for name, definition := range properties {
		childPath := pathJoin(path, "properties", name)
		if !isSchemaValue(definition) {
			problems = append(problems, fmt.Sprintf("%s property definition %q must be a schema object or boolean", childPath, name))
		}
	}
	return problems
}

func schemaRequiresPropertiesForRequired(node map[string]any) bool {
	if node["type"] == "object" {
		return true
	}
	if _, ok := node["additionalProperties"]; ok {
		return true
	}
	if _, ok := node["unevaluatedProperties"]; ok {
		return true
	}
	return false
}

func validatePatternPropertiesKeyword(path string, node map[string]any) []string {
	rawPatternProperties, ok := node["patternProperties"]
	if !ok {
		return nil
	}
	patternProperties, ok := rawPatternProperties.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf("%s/patternProperties patternProperties keyword must be an object", path)}
	}
	var problems []string
	for pattern, definition := range patternProperties {
		childPath := pathJoin(path, "patternProperties", pattern)
		if _, err := regexp2.Compile(pattern, regexp2.ECMAScript); err != nil {
			problems = append(problems, fmt.Sprintf("%s patternProperties pattern %q must compile as ECMA regex: %v", childPath, pattern, err))
		}
		if !isSchemaValue(definition) {
			problems = append(problems, fmt.Sprintf("%s patternProperties definition %q must be a schema object or boolean", childPath, pattern))
		}
	}
	return problems
}

func validateSchemaBoundaryKeywords(path string, node map[string]any) []string {
	var problems []string
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties", "unevaluatedItems"} {
		if raw, ok := node[keyword]; ok && !isSchemaValue(raw) {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a schema object or boolean", pathJoin(path, keyword), keyword))
		}
	}
	return problems
}

func validateArraySchemaKeywords(path string, node map[string]any) []string {
	var problems []string
	for _, keyword := range []string{"items", "contains"} {
		if raw, ok := node[keyword]; ok && !isSchemaValue(raw) {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a schema object or boolean", pathJoin(path, keyword), keyword))
		}
	}
	if raw, ok := node["prefixItems"]; ok {
		items, ok := raw.([]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s prefixItems keyword must be an array", pathJoin(path, "prefixItems")))
		} else {
			for index, item := range items {
				if !isSchemaValue(item) {
					problems = append(problems, fmt.Sprintf("%s prefixItems entry must be a schema object or boolean", pathJoin(path, "prefixItems", fmt.Sprintf("%d", index))))
				}
			}
		}
	}
	return problems
}

func validateCompositionKeywords(path string, node map[string]any) []string {
	var problems []string
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		raw, ok := node[keyword]
		if !ok {
			continue
		}
		children, ok := raw.([]any)
		if !ok || len(children) == 0 {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a non-empty array", pathJoin(path, keyword), keyword))
			continue
		}
		for index, child := range children {
			if !isSchemaValue(child) {
				problems = append(problems, fmt.Sprintf("%s %s entry must be a schema object or boolean", pathJoin(path, keyword, fmt.Sprintf("%d", index)), keyword))
			}
		}
	}
	if raw, ok := node["not"]; ok && !isSchemaValue(raw) {
		problems = append(problems, fmt.Sprintf("%s not keyword must be a schema object or boolean", pathJoin(path, "not")))
	}
	return problems
}

func validateConditionalKeywords(path string, node map[string]any) []string {
	var problems []string
	for _, keyword := range []string{"if", "then", "else"} {
		if raw, ok := node[keyword]; ok && !isSchemaValue(raw) {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a schema object or boolean", pathJoin(path, keyword), keyword))
		}
	}
	return problems
}

func validateScalarKeywords(path string, node map[string]any) []string {
	var problems []string
	if raw, ok := node["pattern"]; ok {
		pattern, ok := raw.(string)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s pattern keyword must be a string", pathJoin(path, "pattern")))
		} else if _, err := regexp2.Compile(pattern, regexp2.ECMAScript); err != nil {
			problems = append(problems, fmt.Sprintf("%s pattern keyword must compile as ECMA regex: %v", pathJoin(path, "pattern"), err))
		}
	}
	if raw, ok := node["format"]; ok {
		format, ok := raw.(string)
		if !ok || strings.TrimSpace(format) == "" {
			problems = append(problems, fmt.Sprintf("%s format keyword must be a non-empty string", pathJoin(path, "format")))
		}
	}
	for _, keyword := range []string{"minLength", "maxLength"} {
		if raw, ok := node[keyword]; ok && !isNonNegativeInteger(raw) {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a non-negative integer", pathJoin(path, keyword), keyword))
		}
	}
	for _, keyword := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"} {
		if raw, ok := node[keyword]; ok && !isNumber(raw) {
			problems = append(problems, fmt.Sprintf("%s %s keyword must be a number", pathJoin(path, keyword), keyword))
		}
	}
	if raw, ok := node["multipleOf"]; ok {
		number, ok := numberValue(raw)
		if !ok || number <= 0 {
			problems = append(problems, fmt.Sprintf("%s multipleOf keyword must be a number greater than zero", pathJoin(path, "multipleOf")))
		}
	}
	if raw, ok := node["type"]; ok {
		problems = append(problems, validateTypeKeyword(pathJoin(path, "type"), raw)...)
	}
	if raw, ok := node["enum"]; ok {
		problems = append(problems, validateEnumKeyword(pathJoin(path, "enum"), raw)...)
	}
	if raw, ok := node["const"]; ok {
		if typeRaw, ok := node["type"]; ok && !valueMatchesTypeKeyword(raw, typeRaw) {
			problems = append(problems, fmt.Sprintf("%s const keyword must match the sibling type keyword", pathJoin(path, "const")))
		}
	}
	return problems
}

func validateTypeKeyword(path string, raw any) []string {
	allowed := map[string]struct{}{
		"array": {}, "boolean": {}, "integer": {}, "null": {}, "number": {}, "object": {}, "string": {},
	}
	var values []any
	switch typed := raw.(type) {
	case string:
		values = []any{typed}
	case []any:
		if len(typed) == 0 {
			return []string{fmt.Sprintf("%s type keyword must be one of array, boolean, integer, null, number, object, string", path)}
		}
		values = typed
	default:
		return []string{fmt.Sprintf("%s type keyword must be one of array, boolean, integer, null, number, object, string", path)}
	}
	var problems []string
	seen := map[string]struct{}{}
	for index, rawValue := range values {
		valuePath := path
		if _, isArray := raw.([]any); isArray {
			valuePath = pathJoin(path, fmt.Sprintf("%d", index))
		}
		value, ok := rawValue.(string)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s type keyword must be one of array, boolean, integer, null, number, object, string", valuePath))
			continue
		}
		if _, ok := allowed[value]; !ok {
			problems = append(problems, fmt.Sprintf("%s type keyword must be one of array, boolean, integer, null, number, object, string", valuePath))
			continue
		}
		if _, ok := seen[value]; ok {
			problems = append(problems, fmt.Sprintf("%s type keyword must not contain duplicates", valuePath))
		}
		seen[value] = struct{}{}
	}
	return problems
}

func validateEnumKeyword(path string, raw any) []string {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return []string{fmt.Sprintf("%s enum keyword must be a non-empty array", path)}
	}
	var problems []string
	seen := map[string]struct{}{}
	for index, value := range values {
		keyBytes, _ := json.Marshal(value)
		key := string(keyBytes)
		if _, ok := seen[key]; ok {
			problems = append(problems, fmt.Sprintf("%s enum keyword must not contain duplicate values", pathJoin(path, fmt.Sprintf("%d", index))))
		}
		seen[key] = struct{}{}
	}
	return problems
}

func validateSchemaRefs(fileName string, schema map[string]any, registeredIDs map[string]struct{}) []string {
	var problems []string
	walkSchema(fileName, "#", schema, func(path string, node map[string]any) {
		ref, ok := node["$ref"].(string)
		if !ok {
			return
		}
		if strings.HasPrefix(ref, "#") {
			if _, found := resolveJSONPointer(schema, strings.TrimPrefix(ref, "#")); !found {
				problems = append(problems, fmt.Sprintf("%s unresolved local $ref %q", pathJoin(path, "$ref"), ref))
			}
			return
		}
		if _, ok := registeredIDs[ref]; !ok {
			problems = append(problems, fmt.Sprintf("%s unregistered external $ref %q", pathJoin(path, "$ref"), ref))
		}
	})
	return problems
}

func walkSchema(fileName string, path string, node any, visit func(string, map[string]any)) {
	_ = fileName
	typed, ok := node.(map[string]any)
	if !ok {
		return
	}
	visit(path, typed)
	if properties, ok := typed["properties"].(map[string]any); ok {
		for name, child := range properties {
			walkSchema(fileName, pathJoin(path, "properties", name), child, visit)
		}
	}
	if patternProperties, ok := typed["patternProperties"].(map[string]any); ok {
		for name, child := range patternProperties {
			walkSchema(fileName, pathJoin(path, "patternProperties", name), child, visit)
		}
	}
	if defs, ok := typed["$defs"].(map[string]any); ok {
		for name, child := range defs {
			walkSchema(fileName, pathJoin(path, "$defs", name), child, visit)
		}
	}
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties", "items", "contains", "unevaluatedItems", "not", "if", "then", "else"} {
		if child, ok := typed[keyword]; ok {
			walkSchema(fileName, pathJoin(path, keyword), child, visit)
		}
	}
	if prefixItems, ok := typed["prefixItems"].([]any); ok {
		for index, child := range prefixItems {
			walkSchema(fileName, pathJoin(path, "prefixItems", fmt.Sprintf("%d", index)), child, visit)
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		children, ok := typed[keyword].([]any)
		if !ok {
			continue
		}
		for index, child := range children {
			walkSchema(fileName, pathJoin(path, keyword, fmt.Sprintf("%d", index)), child, visit)
		}
	}
}

func isSchemaValue(value any) bool {
	switch value.(type) {
	case bool, map[string]any:
		return true
	default:
		return false
	}
}

func isNonNegativeInteger(value any) bool {
	number, ok := numberValue(value)
	return ok && number >= 0 && number == float64(int64(number))
}

func isNumber(value any) bool {
	_, ok := numberValue(value)
	return ok
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		got, err := typed.Float64()
		return got, err == nil
	default:
		return 0, false
	}
}

func valueMatchesTypeKeyword(value any, typeRaw any) bool {
	typeValues := schemaTypeValues(typeRaw)
	if len(typeValues) == 0 {
		return true
	}
	for _, typeValue := range typeValues {
		if valueMatchesType(value, typeValue) {
			return true
		}
	}
	return false
}

func schemaTypeValues(raw any) []string {
	switch typed := raw.(type) {
	case string:
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, rawValue := range typed {
			value, ok := rawValue.(string)
			if ok {
				values = append(values, value)
			}
		}
		return values
	default:
		return nil
	}
}

func valueMatchesType(value any, typeValue string) bool {
	switch typeValue {
	case "array":
		_, ok := value.([]any)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := numberValue(value)
		return ok && number == float64(int64(number))
	case "null":
		return value == nil
	case "number":
		_, ok := numberValue(value)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	default:
		return true
	}
}

func stringSliceContains(value any, want string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	}
	return false
}

func resolveJSONPointer(root any, pointer string) (any, bool) {
	if pointer == "" {
		return root, true
	}
	pointer = strings.TrimPrefix(pointer, "/")
	if pointer == "" {
		return root, true
	}
	current := root
	for _, rawSegment := range strings.Split(pointer, "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for key := range in {
		out[key] = struct{}{}
	}
	return out
}

func pathJoin(base string, segments ...string) string {
	out := base
	for _, segment := range segments {
		out += "/" + escapeJSONPointerSegment(segment)
	}
	return out
}

func escapeJSONPointerSegment(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func Catalog() []CatalogEntry {
	catalog := make([]CatalogEntry, 0, len(requiredSchemas))
	for _, entry := range requiredSchemas {
		catalog = append(catalog, CatalogEntry{
			ID:         entry.ID,
			FileName:   entry.FileName,
			SchemaPath: entry.SchemaPath,
		})
	}
	return catalog
}

func KnownSchemaID(schemaID string) bool {
	_, ok := requiredSchemasByID[schemaID]
	return ok
}

func Export(outDir string) ([]ExportedSchema, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create schema export directory: %w", err)
	}
	exported := make([]ExportedSchema, 0, len(requiredSchemas))
	for _, entry := range requiredSchemas {
		bytes, err := embedded.Files.ReadFile(entry.FileName)
		if err != nil {
			return nil, fmt.Errorf("read embedded schema %s: %w", entry.FileName, err)
		}
		writtenPath := filepath.Join(outDir, entry.FileName)
		if err := os.WriteFile(writtenPath, bytes, 0o644); err != nil {
			return nil, fmt.Errorf("write schema %s: %w", writtenPath, err)
		}
		exported = append(exported, ExportedSchema{
			ID:          entry.ID,
			FileName:    entry.FileName,
			SchemaPath:  entry.SchemaPath,
			WrittenPath: filepath.ToSlash(writtenPath),
		})
	}
	return exported, nil
}

func InferSchemaIDBytes(bytes []byte) (string, error) {
	var document map[string]any
	if err := json.Unmarshal(bytes, &document); err != nil {
		return "", fmt.Errorf("parse JSON document: %w", err)
	}
	rawSchemaID, ok := document["schema_version"]
	if !ok {
		return "", fmt.Errorf("schema_version is required")
	}
	schemaID, ok := rawSchemaID.(string)
	if !ok || strings.TrimSpace(schemaID) == "" {
		return "", fmt.Errorf("schema_version is required")
	}
	if !KnownSchemaID(schemaID) {
		return "", fmt.Errorf("unknown schema %q", schemaID)
	}
	return schemaID, nil
}

func ValidateDocumentBytes(schemaID string, bytes []byte) ValidationReport {
	report := ValidationReport{SchemaID: schemaID}
	if err := ValidateBytes(schemaID, bytes); err != nil {
		report.Valid = false
		report.Error = err.Error()
		report.Location = validationErrorLocation(err)
		return report
	}
	report.Valid = true
	return report
}

func ValidateBytes(schemaID string, bytes []byte) error {
	var document any
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("schema validation failed for %s: parse JSON document: %w", schemaID, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("schema validation failed for %s: JSON document must contain exactly one value", schemaID)
	}
	return ValidateValue(schemaID, document)
}

func ValidateValue(schemaID string, value any) error {
	compiled, err := compiledSchema(schemaID)
	if err != nil {
		return err
	}
	jsonValue, err := normalizeJSONValue(value)
	if err != nil {
		return fmt.Errorf("schema validation failed for %s: %w", schemaID, err)
	}
	if err := compiled.Validate(jsonValue); err != nil {
		return fmt.Errorf("schema validation failed for %s: %w", schemaID, err)
	}
	return nil
}

func normalizeJSONValue(value any) (any, error) {
	switch value.(type) {
	case nil, bool, string, json.Number, float64, []any, map[string]any:
		return value, nil
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON value: %w", err)
	}
	var normalized any
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode normalized JSON value: %w", err)
	}
	return normalized, nil
}

func WriteJSONFile(path string, schemaID string, value any, perm fs.FileMode) error {
	if err := ValidateValue(schemaID, value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	return WriteJSON(file, schemaID, value)
}

func WriteJSON(writer io.Writer, schemaID string, value any) error {
	if err := ValidateValue(schemaID, value); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

var compiledSchemas struct {
	sync.Once
	byID map[string]*jsonschema.Schema
	err  error
}

func compiledSchema(schemaID string) (*jsonschema.Schema, error) {
	compiledSchemas.Do(func() {
		compiledSchemas.byID, compiledSchemas.err = compileSchemas()
	})
	if compiledSchemas.err != nil {
		return nil, compiledSchemas.err
	}
	compiled, ok := compiledSchemas.byID[schemaID]
	if !ok {
		return nil, fmt.Errorf("unknown schema %q", schemaID)
	}
	return compiled, nil
}

func compileSchemas() (map[string]*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseRegexpEngine(dlclarkCompile)
	for _, entry := range requiredSchemas {
		bytes, err := embedded.Files.ReadFile(entry.FileName)
		if err != nil {
			return nil, fmt.Errorf("read embedded schema %s: %w", entry.FileName, err)
		}
		var parsed any
		decoder := json.NewDecoder(strings.NewReader(string(bytes)))
		decoder.UseNumber()
		if err := decoder.Decode(&parsed); err != nil {
			return nil, fmt.Errorf("parse embedded schema %s: %w", entry.FileName, err)
		}
		if err := compiler.AddResource(entry.ID, parsed); err != nil {
			return nil, fmt.Errorf("register schema %s: %w", entry.ID, err)
		}
	}
	compiled := make(map[string]*jsonschema.Schema, len(requiredSchemas))
	for _, entry := range requiredSchemas {
		schema, err := compiler.Compile(entry.ID)
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", entry.ID, err)
		}
		compiled[entry.ID] = schema
	}
	return compiled, nil
}

type dlclarkRegexp regexp2.Regexp

func (re *dlclarkRegexp) MatchString(s string) bool {
	matched, err := (*regexp2.Regexp)(re).MatchString(s)
	return err == nil && matched
}

func (re *dlclarkRegexp) String() string {
	return (*regexp2.Regexp)(re).String()
}

func dlclarkCompile(s string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(s, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return (*dlclarkRegexp)(re), nil
}

func validationErrorLocation(err error) string {
	var validationErr *jsonschema.ValidationError
	if errors.As(err, &validationErr) {
		return deepestValidationErrorLocation(validationErr)
	}
	return ""
}

func deepestValidationErrorLocation(err *jsonschema.ValidationError) string {
	if err == nil {
		return ""
	}
	if len(err.Causes) == 0 {
		if len(err.InstanceLocation) == 0 {
			return "/"
		}
		return "/" + strings.Join(escapeInstanceLocation(err.InstanceLocation), "/")
	}
	for _, cause := range err.Causes {
		location := deepestValidationErrorLocation(cause)
		if location != "" && location != "/" {
			return location
		}
	}
	if len(err.InstanceLocation) == 0 {
		return "/"
	}
	return "/" + strings.Join(escapeInstanceLocation(err.InstanceLocation), "/")
}

func escapeInstanceLocation(segments []string) []string {
	escaped := make([]string, len(segments))
	for index, segment := range segments {
		escaped[index] = escapeJSONPointerSegment(segment)
	}
	return escaped
}
