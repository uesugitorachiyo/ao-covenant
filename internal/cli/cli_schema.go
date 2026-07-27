package cli

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func runSchemaCatalog(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema catalog", flag.ContinueOnError)
	flags.SetOutput(stderr)
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	report := schemaCatalogReport{
		SchemaVersion: schema.SchemaCatalogResultSchemaID,
		Schemas:       schema.Catalog(),
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.SchemaCatalogResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write schema catalog: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range report.Schemas {
		fmt.Fprintf(stdout, "schema=%s file=%s path=%s\n", entry.ID, entry.FileName, entry.SchemaPath)
	}
	return 0
}

func runSchemaExport(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema export", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outDir := flags.String("out", "", "directory to write public JSON schemas")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*outDir) == "" {
		fmt.Fprintln(stderr, "--out is required")
		return 2
	}
	exported, err := schema.Export(*outDir)
	if err != nil {
		fmt.Fprintf(stderr, "export schemas: %v\n", err)
		return 1
	}
	report := schemaExportReport{
		SchemaVersion: schema.SchemaExportResultSchemaID,
		Schemas:       exported,
	}
	if *jsonOutput {
		if err := writeSchemaJSON(stdout, schema.SchemaExportResultSchemaID, report); err != nil {
			fmt.Fprintf(stderr, "write schema export: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range report.Schemas {
		fmt.Fprintf(stdout, "schema=%s file=%s written=%s\n", entry.ID, entry.FileName, entry.WrittenPath)
	}
	return 0
}

func runSchemaValidate(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("schema validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	schemaID := flags.String("schema", "", "schema ID to validate against")
	filePath := flags.String("file", "", "JSON document to validate")
	dirPath := flags.String("dir", "", "directory tree of JSON documents to validate")
	stdinInput := flags.Bool("stdin", false, "read JSON document from stdin")
	filesFromPath := flags.String("files-from", "", "newline-delimited list of JSON documents to validate")
	var ignorePatterns repeatedStringFlag
	flags.Var(&ignorePatterns, "ignore", "slash-separated file or directory path to skip during --dir validation")
	var schemaFilterIDs repeatedStringFlag
	flags.Var(&schemaFilterIDs, "schema-filter", "schema ID to include during --dir or --files-from validation")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	sarifOutput := flags.Bool("sarif", false, "emit SARIF")
	junitOutput := flags.Bool("junit", false, "emit JUnit XML")
	sarifBaselinePath := flags.String("sarif-baseline", "", "path to SARIF baseline JSON")
	outPath := flags.String("out", "", "path to write structured validation report")
	failFast := flags.Bool("fail-fast", false, "stop directory validation after the first invalid document")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if countEnabled(*jsonOutput, *sarifOutput, *junitOutput) > 1 {
		fmt.Fprintln(stderr, "--json, --sarif, and --junit are mutually exclusive")
		return 2
	}
	if strings.TrimSpace(*sarifBaselinePath) != "" && !*sarifOutput {
		fmt.Fprintln(stderr, "--sarif-baseline requires --sarif")
		return 2
	}
	selectedOutPath := strings.TrimSpace(*outPath)
	if selectedOutPath != "" && countEnabled(*jsonOutput, *sarifOutput, *junitOutput) == 0 {
		fmt.Fprintln(stderr, "--out requires --json, --sarif, or --junit")
		return 2
	}
	selectedFilePath := strings.TrimSpace(*filePath)
	selectedDirPath := strings.TrimSpace(*dirPath)
	selectedFilesFromPath := strings.TrimSpace(*filesFromPath)
	if countEnabled(selectedFilePath != "", selectedDirPath != "", *stdinInput, selectedFilesFromPath != "") != 1 {
		fmt.Fprintln(stderr, "provide exactly one of --file, --dir, --stdin, or --files-from")
		return 2
	}
	selectedSchemaFilters, schemaFilterErr := normalizeSchemaValidationSchemaFilters(schemaFilterIDs.Values())
	if schemaFilterErr != nil {
		fmt.Fprintln(stderr, schemaFilterErr)
		return 2
	}
	if len(selectedSchemaFilters) > 0 {
		if selectedDirPath == "" && selectedFilesFromPath == "" {
			fmt.Fprintln(stderr, "--schema-filter can only be used with --dir or --files-from")
			return 2
		}
		if strings.TrimSpace(*schemaID) != "" {
			fmt.Fprintln(stderr, "--schema-filter cannot be combined with --schema")
			return 2
		}
	}
	selectedIgnorePatterns, ignoreErr := normalizeSchemaValidationIgnorePatterns(ignorePatterns.Values())
	if ignoreErr != nil {
		fmt.Fprintf(stderr, "%v\n", ignoreErr)
		return 2
	}
	if len(selectedIgnorePatterns) > 0 && selectedDirPath == "" {
		fmt.Fprintln(stderr, "--ignore can only be used with --dir")
		return 2
	}

	if selectedDirPath != "" || selectedFilesFromPath != "" {
		var documents []schemaValidationInputDocument
		var ignoredDocuments []schemaValidationIgnoredDocument
		if selectedDirPath != "" {
			paths, ignored, err := collectSchemaValidationDirectory(selectedDirPath, selectedIgnorePatterns)
			if err != nil {
				fmt.Fprintf(stderr, "collect schema documents: %v\n", err)
				return 1
			}
			ignoredDocuments = ignored
			if len(paths) == 0 {
				fmt.Fprintf(stderr, "no JSON documents found under %s\n", selectedDirPath)
				return 1
			}
			documents = make([]schemaValidationInputDocument, 0, len(paths))
			for _, path := range paths {
				displayPath, err := schemaValidationDisplayPath(selectedDirPath, path)
				if err != nil {
					fmt.Fprintf(stderr, "%s: %v\n", path, err)
					return 1
				}
				documents = append(documents, schemaValidationInputDocument{
					Path:        path,
					DisplayPath: displayPath,
				})
			}
		} else {
			var err error
			documents, err = readSchemaValidationManifest(selectedFilesFromPath)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
		report := validateSchemaInputDocuments(documents, *schemaID, selectedSchemaFilters, *failFast, stderr)
		inputMode := "files-from"
		source := selectedFilesFromPath
		if selectedDirPath != "" {
			inputMode = "dir"
			source = selectedDirPath
		}
		report.Metadata = schemaValidationMetadata(inputMode, source, *schemaID, selectedSchemaFilters, selectedIgnorePatterns, *failFast)
		report.Ignored = ignoredDocuments
		report.IgnoredCount = len(ignoredDocuments)
		if *sarifOutput {
			baseline, err := readSchemaValidationSARIFBaseline(*sarifBaselinePath)
			if err != nil {
				fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
				return 1
			}
			sarifReports := schemaValidationSARIFReports(report.Validations)
			sarifOptions := schema.ValidationSARIFOptions{Baseline: baseline}
			bytes, err := json.MarshalIndent(schema.ValidationSARIFWithOptions(sarifReports, sarifOptions), "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "encode schema validation sarif: %v\n", err)
				return 1
			}
			if err := writeSchemaValidationOutput(stdout, selectedOutPath, bytes); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
			if !report.Valid && schema.ValidationSARIFReportsAllSuppressed(sarifReports, sarifOptions) {
				return 0
			}
		} else if *junitOutput {
			bytes, err := xml.MarshalIndent(schema.ValidationJUnit(schemaValidationJUnitReports(report.Validations), ""), "", "  ")
			if err != nil {
				fmt.Fprintf(stderr, "encode schema validation junit: %v\n", err)
				return 1
			}
			if err := writeSchemaValidationOutput(stdout, selectedOutPath, bytes); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
		} else if *jsonOutput {
			if err := writeSchemaValidationJSON(stdout, selectedOutPath, report); err != nil {
				fmt.Fprintf(stderr, "write schema validation: %v\n", err)
				return 1
			}
		} else {
			for _, validation := range report.Validations {
				printSchemaValidationLine(stdout, validation)
			}
			for _, ignored := range report.Ignored {
				fmt.Fprintf(stdout, "ignored=%s pattern=%s\n", ignored.File, ignored.Pattern)
			}
			for _, summary := range report.Schemas {
				fmt.Fprintf(stdout, "schema_summary=%s", summary.SchemaID)
				if summary.Total > 0 {
					fmt.Fprintf(stdout, " total=%d valid_count=%d invalid_count=%d", summary.Total, summary.ValidCount, summary.InvalidCount)
				}
				if summary.SkippedCount > 0 {
					fmt.Fprintf(stdout, " skipped_count=%d", summary.SkippedCount)
				}
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "valid=%t total=%d valid_count=%d invalid_count=%d", report.Valid, report.Total, report.ValidCount, report.InvalidCount)
			if report.SkippedCount > 0 {
				fmt.Fprintf(stdout, " skipped_count=%d", report.SkippedCount)
			}
			if report.IgnoredCount > 0 {
				fmt.Fprintf(stdout, " ignored_count=%d", report.IgnoredCount)
			}
			fmt.Fprintln(stdout)
		}
		if len(selectedSchemaFilters) > 0 && report.Total == 0 {
			fmt.Fprintln(stderr, "no schema documents matched --schema-filter")
			return 1
		}
		if !report.Valid {
			return 1
		}
		return 0
	}

	var report schemaValidationReport
	var err error
	if *stdinInput {
		var bytes []byte
		bytes, err = io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return 1
		}
		report, err = validateSchemaDocumentBytes("-", bytes, *schemaID)
	} else {
		report, err = validateSchemaDocument(selectedFilePath, *schemaID)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	inputMode := "file"
	source := selectedFilePath
	if *stdinInput {
		inputMode = "stdin"
		source = "-"
	}
	report.Metadata = schemaValidationMetadata(inputMode, source, *schemaID, nil, nil, false)
	return printSingleSchemaValidationReport(report, *sarifOutput, *junitOutput, *jsonOutput, selectedOutPath, *sarifBaselinePath, stdout, stderr)
}

func schemaValidationMetadata(inputMode string, source string, schemaID string, schemaFilters []string, ignorePatterns []string, failFast bool) *schemaValidationReportMetadata {
	metadata := &schemaValidationReportMetadata{
		Command:   "schema validate",
		InputMode: inputMode,
		Source:    source,
	}
	if value := strings.TrimSpace(schemaID); value != "" {
		metadata.ExplicitSchemaID = value
	}
	if len(schemaFilters) > 0 {
		metadata.SchemaFilters = append([]string(nil), schemaFilters...)
	}
	if len(ignorePatterns) > 0 {
		metadata.IgnorePatterns = append([]string(nil), ignorePatterns...)
	}
	if failFast {
		metadata.FailFast = true
	}
	return metadata
}

func printSingleSchemaValidationReport(report schemaValidationReport, sarifOutput bool, junitOutput bool, jsonOutput bool, outPath string, sarifBaselinePath string, stdout io.Writer, stderr io.Writer) int {
	if sarifOutput {
		baseline, err := readSchemaValidationSARIFBaseline(sarifBaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "read sarif baseline: %v\n", err)
			return 1
		}
		sarifReports := schemaValidationSARIFReports([]schemaValidationReport{report})
		sarifOptions := schema.ValidationSARIFOptions{Baseline: baseline}
		bytes, err := json.MarshalIndent(schema.ValidationSARIFWithOptions(sarifReports, sarifOptions), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode schema validation sarif: %v\n", err)
			return 1
		}
		if err := writeSchemaValidationOutput(stdout, outPath, bytes); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
		if !report.Valid && schema.ValidationSARIFReportsAllSuppressed(sarifReports, sarifOptions) {
			return 0
		}
	} else if junitOutput {
		bytes, err := xml.MarshalIndent(schema.ValidationJUnit(schemaValidationJUnitReports([]schemaValidationReport{report}), ""), "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encode schema validation junit: %v\n", err)
			return 1
		}
		if err := writeSchemaValidationOutput(stdout, outPath, bytes); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
	} else if jsonOutput {
		if err := writeSchemaValidationJSON(stdout, outPath, report); err != nil {
			fmt.Fprintf(stderr, "write schema validation: %v\n", err)
			return 1
		}
	} else {
		printSchemaValidationLine(stdout, report)
	}
	if !report.Valid {
		if report.Error != "" {
			fmt.Fprintln(stderr, schemaValidationErrorMessage(report))
		}
		return 1
	}
	return 0
}

func printSchemaValidationLine(stdout io.Writer, validation schemaValidationReport) {
	if validation.Location != "" {
		fmt.Fprintf(stdout, "schema=%s file=%s valid=%t location=%s\n", validation.SchemaID, validation.File, validation.Valid, validation.Location)
		return
	}
	fmt.Fprintf(stdout, "schema=%s file=%s valid=%t\n", validation.SchemaID, validation.File, validation.Valid)
}

func schemaValidationErrorMessage(validation schemaValidationReport) string {
	message := validation.Error
	if validation.Location != "" {
		message += " location=" + validation.Location
	}
	return message
}

func schemaValidationDisplayPath(root string, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	normalized := filepath.ToSlash(filepath.Clean(relative))
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("schema document %q is outside %q", path, root)
	}
	return normalized, nil
}

func countEnabled(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func schemaValidationSARIFReports(validations []schemaValidationReport) []schema.ValidationSARIFReport {
	reports := make([]schema.ValidationSARIFReport, 0, len(validations))
	for _, validation := range validations {
		reports = append(reports, schema.ValidationSARIFReport{
			SchemaID: validation.SchemaID,
			File:     validation.File,
			Valid:    validation.Valid,
			Error:    validation.Error,
			Location: validation.Location,
		})
	}
	return reports
}

func schemaValidationJUnitReports(validations []schemaValidationReport) []schema.ValidationJUnitReport {
	reports := make([]schema.ValidationJUnitReport, 0, len(validations))
	for _, validation := range validations {
		reports = append(reports, schema.ValidationJUnitReport{
			SchemaID: validation.SchemaID,
			File:     validation.File,
			Valid:    validation.Valid,
			Error:    validation.Error,
			Location: validation.Location,
		})
	}
	return reports
}

func validateSchemaDocument(path string, schemaID string) (schemaValidationReport, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: displayPath(path), Valid: false, Error: err.Error()}, fmt.Errorf("read schema document: %w", err)
	}
	return validateSchemaDocumentBytes(displayPath(path), bytes, schemaID)
}

func validateSchemaDocumentBytes(displayPath string, bytes []byte, schemaID string) (schemaValidationReport, error) {
	selectedSchemaID := strings.TrimSpace(schemaID)
	var err error
	if selectedSchemaID == "" {
		selectedSchemaID, err = schema.InferSchemaIDBytes(bytes)
		if err != nil {
			return schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: displayPath, Valid: false, Error: err.Error()}, fmt.Errorf("infer schema: %w when --schema is omitted", err)
		}
	}
	validation := schema.ValidateDocumentBytes(selectedSchemaID, bytes)
	return schemaValidationReport{
		SchemaVersion: schema.SchemaValidationReportSchemaID,
		SchemaID:      validation.SchemaID,
		File:          displayPath,
		Valid:         validation.Valid,
		Error:         validation.Error,
		Location:      validation.Location,
	}, nil
}

func validateSchemaInputDocuments(documents []schemaValidationInputDocument, schemaID string, schemaFilters []string, failFast bool, stderr io.Writer) schemaValidationSetReport {
	report := schemaValidationSetReport{
		SchemaVersion: schema.SchemaValidationReportSchemaID,
		Valid:         true,
		Validations:   make([]schemaValidationReport, 0, len(documents)),
	}
	filterSet := schemaValidationFilterSet(schemaFilters)
	schemaSummaries := map[string]*schemaValidationSchemaSummary{}
	recordSchemaSummary := func(schemaID string, valid bool, skipped bool) {
		value := strings.TrimSpace(schemaID)
		if value == "" {
			value = "unknown"
		}
		summary, ok := schemaSummaries[value]
		if !ok {
			summary = &schemaValidationSchemaSummary{SchemaID: value}
			schemaSummaries[value] = summary
		}
		if skipped {
			summary.SkippedCount++
			return
		}
		summary.Total++
		if valid {
			summary.ValidCount++
		} else {
			summary.InvalidCount++
		}
	}
	for _, document := range documents {
		bytes, readErr := os.ReadFile(document.Path)
		if readErr != nil {
			validation := schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: document.DisplayPath, Valid: false, Error: readErr.Error()}
			report.Valid = false
			report.Total++
			report.InvalidCount++
			report.Validations = append(report.Validations, validation)
			recordSchemaSummary(validation.SchemaID, validation.Valid, false)
			fmt.Fprintf(stderr, "%s: read schema document: %v\n", validation.File, readErr)
			if failFast {
				break
			}
			continue
		}
		if len(filterSet) > 0 {
			documentSchemaID, matches, err := schemaValidationFilterMatch(bytes, filterSet)
			if err != nil {
				validation := schemaValidationReport{SchemaVersion: schema.SchemaValidationReportSchemaID, File: document.DisplayPath, Valid: false, Error: err.Error()}
				report.Valid = false
				report.Total++
				report.InvalidCount++
				report.Validations = append(report.Validations, validation)
				recordSchemaSummary(validation.SchemaID, validation.Valid, false)
				fmt.Fprintf(stderr, "%s: %v\n", validation.File, err)
				if failFast {
					break
				}
				continue
			}
			if !matches {
				report.SkippedCount++
				recordSchemaSummary(documentSchemaID, false, true)
				continue
			}
			validation := schema.ValidateDocumentBytes(documentSchemaID, bytes)
			validationReport := schemaValidationReport{
				SchemaVersion: schema.SchemaValidationReportSchemaID,
				SchemaID:      validation.SchemaID,
				File:          document.DisplayPath,
				Valid:         validation.Valid,
				Error:         validation.Error,
				Location:      validation.Location,
			}
			if !validationReport.Valid {
				report.Valid = false
				fmt.Fprintf(stderr, "%s: %s\n", validationReport.File, schemaValidationErrorMessage(validationReport))
			}
			report.Total++
			if validationReport.Valid {
				report.ValidCount++
			} else {
				report.InvalidCount++
			}
			report.Validations = append(report.Validations, validationReport)
			recordSchemaSummary(validationReport.SchemaID, validationReport.Valid, false)
			if failFast && !validationReport.Valid {
				break
			}
			continue
		}
		validation, err := validateSchemaDocumentBytes(document.DisplayPath, bytes, schemaID)
		if err != nil {
			report.Valid = false
			fmt.Fprintf(stderr, "%s: %v\n", validation.File, err)
		}
		if !validation.Valid {
			report.Valid = false
			if validation.Error != "" && err == nil {
				fmt.Fprintf(stderr, "%s: %s\n", validation.File, schemaValidationErrorMessage(validation))
			}
		}
		report.Total++
		if validation.Valid {
			report.ValidCount++
		} else {
			report.InvalidCount++
		}
		report.Validations = append(report.Validations, validation)
		recordSchemaSummary(validation.SchemaID, validation.Valid, false)
		if failFast && !validation.Valid {
			break
		}
	}
	report.Schemas = sortedSchemaValidationSummaries(schemaSummaries)
	return report
}

func sortedSchemaValidationSummaries(values map[string]*schemaValidationSchemaSummary) []schemaValidationSchemaSummary {
	summaries := make([]schemaValidationSchemaSummary, 0, len(values))
	for _, summary := range values {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].SchemaID < summaries[j].SchemaID
	})
	return summaries
}

func schemaValidationFilterSet(filters []string) map[string]bool {
	if len(filters) == 0 {
		return nil
	}
	set := make(map[string]bool, len(filters))
	for _, filter := range filters {
		value := strings.TrimSpace(filter)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func schemaValidationFilterMatch(bytes []byte, filters map[string]bool) (string, bool, error) {
	var document map[string]any
	if err := json.Unmarshal(bytes, &document); err != nil {
		return "", false, fmt.Errorf("decode JSON for schema filter: %w", err)
	}
	rawSchemaID, ok := document["schema_version"]
	if !ok {
		return "", false, nil
	}
	schemaID, ok := rawSchemaID.(string)
	if !ok {
		return "", false, nil
	}
	schemaID = strings.TrimSpace(schemaID)
	if schemaID == "" || !schema.KnownSchemaID(schemaID) {
		return "", false, nil
	}
	return schemaID, filters[schemaID], nil
}

func collectSchemaValidationDirectory(root string, ignored []string) ([]string, []schemaValidationIgnoredDocument, error) {
	if err := ensureSchemaValidationDirectoryRoot(root); err != nil {
		return nil, nil, err
	}
	var paths []string
	var ignoredDocuments []schemaValidationIgnoredDocument
	budget := schemaValidationDirectoryScanBudget{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("schema validation directory symlink is not allowed: %s", filepath.ToSlash(path))
		}
		if path != root {
			displayPath, err := schemaValidationDisplayPath(root, path)
			if err != nil {
				return err
			}
			if pattern, ok := schemaValidationIgnoredByPattern(displayPath, ignored); ok {
				if entry.IsDir() {
					nestedIgnored, err := collectIgnoredSchemaValidationJSON(root, path, pattern, &budget)
					if err != nil {
						return err
					}
					ignoredDocuments = append(ignoredDocuments, nestedIgnored...)
					return filepath.SkipDir
				}
				if strings.EqualFold(filepath.Ext(path), ".json") {
					if err := budget.accept(path, entry); err != nil {
						return err
					}
					ignoredDocuments = append(ignoredDocuments, schemaValidationIgnoredDocument{File: displayPath, Pattern: pattern})
				}
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			if err := budget.accept(path, entry); err != nil {
				return err
			}
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return paths, ignoredDocuments, nil
}

func (budget *schemaValidationDirectoryScanBudget) accept(path string, entry os.DirEntry) error {
	budget.files++
	if budget.files > maxSchemaValidationDirectoryFiles {
		return fmt.Errorf("schema validation directory file count limit exceeded: max %d", maxSchemaValidationDirectoryFiles)
	}
	info, err := entry.Info()
	if err != nil {
		return err
	}
	size := info.Size()
	if size > maxSchemaValidationDirectoryFileBytes {
		return fmt.Errorf("schema validation directory file size limit exceeded for %s: max %d bytes", filepath.ToSlash(path), maxSchemaValidationDirectoryFileBytes)
	}
	budget.totalBytes += size
	if budget.totalBytes > maxSchemaValidationDirectoryTotalBytes {
		return fmt.Errorf("schema validation directory total byte limit exceeded: max %d bytes", maxSchemaValidationDirectoryTotalBytes)
	}
	return nil
}

func collectIgnoredSchemaValidationJSON(root string, ignoredRoot string, pattern string, budget *schemaValidationDirectoryScanBudget) ([]schemaValidationIgnoredDocument, error) {
	var documents []schemaValidationIgnoredDocument
	if err := filepath.WalkDir(ignoredRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("schema validation directory symlink is not allowed: %s", filepath.ToSlash(path))
		}
		if entry.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		if err := budget.accept(path, entry); err != nil {
			return err
		}
		displayPath, err := schemaValidationDisplayPath(root, path)
		if err != nil {
			return err
		}
		documents = append(documents, schemaValidationIgnoredDocument{File: displayPath, Pattern: pattern})
		return nil
	}); err != nil {
		return nil, err
	}
	return documents, nil
}

func normalizeSchemaValidationIgnorePatterns(patterns []string) ([]string, error) {
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		value := strings.TrimSpace(pattern)
		displayPath := filepath.ToSlash(filepath.Clean(value))
		if value == "" || displayPath == "." || displayPath == ".." || strings.HasPrefix(displayPath, "../") || strings.HasPrefix(displayPath, "/") || strings.Contains(value, "\\") || filepath.IsAbs(value) {
			return nil, fmt.Errorf("invalid ignore pattern %q", pattern)
		}
		normalized = append(normalized, displayPath)
	}
	return normalized, nil
}

func normalizeSchemaValidationSchemaFilters(values []string) ([]string, error) {
	filters := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("invalid schema filter %q", raw)
		}
		if !schema.KnownSchemaID(value) {
			return nil, fmt.Errorf("unknown schema filter %q", value)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		filters = append(filters, value)
	}
	return filters, nil
}

func schemaValidationPathIgnored(displayPath string, ignored []string) bool {
	_, ok := schemaValidationIgnoredByPattern(displayPath, ignored)
	return ok
}

func schemaValidationIgnoredByPattern(displayPath string, ignored []string) (string, bool) {
	for _, pattern := range ignored {
		if displayPath == pattern || strings.HasPrefix(displayPath, pattern+"/") {
			return pattern, true
		}
	}
	return "", false
}

func readSchemaValidationManifest(manifestPath string) ([]schemaValidationInputDocument, error) {
	bytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read schema validation manifest: %w", err)
	}
	baseDir := filepath.Dir(manifestPath)
	lines := strings.Split(string(bytes), "\n")
	documents := make([]schemaValidationInputDocument, 0, len(lines))
	for index, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		displayPath := filepath.ToSlash(filepath.Clean(entry))
		if displayPath == "." || displayPath == ".." || strings.HasPrefix(displayPath, "../") || strings.Contains(entry, "\\") || filepath.IsAbs(entry) {
			return nil, fmt.Errorf("invalid manifest entry on line %d: %q", index+1, entry)
		}
		documents = append(documents, schemaValidationInputDocument{
			Path:        filepath.Join(baseDir, filepath.FromSlash(displayPath)),
			DisplayPath: displayPath,
		})
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("no schema documents listed in %s", manifestPath)
	}
	return documents, nil
}
