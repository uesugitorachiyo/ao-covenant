package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseFixtureIndexMatchesTestdata(t *testing.T) {
	indexBytes, err := os.ReadFile(filepath.Join("testdata", "release-fixture-index.json"))
	if err != nil {
		t.Fatalf("read release fixture index: %v", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseFixtureIndexSchemaID, indexBytes); err != nil {
		t.Fatalf("release fixture index did not validate against published schema: %v\njson:\n%s", err, string(indexBytes))
	}

	var index releaseFixtureIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("decode release fixture index: %v", err)
	}
	if index.SchemaVersion != "covenant.release-fixture-index.v1" {
		t.Fatalf("schema_version = %q, want covenant.release-fixture-index.v1", index.SchemaVersion)
	}
	if len(index.Fixtures) == 0 {
		t.Fatalf("fixture index is empty")
	}
	if problems := releaseFixtureIndexPathProblems(index); len(problems) > 0 {
		t.Fatalf("release fixture index path problems:\n%s", strings.Join(problems, "\n"))
	}
	if problems := releaseFixtureIndexCommandProblems(index); len(problems) > 0 {
		t.Fatalf("release fixture index command problems:\n%s", strings.Join(problems, "\n"))
	}

	gotDirs := map[string]bool{}
	for _, fixture := range index.Fixtures {
		if strings.TrimSpace(fixture.Name) == "" {
			t.Fatalf("fixture entry has empty name: %+v", fixture)
		}
		if strings.TrimSpace(fixture.Directory) == "" {
			t.Fatalf("%s has empty directory", fixture.Name)
		}
		if strings.TrimSpace(fixture.Purpose) == "" {
			t.Fatalf("%s has empty purpose", fixture.Name)
		}
		if strings.TrimSpace(fixture.CheckCommand) == "" {
			t.Fatalf("%s has empty check_command", fixture.Name)
		}
		if fixture.Generated && strings.TrimSpace(fixture.RefreshCommand) == "" {
			t.Fatalf("%s is generated but has empty refresh_command", fixture.Name)
		}
		gotDirs[fixture.Directory] = true

		gotFiles := releaseFixtureFilesInDir(t, fixture.Directory)
		wantFiles := append([]string{}, fixture.Files...)
		sort.Strings(wantFiles)
		if !reflect.DeepEqual(gotFiles, wantFiles) {
			t.Fatalf("%s files = %+v, want %+v", fixture.Directory, gotFiles, wantFiles)
		}
	}

	for _, dir := range releaseFixtureDirectories(t) {
		if !gotDirs[dir] {
			t.Fatalf("release fixture directory %s is not indexed", dir)
		}
	}
}

func TestReleaseFixtureIndexPathProblemsReportMissingDirectoriesAndFiles(t *testing.T) {
	index := releaseFixtureIndex{Fixtures: []releaseFixtureIndexEntry{
		{
			Name:      "missing-dir",
			Directory: "internal/cli/testdata/missing-release-fixtures",
			Files:     []string{"missing.json"},
		},
		{
			Name:      "missing-file",
			Directory: "internal/cli/testdata/redaction-policies",
			Files:     []string{"missing-release-redaction-policy.json"},
		},
	}}

	problems := releaseFixtureIndexPathProblems(index)

	if !containsStringWithSubstring(problems, "missing-dir directory does not exist") {
		t.Fatalf("problems = %+v, want missing directory diagnostic", problems)
	}
	if !containsStringWithSubstring(problems, "missing-file file does not exist") {
		t.Fatalf("problems = %+v, want missing file diagnostic", problems)
	}
}

func TestReleaseFixtureIndexCommandProblemsReportMissingPackagesAndTests(t *testing.T) {
	index := releaseFixtureIndex{Fixtures: []releaseFixtureIndexEntry{
		{
			Name:         "missing-package",
			CheckCommand: "go test ./internal/missing-release-package -run ReleaseJSONFixtures -count=1",
		},
		{
			Name:           "missing-refresh-test",
			Generated:      true,
			CheckCommand:   "go test ./internal/cli -run ReleaseReportTextFixtures -count=1",
			RefreshCommand: "COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1 go test ./internal/cli -run MissingReleaseFixtureRefresh -count=1",
		},
	}}

	problems := releaseFixtureIndexCommandProblems(index)

	if !containsStringWithSubstring(problems, "missing-package check_command package does not exist") {
		t.Fatalf("problems = %+v, want missing package diagnostic", problems)
	}
	if !containsStringWithSubstring(problems, "missing-refresh-test refresh_command has no matching tests") {
		t.Fatalf("problems = %+v, want missing refresh test diagnostic", problems)
	}
}

func TestReleaseFixtureIndexCommandProblemsReportCommandShapeDrift(t *testing.T) {
	index := releaseFixtureIndex{Fixtures: []releaseFixtureIndexEntry{
		{
			Name:         "check-env",
			CheckCommand: "COVENANT_UPDATE_RELEASE_FIXTURES=1 go test ./internal/cli -run ReleaseReportTextFixtures -count=1",
		},
		{
			Name:         "missing-count",
			CheckCommand: "go test ./internal/cli -run ReleaseReportTextFixtures",
		},
		{
			Name:         "wrong-count",
			CheckCommand: "go test ./internal/cli -run ReleaseReportTextFixtures -count=2",
		},
		{
			Name:         "disallowed-package",
			CheckCommand: "go test ./internal/policy -run Policy -count=1",
		},
		{
			Name:           "release-report-text",
			Generated:      true,
			CheckCommand:   "go test ./internal/cli -run ReleaseReportTextFixtures -count=1",
			RefreshCommand: "COVENANT_UPDATE_RELEASE_DIFF_FIXTURES=1 go test ./internal/cli -run ReleaseReportTextFixtures -count=1",
		},
		{
			Name:           "release-diff-sarif",
			Generated:      true,
			CheckCommand:   "go test ./internal/cli -run ReleaseDiffSARIFFixtures -count=1",
			RefreshCommand: "go test ./internal/cli -run ReleaseDiffSARIFFixtures -count=1",
		},
	}}

	problems := releaseFixtureIndexCommandProblems(index)

	for _, want := range []string{
		"check-env check_command must not set environment variables",
		"missing-count check_command is missing -count=1",
		"wrong-count check_command must use -count=1",
		"disallowed-package check_command package is not allowed",
		"release-report-text refresh_command must set COVENANT_UPDATE_RELEASE_REPORT_FIXTURES=1",
		"release-diff-sarif refresh_command must set COVENANT_UPDATE_RELEASE_DIFF_FIXTURES=1",
	} {
		if !containsStringWithSubstring(problems, want) {
			t.Fatalf("problems = %+v, want %q", problems, want)
		}
	}
}

type releaseFixtureIndex struct {
	SchemaVersion string                     `json:"schema_version"`
	Fixtures      []releaseFixtureIndexEntry `json:"fixtures"`
}

type releaseFixtureIndexEntry struct {
	Name           string   `json:"name"`
	Directory      string   `json:"directory"`
	Purpose        string   `json:"purpose"`
	Generated      bool     `json:"generated"`
	RefreshCommand string   `json:"refresh_command,omitempty"`
	CheckCommand   string   `json:"check_command"`
	Files          []string `json:"files"`
}

func releaseFixtureIndexPathProblems(index releaseFixtureIndex) []string {
	var problems []string
	for _, fixture := range index.Fixtures {
		fsDir := releaseFixtureFilesystemPath(fixture.Directory)
		info, err := os.Stat(fsDir)
		if err != nil {
			if os.IsNotExist(err) {
				problems = append(problems, fmt.Sprintf("%s directory does not exist: %s", fixture.Name, fixture.Directory))
				continue
			}
			problems = append(problems, fmt.Sprintf("%s directory cannot be inspected: %s: %v", fixture.Name, fixture.Directory, err))
			continue
		}
		if !info.IsDir() {
			problems = append(problems, fmt.Sprintf("%s directory is not a directory: %s", fixture.Name, fixture.Directory))
			continue
		}
		for _, name := range fixture.Files {
			path := filepath.Join(fsDir, name)
			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					problems = append(problems, fmt.Sprintf("%s file does not exist: %s/%s", fixture.Name, fixture.Directory, name))
					continue
				}
				problems = append(problems, fmt.Sprintf("%s file cannot be inspected: %s/%s: %v", fixture.Name, fixture.Directory, name, err))
				continue
			}
			if info.IsDir() {
				problems = append(problems, fmt.Sprintf("%s file is a directory: %s/%s", fixture.Name, fixture.Directory, name))
			}
		}
	}
	return problems
}

func containsStringWithSubstring(values []string, substring string) bool {
	for _, value := range values {
		if strings.Contains(value, substring) {
			return true
		}
	}
	return false
}

func releaseFixtureIndexCommandProblems(index releaseFixtureIndex) []string {
	var problems []string
	for _, fixture := range index.Fixtures {
		problems = append(problems, releaseFixtureCommandProblems(fixture.Name, "check_command", fixture.CheckCommand)...)
		if fixture.Generated {
			problems = append(problems, releaseFixtureCommandProblems(fixture.Name, "refresh_command", fixture.RefreshCommand)...)
		}
	}
	return problems
}

func releaseFixtureCommandProblems(fixtureName string, fieldName string, command string) []string {
	var problems []string
	parsed, ok, problem := parseReleaseFixtureGoTestCommand(command)
	if !ok {
		return append(problems, fmt.Sprintf("%s %s %s", fixtureName, fieldName, problem))
	}
	problems = append(problems, releaseFixtureCommandShapeProblems(fixtureName, fieldName, parsed)...)
	packagePath := parsed.PackagePath
	packageDir := releaseFixtureGoTestPackageDir(packagePath)
	info, err := os.Stat(packageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return append(problems, fmt.Sprintf("%s %s package does not exist: %s", fixtureName, fieldName, packagePath))
		}
		return append(problems, fmt.Sprintf("%s %s package cannot be inspected: %s: %v", fixtureName, fieldName, packagePath, err))
	}
	if !info.IsDir() {
		return append(problems, fmt.Sprintf("%s %s package is not a directory: %s", fixtureName, fieldName, packagePath))
	}
	runPattern := parsed.RunPattern
	matcher, err := regexp.Compile(runPattern)
	if err != nil {
		return append(problems, fmt.Sprintf("%s %s has invalid -run regexp %q: %v", fixtureName, fieldName, runPattern, err))
	}
	tests, err := releaseFixtureGoTestNames(packageDir)
	if err != nil {
		return append(problems, fmt.Sprintf("%s %s package tests cannot be inspected: %s: %v", fixtureName, fieldName, packagePath, err))
	}
	for _, testName := range tests {
		if matcher.MatchString(testName) {
			return problems
		}
	}
	return append(problems, fmt.Sprintf("%s %s has no matching tests for -run %q in %s", fixtureName, fieldName, runPattern, packagePath))
}

type releaseFixtureGoTestCommand struct {
	Env         map[string]string
	PackagePath string
	RunPattern  string
	Count       string
}

func releaseFixtureCommandShapeProblems(fixtureName string, fieldName string, command releaseFixtureGoTestCommand) []string {
	var problems []string
	if !releaseFixtureAllowedGoTestPackage(command.PackagePath) {
		problems = append(problems, fmt.Sprintf("%s %s package is not allowed: %s", fixtureName, fieldName, command.PackagePath))
	}
	if command.Count == "" {
		problems = append(problems, fmt.Sprintf("%s %s is missing -count=1", fixtureName, fieldName))
	} else if command.Count != "1" {
		problems = append(problems, fmt.Sprintf("%s %s must use -count=1, got -count=%s", fixtureName, fieldName, command.Count))
	}
	if fieldName == "check_command" {
		if len(command.Env) > 0 {
			problems = append(problems, fmt.Sprintf("%s %s must not set environment variables", fixtureName, fieldName))
		}
		return problems
	}

	expectedEnv, ok := releaseFixtureExpectedRefreshEnv(fixtureName)
	if !ok {
		problems = append(problems, fmt.Sprintf("%s %s has no expected refresh environment variable configured", fixtureName, fieldName))
		return problems
	}
	if command.Env[expectedEnv] != "1" || len(command.Env) != 1 {
		problems = append(problems, fmt.Sprintf("%s %s must set %s=1", fixtureName, fieldName, expectedEnv))
	}
	for _, name := range sortedMapKeys(command.Env) {
		if name != expectedEnv {
			problems = append(problems, fmt.Sprintf("%s %s sets unsupported environment variable %s", fixtureName, fieldName, name))
		}
	}
	return problems
}

func releaseFixtureAllowedGoTestPackage(packagePath string) bool {
	switch packagePath {
	case "./internal/cli", "./internal/release", "./internal/schema":
		return true
	default:
		return false
	}
}

func releaseFixtureExpectedRefreshEnv(fixtureName string) (string, bool) {
	switch fixtureName {
	case "release-json":
		return "COVENANT_UPDATE_RELEASE_FIXTURES", true
	case "release-report-text", "release-report-sarif":
		return "COVENANT_UPDATE_RELEASE_REPORT_FIXTURES", true
	case "release-diff-sarif":
		return "COVENANT_UPDATE_RELEASE_DIFF_FIXTURES", true
	default:
		return "", false
	}
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func parseReleaseFixtureGoTestCommand(command string) (releaseFixtureGoTestCommand, bool, string) {
	parsed := releaseFixtureGoTestCommand{Env: map[string]string{}}
	fields := strings.Fields(command)
	index := 0
	for index < len(fields) && releaseFixtureCommandEnvAssignment(fields[index]) {
		name, value, _ := strings.Cut(fields[index], "=")
		parsed.Env[name] = releaseFixtureUnquoteCommandToken(value)
		index++
	}
	if index+2 >= len(fields) || fields[index] != "go" || fields[index+1] != "test" {
		return parsed, false, "is not a go test command"
	}
	parsed.PackagePath = fields[index+2]
	for i := index + 3; i < len(fields); i++ {
		switch {
		case fields[i] == "-run" && i+1 < len(fields):
			parsed.RunPattern = releaseFixtureUnquoteCommandToken(fields[i+1])
			i++
		case fields[i] == "-count" && i+1 < len(fields):
			parsed.Count = releaseFixtureUnquoteCommandToken(fields[i+1])
			i++
		case strings.HasPrefix(fields[i], "-run="):
			parsed.RunPattern = releaseFixtureUnquoteCommandToken(strings.TrimPrefix(fields[i], "-run="))
		case strings.HasPrefix(fields[i], "-count="):
			parsed.Count = releaseFixtureUnquoteCommandToken(strings.TrimPrefix(fields[i], "-count="))
		}
	}
	if strings.TrimSpace(parsed.RunPattern) == "" {
		return parsed, false, "is missing -run"
	}
	return parsed, true, ""
}

func releaseFixtureCommandEnvAssignment(token string) bool {
	if strings.HasPrefix(token, "-") || !strings.Contains(token, "=") {
		return false
	}
	name, _, ok := strings.Cut(token, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
			continue
		}
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func releaseFixtureUnquoteCommandToken(token string) string {
	token = strings.TrimSpace(token)
	if len(token) >= 2 {
		first := token[0]
		last := token[len(token)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			return token[1 : len(token)-1]
		}
	}
	return token
}

func releaseFixtureGoTestPackageDir(packagePath string) string {
	if packagePath == "./internal/cli" {
		return "."
	}
	if strings.HasPrefix(packagePath, "./") {
		return filepath.Join("..", "..", strings.TrimPrefix(packagePath, "./"))
	}
	return packagePath
}

func releaseFixtureGoTestNames(packageDir string) ([]string, error) {
	var tests []string
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, err
	}
	testDecl := regexp.MustCompile(`^func (Test[A-Za-z0-9_]+)\(`)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		bytes, err := os.ReadFile(filepath.Join(packageDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(bytes), "\n") {
			matches := testDecl.FindStringSubmatch(line)
			if len(matches) == 2 {
				tests = append(tests, matches[1])
			}
		}
	}
	sort.Strings(tests)
	return tests, nil
}

func releaseFixtureDirectories(t *testing.T) []string {
	t.Helper()
	dirs := []string{}
	for _, root := range []string{
		filepath.Join("testdata"),
		filepath.Join("..", "schema", "testdata"),
	} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() {
				return nil
			}
			files := releaseFixtureFilesInDir(t, path)
			if len(files) == 0 {
				return nil
			}
			slashPath := filepath.ToSlash(path)
			if strings.Contains(slashPath, "release-") || strings.Contains(slashPath, "redaction-policies") {
				dirs = append(dirs, releaseFixtureRepoPath(path))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func releaseFixtureFilesInDir(t *testing.T, dir string) []string {
	t.Helper()
	fsDir := releaseFixtureFilesystemPath(dir)
	entries, err := os.ReadDir(fsDir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", dir, err)
	}
	files := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files
}

func releaseFixtureFilesystemPath(dir string) string {
	switch {
	case strings.HasPrefix(dir, "internal/cli/"):
		return strings.TrimPrefix(dir, "internal/cli/")
	case strings.HasPrefix(dir, "internal/schema/"):
		return filepath.Join("..", "schema", strings.TrimPrefix(dir, "internal/schema/"))
	default:
		return dir
	}
}

func releaseFixtureRepoPath(path string) string {
	slashPath := filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(slashPath, "testdata/"):
		return "internal/cli/" + slashPath
	case strings.HasPrefix(slashPath, "../schema/"):
		return "internal/schema/" + strings.TrimPrefix(slashPath, "../schema/")
	default:
		return slashPath
	}
}
