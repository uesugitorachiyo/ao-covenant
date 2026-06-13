package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseDiffSARIFFixturesMatchGeneratedGoldenFiles(t *testing.T) {
	for _, fixture := range releaseDiffSARIFFixtureGoldenFiles(t) {
		fixture.assertFresh(t)
	}
}

type releaseDiffSARIFFixtureGoldenFile struct {
	FileName string
	JSON     []byte
}

func releaseDiffSARIFFixtureGoldenFiles(t *testing.T) []releaseDiffSARIFFixtureGoldenFile {
	t.Helper()

	matching := releaseDiffSARIFMatchingFixtureReport()
	changed := releaseDiffSARIFChangedFixtureReport()
	suppressed := releasepkg.DiffSARIFWithOptions(changed, releasepkg.DiffSARIFOptions{
		Baseline: schema.SARIFBaseline{Accepted: []schema.SARIFBaselineEntry{
			{
				RuleID:        "RELEASE_DIFF_METADATA",
				SourceURI:     "dist/v0.2.0/manifest.json",
				Field:         "metadata:version",
				Justification: "accepted fixture version drift",
			},
			{
				RuleID:        "RELEASE_DIFF_ARTIFACT",
				SourceURI:     "dist/v0.2.0/manifest.json",
				Field:         "artifacts:covenant-darwin-arm64",
				Justification: "accepted fixture artifact drift",
			},
			{
				RuleID:        "RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT",
				SourceURI:     "dist/v0.2.0/manifest.json",
				Field:         "supplemental_artifacts:sbom.spdx.json",
				Justification: "accepted fixture supplemental drift",
			},
			{
				RuleID:        "RELEASE_DIFF_SIGNATURE",
				SourceURI:     "dist/v0.2.0/manifest.json",
				Field:         "signatures:public_key_sha256",
				Justification: "accepted fixture signature drift",
			},
			{
				RuleID:        "RELEASE_DIFF_PROBLEM",
				SourceURI:     "dist/v0.1.0/manifest.json",
				Field:         "problems:from",
				Justification: "accepted fixture problem drift",
			},
		}},
	})

	return []releaseDiffSARIFFixtureGoldenFile{
		{FileName: "sarif-matching.json", JSON: marshalReleaseDiffSARIFFixture(t, releasepkg.DiffSARIF(matching))},
		{FileName: "sarif-changed.json", JSON: marshalReleaseDiffSARIFFixture(t, releasepkg.DiffSARIF(changed))},
		{FileName: "sarif-baseline-suppressed.json", JSON: marshalReleaseDiffSARIFFixture(t, suppressed)},
	}
}

func releaseDiffSARIFMatchingFixtureReport() releasepkg.DiffReport {
	return releasepkg.DiffReport{
		FromDir: "dist/v0.1.0",
		ToDir:   "dist/v0.1.0",
		Changed: false,
		Entries: []releasepkg.DiffEntry{},
	}
}

func releaseDiffSARIFChangedFixtureReport() releasepkg.DiffReport {
	return releasepkg.DiffReport{
		FromDir: "dist/v0.1.0",
		ToDir:   "dist/v0.2.0",
		Changed: true,
		Entries: []releasepkg.DiffEntry{
			{Category: "metadata", Action: "changed", Name: "version", Detail: "v0.1.0 -> v0.2.0"},
			{Category: "artifacts", Action: "added", Name: "covenant-darwin-arm64", Detail: "darwin/arm64"},
			{Category: "supplemental_artifacts", Action: "changed", Name: "sbom.spdx.json", Detail: "sha256 changed"},
			{Category: "signatures", Action: "changed", Name: "public_key_sha256", Detail: "1111111111111111111111111111111111111111111111111111111111111111 -> bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			{Category: "problems", Action: "present", Name: "from", Detail: "release signature verification failed"},
		},
	}
}

func marshalReleaseDiffSARIFFixture(t *testing.T, value schema.SARIFLog) []byte {
	t.Helper()
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal release diff SARIF fixture: %v", err)
	}
	return append(bytes, '\n')
}

func (fixture releaseDiffSARIFFixtureGoldenFile) assertFresh(t *testing.T) {
	t.Helper()

	var sarif schema.SARIFLog
	if err := json.Unmarshal(fixture.JSON, &sarif); err != nil {
		t.Fatalf("generated %s is not SARIF JSON: %v\njson:\n%s", fixture.FileName, err, string(fixture.JSON))
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Fatalf("generated %s = %+v, want one SARIF 2.1.0 run", fixture.FileName, sarif)
	}
	switch fixture.FileName {
	case "sarif-matching.json":
		if len(sarif.Runs[0].Results) != 0 {
			t.Fatalf("%s results = %+v, want none", fixture.FileName, sarif.Runs[0].Results)
		}
	case "sarif-changed.json":
		requireReleaseDiffSARIFFixtureRules(t, fixture.FileName, sarif, map[string]bool{
			"RELEASE_DIFF_METADATA":              true,
			"RELEASE_DIFF_ARTIFACT":              true,
			"RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT": true,
			"RELEASE_DIFF_SIGNATURE":             true,
			"RELEASE_DIFF_PROBLEM":               true,
		})
	case "sarif-baseline-suppressed.json":
		if len(sarif.Runs[0].Results) == 0 {
			t.Fatalf("%s results = none, want suppressed findings", fixture.FileName)
		}
		for _, result := range sarif.Runs[0].Results {
			if len(result.Suppressions) != 1 || result.Suppressions[0].Kind != "external" {
				t.Fatalf("%s result = %+v, want one external suppression", fixture.FileName, result)
			}
		}
	default:
		t.Fatalf("unexpected SARIF fixture %s", fixture.FileName)
	}

	path := filepath.Join("testdata", "release-diff-sarif-fixtures", fixture.FileName)
	if os.Getenv("COVENANT_UPDATE_RELEASE_DIFF_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture dir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, fixture.JSON, 0o644); err != nil {
			t.Fatalf("update %s: %v", path, err)
		}
	}

	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(normalizeGoldenFixtureBytes(golden), normalizeGoldenFixtureBytes(fixture.JSON)) {
		t.Fatalf("%s is stale; regenerate with COVENANT_UPDATE_RELEASE_DIFF_FIXTURES=1 go test ./internal/cli -run 'ReleaseDiffSARIFFixtures' -count=1", path)
	}
}

func normalizeGoldenFixtureBytes(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func requireReleaseDiffSARIFFixtureRules(t *testing.T, fileName string, sarif schema.SARIFLog, want map[string]bool) {
	t.Helper()
	got := map[string]bool{}
	for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
		got[rule.ID] = true
	}
	for ruleID := range want {
		if !got[ruleID] {
			t.Fatalf("%s rules = %+v, want %s", fileName, sarif.Runs[0].Tool.Driver.Rules, ruleID)
		}
	}
}
