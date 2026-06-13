package release

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestDefaultTargetsCoverSupportedReleaseMatrix(t *testing.T) {
	want := []Target{
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "windows", Arch: "amd64"},
	}

	got := DefaultTargets()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultTargets() = %+v, want %+v", got, want)
	}
}

func TestPackageDefaultsToSupportedReleaseTargetMatrix(t *testing.T) {
	outDir := t.TempDir()
	var requests []BuildRequest
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		requests = append(requests, req)
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	wantTargets := []Target{
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "windows", Arch: "amd64"},
	}
	wantNames := []string{
		"ao-covenant_v0.1.0_linux_amd64",
		"ao-covenant_v0.1.0_linux_arm64",
		"ao-covenant_v0.1.0_darwin_amd64",
		"ao-covenant_v0.1.0_darwin_arm64",
		"ao-covenant_v0.1.0_windows_amd64.exe",
	}
	if len(requests) != len(wantTargets) {
		t.Fatalf("build requests len = %d, want %d", len(requests), len(wantTargets))
	}
	if len(result.Artifacts) != len(wantNames) {
		t.Fatalf("artifacts len = %d, want %d", len(result.Artifacts), len(wantNames))
	}
	for index, wantTarget := range wantTargets {
		if requests[index].Target != wantTarget {
			t.Fatalf("request[%d].Target = %+v, want %+v", index, requests[index].Target, wantTarget)
		}
		if result.Artifacts[index].Target != wantTarget {
			t.Fatalf("artifact[%d].Target = %+v, want %+v", index, result.Artifacts[index].Target, wantTarget)
		}
		if result.Manifest.Artifacts[index].Target != wantTarget {
			t.Fatalf("manifest artifact[%d].Target = %+v, want %+v", index, result.Manifest.Artifacts[index].Target, wantTarget)
		}
		if result.Artifacts[index].Name != wantNames[index] {
			t.Fatalf("artifact[%d].Name = %q, want %q", index, result.Artifacts[index].Name, wantNames[index])
		}
		if result.Artifacts[index].Path != wantNames[index] {
			t.Fatalf("artifact[%d].Path = %q, want %q", index, result.Artifacts[index].Path, wantNames[index])
		}
		if _, err := os.Stat(filepath.Join(outDir, wantNames[index])); err != nil {
			t.Fatalf("expected artifact %s: %v", wantNames[index], err)
		}
	}
	checksums, err := os.ReadFile(result.ChecksumsPath)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	for _, wantName := range wantNames {
		if !strings.Contains(string(checksums), "  "+wantName+"\n") {
			t.Fatalf("checksums = %q, want %s", string(checksums), wantName)
		}
	}
	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseManifestSchemaID, manifestBytes); err != nil {
		t.Fatalf("manifest did not match published schema: %v\njson:\n%s", err, string(manifestBytes))
	}
}

func TestPackageBuildsArtifactsManifestAndChecksums(t *testing.T) {
	outDir := t.TempDir()
	var requests []BuildRequest
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		requests = append(requests, req)
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets: []Target{
			{OS: "linux", Arch: "amd64"},
			{OS: "windows", Arch: "amd64"},
		},
		Build: fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	if result.ManifestPath != filepath.Join(outDir, "manifest.json") {
		t.Fatalf("manifest path = %q", result.ManifestPath)
	}
	if result.ChecksumsPath != filepath.Join(outDir, "SHA256SUMS") {
		t.Fatalf("checksums path = %q", result.ChecksumsPath)
	}
	wantNames := []string{
		"ao-covenant_v0.1.0_linux_amd64",
		"ao-covenant_v0.1.0_windows_amd64.exe",
	}
	if len(result.Artifacts) != len(wantNames) {
		t.Fatalf("artifacts len = %d, want %d", len(result.Artifacts), len(wantNames))
	}
	for i, want := range wantNames {
		if result.Artifacts[i].Name != want {
			t.Fatalf("artifact %d name = %q, want %q", i, result.Artifacts[i].Name, want)
		}
		if result.Artifacts[i].SHA256 == "" {
			t.Fatalf("artifact %d sha256 is empty", i)
		}
		if result.Artifacts[i].SizeBytes == 0 {
			t.Fatalf("artifact %d size is zero", i)
		}
	}

	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SchemaVersion != schema.ReleaseManifestSchemaID {
		t.Fatalf("manifest schema_version = %q, want %q", manifest.SchemaVersion, schema.ReleaseManifestSchemaID)
	}
	if err := schema.ValidateBytes(schema.ReleaseManifestSchemaID, manifestBytes); err != nil {
		t.Fatalf("manifest did not match published schema: %v\njson:\n%s", err, string(manifestBytes))
	}
	if manifest.Version != "v0.1.0" || manifest.Commit != "abc123" || manifest.Date != "2026-06-11T00:00:00Z" {
		t.Fatalf("manifest metadata = %+v", manifest)
	}
	if len(manifest.Artifacts) != 2 {
		t.Fatalf("manifest artifacts len = %d, want 2", len(manifest.Artifacts))
	}

	checksums, err := os.ReadFile(result.ChecksumsPath)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	for _, want := range wantNames {
		if !strings.Contains(string(checksums), "  "+want+"\n") {
			t.Fatalf("checksums = %q, want %s", string(checksums), want)
		}
	}

	if len(requests) != 2 {
		t.Fatalf("build requests len = %d, want 2", len(requests))
	}
	for _, request := range requests {
		for _, want := range []string{
			"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo.Version=v0.1.0",
			"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo.Commit=abc123",
			"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo.Date=2026-06-11T00:00:00Z",
		} {
			if !strings.Contains(request.LDFlags, want) {
				t.Fatalf("ldflags = %q, want %s", request.LDFlags, want)
			}
		}
	}
}

func TestPackageIncludesSupplementalArtifacts(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	provenancePath := filepath.Join(inputDir, "provenance.intoto.json")
	if err := os.WriteFile(sbomPath, []byte(`{"spdxVersion":"SPDX-2.3"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	if err := os.WriteFile(provenancePath, []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir:       ".",
		OutDir:          outDir,
		Version:         "v0.1.0",
		Commit:          "abc123",
		Date:            "2026-06-12T00:00:00Z",
		Targets:         []Target{{OS: "linux", Arch: "amd64"}},
		Build:           fakeBuild,
		SBOMPaths:       []string{sbomPath},
		ProvenancePaths: []string{provenancePath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	if len(result.Manifest.SupplementalArtifacts) != 2 {
		t.Fatalf("supplemental artifacts len = %d, want 2", len(result.Manifest.SupplementalArtifacts))
	}
	want := map[string]string{
		"sbom":       "sbom.spdx.json",
		"provenance": "provenance.intoto.json",
	}
	for _, supplemental := range result.Manifest.SupplementalArtifacts {
		if want[supplemental.Kind] != supplemental.Path || supplemental.Name != supplemental.Path {
			t.Fatalf("supplemental artifact = %+v, want kind/path in %+v", supplemental, want)
		}
		if supplemental.SHA256 == "" || supplemental.SizeBytes == 0 {
			t.Fatalf("supplemental digest/size = %+v", supplemental)
		}
		if _, err := os.Stat(filepath.Join(outDir, supplemental.Path)); err != nil {
			t.Fatalf("expected supplemental file %s: %v", supplemental.Path, err)
		}
	}
	manifestBytes, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseManifestSchemaID, manifestBytes); err != nil {
		t.Fatalf("manifest did not match published schema: %v\njson:\n%s", err, string(manifestBytes))
	}
	checksums, err := os.ReadFile(result.ChecksumsPath)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	for _, wantPath := range []string{"sbom.spdx.json", "provenance.intoto.json"} {
		if !strings.Contains(string(checksums), "  "+wantPath+"\n") {
			t.Fatalf("checksums = %q, want supplemental %s", string(checksums), wantPath)
		}
	}
	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("verified = false, problems = %+v", report.Problems)
	}
	inspection, err := Inspect(InspectOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.ChecksumStatus != "verified" || len(inspection.Problems) != 0 {
		t.Fatalf("inspection = %+v, want supplemental artifacts accepted", inspection)
	}
}

func TestInspectSARIFReportsArtifactAttestationAndSupplementalProblems(t *testing.T) {
	artifactProblem := `artifact "app-linux-amd64" sha256 mismatch: got bad want good`
	attestationProblem := `attestation "app.intoto.json" missing SHA256SUMS entry`
	supplementalProblem := `supplemental artifact "sbom.spdx.json" missing SHA256SUMS entry`
	releaseProblem := `SHA256SUMS contains unmanifested artifact "extra.bin"`
	result := InspectResult{
		ReleaseDir:    "dist/release",
		ManifestPath:  "dist/release/manifest.json",
		ChecksumsPath: "dist/release/SHA256SUMS",
		Problems: []string{
			artifactProblem,
			attestationProblem,
			supplementalProblem,
			releaseProblem,
		},
		Artifacts: []ArtifactVerifyReport{{
			Name:     "app-linux-amd64",
			Path:     "bin/app",
			Problems: []string{artifactProblem},
			Attestations: []AttestationVerifyReport{{
				Name:     "app.intoto.json",
				Path:     "bin/app.intoto.json",
				Problems: []string{attestationProblem},
			}},
		}},
		SupplementalArtifacts: []SupplementalVerifyReport{{
			Kind:     "sbom",
			Name:     "sbom.spdx.json",
			Path:     "sbom.spdx.json",
			Problems: []string{supplementalProblem},
		}},
	}

	sarif := InspectSARIF(result)

	if sarif.Version != "2.1.0" || sarif.Schema == "" {
		t.Fatalf("sarif header = %+v", sarif)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "AO Covenant Release Inspector" || run.Tool.Driver.InformationURI == "" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %+v, want four rules", run.Tool.Driver.Rules)
	}
	wantRuleIDs := []string{
		"RELEASE_ARTIFACT_PROBLEM",
		"RELEASE_ATTESTATION_PROBLEM",
		"RELEASE_SUPPLEMENTAL_PROBLEM",
		"RELEASE_PROBLEM",
	}
	for index, want := range wantRuleIDs {
		if run.Tool.Driver.Rules[index].ID != want {
			t.Fatalf("rule[%d].ID = %q, want %q", index, run.Tool.Driver.Rules[index].ID, want)
		}
	}
	if len(run.Results) != 4 {
		t.Fatalf("results len = %d, want 4", len(run.Results))
	}
	assertResult := func(index int, ruleID string, message string, uri string, wantProperties schema.SARIFResultProperties) {
		t.Helper()
		got := run.Results[index]
		if got.RuleID != ruleID || got.Level != "error" || got.Message.Text != message {
			t.Fatalf("result[%d] = %+v", index, got)
		}
		if uri == "" {
			if len(got.Locations) != 0 {
				t.Fatalf("result[%d] locations = %+v, want none", index, got.Locations)
			}
		} else if len(got.Locations) != 1 || got.Locations[0].PhysicalLocation.ArtifactLocation.URI != uri {
			t.Fatalf("result[%d] locations = %+v, want %s", index, got.Locations, uri)
		}
		if got.Properties.Component != wantProperties.Component ||
			got.Properties.Name != wantProperties.Name ||
			got.Properties.Kind != wantProperties.Kind ||
			got.Properties.ReleaseDir != wantProperties.ReleaseDir ||
			got.Properties.ArtifactName != wantProperties.ArtifactName {
			t.Fatalf("result[%d] properties = %+v, want %+v", index, got.Properties, wantProperties)
		}
	}
	assertResult(0, "RELEASE_ARTIFACT_PROBLEM", artifactProblem, "bin/app", schema.SARIFResultProperties{
		Component:  "artifact",
		Name:       "app-linux-amd64",
		ReleaseDir: "dist/release",
	})
	assertResult(1, "RELEASE_ATTESTATION_PROBLEM", attestationProblem, "bin/app.intoto.json", schema.SARIFResultProperties{
		Component:    "attestation",
		Name:         "app.intoto.json",
		ArtifactName: "app-linux-amd64",
		ReleaseDir:   "dist/release",
	})
	assertResult(2, "RELEASE_SUPPLEMENTAL_PROBLEM", supplementalProblem, "sbom.spdx.json", schema.SARIFResultProperties{
		Component:  "supplemental_artifact",
		Kind:       "sbom",
		Name:       "sbom.spdx.json",
		ReleaseDir: "dist/release",
	})
	assertResult(3, "RELEASE_PROBLEM", releaseProblem, "dist/release/SHA256SUMS", schema.SARIFResultProperties{
		Component:  "release",
		ReleaseDir: "dist/release",
	})
}

func TestVerifyRejectsTamperedSupplementalArtifact(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"spdxVersion":"SPDX-2.3"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-12T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
		SBOMPaths: []string{sbomPath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "sbom.spdx.json"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatalf("tamper sbom: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if report.Verified {
		t.Fatalf("verified = true, want false")
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), `supplemental artifact "sbom.spdx.json" sha256 mismatch`) {
		t.Fatalf("problems = %+v, want supplemental sha mismatch", report.Problems)
	}
	inspection, err := Inspect(InspectOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.ChecksumStatus != "invalid" || !strings.Contains(strings.Join(inspection.Problems, "\n"), `supplemental artifact "sbom.spdx.json" sha256 mismatch`) {
		t.Fatalf("inspection = %+v, want supplemental sha mismatch", inspection)
	}
	if result.Manifest.SupplementalArtifacts[0].Kind != "sbom" {
		t.Fatalf("supplemental kind = %q, want sbom", result.Manifest.SupplementalArtifacts[0].Kind)
	}
}

func TestPackageIncludesArtifactAttestations(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "attestation.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir:        ".",
		OutDir:           outDir,
		Version:          "v0.1.0",
		Commit:           "abc123",
		Date:             "2026-06-12T00:00:00Z",
		Targets:          []Target{{OS: "linux", Arch: "amd64"}},
		Build:            fakeBuild,
		AttestationPaths: []string{"linux/amd64=" + attestationPath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	artifact := result.Manifest.Artifacts[0]
	if len(artifact.Attestations) != 1 {
		t.Fatalf("attestations = %+v, want one", artifact.Attestations)
	}
	attestation := artifact.Attestations[0]
	if attestation.Name != "attestation.intoto.json" || attestation.Path != "ao-covenant_v0.1.0_linux_amd64.attestation.intoto.json" {
		t.Fatalf("attestation identity = %+v", attestation)
	}
	if attestation.SHA256 == "" || attestation.SizeBytes == 0 {
		t.Fatalf("attestation digest/size = %+v", attestation)
	}
	if _, err := os.Stat(filepath.Join(outDir, attestation.Path)); err != nil {
		t.Fatalf("expected attestation file %s: %v", attestation.Path, err)
	}
	checksums, err := os.ReadFile(result.ChecksumsPath)
	if err != nil {
		t.Fatalf("read checksums: %v", err)
	}
	if !strings.Contains(string(checksums), "  "+attestation.Path+"\n") {
		t.Fatalf("checksums = %q, want attestation %s", string(checksums), attestation.Path)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("verified = false, problems = %+v", report.Problems)
	}
	if len(report.Artifacts) != 1 || len(report.Artifacts[0].Attestations) != 1 || !report.Artifacts[0].Attestations[0].Verified {
		t.Fatalf("artifact attestation reports = %+v", report.Artifacts)
	}
	inspection, err := Inspect(InspectOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.ChecksumStatus != "verified" || len(inspection.Artifacts) != 1 || len(inspection.Artifacts[0].Attestations) != 1 || !inspection.Artifacts[0].Attestations[0].Verified {
		t.Fatalf("inspection = %+v, want verified attestation", inspection)
	}
}

func TestPackageAttestationKindPropagatesToVerifyAndInspect(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "slsa.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir:        ".",
		OutDir:           outDir,
		Version:          "v0.1.0",
		Commit:           "kind123",
		Date:             "2026-06-12T00:00:00Z",
		Targets:          []Target{{OS: "linux", Arch: "amd64"}},
		Build:            fakeBuild,
		AttestationPaths: []string{"kind:slsa,target:linux/amd64=" + attestationPath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	if len(result.Manifest.Artifacts) != 1 || len(result.Manifest.Artifacts[0].Attestations) != 1 {
		t.Fatalf("manifest artifacts = %+v, want one attestation", result.Manifest.Artifacts)
	}
	attestation := result.Manifest.Artifacts[0].Attestations[0]
	if attestation.Kind != "slsa" {
		t.Fatalf("manifest attestation kind = %q, want slsa", attestation.Kind)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if len(report.Artifacts) != 1 || len(report.Artifacts[0].Attestations) != 1 {
		t.Fatalf("verify artifacts = %+v, want one attestation", report.Artifacts)
	}
	if got := report.Artifacts[0].Attestations[0].Kind; got != "slsa" {
		t.Fatalf("verify attestation kind = %q, want slsa", got)
	}

	inspection, err := Inspect(InspectOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if len(inspection.Artifacts) != 1 || len(inspection.Artifacts[0].Attestations) != 1 {
		t.Fatalf("inspection artifacts = %+v, want one attestation", inspection.Artifacts)
	}
	if got := inspection.Artifacts[0].Attestations[0].Kind; got != "slsa" {
		t.Fatalf("inspect attestation kind = %q, want slsa", got)
	}
}

func TestPackageAttestationKindRejectsEmptyLabel(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "empty-kind.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	_, err := Package(context.Background(), Options{
		SourceDir:        ".",
		OutDir:           outDir,
		Version:          "v0.1.0",
		Commit:           "empty-kind",
		Date:             "2026-06-12T00:00:00Z",
		Targets:          []Target{{OS: "linux", Arch: "amd64"}},
		Build:            fakeBuild,
		AttestationPaths: []string{"kind:,target:linux/amd64=" + attestationPath},
	})
	if err == nil || !strings.Contains(err.Error(), "attestation kind label is empty") {
		t.Fatalf("Package error = %v, want empty kind label diagnostic", err)
	}
}

func TestPackageAttestationSelectorsSupportExplicitPrefixes(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	nameAttestationPath := filepath.Join(inputDir, "name.intoto.json")
	targetAttestationPath := filepath.Join(inputDir, "target.intoto.json")
	pathAttestationPath := filepath.Join(inputDir, "path.intoto.json")
	for _, path := range []string{nameAttestationPath, targetAttestationPath, pathAttestationPath} {
		if err := os.WriteFile(path, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
			t.Fatalf("write attestation %s: %v", path, err)
		}
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-12T00:00:00Z",
		Targets: []Target{
			{OS: "linux", Arch: "amd64"},
			{OS: "linux", Arch: "arm64"},
			{OS: "darwin", Arch: "amd64"},
		},
		Build: fakeBuild,
		AttestationPaths: []string{
			"name:ao-covenant_v0.1.0_linux_amd64=" + nameAttestationPath,
			"target:linux/arm64=" + targetAttestationPath,
			"path:ao-covenant_v0.1.0_darwin_amd64=" + pathAttestationPath,
		},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	wantAttestations := map[string]string{
		"ao-covenant_v0.1.0_linux_amd64":  "ao-covenant_v0.1.0_linux_amd64.name.intoto.json",
		"ao-covenant_v0.1.0_linux_arm64":  "ao-covenant_v0.1.0_linux_arm64.target.intoto.json",
		"ao-covenant_v0.1.0_darwin_amd64": "ao-covenant_v0.1.0_darwin_amd64.path.intoto.json",
	}
	if len(result.Manifest.Artifacts) != len(wantAttestations) {
		t.Fatalf("artifacts = %+v, want %d", result.Manifest.Artifacts, len(wantAttestations))
	}
	for _, artifact := range result.Manifest.Artifacts {
		wantPath := wantAttestations[artifact.Name]
		if wantPath == "" {
			t.Fatalf("unexpected artifact %q", artifact.Name)
		}
		if len(artifact.Attestations) != 1 {
			t.Fatalf("%s attestations = %+v, want one", artifact.Name, artifact.Attestations)
		}
		if artifact.Attestations[0].Path != wantPath {
			t.Fatalf("%s attestation path = %q, want %q", artifact.Name, artifact.Attestations[0].Path, wantPath)
		}
	}
}

func TestPackageAttestationSelectorDiagnosticsListAvailableSelectors(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "missing.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-12T00:00:00Z",
		Targets: []Target{
			{OS: "linux", Arch: "amd64"},
			{OS: "darwin", Arch: "arm64"},
		},
		Build:            fakeBuild,
		AttestationPaths: []string{"target:windows/amd64=" + attestationPath},
	})
	if err == nil {
		t.Fatal("Package error = nil, want unmatched selector error")
	}
	message := err.Error()
	for _, want := range []string{
		`attestation selector "target:windows/amd64" did not match a release artifact`,
		"available selectors:",
		"name:ao-covenant_v0.1.0_linux_amd64",
		"target:linux/amd64",
		"path:ao-covenant_v0.1.0_linux_amd64",
		"name:ao-covenant_v0.1.0_darwin_arm64",
		"target:darwin/arm64",
		"path:ao-covenant_v0.1.0_darwin_arm64",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want %s", message, want)
		}
	}
}

func TestVerifyRejectsTamperedArtifactAttestation(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "attestation.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:        ".",
		OutDir:           outDir,
		Version:          "v0.1.0",
		Commit:           "abc123",
		Date:             "2026-06-12T00:00:00Z",
		Targets:          []Target{{OS: "linux", Arch: "amd64"}},
		Build:            fakeBuild,
		AttestationPaths: []string{"linux/amd64=" + attestationPath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	attestationPath = filepath.Join(outDir, result.Manifest.Artifacts[0].Attestations[0].Path)
	if err := os.WriteFile(attestationPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatalf("tamper attestation: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if report.Verified {
		t.Fatalf("verified = true, want false")
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), `attestation "attestation.intoto.json" sha256 mismatch`) {
		t.Fatalf("problems = %+v, want attestation sha mismatch", report.Problems)
	}
	if len(report.Artifacts) != 1 || len(report.Artifacts[0].Attestations) != 1 || report.Artifacts[0].Attestations[0].Verified {
		t.Fatalf("artifact attestation reports = %+v, want failed attestation", report.Artifacts)
	}
}

func TestPackageBuildsRelativeOutDirWhenSourceDirDiffers(t *testing.T) {
	workspace := t.TempDir()
	sourceDir := t.TempDir()
	t.Chdir(workspace)
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		outputPath := req.OutputPath
		if !filepath.IsAbs(outputPath) {
			outputPath = filepath.Join(req.SourceDir, outputPath)
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return err
		}
		return os.WriteFile(outputPath, []byte("fake binary\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir: sourceDir,
		OutDir:    "release",
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	if result.ManifestPath != filepath.Join("release", "manifest.json") {
		t.Fatalf("manifest path = %q, want relative release manifest path", result.ManifestPath)
	}
	if _, err := os.Stat(filepath.Join(workspace, "release", "ao-covenant_v0.1.0_linux_amd64")); err != nil {
		t.Fatalf("expected release artifact in caller workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sourceDir, "release", "ao-covenant_v0.1.0_linux_amd64")); !os.IsNotExist(err) {
		t.Fatalf("source-dir artifact stat = %v, want not exist", err)
	}
}

func TestPackageRejectsManifestThatViolatesPublicSchema(t *testing.T) {
	outDir := t.TempDir()
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, nil, 0o755)
	}

	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
	})

	if err == nil {
		t.Fatalf("Package returned nil error, want release manifest schema validation error")
	}
	if !strings.Contains(err.Error(), "validate release manifest") {
		t.Fatalf("Package error = %v, want release manifest validation context", err)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "manifest.json")); !os.IsNotExist(statErr) {
		t.Fatalf("manifest.json stat error = %v, want file not written", statErr)
	}
}

func TestVerifyAcceptsReleasePackage(t *testing.T) {
	outDir := t.TempDir()
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{
		Dir: outDir,
		Metadata: func(path string) (buildinfo.Info, error) {
			if filepath.Base(path) != "ao-covenant_v0.1.0_linux_amd64" {
				t.Fatalf("metadata path = %q, want linux artifact", path)
			}
			return buildinfo.Info{Version: "v0.1.0", Commit: "abc123", Date: "2026-06-11T00:00:00Z"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if !report.Verified {
		t.Fatalf("report.Verified = false, problems = %v", report.Problems)
	}
	if report.ManifestPath != filepath.Join(outDir, "manifest.json") {
		t.Fatalf("manifest path = %q", report.ManifestPath)
	}
	if report.ChecksumsPath != filepath.Join(outDir, "SHA256SUMS") {
		t.Fatalf("checksums path = %q", report.ChecksumsPath)
	}
	if report.ArtifactCount != 1 {
		t.Fatalf("artifact count = %d, want 1", report.ArtifactCount)
	}
	if len(report.Artifacts) != 1 {
		t.Fatalf("artifact reports len = %d, want 1", len(report.Artifacts))
	}
	artifactReport := report.Artifacts[0]
	if artifactReport.Name != "ao-covenant_v0.1.0_linux_amd64" || artifactReport.Path != "ao-covenant_v0.1.0_linux_amd64" {
		t.Fatalf("artifact report identity = %+v", artifactReport)
	}
	if !artifactReport.Verified || !artifactReport.PathValid || !artifactReport.DigestVerified || !artifactReport.SizeVerified || !artifactReport.ChecksumVerified || !artifactReport.MetadataVerified {
		t.Fatalf("artifact report status = %+v, want all verification booleans true", artifactReport)
	}
	if artifactReport.HostMetadataChecked {
		t.Fatalf("host_metadata_checked = true, want false for all-artifact metadata hook")
	}
	if artifactReport.SHA256 == "" || artifactReport.ActualSHA256 == "" || artifactReport.SHA256 != artifactReport.ActualSHA256 {
		t.Fatalf("artifact report digests = %+v", artifactReport)
	}
	if artifactReport.SizeBytes == 0 || artifactReport.ActualSizeBytes == 0 || artifactReport.SizeBytes != artifactReport.ActualSizeBytes {
		t.Fatalf("artifact report sizes = %+v", artifactReport)
	}
	if len(artifactReport.Problems) != 0 {
		t.Fatalf("artifact problems = %v, want empty", artifactReport.Problems)
	}
	if len(report.Problems) != 0 {
		t.Fatalf("problems = %v, want empty", report.Problems)
	}
}

func TestVerifyRejectsTamperedReleaseArtifact(t *testing.T) {
	outDir := t.TempDir()
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte("original\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64"), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if report.Verified {
		t.Fatalf("report.Verified = true, want false")
	}
	if len(report.Artifacts) != 1 {
		t.Fatalf("artifact reports len = %d, want 1", len(report.Artifacts))
	}
	artifactReport := report.Artifacts[0]
	if artifactReport.Verified {
		t.Fatalf("artifact report verified = true, want false: %+v", artifactReport)
	}
	if !artifactReport.PathValid || artifactReport.DigestVerified || !artifactReport.SizeVerified || !artifactReport.ChecksumVerified {
		t.Fatalf("artifact report status = %+v, want path valid, digest false, size/checksum true", artifactReport)
	}
	if !strings.Contains(strings.Join(artifactReport.Problems, "\n"), "sha256 mismatch") {
		t.Fatalf("artifact problems = %v, want sha256 mismatch", artifactReport.Problems)
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), "sha256 mismatch") {
		t.Fatalf("problems = %v, want sha256 mismatch", report.Problems)
	}
}

func TestVerifyRejectsMismatchedReleaseMetadata(t *testing.T) {
	outDir := t.TempDir()
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte("binary\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: "linux", Arch: "amd64"}},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{
		Dir: outDir,
		Metadata: func(path string) (buildinfo.Info, error) {
			return buildinfo.Info{Version: "v0.2.0", Commit: "abc123", Date: "2026-06-11T00:00:00Z"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if report.Verified {
		t.Fatalf("report.Verified = true, want false")
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), "version metadata mismatch") {
		t.Fatalf("problems = %v, want metadata mismatch", report.Problems)
	}
}

func TestVerifyRejectsMismatchedHostBinaryTargetMetadata(t *testing.T) {
	outDir := t.TempDir()
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte("binary\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{
		Dir: outDir,
		HostMetadata: func(path string) (buildinfo.Info, error) {
			return buildinfo.Info{
				Version: "v0.1.0",
				Commit:  "abc123",
				Date:    "2026-06-11T00:00:00Z",
				OS:      runtime.GOOS,
				Arch:    "wrong-arch",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if report.Verified {
		t.Fatalf("report.Verified = true, want false")
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), "arch metadata mismatch") {
		t.Fatalf("problems = %v, want arch metadata mismatch", report.Problems)
	}
}

func TestVerifySkipsHostBinaryMetadataForForeignTarget(t *testing.T) {
	outDir := t.TempDir()
	foreign := Target{OS: "foreign-os", Arch: "foreign-arch"}
	if foreign.OS == runtime.GOOS || foreign.Arch == runtime.GOARCH {
		t.Fatalf("foreign target unexpectedly matches host: %+v", foreign)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte("binary\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir: ".",
		OutDir:    outDir,
		Version:   "v0.1.0",
		Commit:    "abc123",
		Date:      "2026-06-11T00:00:00Z",
		Targets:   []Target{foreign},
		Build:     fakeBuild,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	called := false
	report, err := Verify(VerifyOptions{
		Dir: outDir,
		HostMetadata: func(path string) (buildinfo.Info, error) {
			called = true
			return buildinfo.Info{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if called {
		t.Fatalf("HostMetadata was called for foreign target")
	}
	if !report.Verified {
		t.Fatalf("report.Verified = false, problems = %v", report.Problems)
	}
}

func TestPackageSignsReleaseManifest(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "keys", "private.json")
	publicKeyPath := filepath.Join(outDir, "keys", "public.json")
	if err := bundlepkg.GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}

	result, err := Package(context.Background(), Options{
		SourceDir:   ".",
		OutDir:      outDir,
		Version:     "v0.1.0",
		Commit:      "abc123",
		Date:        "2026-06-11T00:00:00Z",
		Targets:     []Target{{OS: "linux", Arch: "amd64"}},
		Build:       fakeBuild,
		SignKeyPath: privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	if result.SignaturePath != filepath.Join(outDir, "release-signature.json") {
		t.Fatalf("signature path = %q, want release-signature.json", result.SignaturePath)
	}
	if len(result.PublicKeySHA256) != 64 {
		t.Fatalf("public key sha256 = %q, want 64 hex chars", result.PublicKeySHA256)
	}
	signatureBytes, err := os.ReadFile(result.SignaturePath)
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseSignatureSchemaID, signatureBytes); err != nil {
		t.Fatalf("release signature did not match published schema: %v\njson:\n%s", err, string(signatureBytes))
	}

	report, err := Verify(VerifyOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("report.Verified = false, problems = %v", report.Problems)
	}
	if report.PublicKeySHA256 != result.PublicKeySHA256 {
		t.Fatalf("verify public key sha256 = %q, want %q", report.PublicKeySHA256, result.PublicKeySHA256)
	}
}

func TestVerifyRejectsTamperedSignedReleaseManifest(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "keys", "private.json")
	publicKeyPath := filepath.Join(outDir, "keys", "public.json")
	if err := bundlepkg.GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:   ".",
		OutDir:      outDir,
		Version:     "v0.1.0",
		Commit:      "abc123",
		Date:        "2026-06-11T00:00:00Z",
		Targets:     []Target{{OS: "linux", Arch: "amd64"}},
		Build:       fakeBuild,
		SignKeyPath: privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	manifest := result.Manifest
	manifest.Commit = "tampered-manifest"
	if err := schema.WriteJSONFile(result.ManifestPath, schema.ReleaseManifestSchemaID, manifest, 0o644); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if report.Verified {
		t.Fatalf("report.Verified = true, want false")
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), "release signature verification failed") {
		t.Fatalf("problems = %v, want release signature verification failed", report.Problems)
	}
}

func TestInspectReportsSignedReleaseStatus(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "keys", "private.json")
	publicKeyPath := filepath.Join(outDir, "keys", "public.json")
	if err := bundlepkg.GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:   ".",
		OutDir:      outDir,
		Version:     "v0.1.0",
		Commit:      "abc123",
		Date:        "2026-06-11T00:00:00Z",
		Targets:     []Target{{OS: "linux", Arch: "amd64"}},
		Build:       fakeBuild,
		SignKeyPath: privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	inspection, err := Inspect(InspectOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}

	if inspection.SchemaVersion != schema.ReleaseInspectResultSchemaID {
		t.Fatalf("schema version = %q, want %q", inspection.SchemaVersion, schema.ReleaseInspectResultSchemaID)
	}
	if !inspection.ManifestValid || inspection.ChecksumStatus != "verified" || inspection.ArtifactCount != 1 {
		t.Fatalf("inspection summary = %+v", inspection)
	}
	if inspection.Signature.Status != "verified" || inspection.Signature.PublicKeySHA256 != result.PublicKeySHA256 || inspection.Signature.SignedEntry != "manifest.json" {
		t.Fatalf("signature inspection = %+v", inspection.Signature)
	}
	if len(inspection.Artifacts) != 1 || !inspection.Artifacts[0].Verified {
		t.Fatalf("artifacts = %+v, want one verified artifact", inspection.Artifacts)
	}
	if len(inspection.Problems) != 0 {
		t.Fatalf("problems = %v, want empty", inspection.Problems)
	}
}

func TestInspectReportsInvalidSignedManifestWithoutBinaryExecution(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "keys", "private.json")
	publicKeyPath := filepath.Join(outDir, "keys", "public.json")
	if err := bundlepkg.GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:   ".",
		OutDir:      outDir,
		Version:     "v0.1.0",
		Commit:      "abc123",
		Date:        "2026-06-11T00:00:00Z",
		Targets:     []Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Build:       fakeBuild,
		SignKeyPath: privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}
	manifest := result.Manifest
	manifest.Commit = "tampered-manifest"
	if err := schema.WriteJSONFile(result.ManifestPath, schema.ReleaseManifestSchemaID, manifest, 0o644); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}

	called := false
	inspection, err := Inspect(InspectOptions{
		Dir:           outDir,
		PublicKeyPath: publicKeyPath,
		HostMetadata: func(path string) (buildinfo.Info, error) {
			called = true
			return buildinfo.Info{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}

	if called {
		t.Fatalf("HostMetadata was called; inspect must not execute binaries")
	}
	if inspection.Signature.Status != "invalid" {
		t.Fatalf("signature status = %q, want invalid; inspection = %+v", inspection.Signature.Status, inspection)
	}
	if !strings.Contains(strings.Join(inspection.Problems, "\n"), "release signature verification failed") {
		t.Fatalf("problems = %v, want signature verification problem", inspection.Problems)
	}
}

func TestVerifyReportsReleaseProvenance(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "keys", "private.json")
	publicKeyPath := filepath.Join(outDir, "keys", "public.json")
	if err := bundlepkg.GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:   ".",
		OutDir:      outDir,
		Version:     "v0.1.0",
		Commit:      "abc123",
		Date:        "2026-06-11T00:00:00Z",
		Targets:     []Target{{OS: runtime.GOOS, Arch: runtime.GOARCH}},
		Build:       fakeBuild,
		SignKeyPath: privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{
		Dir:           outDir,
		PublicKeyPath: publicKeyPath,
		HostMetadata: func(path string) (buildinfo.Info, error) {
			return buildinfo.Info{
				SchemaVersion: schema.VersionResultSchemaID,
				Version:       "v0.1.0",
				Commit:        "abc123",
				Date:          "2026-06-11T00:00:00Z",
				GoVersion:     "go-test",
				OS:            runtime.GOOS,
				Arch:          runtime.GOARCH,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if report.Provenance.Version != "v0.1.0" || report.Provenance.Commit != "abc123" || report.Provenance.Date != "2026-06-11T00:00:00Z" {
		t.Fatalf("provenance release metadata = %+v", report.Provenance)
	}
	if !report.Provenance.SignatureVerified || report.Provenance.PublicKeySHA256 != result.PublicKeySHA256 {
		t.Fatalf("provenance signature = %+v, want verified fingerprint %s", report.Provenance, result.PublicKeySHA256)
	}
	if len(report.Provenance.Artifacts) != 1 {
		t.Fatalf("provenance artifacts len = %d, want 1", len(report.Provenance.Artifacts))
	}
	artifact := report.Provenance.Artifacts[0]
	wantName := "ao-covenant_v0.1.0_" + runtime.GOOS + "_" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		wantName += ".exe"
	}
	if artifact.Name != wantName || artifact.Target.OS != runtime.GOOS || artifact.Target.Arch != runtime.GOARCH {
		t.Fatalf("artifact provenance identity = %+v", artifact)
	}
	if artifact.VerificationStatus != "verified" || !artifact.MetadataVerified {
		t.Fatalf("artifact provenance status = %+v, want verified metadata", artifact)
	}
	if artifact.BinaryMetadata == nil || artifact.BinaryMetadata.Version != "v0.1.0" || artifact.BinaryMetadata.Commit != "abc123" || artifact.BinaryMetadata.OS != runtime.GOOS || artifact.BinaryMetadata.Arch != runtime.GOARCH {
		t.Fatalf("artifact binary metadata = %+v", artifact.BinaryMetadata)
	}
}

func TestVerifyReportsReleaseProvenanceAttestations(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "slsa.intoto.json")
	attestationBytes := []byte(`{"_type":"https://in-toto.io/Statement/v1"}` + "\n")
	if err := os.WriteFile(attestationPath, attestationBytes, 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	_, err := Package(context.Background(), Options{
		SourceDir:        ".",
		OutDir:           outDir,
		Version:          "v0.1.0",
		Commit:           "provenance-attestation",
		Date:             "2026-06-12T00:00:00Z",
		Targets:          []Target{{OS: "linux", Arch: "amd64"}},
		Build:            fakeBuild,
		AttestationPaths: []string{"kind:slsa,target:linux/amd64=" + attestationPath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	if len(report.Provenance.Artifacts) != 1 {
		t.Fatalf("artifact provenance = %+v, want one artifact", report.Provenance.Artifacts)
	}
	artifact := report.Provenance.Artifacts[0]
	if len(artifact.Attestations) != 1 {
		t.Fatalf("artifact provenance attestations = %+v, want one attestation", artifact.Attestations)
	}
	attestation := artifact.Attestations[0]
	if attestation.Kind != "slsa" || attestation.Name != "slsa.intoto.json" || attestation.Path != "ao-covenant_v0.1.0_linux_amd64.slsa.intoto.json" || attestation.VerificationStatus != "verified" {
		t.Fatalf("attestation provenance identity/status = %+v", attestation)
	}
	if attestation.SHA256 == "" || attestation.SizeBytes != int64(len(attestationBytes)) {
		t.Fatalf("attestation provenance digest/size = %+v, want digest and size %d", attestation, len(attestationBytes))
	}
}

func TestVerifyReportsReleaseProvenanceSupplementalArtifacts(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	provenancePath := filepath.Join(inputDir, "provenance.intoto.json")
	if err := os.WriteFile(sbomPath, []byte(`{"spdxVersion":"SPDX-2.3"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	if err := os.WriteFile(provenancePath, []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
	fakeBuild := func(_ context.Context, req BuildRequest) error {
		return os.WriteFile(req.OutputPath, []byte(req.Target.OS+"/"+req.Target.Arch+"\n"), 0o755)
	}
	result, err := Package(context.Background(), Options{
		SourceDir:       ".",
		OutDir:          outDir,
		Version:         "v0.1.0",
		Commit:          "abc123",
		Date:            "2026-06-12T00:00:00Z",
		Targets:         []Target{{OS: "linux", Arch: "amd64"}},
		Build:           fakeBuild,
		SBOMPaths:       []string{sbomPath},
		ProvenancePaths: []string{provenancePath},
	})
	if err != nil {
		t.Fatalf("Package error: %v", err)
	}

	report, err := Verify(VerifyOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("verified = false, problems = %+v", report.Problems)
	}
	if len(report.Provenance.SupplementalArtifacts) != 2 {
		t.Fatalf("supplemental provenance = %+v, want 2", report.Provenance.SupplementalArtifacts)
	}
	want := map[string]SupplementalArtifact{}
	for _, supplemental := range result.Manifest.SupplementalArtifacts {
		want[supplemental.Kind] = supplemental
	}
	for _, supplemental := range report.Provenance.SupplementalArtifacts {
		manifestSupplemental := want[supplemental.Kind]
		if manifestSupplemental.Name == "" {
			t.Fatalf("unexpected supplemental provenance = %+v", supplemental)
		}
		if supplemental.Name != manifestSupplemental.Name || supplemental.Path != manifestSupplemental.Path || supplemental.SHA256 != manifestSupplemental.SHA256 || supplemental.SizeBytes != manifestSupplemental.SizeBytes {
			t.Fatalf("supplemental provenance = %+v, want manifest %+v", supplemental, manifestSupplemental)
		}
		if supplemental.VerificationStatus != "verified" {
			t.Fatalf("supplemental provenance status = %+v, want verified", supplemental)
		}
	}
}

func TestParseTargetRejectsInvalidTarget(t *testing.T) {
	_, err := ParseTarget("linux")
	if err == nil || !strings.Contains(err.Error(), "target must be os/arch") {
		t.Fatalf("ParseTarget error = %v, want os/arch error", err)
	}
}
