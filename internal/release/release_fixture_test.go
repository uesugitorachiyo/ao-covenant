package release

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestReleaseJSONFixturesMatchGeneratedGoldenFiles(t *testing.T) {
	for _, fixture := range releaseJSONFixtureGoldenFiles(t) {
		fixture.assertFresh(t)
	}
}

type releaseFixtureGoldenFile struct {
	FileName string
	SchemaID string
	JSON     []byte
}

type releasePackageFixtureResult struct {
	SchemaVersion   string   `json:"schema_version"`
	ManifestPath    string   `json:"manifest_path"`
	ChecksumsPath   string   `json:"checksums_path"`
	SignaturePath   string   `json:"signature_path,omitempty"`
	PublicKeySHA256 string   `json:"public_key_sha256,omitempty"`
	ArtifactPaths   []string `json:"artifact_paths"`
	Manifest        Manifest `json:"manifest"`
}

type releaseVerifyFixtureResult struct {
	SchemaVersion         string                     `json:"schema_version"`
	Verified              bool                       `json:"verified"`
	ManifestPath          string                     `json:"manifest_path"`
	ChecksumsPath         string                     `json:"checksums_path"`
	SignaturePath         string                     `json:"signature_path,omitempty"`
	ArtifactCount         int                        `json:"artifact_count"`
	Problems              []string                   `json:"problems"`
	PublicKeySHA256       string                     `json:"public_key_sha256,omitempty"`
	Artifacts             []ArtifactVerifyReport     `json:"artifacts"`
	SupplementalArtifacts []SupplementalVerifyReport `json:"supplemental_artifacts,omitempty"`
	Provenance            ReleaseProvenance          `json:"provenance"`
}

type releaseDiffFixtureResult struct {
	SchemaVersion    string      `json:"schema_version"`
	FromDir          string      `json:"from_dir"`
	ToDir            string      `json:"to_dir"`
	Changed          bool        `json:"changed"`
	Redacted         bool        `json:"redacted"`
	Redactions       []string    `json:"redactions"`
	RedactionProfile string      `json:"redaction_profile,omitempty"`
	Entries          []DiffEntry `json:"entries"`
}

type releaseReportFixtureResult struct {
	SchemaVersion     string                                `json:"schema_version"`
	Valid             bool                                  `json:"valid"`
	Format            string                                `json:"format"`
	Audience          string                                `json:"audience"`
	Redacted          bool                                  `json:"redacted"`
	Redactions        []string                              `json:"redactions"`
	RedactionProfile  string                                `json:"redaction_profile,omitempty"`
	ProvenanceSummary releaseProvenanceSummaryFixtureFields `json:"provenance_summary"`
	Inspection        InspectResult                         `json:"inspection"`
}

type releaseProvenanceSummaryFixtureFields struct {
	SignatureStatus                     string `json:"signature_status"`
	AttestationVerifiedCount            int    `json:"attestation_verified_count"`
	AttestationInvalidCount             int    `json:"attestation_invalid_count"`
	SBOMVerifiedCount                   int    `json:"sbom_verified_count"`
	SBOMInvalidCount                    int    `json:"sbom_invalid_count"`
	SupplementalProvenanceVerifiedCount int    `json:"supplemental_provenance_verified_count"`
	SupplementalProvenanceInvalidCount  int    `json:"supplemental_provenance_invalid_count"`
	InvalidEvidenceCount                int    `json:"invalid_evidence_count"`
}

func releaseJSONFixtureGoldenFiles(t *testing.T) []releaseFixtureGoldenFile {
	t.Helper()

	const (
		version           = "v0.1.0"
		commit            = "0123456789abcdef0123456789abcdef01234567"
		date              = "2026-06-12T12:00:00Z"
		artifactName      = "covenant-linux-amd64"
		artifactPath      = "covenant-linux-amd64"
		artifactSHA256    = "1111111111111111111111111111111111111111111111111111111111111111"
		artifactSize      = int64(1048576)
		attestationName   = "attestation.intoto.json"
		attestationPath   = "covenant-linux-amd64.attestation.intoto.json"
		attestationSHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
		attestationSize   = int64(4096)
		sbomName          = "sbom.spdx.json"
		sbomSHA256        = "2222222222222222222222222222222222222222222222222222222222222222"
		sbomSize          = int64(2048)
		publicKeySHA256   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		signatureBase64   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		manifestPath      = "dist/manifest.json"
		checksumsPath     = "dist/checksums.txt"
		signaturePath     = "dist/manifest.sig.json"
		artifactFullPath  = "dist/covenant-linux-amd64"
	)

	target := Target{OS: "linux", Arch: "amd64"}
	artifact := Artifact{
		Name:      artifactName,
		Target:    target,
		Path:      artifactPath,
		SHA256:    artifactSHA256,
		SizeBytes: artifactSize,
		Attestations: []Attestation{{
			Name:      attestationName,
			Kind:      "slsa",
			Path:      attestationPath,
			SHA256:    attestationSHA256,
			SizeBytes: attestationSize,
		}},
	}
	manifest := Manifest{
		SchemaVersion: schema.ReleaseManifestSchemaID,
		Version:       version,
		Commit:        commit,
		Date:          date,
		Artifacts:     []Artifact{artifact},
		SupplementalArtifacts: []SupplementalArtifact{{
			Kind:      "sbom",
			Name:      sbomName,
			Path:      sbomName,
			SHA256:    sbomSHA256,
			SizeBytes: sbomSize,
		}},
	}
	verifyArtifact := ArtifactVerifyReport{
		Name:                artifactName,
		Target:              target,
		Path:                artifactPath,
		Verified:            true,
		PathValid:           true,
		DigestVerified:      true,
		SizeVerified:        true,
		ChecksumVerified:    true,
		MetadataVerified:    true,
		HostMetadataChecked: true,
		SHA256:              artifactSHA256,
		SizeBytes:           artifactSize,
		ActualSHA256:        artifactSHA256,
		ActualSizeBytes:     artifactSize,
		Problems:            []string{},
		Attestations: []AttestationVerifyReport{{
			Name:             attestationName,
			Kind:             "slsa",
			Path:             attestationPath,
			Verified:         true,
			PathValid:        true,
			DigestVerified:   true,
			SizeVerified:     true,
			ChecksumVerified: true,
			SHA256:           attestationSHA256,
			SizeBytes:        attestationSize,
			ActualSHA256:     attestationSHA256,
			ActualSizeBytes:  attestationSize,
			Problems:         []string{},
		}},
	}
	verifySupplemental := SupplementalVerifyReport{
		Kind:             "sbom",
		Name:             sbomName,
		Path:             sbomName,
		Verified:         true,
		PathValid:        true,
		DigestVerified:   true,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           sbomSHA256,
		SizeBytes:        sbomSize,
		ActualSHA256:     sbomSHA256,
		ActualSizeBytes:  sbomSize,
		Problems:         []string{},
	}
	binaryMetadata := buildinfo.Info{
		SchemaVersion: schema.VersionResultSchemaID,
		Version:       version,
		Commit:        commit,
		Date:          date,
		GoVersion:     "go1.25.0",
		OS:            target.OS,
		Arch:          target.Arch,
	}
	provenance := ReleaseProvenance{
		Version:           version,
		Commit:            commit,
		Date:              date,
		PublicKeySHA256:   publicKeySHA256,
		SignatureVerified: true,
		Artifacts: []ArtifactProvenance{{
			Name:               artifactName,
			Target:             target,
			VerificationStatus: "verified",
			MetadataVerified:   true,
			BinaryMetadata:     &binaryMetadata,
			Attestations: []AttestationProvenance{{
				Kind:               "slsa",
				Name:               attestationName,
				Path:               attestationPath,
				VerificationStatus: "verified",
				SHA256:             attestationSHA256,
				SizeBytes:          attestationSize,
			}},
		}},
		SupplementalArtifacts: []SupplementalArtifactProvenance{{
			Kind:               "sbom",
			Name:               sbomName,
			Path:               sbomName,
			VerificationStatus: "verified",
			SHA256:             sbomSHA256,
			SizeBytes:          sbomSize,
		}},
	}
	const (
		redactedPath   = "[REDACTED_PATH]"
		redactedDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	)
	redactedArtifact := verifyArtifact
	redactedArtifact.Path = redactedPath
	redactedArtifact.SHA256 = redactedDigest
	redactedArtifact.ActualSHA256 = redactedDigest
	redactedArtifact.Attestations = append([]AttestationVerifyReport{}, verifyArtifact.Attestations...)
	redactedArtifact.Attestations[0].Path = redactedPath
	redactedArtifact.Attestations[0].SHA256 = redactedDigest
	redactedArtifact.Attestations[0].ActualSHA256 = redactedDigest
	redactedInspection := InspectResult{
		SchemaVersion:  schema.ReleaseInspectResultSchemaID,
		ReleaseDir:     redactedPath,
		ManifestPath:   redactedPath,
		ChecksumsPath:  redactedPath,
		SignaturePath:  redactedPath,
		ManifestValid:  true,
		ChecksumStatus: "verified",
		Signature: SignatureInspection{
			Status:          "verified",
			Algorithm:       signatureAlgorithm,
			SignedEntry:     releaseSignedEntryPath,
			PublicKeySHA256: redactedDigest,
		},
		ArtifactCount: 1,
		Artifacts:     []ArtifactVerifyReport{redactedArtifact},
		Problems:      []string{},
	}
	provenanceSummary := releaseProvenanceSummaryFixtureFields{
		SignatureStatus:                     "verified",
		AttestationVerifiedCount:            1,
		SBOMVerifiedCount:                   1,
		SupplementalProvenanceVerifiedCount: 1,
	}

	return []releaseFixtureGoldenFile{
		{
			FileName: "release-package-result.json",
			SchemaID: schema.ReleasePackageResultSchemaID,
			JSON: marshalReleaseFixture(t, releasePackageFixtureResult{
				SchemaVersion:   schema.ReleasePackageResultSchemaID,
				ManifestPath:    manifestPath,
				ChecksumsPath:   checksumsPath,
				SignaturePath:   signaturePath,
				PublicKeySHA256: publicKeySHA256,
				ArtifactPaths:   []string{artifactFullPath},
				Manifest:        manifest,
			}),
		},
		{
			FileName: "release-verify-result.json",
			SchemaID: schema.ReleaseVerifyResultSchemaID,
			JSON: marshalReleaseFixture(t, releaseVerifyFixtureResult{
				SchemaVersion:   schema.ReleaseVerifyResultSchemaID,
				Verified:        true,
				ManifestPath:    manifestPath,
				ChecksumsPath:   checksumsPath,
				SignaturePath:   signaturePath,
				ArtifactCount:   1,
				Problems:        []string{},
				PublicKeySHA256: publicKeySHA256,
				Artifacts:       []ArtifactVerifyReport{verifyArtifact},
				SupplementalArtifacts: []SupplementalVerifyReport{
					verifySupplemental,
				},
				Provenance: provenance,
			}),
		},
		{
			FileName: "release-inspect-result.json",
			SchemaID: schema.ReleaseInspectResultSchemaID,
			JSON: marshalReleaseFixture(t, InspectResult{
				SchemaVersion:  schema.ReleaseInspectResultSchemaID,
				ReleaseDir:     "dist",
				ManifestPath:   manifestPath,
				ChecksumsPath:  checksumsPath,
				SignaturePath:  signaturePath,
				ManifestValid:  true,
				ChecksumStatus: "verified",
				Signature: SignatureInspection{
					Status:          "verified",
					Algorithm:       signatureAlgorithm,
					SignedEntry:     releaseSignedEntryPath,
					PublicKeySHA256: publicKeySHA256,
				},
				ArtifactCount: 1,
				Artifacts:     []ArtifactVerifyReport{verifyArtifact},
				Problems:      []string{},
			}),
		},
		{
			FileName: "release-inspect-result-redacted.json",
			SchemaID: schema.ReleaseInspectResultSchemaID,
			JSON:     marshalReleaseFixture(t, redactedInspection),
		},
		{
			FileName: "release-report-result-redacted.json",
			SchemaID: schema.ReleaseReportResultSchemaID,
			JSON: marshalReleaseFixture(t, releaseReportFixtureResult{
				SchemaVersion:     schema.ReleaseReportResultSchemaID,
				Valid:             true,
				Format:            "json",
				Audience:          "external",
				Redacted:          true,
				Redactions:        []string{"paths", "digests"},
				RedactionProfile:  "partner",
				ProvenanceSummary: provenanceSummary,
				Inspection:        redactedInspection,
			}),
		},
		{
			FileName: "release-diff-result.json",
			SchemaID: schema.ReleaseDiffResultSchemaID,
			JSON: marshalReleaseFixture(t, releaseDiffFixtureResult{
				SchemaVersion: schema.ReleaseDiffResultSchemaID,
				FromDir:       "dist-v0.1.0",
				ToDir:         "dist-v0.2.0",
				Changed:       true,
				Redacted:      false,
				Redactions:    []string{},
				Entries: []DiffEntry{
					{Category: "artifacts", Action: "changed", Name: artifactName, Detail: "sha256 changed"},
					{Category: "metadata", Action: "changed", Name: "version", Detail: "v0.1.0 -> v0.2.0"},
					{Category: "problems", Action: "present", Name: "to", Detail: "SHA256SUMS contains unmanifested artifact \"extra.bin\""},
				},
			}),
		},
		{
			FileName: "release-diff-result-redacted.json",
			SchemaID: schema.ReleaseDiffResultSchemaID,
			JSON: marshalReleaseFixture(t, releaseDiffFixtureResult{
				SchemaVersion:    schema.ReleaseDiffResultSchemaID,
				FromDir:          redactedPath,
				ToDir:            redactedPath,
				Changed:          true,
				Redacted:         true,
				Redactions:       []string{"paths", "digests"},
				RedactionProfile: "partner",
				Entries: []DiffEntry{
					{Category: "metadata", Action: "changed", Name: "version", Detail: "v0.1.0 -> v0.2.0"},
					{Category: "signatures", Action: "changed", Name: "public_key_sha256", Detail: "[REDACTED_DIGEST] -> [REDACTED_DIGEST]"},
				},
			}),
		},
		{
			FileName: "release-signature.json",
			SchemaID: schema.ReleaseSignatureSchemaID,
			JSON: marshalReleaseFixture(t, SignatureFile{
				SchemaVersion:   schema.ReleaseSignatureSchemaID,
				Algorithm:       signatureAlgorithm,
				SignedEntry:     releaseSignedEntryPath,
				PublicKeySHA256: publicKeySHA256,
				Signature:       signatureBase64,
			}),
		},
	}
}

func marshalReleaseFixture(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal release fixture: %v", err)
	}
	return append(data, '\n')
}

func (fixture releaseFixtureGoldenFile) assertFresh(t *testing.T) {
	t.Helper()

	if err := schema.ValidateBytes(fixture.SchemaID, fixture.JSON); err != nil {
		t.Fatalf("generated %s does not validate against %s: %v\njson:\n%s", fixture.FileName, fixture.SchemaID, err, string(fixture.JSON))
	}

	path := filepath.Join("..", "schema", "testdata", "release-fixtures", fixture.FileName)
	if os.Getenv("COVENANT_UPDATE_RELEASE_FIXTURES") == "1" {
		if err := os.WriteFile(path, fixture.JSON, 0o644); err != nil {
			t.Fatalf("update %s: %v", path, err)
		}
	}

	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(golden, fixture.JSON) {
		t.Fatalf("%s is stale; regenerate with COVENANT_UPDATE_RELEASE_FIXTURES=1 go test ./internal/release -run 'ReleaseJSONFixturesMatchGeneratedGoldenFiles' -count=1", path)
	}
}
