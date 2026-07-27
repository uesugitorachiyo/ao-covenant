package release

import (
	"context"

	"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

const ManifestSchemaVersion = schema.ReleaseManifestSchemaID

const (
	ReleaseSignatureSchemaVersion = schema.ReleaseSignatureSchemaID
	signatureAlgorithm            = "ed25519"
	releaseSignaturePath          = "release-signature.json"
	releaseSignedEntryPath        = "manifest.json"
	redactedPath                  = "[REDACTED_PATH]"
	redactedDigest                = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Target struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type Artifact struct {
	Name         string        `json:"name"`
	Target       Target        `json:"target"`
	Path         string        `json:"path"`
	SHA256       string        `json:"sha256"`
	SizeBytes    int64         `json:"size_bytes"`
	Attestations []Attestation `json:"attestations,omitempty"`
}

type Attestation struct {
	Name      string `json:"name"`
	Kind      string `json:"kind,omitempty"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type SupplementalArtifact struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Manifest struct {
	SchemaVersion         string                 `json:"schema_version"`
	Version               string                 `json:"version"`
	Commit                string                 `json:"commit"`
	Date                  string                 `json:"date"`
	Artifacts             []Artifact             `json:"artifacts"`
	SupplementalArtifacts []SupplementalArtifact `json:"supplemental_artifacts,omitempty"`
}

type Options struct {
	SourceDir        string
	OutDir           string
	Version          string
	Commit           string
	Date             string
	Targets          []Target
	Prebuilt         map[string]string
	Build            BuildFunc
	SignKeyPath      string
	SBOMPaths        []string
	ProvenancePaths  []string
	AttestationPaths []string
}

type Result struct {
	ManifestPath    string
	ChecksumsPath   string
	SignaturePath   string
	Artifacts       []Artifact
	Manifest        Manifest
	PublicKeySHA256 string
}

type BuildRequest struct {
	SourceDir  string
	OutputPath string
	Target     Target
	LDFlags    string
}

type BuildFunc func(context.Context, BuildRequest) error

type MetadataFunc func(path string) (buildinfo.Info, error)

type VerifyOptions struct {
	Dir           string
	PublicKeyPath string
	Metadata      MetadataFunc
	HostMetadata  MetadataFunc
}

type VerifyReport struct {
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

type InspectOptions struct {
	Dir           string
	PublicKeyPath string
	Metadata      MetadataFunc
	HostMetadata  MetadataFunc
}

type InspectResult struct {
	SchemaVersion         string                     `json:"schema_version"`
	ReleaseDir            string                     `json:"release_dir"`
	ManifestPath          string                     `json:"manifest_path"`
	ChecksumsPath         string                     `json:"checksums_path"`
	SignaturePath         string                     `json:"signature_path,omitempty"`
	ManifestValid         bool                       `json:"manifest_valid"`
	ChecksumStatus        string                     `json:"checksum_status"`
	Signature             SignatureInspection        `json:"signature"`
	ArtifactCount         int                        `json:"artifact_count"`
	Artifacts             []ArtifactVerifyReport     `json:"artifacts"`
	SupplementalArtifacts []SupplementalVerifyReport `json:"supplemental_artifacts,omitempty"`
	Problems              []string                   `json:"problems"`
}

type SignatureInspection struct {
	Status          string `json:"status"`
	Algorithm       string `json:"algorithm,omitempty"`
	SignedEntry     string `json:"signed_entry,omitempty"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	Problem         string `json:"problem,omitempty"`
}

type RedactionOptions struct {
	Paths            bool
	Digests          bool
	RedactionProfile string
}

type ReportOptions struct {
	Dir           string
	PublicKeyPath string
	Audience      string
	Redaction     RedactionOptions
}

type ReportResult struct {
	SchemaVersion     string            `json:"schema_version"`
	Valid             bool              `json:"valid"`
	Format            string            `json:"format"`
	Audience          string            `json:"audience"`
	Redacted          bool              `json:"redacted"`
	Redactions        []string          `json:"redactions"`
	RedactionProfile  string            `json:"redaction_profile,omitempty"`
	ProvenanceSummary ProvenanceSummary `json:"provenance_summary"`
	Inspection        InspectResult     `json:"inspection"`
}

type ProvenanceSummary struct {
	SignatureStatus                     string `json:"signature_status"`
	AttestationVerifiedCount            int    `json:"attestation_verified_count"`
	AttestationInvalidCount             int    `json:"attestation_invalid_count"`
	SBOMVerifiedCount                   int    `json:"sbom_verified_count"`
	SBOMInvalidCount                    int    `json:"sbom_invalid_count"`
	SupplementalProvenanceVerifiedCount int    `json:"supplemental_provenance_verified_count"`
	SupplementalProvenanceInvalidCount  int    `json:"supplemental_provenance_invalid_count"`
	InvalidEvidenceCount                int    `json:"invalid_evidence_count"`
}

type DiffOptions struct {
	FromDir           string
	ToDir             string
	Redaction         RedactionOptions
	FromPublicKeyPath string
	ToPublicKeyPath   string
}

type DiffReport struct {
	SchemaVersion    string      `json:"schema_version"`
	FromDir          string      `json:"from_dir"`
	ToDir            string      `json:"to_dir"`
	Changed          bool        `json:"changed"`
	Redacted         bool        `json:"redacted"`
	Redactions       []string    `json:"redactions"`
	RedactionProfile string      `json:"redaction_profile,omitempty"`
	Entries          []DiffEntry `json:"entries"`
}

type DiffEntry struct {
	Category string `json:"category"`
	Action   string `json:"action"`
	Name     string `json:"name"`
	Detail   string `json:"detail"`
}

type InspectSARIFOptions struct {
	Baseline schema.SARIFBaseline
}

type DiffSARIFOptions struct {
	Baseline schema.SARIFBaseline
}

type ArtifactVerifyReport struct {
	Name                string                    `json:"name"`
	Target              Target                    `json:"target"`
	Path                string                    `json:"path"`
	Verified            bool                      `json:"verified"`
	PathValid           bool                      `json:"path_valid"`
	DigestVerified      bool                      `json:"digest_verified"`
	SizeVerified        bool                      `json:"size_verified"`
	ChecksumVerified    bool                      `json:"checksum_verified"`
	MetadataVerified    bool                      `json:"metadata_verified"`
	HostMetadataChecked bool                      `json:"host_metadata_checked"`
	SHA256              string                    `json:"sha256"`
	SizeBytes           int64                     `json:"size_bytes"`
	ActualSHA256        string                    `json:"actual_sha256"`
	ActualSizeBytes     int64                     `json:"actual_size_bytes"`
	Problems            []string                  `json:"problems"`
	Attestations        []AttestationVerifyReport `json:"attestations,omitempty"`
}

type AttestationVerifyReport struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind,omitempty"`
	Path             string   `json:"path"`
	Verified         bool     `json:"verified"`
	PathValid        bool     `json:"path_valid"`
	DigestVerified   bool     `json:"digest_verified"`
	SizeVerified     bool     `json:"size_verified"`
	ChecksumVerified bool     `json:"checksum_verified"`
	SHA256           string   `json:"sha256"`
	SizeBytes        int64    `json:"size_bytes"`
	ActualSHA256     string   `json:"actual_sha256"`
	ActualSizeBytes  int64    `json:"actual_size_bytes"`
	Problems         []string `json:"problems"`
}

type SupplementalVerifyReport struct {
	Kind             string   `json:"kind"`
	Name             string   `json:"name"`
	Path             string   `json:"path"`
	Verified         bool     `json:"verified"`
	PathValid        bool     `json:"path_valid"`
	DigestVerified   bool     `json:"digest_verified"`
	SizeVerified     bool     `json:"size_verified"`
	ChecksumVerified bool     `json:"checksum_verified"`
	SHA256           string   `json:"sha256"`
	SizeBytes        int64    `json:"size_bytes"`
	ActualSHA256     string   `json:"actual_sha256"`
	ActualSizeBytes  int64    `json:"actual_size_bytes"`
	Problems         []string `json:"problems"`
}

type ReleaseProvenance struct {
	Version               string                           `json:"version"`
	Commit                string                           `json:"commit"`
	Date                  string                           `json:"date"`
	PublicKeySHA256       string                           `json:"public_key_sha256,omitempty"`
	SignatureVerified     bool                             `json:"signature_verified"`
	Artifacts             []ArtifactProvenance             `json:"artifacts"`
	SupplementalArtifacts []SupplementalArtifactProvenance `json:"supplemental_artifacts,omitempty"`
}

type ArtifactProvenance struct {
	Name               string                  `json:"name"`
	Target             Target                  `json:"target"`
	VerificationStatus string                  `json:"verification_status"`
	MetadataVerified   bool                    `json:"metadata_verified"`
	BinaryMetadata     *buildinfo.Info         `json:"binary_metadata,omitempty"`
	Attestations       []AttestationProvenance `json:"attestations,omitempty"`
}

type AttestationProvenance struct {
	Kind               string `json:"kind,omitempty"`
	Name               string `json:"name"`
	Path               string `json:"path"`
	VerificationStatus string `json:"verification_status"`
	SHA256             string `json:"sha256"`
	SizeBytes          int64  `json:"size_bytes"`
}

type SupplementalArtifactProvenance struct {
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	Path               string `json:"path"`
	VerificationStatus string `json:"verification_status"`
	SHA256             string `json:"sha256"`
	SizeBytes          int64  `json:"size_bytes"`
}

type PrivateKeyFile struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
}

type PublicKeyFile struct {
	SchemaVersion string `json:"schema_version"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
}

type SignatureFile struct {
	SchemaVersion   string `json:"schema_version"`
	Algorithm       string `json:"algorithm"`
	SignedEntry     string `json:"signed_entry"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	Signature       string `json:"signature"`
}
