package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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

func DefaultTargets() []Target {
	return []Target{
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "windows", Arch: "amd64"},
	}
}

func ParseTarget(raw string) (Target, error) {
	parts := strings.Split(raw, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return Target{}, fmt.Errorf("target must be os/arch")
	}
	return Target{OS: parts[0], Arch: parts[1]}, nil
}

func buildSupplementalArtifacts(outDir string, opts Options, occupiedNames map[string]string) ([]SupplementalArtifact, error) {
	supplementalArtifacts := []SupplementalArtifact{}
	add := func(kind string, paths []string) error {
		for _, sourcePath := range paths {
			sourcePath = strings.TrimSpace(sourcePath)
			if sourcePath == "" {
				continue
			}
			name := filepath.Base(filepath.Clean(sourcePath))
			if name == "." || name == string(filepath.Separator) {
				return fmt.Errorf("%s path %q has invalid file name", kind, sourcePath)
			}
			if existing := occupiedNames[name]; existing != "" {
				return fmt.Errorf("duplicate release artifact name %q already used by %s", name, existing)
			}
			occupiedNames[name] = kind + " supplemental artifact"

			destinationPath := filepath.Join(outDir, name)
			sourceAbs, sourceErr := filepath.Abs(sourcePath)
			destinationAbs, destinationErr := filepath.Abs(destinationPath)
			if sourceErr != nil {
				return fmt.Errorf("resolve %s source %q: %w", kind, sourcePath, sourceErr)
			}
			if destinationErr != nil {
				return fmt.Errorf("resolve %s destination %q: %w", kind, destinationPath, destinationErr)
			}
			if sourceAbs != destinationAbs {
				bytes, err := os.ReadFile(sourcePath)
				if err != nil {
					return fmt.Errorf("read %s supplemental artifact %q: %w", kind, sourcePath, err)
				}
				if err := os.WriteFile(destinationPath, bytes, 0o644); err != nil {
					return fmt.Errorf("write %s supplemental artifact %q: %w", kind, destinationPath, err)
				}
			}
			digest, size, err := fileDigest(destinationPath)
			if err != nil {
				return fmt.Errorf("digest %s supplemental artifact %q: %w", kind, destinationPath, err)
			}
			supplementalArtifacts = append(supplementalArtifacts, SupplementalArtifact{
				Kind:      kind,
				Name:      name,
				Path:      name,
				SHA256:    digest,
				SizeBytes: size,
			})
		}
		return nil
	}
	if err := add("sbom", opts.SBOMPaths); err != nil {
		return nil, err
	}
	if err := add("provenance", opts.ProvenancePaths); err != nil {
		return nil, err
	}
	return supplementalArtifacts, nil
}

func attachArtifactAttestations(outDir string, artifacts []Artifact, specs []string, occupiedNames map[string]string) error {
	for _, raw := range specs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("attestation must be '<artifact-or-target>=<path>'")
		}
		selector, kind, err := parseAttestationSelectorAndKind(strings.TrimSpace(parts[0]))
		if err != nil {
			return err
		}
		sourcePath := strings.TrimSpace(parts[1])
		index, err := matchAttestationSelector(artifacts, selector)
		if err != nil {
			return err
		}
		sourceName := filepath.Base(filepath.Clean(sourcePath))
		if sourceName == "." || sourceName == string(filepath.Separator) {
			return fmt.Errorf("attestation path %q has invalid file name", sourcePath)
		}
		destinationName := artifacts[index].Name + "." + sourceName
		if existing := occupiedNames[destinationName]; existing != "" {
			return fmt.Errorf("duplicate release artifact name %q already used by %s", destinationName, existing)
		}
		occupiedNames[destinationName] = "artifact attestation"
		destinationPath := filepath.Join(outDir, destinationName)
		sourceAbs, sourceErr := filepath.Abs(sourcePath)
		destinationAbs, destinationErr := filepath.Abs(destinationPath)
		if sourceErr != nil {
			return fmt.Errorf("resolve attestation source %q: %w", sourcePath, sourceErr)
		}
		if destinationErr != nil {
			return fmt.Errorf("resolve attestation destination %q: %w", destinationPath, destinationErr)
		}
		if sourceAbs != destinationAbs {
			bytes, err := os.ReadFile(sourcePath)
			if err != nil {
				return fmt.Errorf("read artifact attestation %q: %w", sourcePath, err)
			}
			if err := os.WriteFile(destinationPath, bytes, 0o644); err != nil {
				return fmt.Errorf("write artifact attestation %q: %w", destinationPath, err)
			}
		}
		digest, size, err := fileDigest(destinationPath)
		if err != nil {
			return fmt.Errorf("digest artifact attestation %q: %w", destinationPath, err)
		}
		artifacts[index].Attestations = append(artifacts[index].Attestations, Attestation{
			Name:      sourceName,
			Kind:      kind,
			Path:      destinationName,
			SHA256:    digest,
			SizeBytes: size,
		})
	}
	return nil
}

func parseAttestationSelectorAndKind(raw string) (selector string, kind string, err error) {
	selector = strings.TrimSpace(raw)
	if prefix, rest, ok := strings.Cut(selector, ","); ok && strings.HasPrefix(prefix, "kind:") {
		kind = strings.TrimSpace(strings.TrimPrefix(prefix, "kind:"))
		if kind == "" {
			return "", "", fmt.Errorf("attestation kind label is empty")
		}
		selector = strings.TrimSpace(rest)
		if selector == "" {
			return "", "", fmt.Errorf("attestation selector is empty")
		}
	}
	return selector, kind, nil
}

func matchAttestationSelector(artifacts []Artifact, selector string) (int, error) {
	kind := "bare"
	value := selector
	if prefix, rest, ok := strings.Cut(selector, ":"); ok {
		switch prefix {
		case "name", "target", "path":
			kind = prefix
			value = rest
		}
	}
	for i, artifact := range artifacts {
		if attestationSelectorMatches(artifact, kind, value) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("attestation selector %q did not match a release artifact; available selectors: %s", selector, strings.Join(attestationSelectorChoices(artifacts), ", "))
}

func attestationSelectorMatches(artifact Artifact, kind string, value string) bool {
	switch kind {
	case "name":
		return value == artifact.Name
	case "target":
		return value == targetKey(artifact.Target)
	case "path":
		return value == artifact.Path
	default:
		return value == artifact.Name || value == targetKey(artifact.Target)
	}
}

func attestationSelectorChoices(artifacts []Artifact) []string {
	choices := []string{}
	for _, artifact := range artifacts {
		choices = append(choices,
			"name:"+artifact.Name,
			"target:"+targetKey(artifact.Target),
			"path:"+artifact.Path,
		)
	}
	return choices
}

func targetKey(target Target) string {
	return target.OS + "/" + target.Arch
}

func Package(ctx context.Context, opts Options) (Result, error) {
	sourceDir := defaultString(opts.SourceDir, ".")
	outDir := defaultString(opts.OutDir, "dist")
	version := defaultString(opts.Version, buildinfo.Version)
	commit := defaultString(opts.Commit, buildinfo.Commit)
	date := defaultString(opts.Date, buildinfo.Date)
	targets := opts.Targets
	if len(targets) == 0 {
		targets = DefaultTargets()
	}
	build := opts.Build
	if build == nil {
		build = goBuild
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create release dir: %w", err)
	}
	buildOutDir, err := filepath.Abs(outDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve release dir: %w", err)
	}

	ldflags := buildLDFlags(version, commit, date)
	artifacts := make([]Artifact, 0, len(targets))
	occupiedNames := map[string]string{}
	for _, target := range targets {
		name := artifactName(version, target)
		if existing := occupiedNames[name]; existing != "" {
			return Result{}, fmt.Errorf("duplicate release artifact name %q already used by %s", name, existing)
		}
		occupiedNames[name] = "binary artifact"
		outputPath := filepath.Join(outDir, name)
		buildOutputPath := filepath.Join(buildOutDir, name)
		if err := build(ctx, BuildRequest{
			SourceDir:  sourceDir,
			OutputPath: buildOutputPath,
			Target:     target,
			LDFlags:    ldflags,
		}); err != nil {
			return Result{}, err
		}
		digest, size, err := fileDigest(outputPath)
		if err != nil {
			return Result{}, err
		}
		artifacts = append(artifacts, Artifact{
			Name:      name,
			Target:    target,
			Path:      name,
			SHA256:    digest,
			SizeBytes: size,
		})
	}
	if err := attachArtifactAttestations(outDir, artifacts, opts.AttestationPaths, occupiedNames); err != nil {
		return Result{}, err
	}
	supplementalArtifacts, err := buildSupplementalArtifacts(outDir, opts, occupiedNames)
	if err != nil {
		return Result{}, err
	}

	manifestPath := filepath.Join(outDir, "manifest.json")
	manifest := Manifest{
		SchemaVersion:         ManifestSchemaVersion,
		Version:               version,
		Commit:                commit,
		Date:                  date,
		Artifacts:             artifacts,
		SupplementalArtifacts: supplementalArtifacts,
	}
	if err := writeManifest(manifestPath, manifest); err != nil {
		return Result{}, fmt.Errorf("write manifest: %w", err)
	}
	checksumsPath := filepath.Join(outDir, "SHA256SUMS")
	if err := writeChecksums(checksumsPath, artifacts, supplementalArtifacts); err != nil {
		return Result{}, fmt.Errorf("write checksums: %w", err)
	}
	signaturePath := ""
	publicKeySHA256 := ""
	if strings.TrimSpace(opts.SignKeyPath) != "" {
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			return Result{}, fmt.Errorf("read manifest for signing: %w", err)
		}
		signatureBytes, fingerprint, err := signReleaseManifest(opts.SignKeyPath, manifestBytes)
		if err != nil {
			return Result{}, err
		}
		signaturePath = filepath.Join(outDir, releaseSignaturePath)
		if err := os.WriteFile(signaturePath, signatureBytes, 0o644); err != nil {
			return Result{}, fmt.Errorf("write release signature: %w", err)
		}
		publicKeySHA256 = fingerprint
	}
	return Result{
		ManifestPath:    manifestPath,
		ChecksumsPath:   checksumsPath,
		SignaturePath:   signaturePath,
		Artifacts:       artifacts,
		Manifest:        manifest,
		PublicKeySHA256: publicKeySHA256,
	}, nil
}

func Verify(opts VerifyOptions) (VerifyReport, error) {
	dir := defaultString(opts.Dir, "dist")
	report := VerifyReport{
		Verified:              true,
		ManifestPath:          filepath.Join(dir, "manifest.json"),
		ChecksumsPath:         filepath.Join(dir, "SHA256SUMS"),
		SignaturePath:         filepath.Join(dir, releaseSignaturePath),
		Problems:              []string{},
		Artifacts:             []ArtifactVerifyReport{},
		SupplementalArtifacts: []SupplementalVerifyReport{},
	}
	problem := func(format string, args ...any) {
		report.Verified = false
		report.Problems = append(report.Problems, fmt.Sprintf(format, args...))
	}

	manifestBytes, err := os.ReadFile(report.ManifestPath)
	if err != nil {
		return report, fmt.Errorf("read manifest: %w", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseManifestSchemaID, manifestBytes); err != nil {
		return report, fmt.Errorf("validate manifest schema: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return report, fmt.Errorf("decode manifest: %w", err)
	}
	report.ArtifactCount = len(manifest.Artifacts)
	report.Provenance = ReleaseProvenance{
		Version:               manifest.Version,
		Commit:                manifest.Commit,
		Date:                  manifest.Date,
		Artifacts:             []ArtifactProvenance{},
		SupplementalArtifacts: []SupplementalArtifactProvenance{},
	}
	if strings.TrimSpace(opts.PublicKeyPath) != "" {
		fingerprint, err := verifyReleaseSignature(report.SignaturePath, manifestBytes, opts.PublicKeyPath)
		if err != nil {
			problem("release signature verification failed: %v", err)
		} else {
			report.PublicKeySHA256 = fingerprint
			report.Provenance.PublicKeySHA256 = fingerprint
			report.Provenance.SignatureVerified = true
		}
	}

	checksums, err := readChecksums(report.ChecksumsPath)
	if err != nil {
		return report, err
	}
	seenArtifacts := map[string]struct{}{}
	manifestedChecksumPaths := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		artifactReport := ArtifactVerifyReport{
			Name:                artifact.Name,
			Target:              artifact.Target,
			Path:                artifact.Path,
			Verified:            true,
			PathValid:           true,
			DigestVerified:      true,
			SizeVerified:        true,
			ChecksumVerified:    true,
			MetadataVerified:    true,
			HostMetadataChecked: opts.HostMetadata != nil && isHostTarget(artifact.Target),
			SHA256:              artifact.SHA256,
			SizeBytes:           artifact.SizeBytes,
			Problems:            []string{},
			Attestations:        []AttestationVerifyReport{},
		}
		artifactProblem := func(format string, args ...any) {
			message := fmt.Sprintf(format, args...)
			artifactReport.Verified = false
			artifactReport.Problems = append(artifactReport.Problems, message)
			problem("%s", message)
		}
		manifestedChecksumPaths[artifact.Path] = struct{}{}
		manifestedChecksumPaths[artifact.Name] = struct{}{}
		if strings.TrimSpace(artifact.Path) == "" || filepath.IsAbs(artifact.Path) {
			artifactReport.PathValid = false
			artifactProblem("artifact %q has invalid relative path %q", artifact.Name, artifact.Path)
			report.Artifacts = append(report.Artifacts, artifactReport)
			continue
		}
		cleanPath := filepath.Clean(artifact.Path)
		if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
			artifactReport.PathValid = false
			artifactProblem("artifact %q has escaping path %q", artifact.Name, artifact.Path)
			report.Artifacts = append(report.Artifacts, artifactReport)
			continue
		}
		if _, ok := seenArtifacts[artifact.Name]; ok {
			artifactProblem("duplicate artifact %q", artifact.Name)
		}
		seenArtifacts[artifact.Name] = struct{}{}

		artifactPath := filepath.Join(dir, cleanPath)
		digest, size, err := fileDigest(artifactPath)
		if err != nil {
			artifactReport.DigestVerified = false
			artifactReport.SizeVerified = false
			artifactProblem("artifact %q read failed: %v", artifact.Name, err)
			report.Artifacts = append(report.Artifacts, artifactReport)
			continue
		}
		artifactReport.ActualSHA256 = digest
		artifactReport.ActualSizeBytes = size
		if digest != artifact.SHA256 {
			artifactReport.DigestVerified = false
			artifactProblem("artifact %q sha256 mismatch: got %s want %s", artifact.Name, digest, artifact.SHA256)
		}
		if size != artifact.SizeBytes {
			artifactReport.SizeVerified = false
			artifactProblem("artifact %q size mismatch: got %d want %d", artifact.Name, size, artifact.SizeBytes)
		}
		checksumDigest, ok := checksums[artifact.Path]
		if !ok {
			checksumDigest, ok = checksums[artifact.Name]
		}
		if !ok {
			artifactReport.ChecksumVerified = false
			artifactProblem("artifact %q missing SHA256SUMS entry", artifact.Name)
		} else if checksumDigest != artifact.SHA256 {
			artifactReport.ChecksumVerified = false
			artifactProblem("artifact %q SHA256SUMS mismatch: got %s want %s", artifact.Name, checksumDigest, artifact.SHA256)
		}
		var binaryMetadata *buildinfo.Info
		if opts.Metadata != nil {
			info, err := opts.Metadata(artifactPath)
			if err != nil {
				artifactReport.MetadataVerified = false
				artifactProblem("artifact %q metadata read failed: %v", artifact.Name, err)
			} else {
				binaryMetadata = &info
				before := len(report.Problems)
				compareBuildMetadata(artifactProblem, artifact, manifest, info, false)
				artifactReport.MetadataVerified = len(report.Problems) == before
			}
		}
		if opts.HostMetadata != nil && isHostTarget(artifact.Target) {
			info, err := opts.HostMetadata(artifactPath)
			if err != nil {
				artifactReport.MetadataVerified = false
				artifactProblem("artifact %q host metadata read failed: %v", artifact.Name, err)
			} else {
				binaryMetadata = &info
				before := len(report.Problems)
				compareBuildMetadata(artifactProblem, artifact, manifest, info, true)
				artifactReport.MetadataVerified = artifactReport.MetadataVerified && len(report.Problems) == before
			}
		}
		artifactProvenance := ArtifactProvenance{
			Name:               artifact.Name,
			Target:             artifact.Target,
			VerificationStatus: statusForBool(artifactReport.Verified),
			MetadataVerified:   artifactReport.MetadataVerified,
			BinaryMetadata:     binaryMetadata,
			Attestations:       []AttestationProvenance{},
		}
		for _, attestation := range artifact.Attestations {
			attestationReport := verifyAttestation(dir, checksums, attestation, problem)
			artifactReport.Attestations = append(artifactReport.Attestations, attestationReport)
			manifestedChecksumPaths[attestation.Path] = struct{}{}
			manifestedChecksumPaths[attestation.Name] = struct{}{}
			if !attestationReport.Verified {
				artifactReport.Verified = false
			}
			artifactProvenance.Attestations = append(artifactProvenance.Attestations, AttestationProvenance{
				Kind:               attestation.Kind,
				Name:               attestation.Name,
				Path:               attestation.Path,
				VerificationStatus: statusForBool(attestationReport.Verified),
				SHA256:             attestation.SHA256,
				SizeBytes:          attestation.SizeBytes,
			})
		}
		artifactProvenance.VerificationStatus = statusForBool(artifactReport.Verified)
		report.Artifacts = append(report.Artifacts, artifactReport)
		report.Provenance.Artifacts = append(report.Provenance.Artifacts, artifactProvenance)
	}
	for _, supplemental := range manifest.SupplementalArtifacts {
		reportItem := verifySupplementalArtifact(dir, checksums, supplemental, problem)
		report.SupplementalArtifacts = append(report.SupplementalArtifacts, reportItem)
		manifestedChecksumPaths[supplemental.Path] = struct{}{}
		manifestedChecksumPaths[supplemental.Name] = struct{}{}
		report.Provenance.SupplementalArtifacts = append(report.Provenance.SupplementalArtifacts, SupplementalArtifactProvenance{
			Kind:               supplemental.Kind,
			Name:               supplemental.Name,
			Path:               supplemental.Path,
			VerificationStatus: statusForBool(reportItem.Verified),
			SHA256:             supplemental.SHA256,
			SizeBytes:          supplemental.SizeBytes,
		})
	}
	for path := range checksums {
		if _, found := manifestedChecksumPaths[path]; !found {
			problem("SHA256SUMS contains unmanifested artifact %q", path)
		}
	}
	return report, nil
}

func verifyAttestation(dir string, checksums map[string]string, attestation Attestation, problem func(string, ...any)) AttestationVerifyReport {
	report := AttestationVerifyReport{
		Name:             attestation.Name,
		Kind:             attestation.Kind,
		Path:             attestation.Path,
		Verified:         true,
		PathValid:        true,
		DigestVerified:   true,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           attestation.SHA256,
		SizeBytes:        attestation.SizeBytes,
		Problems:         []string{},
	}
	localProblem := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		report.Verified = false
		report.Problems = append(report.Problems, message)
		problem("%s", message)
	}
	if strings.TrimSpace(attestation.Path) == "" || filepath.IsAbs(attestation.Path) {
		report.PathValid = false
		localProblem("attestation %q has invalid relative path %q", attestation.Name, attestation.Path)
		return report
	}
	cleanPath := filepath.Clean(attestation.Path)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		report.PathValid = false
		localProblem("attestation %q has escaping path %q", attestation.Name, attestation.Path)
		return report
	}
	digest, size, err := fileDigest(filepath.Join(dir, cleanPath))
	if err != nil {
		report.DigestVerified = false
		report.SizeVerified = false
		localProblem("attestation %q read failed: %v", attestation.Name, err)
		return report
	}
	report.ActualSHA256 = digest
	report.ActualSizeBytes = size
	if digest != attestation.SHA256 {
		report.DigestVerified = false
		localProblem("attestation %q sha256 mismatch: got %s want %s", attestation.Name, digest, attestation.SHA256)
	}
	if size != attestation.SizeBytes {
		report.SizeVerified = false
		localProblem("attestation %q size mismatch: got %d want %d", attestation.Name, size, attestation.SizeBytes)
	}
	checksumDigest, ok := checksums[attestation.Path]
	if !ok {
		checksumDigest, ok = checksums[attestation.Name]
	}
	if !ok {
		report.ChecksumVerified = false
		localProblem("attestation %q missing SHA256SUMS entry", attestation.Name)
	} else if checksumDigest != attestation.SHA256 {
		report.ChecksumVerified = false
		localProblem("attestation %q SHA256SUMS mismatch: got %s want %s", attestation.Name, checksumDigest, attestation.SHA256)
	}
	return report
}

func verifySupplementalArtifact(dir string, checksums map[string]string, supplemental SupplementalArtifact, problem func(string, ...any)) SupplementalVerifyReport {
	report := SupplementalVerifyReport{
		Kind:             supplemental.Kind,
		Name:             supplemental.Name,
		Path:             supplemental.Path,
		Verified:         true,
		PathValid:        true,
		DigestVerified:   true,
		SizeVerified:     true,
		ChecksumVerified: true,
		SHA256:           supplemental.SHA256,
		SizeBytes:        supplemental.SizeBytes,
		Problems:         []string{},
	}
	localProblem := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		report.Verified = false
		report.Problems = append(report.Problems, message)
		problem("%s", message)
	}
	if strings.TrimSpace(supplemental.Path) == "" || filepath.IsAbs(supplemental.Path) {
		report.PathValid = false
		localProblem("supplemental artifact %q has invalid relative path %q", supplemental.Name, supplemental.Path)
		return report
	}
	cleanPath := filepath.Clean(supplemental.Path)
	if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		report.PathValid = false
		localProblem("supplemental artifact %q has escaping path %q", supplemental.Name, supplemental.Path)
		return report
	}
	digest, size, err := fileDigest(filepath.Join(dir, cleanPath))
	if err != nil {
		report.DigestVerified = false
		report.SizeVerified = false
		localProblem("supplemental artifact %q read failed: %v", supplemental.Name, err)
		return report
	}
	report.ActualSHA256 = digest
	report.ActualSizeBytes = size
	if digest != supplemental.SHA256 {
		report.DigestVerified = false
		localProblem("supplemental artifact %q sha256 mismatch: got %s want %s", supplemental.Name, digest, supplemental.SHA256)
	}
	if size != supplemental.SizeBytes {
		report.SizeVerified = false
		localProblem("supplemental artifact %q size mismatch: got %d want %d", supplemental.Name, size, supplemental.SizeBytes)
	}
	checksumDigest, ok := checksums[supplemental.Path]
	if !ok {
		checksumDigest, ok = checksums[supplemental.Name]
	}
	if !ok {
		report.ChecksumVerified = false
		localProblem("supplemental artifact %q missing SHA256SUMS entry", supplemental.Name)
	} else if checksumDigest != supplemental.SHA256 {
		report.ChecksumVerified = false
		localProblem("supplemental artifact %q SHA256SUMS mismatch: got %s want %s", supplemental.Name, checksumDigest, supplemental.SHA256)
	}
	return report
}

func statusForBool(ok bool) string {
	if ok {
		return "verified"
	}
	return "invalid"
}

func Inspect(opts InspectOptions) (InspectResult, error) {
	dir := defaultString(opts.Dir, "dist")
	verifyReport, err := Verify(VerifyOptions{
		Dir:           dir,
		PublicKeyPath: opts.PublicKeyPath,
		Metadata:      opts.Metadata,
	})
	if err != nil {
		return InspectResult{}, err
	}
	signature := inspectReleaseSignature(verifyReport.SignaturePath, opts.PublicKeyPath, verifyReport.PublicKeySHA256)
	return InspectResult{
		SchemaVersion:         schema.ReleaseInspectResultSchemaID,
		ReleaseDir:            dir,
		ManifestPath:          verifyReport.ManifestPath,
		ChecksumsPath:         verifyReport.ChecksumsPath,
		SignaturePath:         nonEmptyFilePath(verifyReport.SignaturePath),
		ManifestValid:         true,
		ChecksumStatus:        checksumStatus(verifyReport.Verified),
		Signature:             signature,
		ArtifactCount:         verifyReport.ArtifactCount,
		Artifacts:             verifyReport.Artifacts,
		SupplementalArtifacts: verifyReport.SupplementalArtifacts,
		Problems:              verifyReport.Problems,
	}, nil
}

func Report(opts ReportOptions) (ReportResult, error) {
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		audience = "internal"
	}
	inspection, err := Inspect(InspectOptions{Dir: opts.Dir, PublicKeyPath: opts.PublicKeyPath})
	if err != nil {
		return ReportResult{}, err
	}
	if opts.Redaction.Paths || opts.Redaction.Digests {
		inspection = RedactInspect(inspection, opts.Redaction)
	}
	result := ReportResult{
		SchemaVersion:     schema.ReleaseReportResultSchemaID,
		Valid:             inspection.ChecksumStatus == "verified" && inspection.Signature.Status != "invalid" && len(inspection.Problems) == 0,
		Format:            "json",
		Audience:          audience,
		Redacted:          opts.Redaction.Paths || opts.Redaction.Digests,
		Redactions:        redactionNames(opts.Redaction),
		RedactionProfile:  opts.Redaction.RedactionProfile,
		ProvenanceSummary: SummarizeProvenance(inspection),
		Inspection:        inspection,
	}
	return result, nil
}

func SummarizeProvenance(inspection InspectResult) ProvenanceSummary {
	summary := ProvenanceSummary{SignatureStatus: inspection.Signature.Status}
	if summary.SignatureStatus == "" {
		summary.SignatureStatus = "unsigned"
	}
	for _, artifact := range inspection.Artifacts {
		for _, attestation := range artifact.Attestations {
			if attestation.Verified {
				summary.AttestationVerifiedCount++
			} else {
				summary.AttestationInvalidCount++
				summary.InvalidEvidenceCount++
			}
		}
	}
	for _, supplemental := range inspection.SupplementalArtifacts {
		switch supplemental.Kind {
		case "sbom":
			if supplemental.Verified {
				summary.SBOMVerifiedCount++
			} else {
				summary.SBOMInvalidCount++
				summary.InvalidEvidenceCount++
			}
		case "provenance":
			if supplemental.Verified {
				summary.SupplementalProvenanceVerifiedCount++
			} else {
				summary.SupplementalProvenanceInvalidCount++
				summary.InvalidEvidenceCount++
			}
		}
	}
	if inspection.Signature.Status == "invalid" {
		summary.InvalidEvidenceCount++
	}
	return summary
}

func RedactInspect(result InspectResult, opts RedactionOptions) InspectResult {
	if opts.Paths {
		result.ReleaseDir = redactedPath
		result.ManifestPath = redactedPath
		result.ChecksumsPath = redactedPath
		if result.SignaturePath != "" {
			result.SignaturePath = redactedPath
		}
	}
	if opts.Digests {
		result.Signature.PublicKeySHA256 = redactedDigest
	}
	for i := range result.Artifacts {
		if opts.Paths {
			result.Artifacts[i].Path = redactedPath
		}
		if opts.Digests {
			result.Artifacts[i].SHA256 = redactedDigest
			result.Artifacts[i].ActualSHA256 = redactedDigest
		}
		for j := range result.Artifacts[i].Attestations {
			if opts.Paths {
				result.Artifacts[i].Attestations[j].Path = redactedPath
			}
			if opts.Digests {
				result.Artifacts[i].Attestations[j].SHA256 = redactedDigest
				result.Artifacts[i].Attestations[j].ActualSHA256 = redactedDigest
			}
		}
	}
	for i := range result.SupplementalArtifacts {
		if opts.Paths {
			result.SupplementalArtifacts[i].Path = redactedPath
		}
		if opts.Digests {
			result.SupplementalArtifacts[i].SHA256 = redactedDigest
			result.SupplementalArtifacts[i].ActualSHA256 = redactedDigest
		}
	}
	if opts.Digests {
		result.Problems = redactProblemDigests(result.Problems)
	}
	if opts.Paths {
		result.Problems = redactProblemPaths(result.Problems)
	}
	return result
}

func RedactReport(result ReportResult, opts RedactionOptions) ReportResult {
	result.Redacted = opts.Paths || opts.Digests
	result.Redactions = redactionNames(opts)
	result.RedactionProfile = opts.RedactionProfile
	result.Inspection = RedactInspect(result.Inspection, opts)
	return result
}

func Diff(opts DiffOptions) (DiffReport, error) {
	fromInspection, err := Inspect(InspectOptions{Dir: opts.FromDir, PublicKeyPath: opts.FromPublicKeyPath})
	if err != nil {
		return DiffReport{}, fmt.Errorf("inspect from release: %w", err)
	}
	toInspection, err := Inspect(InspectOptions{Dir: opts.ToDir, PublicKeyPath: opts.ToPublicKeyPath})
	if err != nil {
		return DiffReport{}, fmt.Errorf("inspect to release: %w", err)
	}
	report := DiffReport{
		SchemaVersion:    schema.ReleaseDiffResultSchemaID,
		FromDir:          opts.FromDir,
		ToDir:            opts.ToDir,
		Entries:          []DiffEntry{},
		Redacted:         opts.Redaction.Paths || opts.Redaction.Digests,
		Redactions:       redactionNames(opts.Redaction),
		RedactionProfile: opts.Redaction.RedactionProfile,
	}
	fromManifest, err := readManifestFile(fromInspection.ManifestPath)
	if err != nil {
		return DiffReport{}, err
	}
	toManifest, err := readManifestFile(toInspection.ManifestPath)
	if err != nil {
		return DiffReport{}, err
	}
	if fromManifest.Version != toManifest.Version {
		report.Entries = append(report.Entries, DiffEntry{Category: "metadata", Action: "changed", Name: "version", Detail: fromManifest.Version + " -> " + toManifest.Version})
	}
	if fromManifest.Commit != toManifest.Commit {
		report.Entries = append(report.Entries, DiffEntry{Category: "metadata", Action: "changed", Name: "commit", Detail: redactDigestPair(fromManifest.Commit, toManifest.Commit, opts.Redaction)})
	}
	diffArtifacts(&report, fromManifest.Artifacts, toManifest.Artifacts, opts.Redaction)
	diffSupplementalArtifacts(&report, fromManifest.SupplementalArtifacts, toManifest.SupplementalArtifacts, opts.Redaction)
	if fromInspection.Signature.PublicKeySHA256 != toInspection.Signature.PublicKeySHA256 {
		report.Entries = append(report.Entries, DiffEntry{
			Category: "signatures",
			Action:   "changed",
			Name:     "public_key_sha256",
			Detail:   redactDigestPair(fromInspection.Signature.PublicKeySHA256, toInspection.Signature.PublicKeySHA256, opts.Redaction),
		})
	}
	for _, problem := range fromInspection.Problems {
		report.Entries = append(report.Entries, DiffEntry{Category: "problems", Action: "present", Name: "from", Detail: redactProblem(problem, opts.Redaction)})
	}
	for _, problem := range toInspection.Problems {
		report.Entries = append(report.Entries, DiffEntry{Category: "problems", Action: "present", Name: "to", Detail: redactProblem(problem, opts.Redaction)})
	}
	if opts.Redaction.Paths {
		report.FromDir = redactedPath
		report.ToDir = redactedPath
	}
	report.Changed = len(report.Entries) > 0
	return report, nil
}

func InspectSARIF(result InspectResult) schema.SARIFLog {
	return InspectSARIFWithOptions(result, InspectSARIFOptions{})
}

func InspectSARIFWithOptions(result InspectResult, opts InspectSARIFOptions) schema.SARIFLog {
	rules := []schema.SARIFRule{
		sarifRule("RELEASE_ARTIFACT_PROBLEM", "Release artifact problem"),
		sarifRule("RELEASE_ATTESTATION_PROBLEM", "Release attestation problem"),
		sarifRule("RELEASE_SUPPLEMENTAL_PROBLEM", "Release supplemental artifact problem"),
		sarifRule("RELEASE_PROBLEM", "Release problem"),
	}
	results := []schema.SARIFResult{}
	for _, artifact := range result.Artifacts {
		for _, message := range artifact.Problems {
			field := "artifact:" + artifact.Name
			results = append(results, releaseSARIFResult("RELEASE_ARTIFACT_PROBLEM", message, artifact.Path, schema.SARIFResultProperties{Component: "artifact", Name: artifact.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
		}
		for _, attestation := range artifact.Attestations {
			for _, message := range attestation.Problems {
				field := "attestation:" + artifact.Name + "/" + attestation.Name
				results = append(results, releaseSARIFResult("RELEASE_ATTESTATION_PROBLEM", message, attestation.Path, schema.SARIFResultProperties{Component: "attestation", Name: attestation.Name, ArtifactName: artifact.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
			}
		}
	}
	for _, supplemental := range result.SupplementalArtifacts {
		for _, message := range supplemental.Problems {
			field := "supplemental:" + supplemental.Kind + "/" + supplemental.Name
			results = append(results, releaseSARIFResult("RELEASE_SUPPLEMENTAL_PROBLEM", message, supplemental.Path, schema.SARIFResultProperties{Component: "supplemental_artifact", Kind: supplemental.Kind, Name: supplemental.Name, Location: field, ReleaseDir: result.ReleaseDir}, opts.Baseline, field))
		}
	}
	for _, message := range result.Problems {
		if problemCoveredByComponent(result, message) {
			continue
		}
		results = append(results, releaseSARIFResult("RELEASE_PROBLEM", message, result.ChecksumsPath, schema.SARIFResultProperties{Component: "release", Location: "release", ReleaseDir: result.ReleaseDir}, opts.Baseline, "release"))
	}
	return schema.SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []schema.SARIFRun{{
			Tool:    schema.SARIFTool{Driver: schema.SARIFDriver{Name: "AO Covenant Release Inspector", InformationURI: "https://github.com/uesugitorachiyo/ao-covenant", Rules: rules}},
			Results: results,
		}},
	}
}

func DiffSARIF(result DiffReport) schema.SARIFLog {
	return DiffSARIFWithOptions(result, DiffSARIFOptions{})
}

func DiffSARIFWithOptions(result DiffReport, opts DiffSARIFOptions) schema.SARIFLog {
	rules := []schema.SARIFRule{
		sarifRule("RELEASE_DIFF_METADATA", "Release metadata changed"),
		sarifRule("RELEASE_DIFF_ARTIFACT", "Release artifact changed"),
		sarifRule("RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT", "Release supplemental artifact changed"),
		sarifRule("RELEASE_DIFF_SIGNATURE", "Release signature changed"),
		sarifRule("RELEASE_DIFF_PROBLEM", "Release problem changed"),
	}
	results := []schema.SARIFResult{}
	for _, entry := range result.Entries {
		ruleID := diffRuleID(entry.Category)
		field := entry.Category + ":" + entry.Name
		uri := filepath.ToSlash(filepath.Join(result.ToDir, "manifest.json"))
		if entry.Category == "problems" && entry.Name == "from" {
			uri = filepath.ToSlash(filepath.Join(result.FromDir, "manifest.json"))
		}
		sarifResult := releaseSARIFResult(ruleID, entry.Detail, uri, schema.SARIFResultProperties{
			Component:  entry.Category,
			Kind:       entry.Action,
			Name:       entry.Name,
			Location:   field,
			ReleaseDir: result.ToDir,
		}, opts.Baseline, field)
		sarifResult.Level = "warning"
		results = append(results, sarifResult)
	}
	return schema.SARIFLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []schema.SARIFRun{{
			Tool:    schema.SARIFTool{Driver: schema.SARIFDriver{Name: "AO Covenant Release Diff", InformationURI: "https://github.com/uesugitorachiyo/ao-covenant", Rules: rules}},
			Results: results,
		}},
	}
}

func inspectReleaseSignature(signaturePath string, publicKeyPath string, verifiedFingerprint string) SignatureInspection {
	bytes, err := os.ReadFile(signaturePath)
	if err != nil {
		if strings.TrimSpace(publicKeyPath) == "" {
			return SignatureInspection{Status: "unsigned"}
		}
		return SignatureInspection{Status: "invalid", Problem: err.Error()}
	}
	var signature SignatureFile
	if err := json.Unmarshal(bytes, &signature); err != nil {
		return SignatureInspection{Status: "invalid", Problem: err.Error()}
	}
	status := "present_unverified"
	if strings.TrimSpace(publicKeyPath) != "" {
		if verifiedFingerprint != "" {
			status = "verified"
		} else {
			status = "invalid"
		}
	}
	return SignatureInspection{
		Status:          status,
		Algorithm:       signature.Algorithm,
		SignedEntry:     signature.SignedEntry,
		PublicKeySHA256: signature.PublicKeySHA256,
	}
}

func nonEmptyFilePath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func checksumStatus(verified bool) string {
	if verified {
		return "verified"
	}
	return "invalid"
}

func redactionNames(opts RedactionOptions) []string {
	names := []string{}
	if opts.Paths {
		names = append(names, "paths")
	}
	if opts.Digests {
		names = append(names, "digests")
	}
	return names
}

func redactProblem(problem string, opts RedactionOptions) string {
	if opts.Digests {
		problem = redactProblemDigests([]string{problem})[0]
	}
	if opts.Paths {
		problem = redactProblemPaths([]string{problem})[0]
	}
	return problem
}

func redactProblemDigests(problems []string) []string {
	redacted := append([]string{}, problems...)
	for i, problem := range redacted {
		fields := strings.Fields(problem)
		for _, field := range fields {
			candidate := strings.Trim(field, `"'.,:;()[]`)
			if len(candidate) == 64 && isLowerHex(candidate) {
				problem = strings.ReplaceAll(problem, candidate, "[REDACTED_DIGEST]")
			}
		}
		redacted[i] = problem
	}
	return redacted
}

func redactProblemPaths(problems []string) []string {
	redacted := append([]string{}, problems...)
	for i := range redacted {
		redacted[i] = strings.ReplaceAll(redacted[i], "\\", "/")
	}
	return redacted
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func redactDigestPair(from string, to string, opts RedactionOptions) string {
	if opts.Digests {
		return "[REDACTED_DIGEST] -> [REDACTED_DIGEST]"
	}
	return from + " -> " + to
}

func readManifestFile(path string) (Manifest, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func diffArtifacts(report *DiffReport, from []Artifact, to []Artifact, redaction RedactionOptions) {
	fromByName := map[string]Artifact{}
	toByName := map[string]Artifact{}
	for _, artifact := range from {
		fromByName[artifact.Name] = artifact
	}
	for _, artifact := range to {
		toByName[artifact.Name] = artifact
	}
	for name, artifact := range fromByName {
		next, ok := toByName[name]
		if !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "removed", Name: name, Detail: artifact.Target.OS + "/" + artifact.Target.Arch})
			continue
		}
		if artifact.SHA256 != next.SHA256 {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "changed", Name: name, Detail: redactDigestPair(artifact.SHA256, next.SHA256, redaction)})
		}
	}
	for name, artifact := range toByName {
		if _, ok := fromByName[name]; !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "artifacts", Action: "added", Name: name, Detail: artifact.Target.OS + "/" + artifact.Target.Arch})
		}
	}
}

func diffSupplementalArtifacts(report *DiffReport, from []SupplementalArtifact, to []SupplementalArtifact, redaction RedactionOptions) {
	fromByName := map[string]SupplementalArtifact{}
	toByName := map[string]SupplementalArtifact{}
	for _, artifact := range from {
		fromByName[artifact.Name] = artifact
	}
	for _, artifact := range to {
		toByName[artifact.Name] = artifact
	}
	for name, artifact := range fromByName {
		next, ok := toByName[name]
		if !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "removed", Name: name, Detail: artifact.Kind})
			continue
		}
		if artifact.SHA256 != next.SHA256 {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "changed", Name: name, Detail: redactDigestPair(artifact.SHA256, next.SHA256, redaction)})
		}
	}
	for name, artifact := range toByName {
		if _, ok := fromByName[name]; !ok {
			report.Entries = append(report.Entries, DiffEntry{Category: "supplemental_artifacts", Action: "added", Name: name, Detail: artifact.Kind})
		}
	}
}

func sarifRule(id string, text string) schema.SARIFRule {
	return schema.SARIFRule{
		ID:               id,
		ShortDescription: schema.SARIFMessage{Text: text},
	}
}

func releaseSARIFResult(ruleID string, message string, uri string, properties schema.SARIFResultProperties, baseline schema.SARIFBaseline, field string) schema.SARIFResult {
	result := schema.SARIFResult{
		RuleID:     ruleID,
		Level:      "error",
		Message:    schema.SARIFMessage{Text: message},
		Properties: properties,
	}
	if uri != "" {
		result.Locations = []schema.SARIFLocation{{
			PhysicalLocation: schema.SARIFPhysicalLocation{
				ArtifactLocation: schema.SARIFArtifactLocation{URI: filepath.ToSlash(uri)},
			},
		}}
	}
	if suppression, ok := matchingReleaseBaseline(ruleID, filepath.ToSlash(uri), field, baseline); ok {
		result.Suppressions = []schema.SARIFSuppression{{Kind: "external", Justification: suppression.Justification}}
	}
	return result
}

func matchingReleaseBaseline(ruleID string, uri string, field string, baseline schema.SARIFBaseline) (schema.SARIFBaselineEntry, bool) {
	for _, entry := range baseline.Accepted {
		if entry.RuleID != ruleID {
			continue
		}
		if entry.SourceURI != "" && entry.SourceURI != uri {
			continue
		}
		if entry.Field != "" && entry.Field != field {
			continue
		}
		return entry, true
	}
	return schema.SARIFBaselineEntry{}, false
}

func problemCoveredByComponent(result InspectResult, message string) bool {
	for _, artifact := range result.Artifacts {
		for _, problem := range artifact.Problems {
			if problem == message {
				return true
			}
		}
		for _, attestation := range artifact.Attestations {
			for _, problem := range attestation.Problems {
				if problem == message {
					return true
				}
			}
		}
	}
	for _, supplemental := range result.SupplementalArtifacts {
		for _, problem := range supplemental.Problems {
			if problem == message {
				return true
			}
		}
	}
	return false
}

func diffRuleID(category string) string {
	switch category {
	case "metadata":
		return "RELEASE_DIFF_METADATA"
	case "artifacts":
		return "RELEASE_DIFF_ARTIFACT"
	case "supplemental_artifacts":
		return "RELEASE_DIFF_SUPPLEMENTAL_ARTIFACT"
	case "signatures":
		return "RELEASE_DIFF_SIGNATURE"
	default:
		return "RELEASE_DIFF_PROBLEM"
	}
}

func ReadBinaryMetadata(path string) (buildinfo.Info, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "version", "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return buildinfo.Info{}, fmt.Errorf("run version --json timed out")
		}
		return buildinfo.Info{}, fmt.Errorf("run version --json: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := schema.ValidateBytes(schema.VersionResultSchemaID, output); err != nil {
		return buildinfo.Info{}, fmt.Errorf("validate version metadata: %w", err)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(output, &info); err != nil {
		return buildinfo.Info{}, fmt.Errorf("decode version metadata: %w", err)
	}
	return info, nil
}

func signReleaseManifest(privateKeyPath string, manifestBytes []byte) ([]byte, string, error) {
	privateKey, publicKey, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, "", err
	}
	fingerprint := publicKeyFingerprint(publicKey)
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureFile := SignatureFile{
		SchemaVersion:   ReleaseSignatureSchemaVersion,
		Algorithm:       signatureAlgorithm,
		SignedEntry:     releaseSignedEntryPath,
		PublicKeySHA256: fingerprint,
		Signature:       base64.StdEncoding.EncodeToString(signature),
	}
	bytes, err := json.MarshalIndent(signatureFile, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("encode release signature: %w", err)
	}
	bytes = append(bytes, '\n')
	if err := schema.ValidateBytes(schema.ReleaseSignatureSchemaID, bytes); err != nil {
		return nil, "", err
	}
	return bytes, fingerprint, nil
}

func verifyReleaseSignature(signaturePath string, manifestBytes []byte, publicKeyPath string) (string, error) {
	publicKey, err := readPublicKey(publicKeyPath)
	if err != nil {
		return "", err
	}
	signatureBytes, err := os.ReadFile(signaturePath)
	if err != nil {
		return "", fmt.Errorf("read release signature: %w", err)
	}
	if err := schema.ValidateBytes(schema.ReleaseSignatureSchemaID, signatureBytes); err != nil {
		return "", err
	}
	var signatureFile SignatureFile
	if err := json.Unmarshal(signatureBytes, &signatureFile); err != nil {
		return "", fmt.Errorf("decode release signature: %w", err)
	}
	if signatureFile.SchemaVersion != ReleaseSignatureSchemaVersion {
		return "", fmt.Errorf("unsupported release signature schema_version %q", signatureFile.SchemaVersion)
	}
	if signatureFile.Algorithm != signatureAlgorithm {
		return "", fmt.Errorf("unsupported release signature algorithm %q", signatureFile.Algorithm)
	}
	if signatureFile.SignedEntry != releaseSignedEntryPath {
		return "", fmt.Errorf("release signature signed_entry %q does not match %s", signatureFile.SignedEntry, releaseSignedEntryPath)
	}
	fingerprint := publicKeyFingerprint(publicKey)
	if signatureFile.PublicKeySHA256 != fingerprint {
		return "", fmt.Errorf("release signature public key fingerprint mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureFile.Signature)
	if err != nil {
		return "", fmt.Errorf("decode release signature bytes: %w", err)
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return "", fmt.Errorf("signature does not match manifest.json")
	}
	return fingerprint, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	if err := schema.ValidateBytes(schema.BundlePrivateKeySchemaID, bytes); err != nil {
		return nil, nil, err
	}
	var keyFile PrivateKeyFile
	if err := json.Unmarshal(bytes, &keyFile); err != nil {
		return nil, nil, fmt.Errorf("decode private key: %w", err)
	}
	if keyFile.SchemaVersion != "covenant.bundle-private-key.v1" {
		return nil, nil, fmt.Errorf("unsupported private key schema_version %q", keyFile.SchemaVersion)
	}
	if keyFile.Algorithm != signatureAlgorithm {
		return nil, nil, fmt.Errorf("unsupported private key algorithm %q", keyFile.Algorithm)
	}
	publicKey, err := decodePublicKey(keyFile.PublicKey, "private key public key")
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(keyFile.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key bytes: %w", err)
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("private key length = %d, want %d", len(privateKeyBytes), ed25519.PrivateKeySize)
	}
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		return nil, nil, fmt.Errorf("private key public key mismatch")
	}
	return privateKey, publicKey, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	if err := schema.ValidateBytes(schema.BundlePublicKeySchemaID, bytes); err != nil {
		return nil, err
	}
	var keyFile PublicKeyFile
	if err := json.Unmarshal(bytes, &keyFile); err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if keyFile.SchemaVersion != "covenant.bundle-public-key.v1" {
		return nil, fmt.Errorf("unsupported public key schema_version %q", keyFile.SchemaVersion)
	}
	if keyFile.Algorithm != signatureAlgorithm {
		return nil, fmt.Errorf("unsupported public key algorithm %q", keyFile.Algorithm)
	}
	return decodePublicKey(keyFile.PublicKey, "public key")
}

func decodePublicKey(encoded string, label string) (ed25519.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s length = %d, want %d", label, len(bytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(bytes), nil
}

func publicKeyFingerprint(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func compareBuildMetadata(problem func(string, ...any), artifact Artifact, manifest Manifest, info buildinfo.Info, checkTarget bool) {
	if info.Version != manifest.Version {
		problem("artifact %q version metadata mismatch: got %s want %s", artifact.Name, info.Version, manifest.Version)
	}
	if info.Commit != manifest.Commit {
		problem("artifact %q commit metadata mismatch: got %s want %s", artifact.Name, info.Commit, manifest.Commit)
	}
	if info.Date != manifest.Date {
		problem("artifact %q date metadata mismatch: got %s want %s", artifact.Name, info.Date, manifest.Date)
	}
	if checkTarget {
		if info.OS != artifact.Target.OS {
			problem("artifact %q os metadata mismatch: got %s want %s", artifact.Name, info.OS, artifact.Target.OS)
		}
		if info.Arch != artifact.Target.Arch {
			problem("artifact %q arch metadata mismatch: got %s want %s", artifact.Name, info.Arch, artifact.Target.Arch)
		}
	}
}

func isHostTarget(target Target) bool {
	return target.OS == runtime.GOOS && target.Arch == runtime.GOARCH
}

func buildLDFlags(version string, commit string, date string) string {
	prefix := "github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	return strings.Join([]string{
		"-s",
		"-w",
		"-X", prefix + ".Version=" + version,
		"-X", prefix + ".Commit=" + commit,
		"-X", prefix + ".Date=" + date,
	}, " ")
}

func artifactName(version string, target Target) string {
	name := fmt.Sprintf("ao-covenant_%s_%s_%s", version, target.OS, target.Arch)
	if target.OS == "windows" {
		name += ".exe"
	}
	return name
}

func goBuild(ctx context.Context, req BuildRequest) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", req.LDFlags, "-o", req.OutputPath, "./cmd/covenant")
	cmd.Dir = req.SourceDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+req.Target.OS, "GOARCH="+req.Target.Arch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build %s/%s: %w: %s", req.Target.OS, req.Target.Arch, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeManifest(path string, manifest Manifest) error {
	if err := schema.WriteJSONFile(path, schema.ReleaseManifestSchemaID, manifest, 0o644); err != nil {
		return fmt.Errorf("validate release manifest: %w", err)
	}
	return nil
}

func writeChecksums(path string, artifacts []Artifact, supplementalArtifacts []SupplementalArtifact) error {
	var builder strings.Builder
	for _, artifact := range artifacts {
		fmt.Fprintf(&builder, "%s  %s\n", artifact.SHA256, artifact.Name)
		for _, attestation := range artifact.Attestations {
			fmt.Fprintf(&builder, "%s  %s\n", attestation.SHA256, attestation.Path)
		}
	}
	for _, supplemental := range supplementalArtifacts {
		fmt.Fprintf(&builder, "%s  %s\n", supplemental.SHA256, supplemental.Path)
	}
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func readChecksums(path string) (map[string]string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read checksums: %w", err)
	}
	checksums := map[string]string{}
	for index, line := range strings.Split(strings.TrimSpace(string(bytes)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("parse checksums line %d: expected '<sha256>  <artifact>'", index+1)
		}
		if len(fields[0]) != 64 {
			return nil, fmt.Errorf("parse checksums line %d: invalid sha256 %q", index+1, fields[0])
		}
		checksums[fields[1]] = fields[0]
	}
	return checksums, nil
}

func fileDigest(path string) (string, int64, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), int64(len(bytes)), nil
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
