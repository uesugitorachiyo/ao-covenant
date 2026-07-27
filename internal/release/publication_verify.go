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
