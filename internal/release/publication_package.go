package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

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
	if len(opts.Prebuilt) > 0 && len(opts.Prebuilt) != len(targets) {
		return Result{}, fmt.Errorf("prebuilt candidate count = %d, want %d targets", len(opts.Prebuilt), len(targets))
	}
	for _, target := range targets {
		name := artifactName(version, target)
		if existing := occupiedNames[name]; existing != "" {
			return Result{}, fmt.Errorf("duplicate release artifact name %q already used by %s", name, existing)
		}
		occupiedNames[name] = "binary artifact"
		outputPath := filepath.Join(outDir, name)
		buildOutputPath := filepath.Join(buildOutDir, name)
		if len(opts.Prebuilt) > 0 {
			prebuiltPath, ok := opts.Prebuilt[targetKey(target)]
			if !ok {
				return Result{}, fmt.Errorf("prebuilt candidate for target %s is required", targetKey(target))
			}
			if err := copyPrebuiltCandidate(prebuiltPath, buildOutputPath); err != nil {
				return Result{}, fmt.Errorf("copy prebuilt candidate for %s: %w", targetKey(target), err)
			}
		} else {
			if err := build(ctx, BuildRequest{
				SourceDir:  sourceDir,
				OutputPath: buildOutputPath,
				Target:     target,
				LDFlags:    ldflags,
			}); err != nil {
				return Result{}, err
			}
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

func copyPrebuiltCandidate(sourcePath string, outputPath string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("candidate must be a regular file")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	copied := false
	defer func() {
		output.Close()
		if !copied {
			os.Remove(outputPath)
		}
	}()
	if _, err := io.Copy(output, source); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	copied = true
	return nil
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
