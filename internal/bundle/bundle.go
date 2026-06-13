package bundle

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	"github.com/uesugitorachiyo/ao-covenant/internal/closure"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/run"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
	verifypkg "github.com/uesugitorachiyo/ao-covenant/internal/verify"
)

const ManifestSchemaVersion = "covenant.evidence-bundle.v1"

const (
	redactedPath   = "[REDACTED_PATH]"
	redactedDigest = "[REDACTED_DIGEST]"
)

type Options struct {
	ContractPath    string
	LedgerPath      string
	EvidencePath    string
	WorkspaceDir    string
	OutPath         string
	SignKeyPath     string
	RevocationPaths []string
}

type Result struct {
	BundlePath      string
	Manifest        Manifest
	PublicKeySHA256 string
}

type VerifyOptions struct {
	BundlePath               string
	PublicKeyPath            string
	RevokedApprovalTicketIDs map[string]bool
}

type InspectOptions struct {
	BundlePath    string
	PublicKeyPath string
}

type ReportOptions struct {
	BundlePath    string
	PublicKeyPath string
}

type RedactionOptions struct {
	Paths   bool
	Digests bool
}

type InspectResult struct {
	BundlePath          string                    `json:"bundle_path"`
	SchemaVersion       string                    `json:"schema_version"`
	RunID               string                    `json:"run_id"`
	ContractDigest      string                    `json:"contract_digest"`
	LedgerDigest        string                    `json:"ledger_digest"`
	EntryCount          int                       `json:"entry_count"`
	ChecksumStatus      string                    `json:"checksum_status"`
	Signature           SignatureInspection       `json:"signature"`
	Verification        VerificationSummary       `json:"verification"`
	EventCount          int                       `json:"event_count"`
	ArtifactCount       int                       `json:"artifact_count"`
	InputSnapshotCount  int                       `json:"input_snapshot_count"`
	PolicyDecisionCount int                       `json:"policy_decision_count"`
	ClosureRowCount     int                       `json:"closure_row_count"`
	FailureCount        int                       `json:"failure_count"`
	RevocationListCount int                       `json:"revocation_list_count"`
	RevokedTicketCount  int                       `json:"revoked_ticket_count"`
	Entries             []Entry                   `json:"entries"`
	Artifacts           []ArtifactInspection      `json:"artifacts"`
	InputSnapshots      []InputSnapshotInspection `json:"input_snapshots"`
	PolicyExplanations  []policy.Explanation      `json:"policy_explanations"`
	Revocations         []RevocationInspection    `json:"revocations,omitempty"`
}

type ReportResult struct {
	BundlePath          string                    `json:"bundle_path"`
	SchemaVersion       string                    `json:"schema_version"`
	RunID               string                    `json:"run_id"`
	ContractDigest      string                    `json:"contract_digest"`
	LedgerDigest        string                    `json:"ledger_digest"`
	EntryCount          int                       `json:"entry_count"`
	ChecksumStatus      string                    `json:"checksum_status"`
	Signature           SignatureInspection       `json:"signature"`
	Verification        VerificationSummary       `json:"verification"`
	EventCount          int                       `json:"event_count"`
	ArtifactCount       int                       `json:"artifact_count"`
	InputSnapshotCount  int                       `json:"input_snapshot_count"`
	PolicyDecisionCount int                       `json:"policy_decision_count"`
	ClosureRowCount     int                       `json:"closure_row_count"`
	FailureCount        int                       `json:"failure_count"`
	RevocationListCount int                       `json:"revocation_list_count"`
	RevokedTicketCount  int                       `json:"revoked_ticket_count"`
	Entries             []Entry                   `json:"entries"`
	Events              []EventInspection         `json:"events"`
	Artifacts           []ArtifactInspection      `json:"artifacts"`
	InputSnapshots      []InputSnapshotInspection `json:"input_snapshots"`
	PolicyDecisions     []policy.Decision         `json:"policy_decisions"`
	PolicyExplanations  []policy.Explanation      `json:"policy_explanations"`
	Failures            []FailureInspection       `json:"failures"`
	ClosureRows         []ClosureRowInspection    `json:"closure_rows"`
	Revocations         []RevocationInspection    `json:"revocations,omitempty"`
}

type SignatureInspection struct {
	Status          string `json:"status"`
	Algorithm       string `json:"algorithm,omitempty"`
	SignedEntry     string `json:"signed_entry,omitempty"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
}

type ArtifactInspection struct {
	ArtifactID      string `json:"artifact_id"`
	Path            string `json:"path"`
	Digest          string `json:"digest"`
	MediaType       string `json:"media_type"`
	ProducerEventID string `json:"producer_event_id"`
	ProducerTaskID  string `json:"producer_task_id,omitempty"`
	ProducerFound   bool   `json:"producer_found"`
}

type EventInspection struct {
	EventID          string   `json:"event_id"`
	Sequence         int      `json:"sequence"`
	Line             int      `json:"line"`
	Type             string   `json:"type"`
	TaskID           string   `json:"task_id,omitempty"`
	Status           string   `json:"status"`
	Message          string   `json:"message,omitempty"`
	ArtifactIDs      []string `json:"artifact_ids,omitempty"`
	DecisionID       string   `json:"decision_id,omitempty"`
	Decision         string   `json:"decision,omitempty"`
	EffectType       string   `json:"effect_type,omitempty"`
	Resource         string   `json:"resource,omitempty"`
	ApprovalTicketID string   `json:"approval_ticket_id,omitempty"`
}

type InputSnapshotInspection struct {
	SnapshotID   string `json:"snapshot_id"`
	SourcePath   string `json:"source_path"`
	SnapshotPath string `json:"snapshot_path"`
	Digest       string `json:"digest"`
	MediaType    string `json:"media_type"`
}

type FailureInspection struct {
	FailureID  string `json:"failure_id"`
	EventID    string `json:"event_id"`
	EventLine  int    `json:"event_line"`
	EventFound bool   `json:"event_found"`
	TaskID     string `json:"task_id,omitempty"`
	Phase      string `json:"phase"`
	Reason     string `json:"reason"`
}

type RevocationInspection struct {
	Path           string                    `json:"path"`
	RevokedCount   int                       `json:"revoked_count"`
	RevokedTickets []RevokedTicketInspection `json:"revoked_tickets"`
}

type RevokedTicketInspection struct {
	TicketID string `json:"ticket_id"`
	Reason   string `json:"reason"`
}

type ClosureRowInspection struct {
	ObligationID             string   `json:"obligation_id"`
	Required                 bool     `json:"required"`
	Status                   string   `json:"status"`
	TaskIDs                  []string `json:"task_ids"`
	ArtifactIDs              []string `json:"artifact_ids"`
	MissingArtifactIDs       []string `json:"missing_artifact_ids"`
	PolicyDecisionIDs        []string `json:"policy_decision_ids"`
	MissingPolicyDecisionIDs []string `json:"missing_policy_decision_ids"`
	Reason                   string   `json:"reason"`
}

type Manifest struct {
	SchemaVersion  string              `json:"schema_version"`
	RunID          string              `json:"run_id"`
	ContractDigest string              `json:"contract_digest"`
	LedgerDigest   string              `json:"ledger_digest"`
	Verification   VerificationSummary `json:"verification"`
	Entries        []Entry             `json:"entries"`
}

type VerificationSummary struct {
	Verified           bool `json:"verified"`
	EventCount         int  `json:"event_count"`
	ArtifactCount      int  `json:"artifact_count"`
	InputSnapshotCount int  `json:"input_snapshot_count"`
	FailureCount       int  `json:"failure_count"`
}

type Entry struct {
	Path      string `json:"path"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

const (
	PrivateKeySchemaVersion = "covenant.bundle-private-key.v1"
	PublicKeySchemaVersion  = "covenant.bundle-public-key.v1"
	SignatureSchemaVersion  = "covenant.bundle-signature.v1"
	signatureAlgorithm      = "ed25519"
	signatureEntryPath      = "bundle-signature.json"
	signedManifestPath      = "bundle-manifest.json"
)

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

type KeyPairResult struct {
	PrivateKeyPath  string `json:"private_key_path"`
	PublicKeyPath   string `json:"public_key_path"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type SignatureFile struct {
	SchemaVersion   string `json:"schema_version"`
	Algorithm       string `json:"algorithm"`
	SignedEntry     string `json:"signed_entry"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	Signature       string `json:"signature"`
}

type bundleFile struct {
	path   string
	source string
	bytes  []byte
}

func GenerateKeyPair(privatePath string, publicPath string) error {
	_, err := GenerateKeyPairWithResult(privatePath, publicPath)
	return err
}

func GenerateKeyPairWithResult(privatePath string, publicPath string) (KeyPairResult, error) {
	if strings.TrimSpace(privatePath) == "" {
		return KeyPairResult{}, fmt.Errorf("private key path is required")
	}
	if strings.TrimSpace(publicPath) == "" {
		return KeyPairResult{}, fmt.Errorf("public key path is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPairResult{}, fmt.Errorf("generate ed25519 key: %w", err)
	}
	privateFile := PrivateKeyFile{
		SchemaVersion: PrivateKeySchemaVersion,
		Algorithm:     signatureAlgorithm,
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		PrivateKey:    base64.StdEncoding.EncodeToString(privateKey),
	}
	publicFile := PublicKeyFile{
		SchemaVersion: PublicKeySchemaVersion,
		Algorithm:     signatureAlgorithm,
		PublicKey:     privateFile.PublicKey,
	}
	if err := schema.WriteJSONFile(privatePath, schema.BundlePrivateKeySchemaID, privateFile, 0o600); err != nil {
		return KeyPairResult{}, fmt.Errorf("write private key: %w", err)
	}
	if err := schema.WriteJSONFile(publicPath, schema.BundlePublicKeySchemaID, publicFile, 0o644); err != nil {
		return KeyPairResult{}, fmt.Errorf("write public key: %w", err)
	}
	return KeyPairResult{
		PrivateKeyPath:  privatePath,
		PublicKeyPath:   publicPath,
		PublicKeySHA256: publicKeyFingerprint(publicKey),
	}, nil
}

func Export(opts Options) (Result, error) {
	if strings.TrimSpace(opts.ContractPath) == "" {
		return Result{}, fmt.Errorf("contract path is required")
	}
	if strings.TrimSpace(opts.LedgerPath) == "" {
		return Result{}, fmt.Errorf("ledger path is required")
	}
	if strings.TrimSpace(opts.EvidencePath) == "" {
		return Result{}, fmt.Errorf("evidence path is required")
	}
	if strings.TrimSpace(opts.OutPath) == "" {
		return Result{}, fmt.Errorf("out path is required")
	}
	workspaceDir := opts.WorkspaceDir
	if strings.TrimSpace(workspaceDir) == "" {
		workspaceDir = "."
	}
	verification, err := verifypkg.Verify(verifypkg.Options{
		LedgerPath:   opts.LedgerPath,
		EvidencePath: opts.EvidencePath,
		WorkspaceDir: workspaceDir,
	})
	if err != nil {
		return Result{}, fmt.Errorf("verify run before bundle export: %w", err)
	}

	evidence, err := readEvidence(opts.EvidencePath)
	if err != nil {
		return Result{}, err
	}
	if err := verifyContractDigest(opts.ContractPath, evidence.ContractDigest); err != nil {
		return Result{}, err
	}
	files, err := gatherBundleFiles(opts, workspaceDir, evidence)
	if err != nil {
		return Result{}, err
	}
	revocationFiles, _, err := loadRevocationFiles(opts.RevocationPaths)
	if err != nil {
		return Result{}, err
	}
	files = append(files, revocationFiles...)
	entries, err := entriesForFiles(files)
	if err != nil {
		return Result{}, err
	}
	manifest := Manifest{
		SchemaVersion:  ManifestSchemaVersion,
		RunID:          evidence.RunID,
		ContractDigest: evidence.ContractDigest,
		LedgerDigest:   evidence.LedgerDigest,
		Verification: VerificationSummary{
			Verified:           verification.Verified,
			EventCount:         verification.EventCount,
			ArtifactCount:      verification.ArtifactCount,
			InputSnapshotCount: verification.InputSnapshotCount,
			FailureCount:       verification.FailureCount,
		},
		Entries: entries,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Result{}, err
	}
	manifestBytes = append(manifestBytes, '\n')
	files = append(files,
		bundleFile{path: "bundle-manifest.json", source: "generated", bytes: manifestBytes},
	)
	publicKeySHA256 := ""
	if strings.TrimSpace(opts.SignKeyPath) != "" {
		signatureBytes, fingerprint, err := signManifest(opts.SignKeyPath, manifestBytes)
		if err != nil {
			return Result{}, err
		}
		publicKeySHA256 = fingerprint
		files = append(files, bundleFile{path: signatureEntryPath, source: "generated", bytes: signatureBytes})
	}
	checksumEntries, err := entriesForFiles(files)
	if err != nil {
		return Result{}, err
	}
	checksums := checksumsForEntries(checksumEntries)
	files = append(files, bundleFile{path: "SHA256SUMS", source: "generated", bytes: []byte(checksums)})
	if err := writeZip(opts.OutPath, files); err != nil {
		return Result{}, err
	}
	return Result{BundlePath: opts.OutPath, Manifest: manifest, PublicKeySHA256: publicKeySHA256}, nil
}

func Verify(opts VerifyOptions) (verifypkg.Result, error) {
	if strings.TrimSpace(opts.BundlePath) == "" {
		return verifypkg.Result{}, fmt.Errorf("bundle path is required")
	}
	entries, err := readZipEntries(opts.BundlePath)
	if err != nil {
		return verifypkg.Result{}, err
	}
	if err := requireBundleEntries(entries); err != nil {
		return verifypkg.Result{}, err
	}
	if err := verifyBundleChecksums(entries); err != nil {
		return verifypkg.Result{}, err
	}
	if strings.TrimSpace(opts.PublicKeyPath) != "" {
		if err := verifyBundleSignature(entries, opts.PublicKeyPath); err != nil {
			return verifypkg.Result{}, err
		}
	}
	tmpDir, err := os.MkdirTemp("", "ao-covenant-bundle-*")
	if err != nil {
		return verifypkg.Result{}, fmt.Errorf("create bundle verification dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	for name, contents := range entries {
		if name == "bundle-manifest.json" || name == "SHA256SUMS" {
			continue
		}
		target := filepath.Join(tmpDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return verifypkg.Result{}, fmt.Errorf("create extracted dir: %w", err)
		}
		if err := os.WriteFile(target, contents, 0o644); err != nil {
			return verifypkg.Result{}, fmt.Errorf("write extracted entry %s: %w", name, err)
		}
	}
	evidencePath := filepath.Join(tmpDir, "evidence-pack.json")
	evidence, err := readEvidence(evidencePath)
	if err != nil {
		return verifypkg.Result{}, err
	}
	if err := verifyContractDigest(filepath.Join(tmpDir, "contract.json"), evidence.ContractDigest); err != nil {
		return verifypkg.Result{}, err
	}
	bundledRevokedIDs, err := readBundledRevokedApprovalIDs(filepath.Join(tmpDir, "revocations"))
	if err != nil {
		return verifypkg.Result{}, err
	}
	revokedIDs := mergeRevokedApprovalIDs(opts.RevokedApprovalTicketIDs, bundledRevokedIDs)
	result, err := verifypkg.Verify(verifypkg.Options{
		LedgerPath:               filepath.Join(tmpDir, "events.ndjson"),
		EvidencePath:             evidencePath,
		WorkspaceDir:             filepath.Join(tmpDir, "artifacts"),
		RevokedApprovalTicketIDs: revokedIDs,
	})
	if err != nil {
		return verifypkg.Result{}, err
	}
	if strings.TrimSpace(opts.PublicKeyPath) != "" {
		fingerprint, err := PublicKeyFingerprint(opts.PublicKeyPath)
		if err != nil {
			return verifypkg.Result{}, err
		}
		result.PublicKeySHA256 = fingerprint
	}
	return result, nil
}

func Inspect(opts InspectOptions) (InspectResult, error) {
	if strings.TrimSpace(opts.BundlePath) == "" {
		return InspectResult{}, fmt.Errorf("bundle path is required")
	}
	entries, err := readZipEntries(opts.BundlePath)
	if err != nil {
		return InspectResult{}, err
	}
	if err := requireBundleEntries(entries); err != nil {
		return InspectResult{}, err
	}
	if err := verifyBundleChecksums(entries); err != nil {
		return InspectResult{}, err
	}
	var manifest Manifest
	if err := schema.ValidateBytes(schema.EvidenceBundleSchemaID, entries["bundle-manifest.json"]); err != nil {
		return InspectResult{}, fmt.Errorf("validate bundle manifest: %w", err)
	}
	if err := json.Unmarshal(entries["bundle-manifest.json"], &manifest); err != nil {
		return InspectResult{}, fmt.Errorf("decode bundle manifest: %w", err)
	}
	evidence, err := decodeEvidence(entries["evidence-pack.json"])
	if err != nil {
		return InspectResult{}, err
	}
	events, err := decodeLedgerEvents(entries["events.ndjson"])
	if err != nil {
		return InspectResult{}, err
	}
	signature, err := inspectSignature(entries, opts.PublicKeyPath)
	if err != nil {
		return InspectResult{}, err
	}
	revocations, err := inspectBundledRevocations(entries)
	if err != nil {
		return InspectResult{}, err
	}
	return InspectResult{
		BundlePath:          opts.BundlePath,
		SchemaVersion:       schema.BundleInspectResultSchemaID,
		RunID:               manifest.RunID,
		ContractDigest:      manifest.ContractDigest,
		LedgerDigest:        manifest.LedgerDigest,
		EntryCount:          len(entries),
		ChecksumStatus:      "verified",
		Signature:           signature,
		Verification:        manifest.Verification,
		EventCount:          len(events),
		ArtifactCount:       len(evidence.ArtifactManifest),
		InputSnapshotCount:  len(evidence.InputSnapshots),
		PolicyDecisionCount: len(evidence.PolicyDecisions),
		ClosureRowCount:     len(evidence.ClosureMatrix.Rows),
		FailureCount:        len(evidence.Failures),
		RevocationListCount: len(revocations),
		RevokedTicketCount:  revokedTicketInspectionCount(revocations),
		Entries:             manifest.Entries,
		Artifacts:           inspectArtifacts(evidence.ArtifactManifest, events),
		InputSnapshots:      inspectInputSnapshots(evidence.InputSnapshots),
		PolicyExplanations:  policy.ExplainDecisions(evidence.PolicyDecisions),
		Revocations:         revocations,
	}, nil
}

func Report(opts ReportOptions) (ReportResult, error) {
	inspection, err := Inspect(InspectOptions{BundlePath: opts.BundlePath, PublicKeyPath: opts.PublicKeyPath})
	if err != nil {
		return ReportResult{}, err
	}
	entries, err := readZipEntries(opts.BundlePath)
	if err != nil {
		return ReportResult{}, err
	}
	evidence, err := decodeEvidence(entries["evidence-pack.json"])
	if err != nil {
		return ReportResult{}, err
	}
	events, err := decodeLedgerEvents(entries["events.ndjson"])
	if err != nil {
		return ReportResult{}, err
	}
	return ReportResult{
		BundlePath:          inspection.BundlePath,
		SchemaVersion:       "covenant.bundle-report-result.v1",
		RunID:               inspection.RunID,
		ContractDigest:      inspection.ContractDigest,
		LedgerDigest:        inspection.LedgerDigest,
		EntryCount:          inspection.EntryCount,
		ChecksumStatus:      inspection.ChecksumStatus,
		Signature:           inspection.Signature,
		Verification:        inspection.Verification,
		EventCount:          inspection.EventCount,
		ArtifactCount:       inspection.ArtifactCount,
		InputSnapshotCount:  inspection.InputSnapshotCount,
		PolicyDecisionCount: inspection.PolicyDecisionCount,
		ClosureRowCount:     inspection.ClosureRowCount,
		FailureCount:        inspection.FailureCount,
		RevocationListCount: inspection.RevocationListCount,
		RevokedTicketCount:  inspection.RevokedTicketCount,
		Entries:             inspection.Entries,
		Events:              inspectEvents(events),
		Artifacts:           inspection.Artifacts,
		InputSnapshots:      inspection.InputSnapshots,
		PolicyDecisions:     evidence.PolicyDecisions,
		PolicyExplanations:  inspection.PolicyExplanations,
		Failures:            inspectFailures(evidence.Failures, events),
		ClosureRows:         inspectClosureRows(evidence.ClosureMatrix, evidence.ArtifactManifest, evidence.PolicyDecisions),
		Revocations:         inspection.Revocations,
	}, nil
}

func RedactInspect(result InspectResult, opts RedactionOptions) InspectResult {
	result = cloneInspectResult(result)
	if opts.Paths {
		result.BundlePath = redactedPath
		for i := range result.Entries {
			result.Entries[i].Path = redactedPath
			result.Entries[i].Source = redactedPath
		}
		for i := range result.Artifacts {
			result.Artifacts[i].Path = redactedPath
		}
		for i := range result.InputSnapshots {
			result.InputSnapshots[i].SourcePath = redactedPath
			result.InputSnapshots[i].SnapshotPath = redactedPath
		}
		for i := range result.Revocations {
			result.Revocations[i].Path = redactedPath
		}
	}
	if opts.Digests {
		result.ContractDigest = redactedDigest
		result.LedgerDigest = redactedDigest
		for i := range result.Entries {
			result.Entries[i].SHA256 = redactedDigest
		}
		for i := range result.Artifacts {
			result.Artifacts[i].Digest = redactedDigest
		}
		for i := range result.InputSnapshots {
			result.InputSnapshots[i].Digest = redactedDigest
		}
		for i := range result.Revocations {
			for j := range result.Revocations[i].RevokedTickets {
				result.Revocations[i].RevokedTickets[j].TicketID = redactedDigest
				result.Revocations[i].RevokedTickets[j].Reason = redactedDigest
			}
		}
	}
	return result
}

func RedactReport(result ReportResult, opts RedactionOptions) ReportResult {
	result = cloneReportResult(result)
	inspection := RedactInspect(InspectResult{
		BundlePath:          result.BundlePath,
		SchemaVersion:       result.SchemaVersion,
		RunID:               result.RunID,
		ContractDigest:      result.ContractDigest,
		LedgerDigest:        result.LedgerDigest,
		EntryCount:          result.EntryCount,
		ChecksumStatus:      result.ChecksumStatus,
		Signature:           result.Signature,
		Verification:        result.Verification,
		EventCount:          result.EventCount,
		ArtifactCount:       result.ArtifactCount,
		InputSnapshotCount:  result.InputSnapshotCount,
		PolicyDecisionCount: result.PolicyDecisionCount,
		ClosureRowCount:     result.ClosureRowCount,
		FailureCount:        result.FailureCount,
		RevocationListCount: result.RevocationListCount,
		RevokedTicketCount:  result.RevokedTicketCount,
		Entries:             result.Entries,
		Artifacts:           result.Artifacts,
		InputSnapshots:      result.InputSnapshots,
		PolicyExplanations:  result.PolicyExplanations,
		Revocations:         result.Revocations,
	}, opts)
	result.BundlePath = inspection.BundlePath
	result.ContractDigest = inspection.ContractDigest
	result.LedgerDigest = inspection.LedgerDigest
	result.Entries = inspection.Entries
	result.Artifacts = inspection.Artifacts
	result.InputSnapshots = inspection.InputSnapshots
	result.PolicyExplanations = inspection.PolicyExplanations
	result.Revocations = inspection.Revocations
	if opts.Paths {
		for i := range result.Events {
			if result.Events[i].Resource != "" {
				result.Events[i].Resource = redactedPath
			}
		}
		for i := range result.PolicyDecisions {
			result.PolicyDecisions[i].Resource = redactedPath
		}
		for i := range result.PolicyExplanations {
			result.PolicyExplanations[i].Resource = redactedPath
			result.PolicyExplanations[i].Summary = redactTextPath(result.PolicyExplanations[i].Summary)
			result.PolicyExplanations[i].Detail = redactTextPath(result.PolicyExplanations[i].Detail)
		}
	}
	return result
}

func MarkdownReport(result ReportResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# AO Covenant Bundle Report\n\n")
	fmt.Fprintf(&builder, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&builder, "| Bundle | %s |\n", result.BundlePath)
	fmt.Fprintf(&builder, "| Run ID | %s |\n", result.RunID)
	fmt.Fprintf(&builder, "| Contract Digest | %s |\n", result.ContractDigest)
	fmt.Fprintf(&builder, "| Ledger Digest | %s |\n", result.LedgerDigest)
	fmt.Fprintf(&builder, "| Verified | %t |\n", result.Verification.Verified)
	fmt.Fprintf(&builder, "\n## Manifest Entries\n\n| Path | Source | SHA256 | Size |\n| --- | --- | --- | ---: |\n")
	for _, entry := range result.Entries {
		fmt.Fprintf(&builder, "| %s | %s | %s | %d |\n", entry.Path, entry.Source, entry.SHA256, entry.SizeBytes)
	}
	fmt.Fprintf(&builder, "\n## Ledger Events\n\n| Event ID | Sequence | Line | Type | Status |\n| --- | ---: | ---: | --- | --- |\n")
	for _, event := range result.Events {
		fmt.Fprintf(&builder, "| %s | %d | %d | %s | %s |\n", event.EventID, event.Sequence, event.Line, event.Type, event.Status)
	}
	fmt.Fprintf(&builder, "\n## Artifacts\n\n| Artifact ID | Path | Digest |\n| --- | --- | --- |\n")
	for _, artifact := range result.Artifacts {
		fmt.Fprintf(&builder, "| %s | %s | %s |\n", artifact.ArtifactID, artifact.Path, artifact.Digest)
	}
	fmt.Fprintf(&builder, "\n## Input Snapshots\n\n| Snapshot ID | Source Path | Snapshot Path | Digest |\n| --- | --- | --- | --- |\n")
	for _, snapshot := range result.InputSnapshots {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s |\n", snapshot.SnapshotID, snapshot.SourcePath, snapshot.SnapshotPath, snapshot.Digest)
	}
	fmt.Fprintf(&builder, "\n## Policy Decisions\n\n| Decision ID | Task ID | Decision | Effect | Resource | Summary |\n| --- | --- | --- | --- | --- | --- |\n")
	explanations := map[string]policy.Explanation{}
	for _, explanation := range result.PolicyExplanations {
		explanations[explanation.DecisionID] = explanation
	}
	for _, decision := range result.PolicyDecisions {
		fmt.Fprintf(&builder, "| %s | %s | %s | %s | %s | %s |\n", decision.DecisionID, decision.TaskID, decision.Decision, decision.EffectType, decision.Resource, explanations[decision.DecisionID].Summary)
	}
	fmt.Fprintf(&builder, "\n## Closure Rows\n\n| Obligation ID | Required | Status | Reason |\n| --- | --- | --- | --- |\n")
	for _, row := range result.ClosureRows {
		fmt.Fprintf(&builder, "| %s | %t | %s | %s |\n", row.ObligationID, row.Required, row.Status, row.Reason)
	}
	if len(result.Revocations) > 0 {
		fmt.Fprintf(&builder, "\n## Revocations\n\n| Path | Revoked Count | Ticket ID | Reason |\n| --- | ---: | --- | --- |\n")
		for _, revocation := range result.Revocations {
			if len(revocation.RevokedTickets) == 0 {
				fmt.Fprintf(&builder, "| %s | %d |  |  |\n", revocation.Path, revocation.RevokedCount)
				continue
			}
			for _, ticket := range revocation.RevokedTickets {
				fmt.Fprintf(&builder, "| %s | %d | %s | %s |\n", revocation.Path, revocation.RevokedCount, ticket.TicketID, ticket.Reason)
			}
		}
	}
	return builder.String()
}

func redactTextPath(value string) string {
	value = strings.ReplaceAll(value, "demo-output/report.txt", redactedPath)
	value = strings.ReplaceAll(value, "examples/risky-change/brief.md", redactedPath)
	return value
}

func cloneInspectResult(result InspectResult) InspectResult {
	bytes, err := json.Marshal(result)
	if err != nil {
		return result
	}
	var cloned InspectResult
	if err := json.Unmarshal(bytes, &cloned); err != nil {
		return result
	}
	return cloned
}

func cloneReportResult(result ReportResult) ReportResult {
	bytes, err := json.Marshal(result)
	if err != nil {
		return result
	}
	var cloned ReportResult
	if err := json.Unmarshal(bytes, &cloned); err != nil {
		return result
	}
	return cloned
}

func readZipEntries(bundlePath string) (map[string][]byte, error) {
	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer reader.Close()
	entries := map[string][]byte{}
	for _, file := range reader.File {
		name, err := validateBundlePath(file.Name)
		if err != nil {
			return nil, err
		}
		if _, exists := entries[name]; exists {
			return nil, fmt.Errorf("duplicate bundle entry %s", name)
		}
		fileReader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open bundle entry %s: %w", name, err)
		}
		contents, readErr := io.ReadAll(fileReader)
		closeErr := fileReader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read bundle entry %s: %w", name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close bundle entry %s: %w", name, closeErr)
		}
		entries[name] = contents
	}
	return entries, nil
}

func requireBundleEntries(entries map[string][]byte) error {
	for _, required := range []string{"contract.json", "events.ndjson", "evidence-pack.json", "bundle-manifest.json", "SHA256SUMS"} {
		if _, ok := entries[required]; !ok {
			return fmt.Errorf("bundle missing required entry %s", required)
		}
	}
	return nil
}

func verifyBundleChecksums(entries map[string][]byte) error {
	lines := strings.Split(strings.TrimSpace(string(entries["SHA256SUMS"])), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return fmt.Errorf("bundle checksums are empty")
	}
	for _, line := range lines {
		digest, entryPath, ok := strings.Cut(line, "  ")
		if !ok {
			return fmt.Errorf("invalid bundle checksum line %q", line)
		}
		entryPath, err := validateBundlePath(entryPath)
		if err != nil {
			return err
		}
		contents, ok := entries[entryPath]
		if !ok {
			return fmt.Errorf("bundle checksum references missing entry %s", entryPath)
		}
		sum := sha256.Sum256(contents)
		actual := hex.EncodeToString(sum[:])
		if actual != digest {
			return fmt.Errorf("bundle checksum mismatch for %s: expected %s actual %s", entryPath, digest, actual)
		}
	}
	return nil
}

func decodeEvidence(contents []byte) (run.EvidencePack, error) {
	var evidence run.EvidencePack
	if err := json.Unmarshal(contents, &evidence); err != nil {
		return run.EvidencePack{}, fmt.Errorf("decode evidence: %w", err)
	}
	return evidence, nil
}

func decodeLedgerEvents(contents []byte) ([]run.Event, error) {
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	events := make([]run.Event, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event run.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("decode ledger event: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

func inspectSignature(entries map[string][]byte, publicKeyPath string) (SignatureInspection, error) {
	signatureBytes, hasSignature := entries[signatureEntryPath]
	if strings.TrimSpace(publicKeyPath) != "" {
		if err := verifyBundleSignature(entries, publicKeyPath); err != nil {
			return SignatureInspection{}, err
		}
		signature, err := decodeSignatureInspection(signatureBytes)
		if err != nil {
			return SignatureInspection{}, err
		}
		signature.Status = "verified"
		return signature, nil
	}
	if !hasSignature {
		return SignatureInspection{Status: "unsigned"}, nil
	}
	signature, err := decodeSignatureInspection(signatureBytes)
	if err != nil {
		return SignatureInspection{}, err
	}
	signature.Status = "present_unverified"
	return signature, nil
}

func decodeSignatureInspection(contents []byte) (SignatureInspection, error) {
	var signature SignatureFile
	if err := json.Unmarshal(contents, &signature); err != nil {
		return SignatureInspection{}, fmt.Errorf("decode bundle signature: %w", err)
	}
	return SignatureInspection{
		Algorithm:       signature.Algorithm,
		SignedEntry:     signature.SignedEntry,
		PublicKeySHA256: signature.PublicKeySHA256,
	}, nil
}

func inspectArtifacts(artifacts []run.ArtifactRef, events []run.Event) []ArtifactInspection {
	eventByID := map[string]run.Event{}
	for _, event := range events {
		eventByID[event.EventID] = event
	}
	inspections := make([]ArtifactInspection, 0, len(artifacts))
	for _, artifact := range artifacts {
		event, found := eventByID[artifact.ProducerEventID]
		inspection := ArtifactInspection{
			ArtifactID:      artifact.ArtifactID,
			Path:            artifact.Path,
			Digest:          artifact.Digest,
			MediaType:       artifact.MediaType,
			ProducerEventID: artifact.ProducerEventID,
			ProducerFound:   found,
		}
		if found {
			inspection.ProducerTaskID = event.TaskID
		}
		inspections = append(inspections, inspection)
	}
	return inspections
}

func inspectEvents(events []run.Event) []EventInspection {
	inspections := make([]EventInspection, 0, len(events))
	for i, event := range events {
		inspections = append(inspections, EventInspection{
			EventID:          event.EventID,
			Sequence:         event.Sequence,
			Line:             i + 1,
			Type:             event.Type,
			TaskID:           event.TaskID,
			Status:           event.Status,
			Message:          event.Message,
			ArtifactIDs:      append([]string(nil), event.ArtifactIDs...),
			DecisionID:       event.DecisionID,
			Decision:         event.Decision,
			EffectType:       event.EffectType,
			Resource:         event.Resource,
			ApprovalTicketID: event.ApprovalTicketID,
		})
	}
	return inspections
}

func inspectInputSnapshots(snapshots []run.InputSnapshot) []InputSnapshotInspection {
	inspections := make([]InputSnapshotInspection, 0, len(snapshots))
	for _, snapshot := range snapshots {
		inspections = append(inspections, InputSnapshotInspection{
			SnapshotID:   snapshot.SnapshotID,
			SourcePath:   snapshot.SourcePath,
			SnapshotPath: snapshot.SnapshotPath,
			Digest:       snapshot.Digest,
			MediaType:    snapshot.MediaType,
		})
	}
	return inspections
}

func inspectBundledRevocations(entries map[string][]byte) ([]RevocationInspection, error) {
	paths := make([]string, 0)
	for entryPath := range entries {
		if strings.HasPrefix(entryPath, "revocations/") && strings.HasSuffix(entryPath, ".json") {
			paths = append(paths, entryPath)
		}
	}
	slices.Sort(paths)
	inspections := make([]RevocationInspection, 0, len(paths))
	for _, entryPath := range paths {
		var list approval.RevocationList
		if err := json.Unmarshal(entries[entryPath], &list); err != nil {
			return nil, fmt.Errorf("decode bundled revocation %s: %w", entryPath, err)
		}
		if err := approval.ValidateRevocationList(list); err != nil {
			return nil, fmt.Errorf("validate bundled revocation %s: %w", entryPath, err)
		}
		tickets := make([]RevokedTicketInspection, 0, len(list.RevokedTickets))
		for _, ticket := range list.RevokedTickets {
			tickets = append(tickets, RevokedTicketInspection{
				TicketID: ticket.TicketID,
				Reason:   ticket.Reason,
			})
		}
		inspections = append(inspections, RevocationInspection{
			Path:           entryPath,
			RevokedCount:   len(tickets),
			RevokedTickets: tickets,
		})
	}
	return inspections, nil
}

func revokedTicketInspectionCount(revocations []RevocationInspection) int {
	count := 0
	for _, revocation := range revocations {
		count += len(revocation.RevokedTickets)
	}
	return count
}

func inspectFailures(failures []run.FailureRecord, events []run.Event) []FailureInspection {
	eventLineByID := map[string]int{}
	for i, event := range events {
		eventLineByID[event.EventID] = i + 1
	}
	inspections := make([]FailureInspection, 0, len(failures))
	for _, failure := range failures {
		line, found := eventLineByID[failure.EventID]
		inspections = append(inspections, FailureInspection{
			FailureID:  failure.FailureID,
			EventID:    failure.EventID,
			EventLine:  line,
			EventFound: found,
			TaskID:     failure.TaskID,
			Phase:      failure.Phase,
			Reason:     failure.Reason,
		})
	}
	return inspections
}

func inspectClosureRows(matrix closure.Matrix, artifacts []run.ArtifactRef, decisions []policy.Decision) []ClosureRowInspection {
	artifactIDs := map[string]bool{}
	for _, artifact := range artifacts {
		artifactIDs[artifact.ArtifactID] = true
	}
	decisionIDs := map[string]bool{}
	for _, decision := range decisions {
		decisionIDs[decision.DecisionID] = true
	}
	inspections := make([]ClosureRowInspection, 0, len(matrix.Rows))
	for _, row := range matrix.Rows {
		inspections = append(inspections, ClosureRowInspection{
			ObligationID:             row.ObligationID,
			Required:                 row.Required,
			Status:                   row.Status,
			TaskIDs:                  append([]string(nil), row.TaskIDs...),
			ArtifactIDs:              append([]string(nil), row.ArtifactIDs...),
			MissingArtifactIDs:       missingIDs(row.ArtifactIDs, artifactIDs),
			PolicyDecisionIDs:        append([]string(nil), row.PolicyDecisionIDs...),
			MissingPolicyDecisionIDs: missingIDs(row.PolicyDecisionIDs, decisionIDs),
			Reason:                   row.Reason,
		})
	}
	return inspections
}

func missingIDs(references []string, known map[string]bool) []string {
	missing := []string{}
	for _, reference := range references {
		if !known[reference] {
			missing = append(missing, reference)
		}
	}
	return missing
}

func gatherBundleFiles(opts Options, workspaceDir string, evidence run.EvidencePack) ([]bundleFile, error) {
	files := []bundleFile{}
	contractFile, err := newBundleFile("contract.json", opts.ContractPath)
	if err != nil {
		return nil, err
	}
	files = append(files, contractFile)
	ledgerFile, err := newBundleFile("events.ndjson", opts.LedgerPath)
	if err != nil {
		return nil, err
	}
	files = append(files, ledgerFile)
	evidenceFile, err := newBundleFile("evidence-pack.json", opts.EvidencePath)
	if err != nil {
		return nil, err
	}
	files = append(files, evidenceFile)

	runDir := filepath.Dir(opts.EvidencePath)
	for _, snapshot := range evidence.InputSnapshots {
		source := filepath.Join(runDir, filepath.FromSlash(snapshot.SnapshotPath))
		bundlePath := slashJoin("input-snapshots", strings.TrimPrefix(slashClean(snapshot.SnapshotPath), "input-snapshots/"))
		file, err := newBundleFile(bundlePath, source)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	for _, artifact := range evidence.ArtifactManifest {
		source := filepath.Join(workspaceDir, filepath.FromSlash(slashClean(artifact.Path)))
		bundlePath := slashJoin("artifacts", slashClean(artifact.Path))
		file, err := newBundleFile(bundlePath, source)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func loadRevocationFiles(paths []string) ([]bundleFile, map[string]bool, error) {
	files := make([]bundleFile, 0, len(paths))
	lists := make([]approval.RevocationList, 0, len(paths))
	for _, revocationPath := range paths {
		if strings.TrimSpace(revocationPath) == "" {
			return nil, nil, fmt.Errorf("revocation path is required")
		}
		list, err := approval.ReadRevocationList(revocationPath)
		if err != nil {
			return nil, nil, err
		}
		bundlePath := slashJoin("revocations", path.Base(slashClean(revocationPath)))
		file, err := newBundleFile(bundlePath, revocationPath)
		if err != nil {
			return nil, nil, err
		}
		lists = append(lists, list)
		files = append(files, file)
	}
	return files, approval.RevokedTicketIDs(lists), nil
}

func readBundledRevokedApprovalIDs(revocationDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(revocationDir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("read bundled revocations: %w", err)
	}
	lists := make([]approval.RevocationList, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		list, err := approval.ReadRevocationList(filepath.Join(revocationDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read bundled revocation %s: %w", entry.Name(), err)
		}
		lists = append(lists, list)
	}
	return approval.RevokedTicketIDs(lists), nil
}

func mergeRevokedApprovalIDs(left map[string]bool, right map[string]bool) map[string]bool {
	merged := map[string]bool{}
	for id, revoked := range left {
		if revoked {
			merged[id] = true
		}
	}
	for id, revoked := range right {
		if revoked {
			merged[id] = true
		}
	}
	return merged
}

func newBundleFile(bundlePath string, sourcePath string) (bundleFile, error) {
	normalized, err := validateBundlePath(bundlePath)
	if err != nil {
		return bundleFile{}, err
	}
	bytes, err := os.ReadFile(sourcePath)
	if err != nil {
		return bundleFile{}, fmt.Errorf("read bundle source %s: %w", sourcePath, err)
	}
	return bundleFile{path: normalized, source: sourcePath, bytes: bytes}, nil
}

func entriesForFiles(files []bundleFile) ([]Entry, error) {
	seen := map[string]bool{}
	entries := make([]Entry, 0, len(files)+2)
	for _, file := range files {
		if seen[file.path] {
			return nil, fmt.Errorf("duplicate bundle path %s", file.path)
		}
		seen[file.path] = true
		sum := sha256.Sum256(file.bytes)
		entries = append(entries, Entry{
			Path:      file.path,
			Source:    file.source,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(file.bytes)),
		})
	}
	return entries, nil
}

func checksumsForEntries(entries []Entry) string {
	var builder strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&builder, "%s  %s\n", entry.SHA256, entry.Path)
	}
	return builder.String()
}

func signManifest(privateKeyPath string, manifestBytes []byte) ([]byte, string, error) {
	privateKey, publicKey, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return nil, "", err
	}
	fingerprint := publicKeyFingerprint(publicKey)
	signature := ed25519.Sign(privateKey, manifestBytes)
	signatureFile := SignatureFile{
		SchemaVersion:   SignatureSchemaVersion,
		Algorithm:       signatureAlgorithm,
		SignedEntry:     signedManifestPath,
		PublicKeySHA256: fingerprint,
		Signature:       base64.StdEncoding.EncodeToString(signature),
	}
	bytes, err := json.MarshalIndent(signatureFile, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("encode bundle signature: %w", err)
	}
	bytes = append(bytes, '\n')
	if err := schema.ValidateBytes(schema.BundleSignatureSchemaID, bytes); err != nil {
		return nil, "", err
	}
	return bytes, fingerprint, nil
}

func verifyBundleSignature(entries map[string][]byte, publicKeyPath string) error {
	manifestBytes, ok := entries[signedManifestPath]
	if !ok {
		return fmt.Errorf("bundle missing required entry %s", signedManifestPath)
	}
	signatureBytes, ok := entries[signatureEntryPath]
	if !ok {
		return fmt.Errorf("bundle signature is required when public key is supplied")
	}
	publicKey, err := readPublicKey(publicKeyPath)
	if err != nil {
		return err
	}
	if err := schema.ValidateBytes(schema.BundleSignatureSchemaID, signatureBytes); err != nil {
		return err
	}
	var signatureFile SignatureFile
	if err := json.Unmarshal(signatureBytes, &signatureFile); err != nil {
		return fmt.Errorf("decode bundle signature: %w", err)
	}
	if signatureFile.SchemaVersion != SignatureSchemaVersion {
		return fmt.Errorf("unsupported bundle signature schema_version %q", signatureFile.SchemaVersion)
	}
	if signatureFile.Algorithm != signatureAlgorithm {
		return fmt.Errorf("unsupported bundle signature algorithm %q", signatureFile.Algorithm)
	}
	if signatureFile.SignedEntry != signedManifestPath {
		return fmt.Errorf("bundle signature signed_entry %q does not match %s", signatureFile.SignedEntry, signedManifestPath)
	}
	if signatureFile.PublicKeySHA256 != publicKeyFingerprint(publicKey) {
		return fmt.Errorf("bundle signature public key fingerprint mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(signatureFile.Signature)
	if err != nil {
		return fmt.Errorf("decode bundle signature bytes: %w", err)
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return fmt.Errorf("bundle signature verification failed")
	}
	return nil
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
	if keyFile.SchemaVersion != PrivateKeySchemaVersion {
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
	if keyFile.SchemaVersion != PublicKeySchemaVersion {
		return nil, fmt.Errorf("unsupported public key schema_version %q", keyFile.SchemaVersion)
	}
	if keyFile.Algorithm != signatureAlgorithm {
		return nil, fmt.Errorf("unsupported public key algorithm %q", keyFile.Algorithm)
	}
	return decodePublicKey(keyFile.PublicKey, "public key")
}

func PublicKeyFingerprint(path string) (string, error) {
	publicKey, err := readPublicKey(path)
	if err != nil {
		return "", err
	}
	return publicKeyFingerprint(publicKey), nil
}

func publicKeyFingerprint(publicKey ed25519.PublicKey) string {
	publicKeySum := sha256.Sum256(publicKey)
	return hex.EncodeToString(publicKeySum[:])
}

func decodePublicKey(encoded string, label string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s length = %d, want %d", label, len(key), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

func writeZip(outPath string, files []bundleFile) error {
	slices.SortFunc(files, func(a bundleFile, b bundleFile) int {
		return strings.Compare(a.path, b.path)
	})
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create bundle dir: %w", err)
	}
	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create bundle: %w", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	defer writer.Close()
	fixedTime := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, bundleFile := range files {
		header := &zip.FileHeader{
			Name:   bundleFile.path,
			Method: zip.Deflate,
		}
		header.SetModTime(fixedTime)
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("create zip entry %s: %w", bundleFile.path, err)
		}
		if _, err := entryWriter.Write(bundleFile.bytes); err != nil {
			return fmt.Errorf("write zip entry %s: %w", bundleFile.path, err)
		}
	}
	return nil
}

func readEvidence(evidencePath string) (run.EvidencePack, error) {
	bytes, err := os.ReadFile(evidencePath)
	if err != nil {
		return run.EvidencePack{}, fmt.Errorf("read evidence: %w", err)
	}
	var evidence run.EvidencePack
	if err := json.Unmarshal(bytes, &evidence); err != nil {
		return run.EvidencePack{}, fmt.Errorf("decode evidence: %w", err)
	}
	return evidence, nil
}

func verifyContractDigest(contractPath string, wantDigest string) error {
	bytes, err := os.ReadFile(contractPath)
	if err != nil {
		return fmt.Errorf("read contract: %w", err)
	}
	var c contract.Contract
	if err := json.Unmarshal(bytes, &c); err != nil {
		return fmt.Errorf("decode contract: %w", err)
	}
	digest, err := contract.Digest(c)
	if err != nil {
		return fmt.Errorf("digest contract: %w", err)
	}
	if digest != wantDigest {
		return fmt.Errorf("contract digest mismatch: evidence %s != contract %s", wantDigest, digest)
	}
	return nil
}

func validateBundlePath(raw string) (string, error) {
	normalized := slashClean(raw)
	if normalized == "" || normalized == "." {
		return "", fmt.Errorf("bundle path is required")
	}
	if strings.HasPrefix(strings.ReplaceAll(raw, "\\", "/"), "//") {
		return "", fmt.Errorf("bundle path %q escapes archive", raw)
	}
	if path.IsAbs(normalized) || normalized == ".." || strings.HasPrefix(normalized, "../") || hasWindowsDrivePrefix(normalized) {
		return "", fmt.Errorf("bundle path %q escapes archive", raw)
	}
	return normalized, nil
}

func slashJoin(parts ...string) string {
	return slashClean(path.Join(parts...))
}

func slashClean(raw string) string {
	return path.Clean(strings.ReplaceAll(raw, "\\", "/"))
}

func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 {
		return false
	}
	drive := p[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) && p[1] == ':'
}
