package bundle

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	"github.com/uesugitorachiyo/ao-covenant/internal/policy"
	"github.com/uesugitorachiyo/ao-covenant/internal/run"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestExportWritesPortableBundle(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")

	exported, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	})
	if err != nil {
		t.Fatalf("Export error: %v", err)
	}
	if exported.BundlePath != bundlePath {
		t.Fatalf("bundle path = %q, want %q", exported.BundlePath, bundlePath)
	}

	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatalf("open bundle zip: %v", err)
	}
	defer reader.Close()
	names := zipEntryNames(reader.File)
	for _, want := range []string{
		"SHA256SUMS",
		"artifacts/demo-output/report.txt",
		"bundle-manifest.json",
		"contract.json",
		"events.ndjson",
		"evidence-pack.json",
		"input-snapshots/examples/risky-change/brief.md",
	} {
		if !slices.Contains(names, want) {
			t.Fatalf("zip entries = %v, want %s", names, want)
		}
	}

	manifestBytes := readZipEntry(t, reader.File, "bundle-manifest.json")
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SchemaVersion != ManifestSchemaVersion {
		t.Fatalf("schema version = %q, want %q", manifest.SchemaVersion, ManifestSchemaVersion)
	}
	if manifest.RunID != "bundle-test" {
		t.Fatalf("run id = %q, want bundle-test", manifest.RunID)
	}
	if !manifest.Verification.Verified {
		t.Fatalf("manifest verification = false")
	}
	if manifest.Verification.ArtifactCount != 1 {
		t.Fatalf("artifact count = %d, want 1", manifest.Verification.ArtifactCount)
	}
	if len(manifest.Entries) != len(names)-2 {
		t.Fatalf("manifest entries len = %d, want zip source entries %d", len(manifest.Entries), len(names)-2)
	}
	for _, entry := range manifest.Entries {
		if entry.Path == "" || entry.SHA256 == "" || entry.SizeBytes == 0 {
			t.Fatalf("manifest entry incomplete: %+v", entry)
		}
	}
	checksums := string(readZipEntry(t, reader.File, "SHA256SUMS"))
	if !strings.Contains(checksums, "  contract.json\n") || !strings.Contains(checksums, "  artifacts/demo-output/report.txt\n") {
		t.Fatalf("checksums = %q, want contract and artifact entries", checksums)
	}
}

func TestExportRejectsUnverifiedRun(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	artifactPath := filepath.Join(workspace, "demo-output", "report.txt")
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	_, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      filepath.Join(workspace, "bundle.zip"),
	})
	if err == nil || !strings.Contains(err.Error(), "verify run before bundle export") {
		t.Fatalf("Export error = %v, want verification failure", err)
	}
}

func TestVerifyReadsExportedBundle(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	verification, err := Verify(VerifyOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !verification.Verified {
		t.Fatalf("verified = false, want true")
	}
	if verification.RunID != "bundle-test" {
		t.Fatalf("run id = %q, want bundle-test", verification.RunID)
	}
	if verification.ArtifactCount != 1 {
		t.Fatalf("artifact count = %d, want 1", verification.ArtifactCount)
	}
	if verification.InputSnapshotCount != 1 {
		t.Fatalf("input snapshot count = %d, want 1", verification.InputSnapshotCount)
	}
}

func TestExportAttachesRevocationLists(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	revocationPath := filepath.Join(workspace, "revocations.json")
	writeBundleRevocationList(t, revocationPath, "approval-not-used")
	bundlePath := filepath.Join(workspace, "bundle.zip")

	exported, err := Export(Options{
		ContractPath:    result.contractPath,
		LedgerPath:      result.runResult.LedgerPath,
		EvidencePath:    result.runResult.EvidencePackPath,
		WorkspaceDir:    workspace,
		OutPath:         bundlePath,
		RevocationPaths: []string{revocationPath},
	})
	if err != nil {
		t.Fatalf("Export error: %v", err)
	}

	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatalf("open bundle zip: %v", err)
	}
	defer reader.Close()
	if !slices.Contains(zipEntryNames(reader.File), "revocations/revocations.json") {
		t.Fatalf("zip entries = %v, want revocations/revocations.json", zipEntryNames(reader.File))
	}
	checksums := string(readZipEntry(t, reader.File, "SHA256SUMS"))
	if !strings.Contains(checksums, "  revocations/revocations.json\n") {
		t.Fatalf("checksums = %q, want revocation entry", checksums)
	}
	if !manifestHasEntry(exported.Manifest, "revocations/revocations.json") {
		t.Fatalf("manifest entries = %+v, want revocation entry", exported.Manifest.Entries)
	}
}

func TestVerifyAppliesBundledRevocationLists(t *testing.T) {
	workspace := t.TempDir()
	result := generateApprovedProcessBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	revocationBytes := marshalBundleRevocationList(t, "approve-process")
	checksums := appendChecksumEntry(t, readZipEntryFromPath(t, bundlePath, "SHA256SUMS"), "revocations/revocations.json", revocationBytes)
	addZipEntries(t, bundlePath, map[string][]byte{
		"revocations/revocations.json": revocationBytes,
		"SHA256SUMS":                   checksums,
	})

	_, err := Verify(VerifyOptions{BundlePath: bundlePath})
	if err == nil || !strings.Contains(err.Error(), `references revoked approval ticket "approve-process"`) {
		t.Fatalf("Verify error = %v, want bundled revoked approval rejection", err)
	}
}

func TestInspectAndReportExposeBundledRevocations(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	revocationPath := filepath.Join(workspace, "revocations.json")
	writeBundleRevocationList(t, revocationPath, "approval-not-used")
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath:    result.contractPath,
		LedgerPath:      result.runResult.LedgerPath,
		EvidencePath:    result.runResult.EvidencePackPath,
		WorkspaceDir:    workspace,
		OutPath:         bundlePath,
		RevocationPaths: []string{revocationPath},
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	inspection, err := Inspect(InspectOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.RevocationListCount != 1 || inspection.RevokedTicketCount != 1 {
		t.Fatalf("inspection revocation counts = %d/%d, want 1/1", inspection.RevocationListCount, inspection.RevokedTicketCount)
	}
	if len(inspection.Revocations) != 1 || inspection.Revocations[0].Path != "revocations/revocations.json" || inspection.Revocations[0].RevokedTickets[0].TicketID != "approval-not-used" {
		t.Fatalf("inspection revocations = %+v, want bundled ticket detail", inspection.Revocations)
	}

	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}
	if report.RevocationListCount != 1 || report.RevokedTicketCount != 1 {
		t.Fatalf("report revocation counts = %d/%d, want 1/1", report.RevocationListCount, report.RevokedTicketCount)
	}
	if len(report.Revocations) != 1 || report.Revocations[0].RevokedTickets[0].Reason != "operator revoked local approval" {
		t.Fatalf("report revocations = %+v, want reason detail", report.Revocations)
	}
	markdown := MarkdownReport(report)
	if !strings.Contains(markdown, "## Revocations") || !strings.Contains(markdown, "approval-not-used") {
		t.Fatalf("markdown = %q, want revocation section", markdown)
	}
}

func TestVerifyRejectsTamperedBundleEntry(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	tamperZipEntry(t, bundlePath, "artifacts/demo-output/report.txt", []byte("tampered artifact\n"))

	_, err := Verify(VerifyOptions{BundlePath: bundlePath})
	if err == nil || !strings.Contains(err.Error(), "bundle checksum mismatch") {
		t.Fatalf("Verify error = %v, want bundle checksum mismatch", err)
	}
}

func TestInspectRejectsBundleManifestSchemaViolation(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	manifestBytes := readZipEntryFromPath(t, bundlePath, "bundle-manifest.json")
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	delete(manifest, "entries")
	tamperedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	tamperedManifest = append(tamperedManifest, '\n')
	tamperZipEntries(t, bundlePath, map[string][]byte{
		"bundle-manifest.json": tamperedManifest,
		"SHA256SUMS":           rewriteChecksumEntry(t, readZipEntryFromPath(t, bundlePath, "SHA256SUMS"), "bundle-manifest.json", tamperedManifest),
	})

	_, err = Inspect(InspectOptions{BundlePath: bundlePath})
	if err == nil {
		t.Fatalf("Inspect returned nil, want schema error")
	}
	if !strings.Contains(err.Error(), "validate bundle manifest") || !strings.Contains(err.Error(), "schema validation failed for covenant.evidence-bundle.v1") {
		t.Fatalf("Inspect error = %v, want bundle manifest schema context", err)
	}
}

func TestExportValidatesGeneratedBundleManifest(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")

	exported, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	})
	if err != nil {
		t.Fatalf("Export error: %v", err)
	}
	if exported.Manifest.SchemaVersion != ManifestSchemaVersion {
		t.Fatalf("manifest schema version = %q, want %q", exported.Manifest.SchemaVersion, ManifestSchemaVersion)
	}
}

func TestVerifyRejectsPolicyDecisionWithoutLedgerPolicyEvent(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	eventsBytes := readZipEntryFromPath(t, bundlePath, "events.ndjson")
	evidenceBytes := readZipEntryFromPath(t, bundlePath, "evidence-pack.json")
	checksums := readZipEntryFromPath(t, bundlePath, "SHA256SUMS")

	ledgerWithoutPolicy := removeFirstPolicyEventAndRehash(t, eventsBytes)
	evidenceWithUpdatedLedgerDigest := replaceEvidenceLedgerDigest(t, evidenceBytes, ledgerWithoutPolicy)
	checksums = rewriteChecksumEntry(t, checksums, "events.ndjson", ledgerWithoutPolicy)
	checksums = rewriteChecksumEntry(t, checksums, "evidence-pack.json", evidenceWithUpdatedLedgerDigest)
	tamperZipEntries(t, bundlePath, map[string][]byte{
		"events.ndjson":      ledgerWithoutPolicy,
		"evidence-pack.json": evidenceWithUpdatedLedgerDigest,
		"SHA256SUMS":         checksums,
	})

	_, err := Verify(VerifyOptions{BundlePath: bundlePath})
	if err == nil || !strings.Contains(err.Error(), "policy decision policy-scripted_change-1 missing matching ledger policy_decided event") {
		t.Fatalf("Verify error = %v, want missing policy ledger event", err)
	}
}

func TestExportSignsBundleManifest(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	exported, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
		SignKeyPath:  privateKeyPath,
	})
	if err != nil {
		t.Fatalf("Export error: %v", err)
	}
	expectedFingerprint := publicKeyFileFingerprint(t, publicKeyPath)
	if exported.PublicKeySHA256 != expectedFingerprint {
		t.Fatalf("export public key sha256 = %q, want %q", exported.PublicKeySHA256, expectedFingerprint)
	}

	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatalf("open bundle zip: %v", err)
	}
	defer reader.Close()
	names := zipEntryNames(reader.File)
	if !slices.Contains(names, "bundle-signature.json") {
		t.Fatalf("zip entries = %v, want bundle-signature.json", names)
	}
	var signature SignatureFile
	if err := json.Unmarshal(readZipEntry(t, reader.File, "bundle-signature.json"), &signature); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if signature.PublicKeySHA256 != expectedFingerprint {
		t.Fatalf("signature public key sha256 = %q, want %q", signature.PublicKeySHA256, expectedFingerprint)
	}

	verification, err := Verify(VerifyOptions{BundlePath: bundlePath, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !verification.Verified {
		t.Fatalf("verified = false, want true")
	}
	if verification.PublicKeySHA256 != expectedFingerprint {
		t.Fatalf("verify public key sha256 = %q, want %q", verification.PublicKeySHA256, expectedFingerprint)
	}
}

func TestGenerateKeyPairWithResultReturnsPublicKeyFingerprint(t *testing.T) {
	workspace := t.TempDir()
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")

	result, err := GenerateKeyPairWithResult(privateKeyPath, publicKeyPath)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithResult error: %v", err)
	}
	if result.PrivateKeyPath != privateKeyPath || result.PublicKeyPath != publicKeyPath {
		t.Fatalf("result paths = %+v", result)
	}
	if len(result.PublicKeySHA256) != 64 {
		t.Fatalf("public key sha256 len = %d, want 64", len(result.PublicKeySHA256))
	}
	fingerprint, err := PublicKeyFingerprint(publicKeyPath)
	if err != nil {
		t.Fatalf("PublicKeyFingerprint error: %v", err)
	}
	if fingerprint != result.PublicKeySHA256 {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, result.PublicKeySHA256)
	}
}

func TestGenerateKeyPairWritesSchemaValidKeyFiles(t *testing.T) {
	workspace := t.TempDir()
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")

	if _, err := GenerateKeyPairWithResult(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPairWithResult error: %v", err)
	}
	privateBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if err := schema.ValidateBytes(schema.BundlePrivateKeySchemaID, privateBytes); err != nil {
		t.Fatalf("private key did not match published schema: %v\njson:\n%s", err, string(privateBytes))
	}
	publicBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if err := schema.ValidateBytes(schema.BundlePublicKeySchemaID, publicBytes); err != nil {
		t.Fatalf("public key did not match published schema: %v\njson:\n%s", err, string(publicBytes))
	}
}

func TestExportWritesSchemaValidBundleSignature(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}

	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
		SignKeyPath:  privateKeyPath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	signatureBytes := readZipEntryFromPath(t, bundlePath, "bundle-signature.json")
	if err := schema.ValidateBytes(schema.BundleSignatureSchemaID, signatureBytes); err != nil {
		t.Fatalf("signature did not match published schema: %v\njson:\n%s", err, string(signatureBytes))
	}
}

func TestPublicKeyFingerprintRejectsSchemaInvalidPublicKey(t *testing.T) {
	workspace := t.TempDir()
	publicKeyPath := filepath.Join(workspace, "public.json")
	invalidPublicKey := []byte(`{
  "schema_version": "covenant.bundle-public-key.v1",
  "algorithm": "ed25519",
  "public_key": "not-base64"
}`)
	if err := os.WriteFile(publicKeyPath, invalidPublicKey, 0o644); err != nil {
		t.Fatalf("write invalid public key: %v", err)
	}

	_, err := PublicKeyFingerprint(publicKeyPath)
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.bundle-public-key.v1") {
		t.Fatalf("PublicKeyFingerprint error = %v, want public key schema validation failure", err)
	}
}

func TestVerifyRejectsSchemaInvalidBundleSignature(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
		SignKeyPath:  privateKeyPath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	var signature SignatureFile
	if err := json.Unmarshal(readZipEntryFromPath(t, bundlePath, "bundle-signature.json"), &signature); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signature.Signature = "not-base64"
	tamperedSignature, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		t.Fatalf("encode tampered signature: %v", err)
	}
	tamperedSignature = append(tamperedSignature, '\n')
	tamperZipEntries(t, bundlePath, map[string][]byte{
		"bundle-signature.json": tamperedSignature,
		"SHA256SUMS":            rewriteChecksumEntry(t, readZipEntryFromPath(t, bundlePath, "SHA256SUMS"), "bundle-signature.json", tamperedSignature),
	})

	_, err = Verify(VerifyOptions{BundlePath: bundlePath, PublicKeyPath: publicKeyPath})
	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.bundle-signature.v1") {
		t.Fatalf("Verify error = %v, want bundle signature schema validation failure", err)
	}
}

func TestVerifyWithPublicKeyRejectsUnsignedBundle(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	_, err := Verify(VerifyOptions{BundlePath: bundlePath, PublicKeyPath: publicKeyPath})
	if err == nil || !strings.Contains(err.Error(), "bundle signature is required") {
		t.Fatalf("Verify error = %v, want bundle signature is required", err)
	}
}

func TestVerifyRejectsTamperedSignedManifest(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
		SignKeyPath:  privateKeyPath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	manifestBytes := readZipEntryFromPath(t, bundlePath, "bundle-manifest.json")
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.RunID = "tampered-run"
	tamperedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("encode tampered manifest: %v", err)
	}
	tamperedManifest = append(tamperedManifest, '\n')
	tamperZipEntries(t, bundlePath, map[string][]byte{
		"bundle-manifest.json": tamperedManifest,
		"SHA256SUMS":           rewriteChecksumEntry(t, readZipEntryFromPath(t, bundlePath, "SHA256SUMS"), "bundle-manifest.json", tamperedManifest),
	})

	_, err = Verify(VerifyOptions{BundlePath: bundlePath, PublicKeyPath: publicKeyPath})
	if err == nil || !strings.Contains(err.Error(), "bundle signature verification failed") {
		t.Fatalf("Verify error = %v, want bundle signature verification failed", err)
	}
}

func TestInspectSummarizesUnsignedBundle(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	inspection, err := Inspect(InspectOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.RunID != "bundle-test" {
		t.Fatalf("run id = %q, want bundle-test", inspection.RunID)
	}
	if inspection.ChecksumStatus != "verified" {
		t.Fatalf("checksum status = %q, want verified", inspection.ChecksumStatus)
	}
	if inspection.Signature.Status != "unsigned" {
		t.Fatalf("signature status = %q, want unsigned", inspection.Signature.Status)
	}
	if inspection.ArtifactCount != 1 || len(inspection.Artifacts) != 1 {
		t.Fatalf("artifact count = %d len = %d, want 1", inspection.ArtifactCount, len(inspection.Artifacts))
	}
	if inspection.InputSnapshotCount != 1 || len(inspection.InputSnapshots) != 1 {
		t.Fatalf("input snapshot count = %d len = %d, want 1", inspection.InputSnapshotCount, len(inspection.InputSnapshots))
	}
	if inspection.PolicyDecisionCount != 1 || len(inspection.PolicyExplanations) != 1 {
		t.Fatalf("policy decision count = %d explanations len = %d, want 1", inspection.PolicyDecisionCount, len(inspection.PolicyExplanations))
	}
	if inspection.PolicyExplanations[0].Summary != "allowed file.write on demo-output/report.txt" {
		t.Fatalf("policy explanation summary = %q", inspection.PolicyExplanations[0].Summary)
	}
	artifact := inspection.Artifacts[0]
	if artifact.ArtifactID == "" || artifact.ProducerEventID == "" || artifact.ProducerTaskID == "" || !artifact.ProducerFound {
		t.Fatalf("artifact provenance incomplete: %+v", artifact)
	}
	if artifact.Path != "demo-output/report.txt" {
		t.Fatalf("artifact path = %q, want demo-output/report.txt", artifact.Path)
	}
}

func TestInspectVerifiesSignedBundleWhenPublicKeySupplied(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	privateKeyPath := filepath.Join(workspace, "keys", "private.json")
	publicKeyPath := filepath.Join(workspace, "keys", "public.json")
	if err := GenerateKeyPair(privateKeyPath, publicKeyPath); err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
		SignKeyPath:  privateKeyPath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	inspection, err := Inspect(InspectOptions{BundlePath: bundlePath, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}
	if inspection.Signature.Status != "verified" {
		t.Fatalf("signature status = %q, want verified", inspection.Signature.Status)
	}
	if inspection.Signature.SignedEntry != "bundle-manifest.json" {
		t.Fatalf("signed entry = %q, want bundle-manifest.json", inspection.Signature.SignedEntry)
	}
	if inspection.Signature.PublicKeySHA256 == "" {
		t.Fatalf("public key fingerprint is empty")
	}
}

func TestReportLinksBundleProvenance(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}
	if report.RunID != "bundle-test" {
		t.Fatalf("run id = %q, want bundle-test", report.RunID)
	}
	if report.ChecksumStatus != "verified" {
		t.Fatalf("checksum status = %q, want verified", report.ChecksumStatus)
	}
	if len(report.Entries) == 0 {
		t.Fatalf("entries empty")
	}
	if len(report.Events) == 0 || report.Events[0].Line != 1 || report.Events[0].EventID == "" {
		t.Fatalf("events = %+v, want line-numbered ledger events", report.Events)
	}
	policyEvent := findInspectedEventByType(t, report.Events, "policy_decided")
	if policyEvent.DecisionID != "policy-scripted_change-1" || policyEvent.Decision != "allow" || policyEvent.EffectType != "file.write" || policyEvent.Resource != "demo-output/report.txt" {
		t.Fatalf("policy event = %+v, want enriched policy metadata", policyEvent)
	}
	if len(report.Artifacts) != 1 || !report.Artifacts[0].ProducerFound || report.Artifacts[0].ProducerTaskID == "" {
		t.Fatalf("artifacts = %+v, want producer link", report.Artifacts)
	}
	if len(report.InputSnapshots) != 1 {
		t.Fatalf("input snapshots = %+v, want 1", report.InputSnapshots)
	}
	if len(report.PolicyExplanations) != 1 || report.PolicyExplanations[0].Summary != "allowed file.write on demo-output/report.txt" {
		t.Fatalf("policy explanations = %+v", report.PolicyExplanations)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("failures = %+v, want none", report.Failures)
	}
	if len(report.ClosureRows) == 0 {
		t.Fatalf("closure rows empty")
	}
	firstClosed := report.ClosureRows[0]
	if firstClosed.ObligationID == "" || firstClosed.Status == "" || len(firstClosed.MissingArtifactIDs) != 0 || len(firstClosed.MissingPolicyDecisionIDs) != 0 {
		t.Fatalf("closure row = %+v, want linked references without missing refs", firstClosed)
	}
}

func TestReportExposesPolicyDecisions(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}

	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}
	if len(report.PolicyDecisions) != 1 {
		t.Fatalf("policy decisions len = %d, want 1", len(report.PolicyDecisions))
	}
	decision := report.PolicyDecisions[0]
	if decision.DecisionID != "policy-scripted_change-1" || decision.Decision != "allow" || decision.EffectType != "file.write" || decision.Resource != "demo-output/report.txt" {
		t.Fatalf("policy decision = %+v, want bundled file.write allow", decision)
	}
}

func TestRedactReportMasksPathsAndDigests(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}

	redacted := RedactReport(report, RedactionOptions{Paths: true, Digests: true})

	if redacted.BundlePath != "[REDACTED_PATH]" {
		t.Fatalf("bundle path = %q, want redacted", redacted.BundlePath)
	}
	if redacted.ContractDigest != "[REDACTED_DIGEST]" || redacted.LedgerDigest != "[REDACTED_DIGEST]" {
		t.Fatalf("digests = %q %q, want redacted", redacted.ContractDigest, redacted.LedgerDigest)
	}
	if redacted.Entries[0].Path != "[REDACTED_PATH]" || redacted.Entries[0].SHA256 != "[REDACTED_DIGEST]" {
		t.Fatalf("entry = %+v, want path and digest redacted", redacted.Entries[0])
	}
	if redacted.Artifacts[0].Path != "[REDACTED_PATH]" || redacted.Artifacts[0].Digest != "[REDACTED_DIGEST]" {
		t.Fatalf("artifact = %+v, want path and digest redacted", redacted.Artifacts[0])
	}
	if redacted.InputSnapshots[0].SourcePath != "[REDACTED_PATH]" || redacted.InputSnapshots[0].Digest != "[REDACTED_DIGEST]" {
		t.Fatalf("snapshot = %+v, want path and digest redacted", redacted.InputSnapshots[0])
	}
	if redacted.PolicyDecisions[0].Resource != "[REDACTED_PATH]" || redacted.PolicyExplanations[0].Resource != "[REDACTED_PATH]" {
		t.Fatalf("policy resource = %q explanation resource = %q, want redacted", redacted.PolicyDecisions[0].Resource, redacted.PolicyExplanations[0].Resource)
	}
	if redacted.RunID != report.RunID || redacted.PolicyDecisionCount != report.PolicyDecisionCount || redacted.PolicyDecisions[0].DecisionID != report.PolicyDecisions[0].DecisionID {
		t.Fatalf("redacted report changed stable identifiers or counts: %+v", redacted)
	}
}

func TestRedactInspectMasksRevocationDetails(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	revocationPath := filepath.Join(workspace, "revocations.json")
	writeBundleRevocationList(t, revocationPath, "approval-not-used")
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath:    result.contractPath,
		LedgerPath:      result.runResult.LedgerPath,
		EvidencePath:    result.runResult.EvidencePackPath,
		WorkspaceDir:    workspace,
		OutPath:         bundlePath,
		RevocationPaths: []string{revocationPath},
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	inspection, err := Inspect(InspectOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Inspect error: %v", err)
	}

	redacted := RedactInspect(inspection, RedactionOptions{Paths: true, Digests: true})

	if redacted.BundlePath != redactedPath || redacted.ContractDigest != redactedDigest || redacted.LedgerDigest != redactedDigest {
		t.Fatalf("redacted summary = %+v, want path and digest masks", redacted)
	}
	if len(redacted.Revocations) != 1 || redacted.Revocations[0].Path != redactedPath {
		t.Fatalf("redacted revocations = %+v, want redacted revocation path", redacted.Revocations)
	}
	if got := redacted.Revocations[0].RevokedTickets[0]; got.TicketID != redactedDigest || strings.Contains(got.Reason, "approval-not-used") {
		t.Fatalf("redacted ticket = %+v, want masked ticket ID and reason", got)
	}
	if inspection.BundlePath == redactedPath || inspection.Revocations[0].Path == redactedPath || inspection.Revocations[0].RevokedTickets[0].TicketID == redactedDigest {
		t.Fatalf("original inspection mutated: %+v", inspection)
	}
}

func TestRedactReportMasksRevocationDetails(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	revocationPath := filepath.Join(workspace, "revocations.json")
	writeBundleRevocationList(t, revocationPath, "approval-not-used")
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath:    result.contractPath,
		LedgerPath:      result.runResult.LedgerPath,
		EvidencePath:    result.runResult.EvidencePackPath,
		WorkspaceDir:    workspace,
		OutPath:         bundlePath,
		RevocationPaths: []string{revocationPath},
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}

	redacted := RedactReport(report, RedactionOptions{Paths: true, Digests: true})

	if len(redacted.Revocations) != 1 || redacted.Revocations[0].Path != redactedPath {
		t.Fatalf("redacted revocations = %+v, want redacted revocation path", redacted.Revocations)
	}
	ticket := redacted.Revocations[0].RevokedTickets[0]
	if ticket.TicketID != redactedDigest || strings.Contains(ticket.Reason, "approval-not-used") {
		t.Fatalf("redacted ticket = %+v, want masked ticket ID and reason", ticket)
	}
	markdown := MarkdownReport(redacted)
	if strings.Contains(markdown, "approval-not-used") || strings.Contains(markdown, "revocations/revocations.json") {
		t.Fatalf("markdown = %q, want revocation details redacted", markdown)
	}
}

func TestMarkdownReportRendersRedactedValues(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}

	markdown := MarkdownReport(RedactReport(report, RedactionOptions{Paths: true, Digests: true}))

	for _, want := range []string{
		"| Bundle | [REDACTED_PATH] |",
		"| Contract Digest | [REDACTED_DIGEST] |",
		"| scripted_change-artifact-1 | [REDACTED_PATH] | [REDACTED_DIGEST] |",
		"| policy-scripted_change-1 | scripted_change | allow | file.write | [REDACTED_PATH] |",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown = %q, want %s", markdown, want)
		}
	}
	for _, forbidden := range []string{"demo-output/report.txt", report.ContractDigest} {
		if strings.Contains(markdown, forbidden) {
			t.Fatalf("markdown = %q, want %q redacted", markdown, forbidden)
		}
	}
}

func TestMarkdownReportRendersAuditSections(t *testing.T) {
	workspace := t.TempDir()
	result := generateBundleRun(t, workspace)
	bundlePath := filepath.Join(workspace, "bundle.zip")
	if _, err := Export(Options{
		ContractPath: result.contractPath,
		LedgerPath:   result.runResult.LedgerPath,
		EvidencePath: result.runResult.EvidencePackPath,
		WorkspaceDir: workspace,
		OutPath:      bundlePath,
	}); err != nil {
		t.Fatalf("Export error: %v", err)
	}
	report, err := Report(ReportOptions{BundlePath: bundlePath})
	if err != nil {
		t.Fatalf("Report error: %v", err)
	}

	markdown := MarkdownReport(report)

	for _, want := range []string{
		"# AO Covenant Bundle Report",
		"| Run ID | bundle-test |",
		"## Manifest Entries",
		"| contract.json |",
		"## Ledger Events",
		"| event-000001 | 1 | 1 | run_started | success |",
		"## Artifacts",
		"| scripted_change-artifact-1 | demo-output/report.txt |",
		"## Input Snapshots",
		"| input-000001 | examples/risky-change/brief.md |",
		"## Policy Decisions",
		"| policy-scripted_change-1 | scripted_change | allow | file.write | demo-output/report.txt | allowed file.write on demo-output/report.txt |",
		"## Closure Rows",
		"| obl_requested_file |",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown = %q, want %s", markdown, want)
		}
	}
}

type generatedBundleRun struct {
	contractPath string
	runResult    run.Result
}

func generateBundleRun(t *testing.T, workspace string) generatedBundleRun {
	t.Helper()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractPath := filepath.Join(workspace, "contract.json")
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile(contractPath, append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	runResult, err := run.Execute(context.Background(), c, run.Options{
		WorkspaceDir: workspace,
		OutDir:       filepath.Join(workspace, ".covenant", "runs"),
		RunID:        "bundle-test",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	return generatedBundleRun{contractPath: contractPath, runResult: runResult}
}

func generateApprovedProcessBundleRun(t *testing.T, workspace string) generatedBundleRun {
	t.Helper()
	mustWriteFile(t, filepath.Join(workspace, "examples", "risky-change", "brief.md"), "Create a demo report.")
	c, err := contract.CompileBriefWithSource("Create a demo report.", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: "go version"},
	}
	c.Workspace.Writes = []string{}
	c.Approvals = []policy.ApprovalTicket{
		{
			SchemaVersion: policy.ApprovalTicketSchemaVersion,
			TicketID:      "approve-process",
			TaskID:        "scripted_change",
			EffectType:    "process.spawn",
			Resource:      "go version",
			Approved:      true,
			Reason:        "operator approved go version",
		},
	}
	contractPath := filepath.Join(workspace, "contract.json")
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile(contractPath, append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	runResult, err := run.Execute(context.Background(), c, run.Options{
		WorkspaceDir:     workspace,
		OutDir:           filepath.Join(workspace, ".covenant", "runs"),
		RunID:            "bundle-approved-process",
		ProcessAllowlist: []string{"go version"},
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	return generatedBundleRun{contractPath: contractPath, runResult: runResult}
}

func zipEntryNames(files []*zip.File) []string {
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	slices.Sort(names)
	return names
}

func readZipEntry(t *testing.T, files []*zip.File, name string) []byte {
	t.Helper()
	for _, file := range files {
		if file.Name != name {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("open zip entry %s: %v", name, err)
		}
		defer reader.Close()
		bytes, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read zip entry %s: %v", name, err)
		}
		return bytes
	}
	t.Fatalf("zip entry %s not found", name)
	return nil
}

func readZipEntryFromPath(t *testing.T, zipPath string, name string) []byte {
	t.Helper()
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip %s: %v", zipPath, err)
	}
	defer reader.Close()
	return readZipEntry(t, reader.File, name)
}

func tamperZipEntry(t *testing.T, zipPath string, entryName string, replacement []byte) {
	t.Helper()
	tamperZipEntries(t, zipPath, map[string][]byte{entryName: replacement})
}

func tamperZipEntries(t *testing.T, zipPath string, replacements map[string][]byte) {
	t.Helper()
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip for tamper: %v", err)
	}
	defer reader.Close()
	tmpPath := zipPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		t.Fatalf("create tampered zip: %v", err)
	}
	writer := zip.NewWriter(tmpFile)
	replaced := map[string]bool{}
	for _, file := range reader.File {
		header := file.FileHeader
		entryWriter, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatalf("create tampered entry %s: %v", file.Name, err)
		}
		if replacement, ok := replacements[file.Name]; ok {
			if _, err := entryWriter.Write(replacement); err != nil {
				t.Fatalf("write replacement %s: %v", file.Name, err)
			}
			replaced[file.Name] = true
			continue
		}
		fileReader, err := file.Open()
		if err != nil {
			t.Fatalf("open original entry %s: %v", file.Name, err)
		}
		if _, err := io.Copy(entryWriter, fileReader); err != nil {
			_ = fileReader.Close()
			t.Fatalf("copy original entry %s: %v", file.Name, err)
		}
		if err := fileReader.Close(); err != nil {
			t.Fatalf("close original entry %s: %v", file.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tampered writer: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close tampered zip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close original zip: %v", err)
	}
	for entryName := range replacements {
		if !replaced[entryName] {
			t.Fatalf("entry %s not found for tamper", entryName)
		}
	}
	if err := os.Rename(tmpPath, zipPath); err != nil {
		t.Fatalf("replace zip: %v", err)
	}
}

func addZipEntries(t *testing.T, zipPath string, additions map[string][]byte) {
	t.Helper()
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip for additions: %v", err)
	}
	defer reader.Close()
	tmpPath := zipPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		t.Fatalf("create zip with additions: %v", err)
	}
	writer := zip.NewWriter(tmpFile)
	for _, file := range reader.File {
		if _, added := additions[file.Name]; added {
			continue
		}
		header := file.FileHeader
		entryWriter, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatalf("create copied entry %s: %v", file.Name, err)
		}
		fileReader, err := file.Open()
		if err != nil {
			t.Fatalf("open original entry %s: %v", file.Name, err)
		}
		if _, err := io.Copy(entryWriter, fileReader); err != nil {
			_ = fileReader.Close()
			t.Fatalf("copy original entry %s: %v", file.Name, err)
		}
		if err := fileReader.Close(); err != nil {
			t.Fatalf("close original entry %s: %v", file.Name, err)
		}
	}
	for name, contents := range additions {
		entryWriter, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create added entry %s: %v", name, err)
		}
		if _, err := entryWriter.Write(contents); err != nil {
			t.Fatalf("write added entry %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close added zip writer: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close added zip: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close original zip: %v", err)
	}
	if err := os.Rename(tmpPath, zipPath); err != nil {
		t.Fatalf("replace zip: %v", err)
	}
}

func rewriteChecksumEntry(t *testing.T, checksums []byte, entryName string, replacement []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(replacement)
	replacementLine := hex.EncodeToString(sum[:]) + "  " + entryName
	lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
	for i, line := range lines {
		_, path, ok := strings.Cut(line, "  ")
		if ok && path == entryName {
			lines[i] = replacementLine
			return []byte(strings.Join(lines, "\n") + "\n")
		}
	}
	t.Fatalf("checksum entry %s not found", entryName)
	return nil
}

func appendChecksumEntry(t *testing.T, checksums []byte, entryName string, contents []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(contents)
	line := hex.EncodeToString(sum[:]) + "  " + entryName + "\n"
	return append([]byte(strings.TrimRight(string(checksums), "\n")+"\n"), []byte(line)...)
}

func manifestHasEntry(manifest Manifest, path string) bool {
	for _, entry := range manifest.Entries {
		if entry.Path == path {
			return true
		}
	}
	return false
}

func findInspectedEventByType(t *testing.T, events []EventInspection, eventType string) EventInspection {
	t.Helper()
	for _, event := range events {
		if event.Type == eventType {
			return event
		}
	}
	t.Fatalf("inspected event type %s not found", eventType)
	return EventInspection{}
}

func writeBundleRevocationList(t *testing.T, path string, ticketID string) {
	t.Helper()
	if err := os.WriteFile(path, marshalBundleRevocationList(t, ticketID), 0o644); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}
}

func marshalBundleRevocationList(t *testing.T, ticketID string) []byte {
	t.Helper()
	bytes, err := json.MarshalIndent(approval.RevocationList{
		SchemaVersion: approval.RevocationListSchemaVersion,
		RevokedTickets: []approval.RevokedTicket{
			{
				TicketID: ticketID,
				Reason:   "operator revoked local approval",
			},
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("encode revocation list: %v", err)
	}
	return append(bytes, '\n')
}

func removeFirstPolicyEventAndRehash(t *testing.T, ledger []byte) []byte {
	t.Helper()
	events := decodeLedgerForTest(t, ledger)
	filtered := make([]run.Event, 0, len(events)-1)
	removed := false
	for _, event := range events {
		if !removed && event.Type == "policy_decided" {
			removed = true
			continue
		}
		filtered = append(filtered, event)
	}
	if !removed {
		t.Fatalf("policy_decided event not found")
	}
	previous := run.GenesisEventHash
	var b strings.Builder
	for i := range filtered {
		filtered[i].PreviousEventHash = previous
		filtered[i].EventHash = ""
		hash, err := run.EventContentHash(filtered[i])
		if err != nil {
			t.Fatalf("hash event %s: %v", filtered[i].EventID, err)
		}
		filtered[i].EventHash = hash
		previous = hash
		bytes, err := json.Marshal(filtered[i])
		if err != nil {
			t.Fatalf("encode event %s: %v", filtered[i].EventID, err)
		}
		b.Write(bytes)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func decodeLedgerForTest(t *testing.T, ledger []byte) []run.Event {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(ledger)), "\n")
	events := make([]run.Event, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event run.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode ledger event: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func replaceEvidenceLedgerDigest(t *testing.T, evidenceBytes []byte, ledger []byte) []byte {
	t.Helper()
	var evidence run.EvidencePack
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	sum := sha256.Sum256(ledger)
	evidence.LedgerDigest = hex.EncodeToString(sum[:])
	bytes, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		t.Fatalf("encode evidence: %v", err)
	}
	return append(bytes, '\n')
}

func mustWriteFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func publicKeyFileFingerprint(t *testing.T, path string) string {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	var keyFile PublicKeyFile
	if err := json.Unmarshal(bytes, &keyFile); err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(keyFile.PublicKey)
	if err != nil {
		t.Fatalf("decode public key bytes: %v", err)
	}
	sum := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(sum[:])
}
