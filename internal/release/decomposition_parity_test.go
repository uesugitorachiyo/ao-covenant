package release

import "testing"

func TestReleaseArtifactNamesRemainStableAcrossOwnershipBoundary(t *testing.T) {
	tests := []struct {
		target Target
		want   string
	}{
		{target: Target{OS: "linux", Arch: "amd64"}, want: "ao-covenant_v0.2.0_linux_amd64"},
		{target: Target{OS: "darwin", Arch: "arm64"}, want: "ao-covenant_v0.2.0_darwin_arm64"},
		{target: Target{OS: "windows", Arch: "amd64"}, want: "ao-covenant_v0.2.0_windows_amd64.exe"},
	}

	for _, tt := range tests {
		if got := artifactName("v0.2.0", tt.target); got != tt.want {
			t.Fatalf("artifactName(%+v) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestReleaseRedactionSentinelsRemainStableAcrossOwnershipBoundary(t *testing.T) {
	result := InspectResult{
		ReleaseDir:    "/private/release",
		ManifestPath:  "/private/release/manifest.json",
		ChecksumsPath: "/private/release/checksums.txt",
		SignaturePath: "/private/release/release-signature.json",
		Signature: SignatureInspection{
			PublicKeySHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Artifacts: []ArtifactVerifyReport{{
			Path:         "/private/release/ao-covenant",
			SHA256:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			ActualSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}},
	}

	redacted := RedactInspect(result, RedactionOptions{Paths: true, Digests: true})
	if redacted.ReleaseDir != "[REDACTED_PATH]" ||
		redacted.ManifestPath != "[REDACTED_PATH]" ||
		redacted.ChecksumsPath != "[REDACTED_PATH]" ||
		redacted.SignaturePath != "[REDACTED_PATH]" ||
		redacted.Signature.PublicKeySHA256 != "0000000000000000000000000000000000000000000000000000000000000000" ||
		redacted.Artifacts[0].Path != "[REDACTED_PATH]" ||
		redacted.Artifacts[0].SHA256 != "0000000000000000000000000000000000000000000000000000000000000000" ||
		redacted.Artifacts[0].ActualSHA256 != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("release redaction parity changed: %+v", redacted)
	}
}
