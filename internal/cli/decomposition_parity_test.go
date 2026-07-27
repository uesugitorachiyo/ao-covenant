package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIFamilyDiagnosticsRemainStableAcrossRegistryBoundary(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{
			name:       "missing top-level command",
			args:       []string{"covenant"},
			wantStderr: "usage: covenant <command>\ncommands: version, compile, lint, run, verify, self-run, release, bundle, approval, policy, schema\n",
		},
		{
			name:       "unknown top-level command",
			args:       []string{"covenant", "unknown"},
			wantStderr: "unknown command \"unknown\"\nusage: covenant <command>\ncommands: version, compile, lint, run, verify, self-run, release, bundle, approval, policy, schema\n",
		},
		{
			name:       "missing approval command",
			args:       []string{"covenant", "approval"},
			wantStderr: "usage: covenant approval <command>\ncommands: create, inspect, live-docs, mutation-class, low-risk-code-live, validate, attach, revoke, revocations\n",
		},
		{
			name:       "missing policy command",
			args:       []string{"covenant", "policy"},
			wantStderr: "usage: covenant policy <command>\ncommands: explain, index, spine, credential-checklist, claim-publish-gate\n",
		},
		{
			name:       "missing release command",
			args:       []string{"covenant", "release"},
			wantStderr: "usage: covenant release <command>\ncommands: package, verify\n",
		},
		{
			name:       "missing schema command",
			args:       []string{"covenant", "schema"},
			wantStderr: "usage: covenant schema <command>\ncommands: catalog, export, validate\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != tt.wantStderr {
				t.Fatalf("CLI diagnostics changed: stdout=%q stderr=%q want_stderr=%q", stdout.String(), stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestPublicGovernanceAndReleaseFixtureBytesRemainStableAcrossDecomposition(t *testing.T) {
	tests := []struct {
		path   string
		sha256 string
	}{
		{path: "schemas/covenant.approval-ticket.v1.schema.json", sha256: "0868cd9627f654ff9db798c57ea99da94ddb4e4e7bc350b486122da12c78ea59"},
		{path: "schemas/covenant.release-manifest.v1.schema.json", sha256: "e527fb6d4d86416cc98118f92f1b004d3ae3c6b615f11fdac255f0cc90bb42e1"},
		{path: "examples/mutation-class-authority/request-low-risk-code.json", sha256: "16699bc792f75be32451713dd3e706276baa4d557cde5667968b59b01585f634"},
		{path: "examples/mutation-class-authority/ticket-approved-low-risk-code.json", sha256: "27820512596f7eea7884231524590fb30455e6037b64d2e2f94db59208e5dd18"},
		{path: "examples/live-docs-approval/ticket-approved.json", sha256: "0dcbdbe0ff289a7f864758fe81123b7fba04e3de0b080fad6d08568727ca3a17"},
		{path: "internal/cli/testdata/release-fixture-index.json", sha256: "58c2fd4b1480caf3b1df4d2e317c1a2da6d89e1df6eb720ea3f1c57dc5aa8af7"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			bytes, err := os.ReadFile(filepath.Join("..", "..", tt.path))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(bytes)
			if got := hex.EncodeToString(sum[:]); got != tt.sha256 {
				t.Fatalf("%s sha256 = %s, want %s", tt.path, got, tt.sha256)
			}
		})
	}
}
