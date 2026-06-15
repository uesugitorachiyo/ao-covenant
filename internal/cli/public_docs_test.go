package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicThreatModelDocumentationIsLinkedAndComplete(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	readText := func(path ...string) string {
		t.Helper()
		bytes, err := os.ReadFile(filepath.Join(append([]string{repoRoot}, path...)...))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Join(path...), err)
		}
		return string(bytes)
	}

	readme := readText("README.md")
	security := readText("SECURITY.md")
	threatModel := readText("docs", "threat-model.md")

	for _, check := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "README link", doc: readme, want: "[Threat Model](docs/threat-model.md)"},
		{name: "SECURITY link", doc: security, want: "[Threat Model](docs/threat-model.md)"},
		{name: "trust boundaries", doc: threatModel, want: "## Trust Boundaries"},
		{name: "protected assets", doc: threatModel, want: "## Protected Assets"},
		{name: "threats and mitigations", doc: threatModel, want: "## Threats And Mitigations"},
		{name: "non-goals", doc: threatModel, want: "## Non-Goals"},
		{name: "release keys", doc: threatModel, want: "`COVENANT_RELEASE_SIGNING_KEY`"},
		{name: "private keys", doc: threatModel, want: "Private signing keys"},
		{name: "evidence packs", doc: threatModel, want: "evidence packs"},
		{name: "local paths", doc: threatModel, want: "local paths"},
		{name: "release verification", doc: threatModel, want: "[release operations](release.md)"},
		{name: "security reporting", doc: threatModel, want: "[security policy](../SECURITY.md)"},
	} {
		if !strings.Contains(check.doc, check.want) {
			t.Fatalf("%s missing %q", check.name, check.want)
		}
	}
}
