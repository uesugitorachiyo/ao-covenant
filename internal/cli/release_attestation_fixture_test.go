package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

type releaseAttestationFixture struct {
	SchemaVersion string                         `json:"schema_version"`
	Name          string                         `json:"name"`
	Description   string                         `json:"description"`
	Expected      string                         `json:"expected"`
	Release       releaseAttestationFixtureMeta  `json:"release"`
	Checks        []releaseAttestationCheck      `json:"checks"`
	Failure       *releaseAttestationFailureCase `json:"failure,omitempty"`
}

type releaseAttestationFixtureMeta struct {
	Version    string `json:"version"`
	Repo       string `json:"repo"`
	Manifest   string `json:"manifest"`
	Artifact   string `json:"artifact"`
	Target     string `json:"target"`
	PublicOnly bool   `json:"public_only"`
}

type releaseAttestationCheck struct {
	Name     string `json:"name"`
	Artifact string `json:"artifact"`
	Command  string `json:"command"`
	Required bool   `json:"required"`
}

type releaseAttestationFailureCase struct {
	Reason           string   `json:"reason"`
	FailingCheck     string   `json:"failing_check"`
	ConsumerAction   string   `json:"consumer_action"`
	SensitiveOmitted []string `json:"sensitive_omitted"`
}

func TestReleaseAttestationFixturesAreStableAndIndexed(t *testing.T) {
	const fixtureDir = "internal/cli/testdata/release-attestation-fixtures"
	indexBytes, err := os.ReadFile(filepath.Join("testdata", "release-fixture-index.json"))
	if err != nil {
		t.Fatalf("read release fixture index: %v", err)
	}
	if !strings.Contains(string(indexBytes), `"name": "release-attestation"`) {
		t.Fatalf("release fixture index missing release-attestation entry")
	}
	if !strings.Contains(string(indexBytes), `"directory": "`+fixtureDir+`"`) {
		t.Fatalf("release fixture index missing %s", fixtureDir)
	}

	fixtures := map[string]releaseAttestationFixture{}
	for _, name := range []string{
		"coverage-valid.json",
		"failure-missing-binary-attestation.json",
		"failure-tampered-manifest-attestation.json",
	} {
		path := filepath.Join("testdata", "release-attestation-fixtures", name)
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if err := schema.ValidateBytes(schema.ReleaseAttestationFixtureSchemaID, bytes); err != nil {
			t.Fatalf("%s did not validate against published schema: %v", path, err)
		}
		var fixture releaseAttestationFixture
		if err := json.Unmarshal(bytes, &fixture); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if fixture.SchemaVersion != "covenant.release-attestation-fixture.v1" {
			t.Fatalf("%s schema_version = %q", name, fixture.SchemaVersion)
		}
		if fixture.Release.Repo != "uesugitorachiyo/ao-covenant" {
			t.Fatalf("%s repo = %q", name, fixture.Release.Repo)
		}
		if fixture.Release.Manifest != "manifest.json" {
			t.Fatalf("%s manifest = %q", name, fixture.Release.Manifest)
		}
		if !fixture.Release.PublicOnly {
			t.Fatalf("%s must be marked public_only", name)
		}
		if len(fixture.Checks) < 2 {
			t.Fatalf("%s checks = %d, want manifest and binary checks", name, len(fixture.Checks))
		}
		requireAttestationFixtureCommand(t, name, fixture, "manifest", "manifest.json")
		requireAttestationFixtureCommand(t, name, fixture, "platform-binary", fixture.Release.Artifact)
		requireNoSensitiveReleaseFixtureText(t, name, string(bytes))
		fixtures[name] = fixture
	}

	valid := fixtures["coverage-valid.json"]
	if valid.Expected != "pass" || valid.Failure != nil {
		t.Fatalf("coverage-valid expected=%q failure=%+v, want pass without failure", valid.Expected, valid.Failure)
	}
	if valid.Release.Artifact != "ao-covenant_v0.1.0_linux_amd64" || valid.Release.Target != "linux/amd64" {
		t.Fatalf("coverage-valid release = %+v, want linux amd64 artifact", valid.Release)
	}

	missing := fixtures["failure-missing-binary-attestation.json"]
	if missing.Expected != "fail" || missing.Failure == nil {
		t.Fatalf("missing-binary expected=%q failure=%+v, want failure", missing.Expected, missing.Failure)
	}
	if missing.Failure.FailingCheck != "platform-binary" || !strings.Contains(missing.Failure.ConsumerAction, "do not install") {
		t.Fatalf("missing-binary failure = %+v", missing.Failure)
	}

	tampered := fixtures["failure-tampered-manifest-attestation.json"]
	if tampered.Expected != "fail" || tampered.Failure == nil {
		t.Fatalf("tampered-manifest expected=%q failure=%+v, want failure", tampered.Expected, tampered.Failure)
	}
	if tampered.Failure.FailingCheck != "manifest" || !strings.Contains(tampered.Failure.ConsumerAction, "security policy") {
		t.Fatalf("tampered-manifest failure = %+v", tampered.Failure)
	}
}

func requireAttestationFixtureCommand(t *testing.T, fileName string, fixture releaseAttestationFixture, checkName string, artifact string) {
	t.Helper()
	for _, check := range fixture.Checks {
		if check.Name == checkName {
			if !check.Required {
				t.Fatalf("%s %s check must be required", fileName, checkName)
			}
			want := "gh attestation verify " + artifact + " --repo " + fixture.Release.Repo
			if check.Artifact != artifact || check.Command != want {
				t.Fatalf("%s %s check = %+v, want artifact %q command %q", fileName, checkName, check, artifact, want)
			}
			return
		}
	}
	t.Fatalf("%s missing %s check", fileName, checkName)
}

func requireNoSensitiveReleaseFixtureText(t *testing.T, fileName string, text string) {
	t.Helper()
	for _, forbidden := range []string{
		"BEGIN PRIVATE KEY",
		"private_key\":",
		"/Users/",
		"\\\\Users\\\\",
		"gho_",
		"token=",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("%s contains forbidden sensitive/local text %q", fileName, forbidden)
		}
	}
}
