package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/uesugitorachiyo/ao-covenant/internal/approval"
	bundlepkg "github.com/uesugitorachiyo/ao-covenant/internal/bundle"
	"github.com/uesugitorachiyo/ao-covenant/internal/contract"
	releasepkg "github.com/uesugitorachiyo/ao-covenant/internal/release"
	"github.com/uesugitorachiyo/ao-covenant/internal/schema"
)

func TestRunRejectsMissingCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: covenant <command>") {
		t.Fatalf("stderr = %q, want usage text", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestLiveDocsApprovalValidateAcceptsExactApprovedTicket(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "live-docs", "validate",
		"--request", filepath.Join("..", "..", "examples", "live-docs-approval", "request.json"),
		"--ticket", filepath.Join("..", "..", "examples", "live-docs-approval", "ticket-approved.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"approval_state=approved",
		"safe_to_execute=true",
		"ticket_id=live-docs-approval-ticket",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestLiveDocsApprovalValidateFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		ticketPath string
		wantError  string
	}{
		{
			name:       "pending",
			ticketPath: filepath.Join("..", "..", "examples", "live-docs-approval", "ticket-pending.json"),
			wantError:  "approval_state must be approved",
		},
		{
			name:       "denied",
			ticketPath: filepath.Join("..", "..", "examples", "live-docs-approval", "ticket-denied.json"),
			wantError:  "approval_state must be approved",
		},
		{
			name:       "stale",
			ticketPath: filepath.Join("..", "..", "examples", "live-docs-approval", "ticket-stale.json"),
			wantError:  "approval ticket expired",
		},
		{
			name:       "mismatched_scope",
			ticketPath: filepath.Join("..", "..", "examples", "live-docs-approval", "ticket-mismatched-scope.json"),
			wantError:  "ticket scope does not exactly match request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{
				"covenant", "approval", "live-docs", "validate",
				"--request", filepath.Join("..", "..", "examples", "live-docs-approval", "request.json"),
				"--ticket", tc.ticketPath,
			}, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("Run returned success; stdout=%s", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantError) {
				t.Fatalf("stderr missing %q: %s", tc.wantError, stderr.String())
			}
		})
	}
}

func TestMutationClassAuthorityValidateAcceptsExactTicket(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "mutation-class", "validate",
		"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-docs-multi.json"),
		"--ticket", filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-approved-docs-multi.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"ticket_id=mutation-class-docs-multi-ticket",
		"request_id=docs-multi-authority-request",
		"mutation_class=docs_only_multi_file",
		"safe_to_request=true",
		"safe_to_execute=false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestMutationClassAuthorityValidateAcceptsTestOnlyTicket(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "mutation-class", "validate",
		"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-test-only.json"),
		"--ticket", filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-approved-test-only.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"ticket_id=mutation-class-test-only-ticket",
		"request_id=test-only-authority-request",
		"mutation_class=test_only",
		"safe_to_request=true",
		"safe_to_execute=false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestMutationClassAuthorityValidateAcceptsLowRiskCodeDryRunTicket(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "mutation-class", "validate",
		"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-low-risk-code.json"),
		"--ticket", filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-approved-low-risk-code.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"ticket_id=mutation-class-low-risk-code-ticket",
		"request_id=low-risk-code-authority-request",
		"mutation_class=low_risk_code",
		"safe_to_request=true",
		"safe_to_execute=false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestGatewayIntentAuthorityDenialFixtureStaysReadOnly(t *testing.T) {
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeBytes)
	for _, want := range []string{
		"AO Mission gateway intents have a separate denial boundary",
		"gateway inputs can create operator intents and readback requests only",
		"decision=deny_gateway_intent_mutation_authority",
		"mutates_repositories=false",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README missing gateway authority denial term %q", want)
		}
	}
	var fixture map[string]any
	body, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway-intent-authority-denial", "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.GatewayIntentAuthorityDenialSchemaID, body); err != nil {
		t.Fatalf("gateway intent authority fixture schema validation failed: %v\n%s", err, string(body))
	}
	for _, key := range []string{
		"telegram_intents_grant_mutation_authority",
		"a2a_intents_grant_mutation_authority",
		"safe_to_execute",
		"executes_work",
		"approves_work",
		"mutates_repositories",
		"provider_calls_allowed",
		"release_or_publish_allowed",
	} {
		if fixture[key] != false {
			t.Fatalf("gateway authority fixture %s = %#v, want false", key, fixture[key])
		}
	}
}

func TestTelegramAndA2AIntentAuthorityDenialFixturesStayReadOnly(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		schemaID string
		decision string
	}{
		{
			name:     "telegram",
			path:     filepath.Join("..", "..", "examples", "telegram-intent-authority-denial", "decision.json"),
			schemaID: schema.TelegramIntentAuthorityDenialSchemaID,
			decision: "deny_telegram_intent_mutation_authority",
		},
		{
			name:     "a2a",
			path:     filepath.Join("..", "..", "examples", "a2a-intent-authority-denial", "decision.json"),
			schemaID: schema.A2AIntentAuthorityDenialSchemaID,
			decision: "deny_a2a_intent_mutation_authority",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture map[string]any
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatal(err)
			}
			if err := schema.ValidateBytes(tc.schemaID, body); err != nil {
				t.Fatalf("%s authority fixture schema validation failed: %v\n%s", tc.name, err, string(body))
			}
			if fixture["decision"] != tc.decision {
				t.Fatalf("%s decision = %#v, want %s", tc.name, fixture["decision"], tc.decision)
			}
			for _, key := range []string{
				"safe_to_execute",
				"executes_work",
				"approves_work",
				"mutates_repositories",
				"provider_calls_allowed",
				"release_or_publish_allowed",
			} {
				if fixture[key] != false {
					t.Fatalf("%s authority fixture %s = %#v, want false", tc.name, key, fixture[key])
				}
			}
		})
	}
}

func TestGatewaySchedulerAuthorityDenialBundleFixtureStaysReadOnly(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway-scheduler-authority-denial-bundle", "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.GatewaySchedulerAuthorityDenialBundleSchemaID, body); err != nil {
		t.Fatalf("gateway scheduler authority bundle schema validation failed: %v\n%s", err, string(body))
	}
	if fixture["decision"] != "deny_gateway_scheduler_mutation_authority" {
		t.Fatalf("unexpected bundle decision: %#v", fixture["decision"])
	}
	for _, key := range []string{
		"safe_to_execute",
		"schedules_work",
		"executes_work",
		"approves_work",
		"mutates_repositories",
		"a2a_push_notifications_grant_execution_authority",
		"provider_calls_allowed",
		"release_or_publish_allowed",
		"credential_use_allowed",
	} {
		if fixture[key] != false {
			t.Fatalf("gateway scheduler bundle %s = %#v, want false", key, fixture[key])
		}
	}
}

func TestGatewaySchedulerAuthorityDenialBundleInvalidFixturesFail(t *testing.T) {
	for _, name := range []string{
		"telegram-a2a-authority-widening.json",
		"scheduler-authority-widening.json",
		"a2a-streaming-execution-widening.json",
		"a2a-push-notification-execution-widening.json",
	} {
		body, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway-scheduler-authority-denial-bundle", "invalid", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.ValidateBytes(schema.GatewaySchedulerAuthorityDenialBundleSchemaID, body); err == nil {
			t.Fatalf("invalid gateway scheduler authority bundle %s unexpectedly passed schema validation", name)
		}
	}
}

func TestSchedulerRecoveryAuthorityDenialFixtureStaysReadOnly(t *testing.T) {
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeBytes)
	for _, want := range []string{
		"AO Mission scheduler recovery has a separate execution-authority denial",
		"Recovery readbacks can record missed wakeups and recommend governed",
		"decision=deny_scheduler_recovery_execution_authority",
		"schedules_work=false",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README missing scheduler recovery authority denial term %q", want)
		}
	}
	var fixture map[string]any
	body, err := os.ReadFile(filepath.Join("..", "..", "examples", "scheduler-recovery-authority-denial", "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateBytes(schema.SchedulerRecoveryAuthorityDenialSchemaID, body); err != nil {
		t.Fatalf("scheduler recovery authority fixture schema validation failed: %v\n%s", err, string(body))
	}
	for _, key := range []string{
		"scheduler_recovery_grants_scheduling_authority",
		"scheduler_recovery_grants_execution_authority",
		"safe_to_execute",
		"schedules_work",
		"executes_work",
		"approves_work",
		"mutates_repositories",
		"provider_calls_allowed",
		"release_or_publish_allowed",
		"credential_use_allowed",
		"direct_main_mutation_allowed",
		"concurrent_mutation_allowed",
	} {
		if fixture[key] != false {
			t.Fatalf("scheduler recovery authority fixture %s = %#v, want false", key, fixture[key])
		}
	}
}

func TestLowRiskCodeLivePolicyValidateAcceptsExactCandidatePolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "low-risk-code-live", "validate",
		"--policy", filepath.Join("..", "..", "examples", "low-risk-code-live-policy", "policy-approved-candidate-one.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"policy_id=low-risk-code-live-policy-candidate-one",
		"mutation_class=low_risk_code",
		"candidate_repo=ao-atlas",
		"base_branch=main",
		"proposed_branch=codex/low-risk-code-rehearsal-one",
		"file_allowlist=internal/atlas/validate.go",
		"command_allowlist=git diff --check",
		"command_allowlist=go test ./...",
		"safe_to_request=true",
		"safe_to_execute=false",
		"live_mutation_grant=false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestLowRiskCodeLivePolicyValidateFailsClosedOnScopeMismatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "low-risk-code-live", "validate",
		"--policy", filepath.Join("..", "..", "examples", "low-risk-code-live-policy", "policy-mismatched-branch.json"),
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("Run returned success; stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "proposed_branch must be codex/low-risk-code-rehearsal-one") {
		t.Fatalf("stderr missing proposed branch diagnostic: %s", stderr.String())
	}
}

func TestMutationClassAuthorityValidateAcceptsMultiRepoLowRiskTicket(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "mutation-class", "validate",
		"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-multi-repo-low-risk.json"),
		"--ticket", filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-approved-multi-repo-low-risk.json"),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run returned %d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"valid=true",
		"ticket_id=mutation-class-multi-repo-low-risk-ticket",
		"request_id=multi-repo-low-risk-authority-request",
		"mutation_class=multi_repo_low_risk",
		"safe_to_request=true",
		"safe_to_execute=false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q: %s", want, stdout.String())
		}
	}
}

func TestMutationClassAuthorityValidateRejectsLowRiskDiffLimitBroadening(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"covenant", "approval", "mutation-class", "validate",
		"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-low-risk-code.json"),
		"--ticket", filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-broadened-diff-limit-low-risk-code.json"),
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("Run returned success; stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "ticket diff limit does not exactly match request") {
		t.Fatalf("stderr missing diff-limit diagnostic: %s", stderr.String())
	}
}

func TestMutationClassAuthorityValidateRejectsInvalidMultiRepoLowRiskScope(t *testing.T) {
	cases := []struct {
		name        string
		requestPath string
		ticketPath  string
		wantError   string
	}{
		{
			name:        "missing_dependency",
			requestPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "request-multi-repo-low-risk-missing-dependency.json"),
			ticketPath:  filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-missing-dependency-multi-repo-low-risk.json"),
			wantError:   "ordered dependency is missing or not earlier",
		},
		{
			name:        "stale_repo_state",
			requestPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "request-multi-repo-low-risk-stale-repo-state.json"),
			ticketPath:  filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-stale-repo-state-multi-repo-low-risk.json"),
			wantError:   "repo state evidence is stale",
		},
		{
			name:        "partial_rollback",
			requestPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "request-multi-repo-low-risk-partial-rollback.json"),
			ticketPath:  filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-partial-rollback-multi-repo-low-risk.json"),
			wantError:   "per-repo rollback is incomplete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{
				"covenant", "approval", "mutation-class", "validate",
				"--request", tc.requestPath,
				"--ticket", tc.ticketPath,
			}, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("Run returned success; stdout=%s", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantError) {
				t.Fatalf("stderr missing %q: %s", tc.wantError, stderr.String())
			}
		})
	}
}

func TestMutationClassAuthorityValidateFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		ticketPath string
		wantError  string
	}{
		{
			name:       "broadened_path_scope",
			ticketPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-broadened-path-scope.json"),
			wantError:  "ticket path scope is broader than request",
		},
		{
			name:       "stale_digest",
			ticketPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-stale-digest.json"),
			wantError:  "scope_digest does not match approved_scope",
		},
		{
			name:       "wrong_class",
			ticketPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-wrong-class.json"),
			wantError:  "ticket mutation_class does not match request",
		},
		{
			name:       "consumed",
			ticketPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-consumed.json"),
			wantError:  "authority ticket has already been consumed",
		},
		{
			name:       "missing_rollback",
			ticketPath: filepath.Join("..", "..", "examples", "mutation-class-authority", "ticket-missing-rollback.json"),
			wantError:  "rollback",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{
				"covenant", "approval", "mutation-class", "validate",
				"--request", filepath.Join("..", "..", "examples", "mutation-class-authority", "request-docs-multi.json"),
				"--ticket", tc.ticketPath,
			}, &stdout, &stderr)
			if code == 0 {
				t.Fatalf("Run returned success; stdout=%s", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantError) {
				t.Fatalf("stderr missing %q: %s", tc.wantError, stderr.String())
			}
		})
	}
}

func TestREADMEOutputSidecarGuaranteesStayAlignedWithHelperCoverage(t *testing.T) {
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	testNames := cliTestFunctionNames(t)

	checks := []struct {
		docPhrase string
		testName  string
	}{
		{
			docPhrase: "`compile --out <path>` also writes `<path>.sha256`",
			testName:  "TestCompileWritesContractAndDigest",
		},
		{
			docPhrase: "`approval attach --out <path>` writes the approved contract and `<path>.sha256`",
			testName:  "TestApprovalAttachWritesApprovedContractAndDigest",
		},
		{
			docPhrase: "Commands that write a primary artifact plus a digest sidecar, currently `compile --out` and `approval attach --out`, use the same output-sidecar guarantees",
			testName:  "TestWriteOutputPairWithRollbackWritesOutputAndSidecar",
		},
		{
			docPhrase: "the `--out` parent directory must already exist",
			testName:  "TestCompileCommandRejectsOutputFileWithMissingParent",
		},
		{
			docPhrase: "`--out` must point to a file path rather than a directory",
			testName:  "TestApprovalAttachRejectsOutputPathDirectoryTarget",
		},
		{
			docPhrase: "If the sidecar write fails after the primary artifact is written, AO Covenant rolls the primary artifact back",
			testName:  "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
		},
		{
			docPhrase: "pre-existing primary artifacts are restored with their previous contents and permission bits",
			testName:  "TestWriteOutputPairWithRollbackPreservesExistingOutputModeOnSidecarFailure",
		},
		{
			docPhrase: "Existing sidecar artifacts are left in their previous state when a write fails",
			testName:  "TestWriteOutputPairWithRollbackPreservesExistingSidecarWhenOutputWriteFails",
		},
		{
			docPhrase: "If rollback itself fails, the command reports both the sidecar write failure and the rollback failure",
			testName:  "TestCompileCommandReportsRollbackFailureWhenDigestSidecarFails",
		},
	}
	readme := string(readmeBytes)
	for _, check := range checks {
		if !containsCollapsedText(readme, check.docPhrase) {
			t.Fatalf("README missing documented output-sidecar guarantee %q", check.docPhrase)
		}
		if !testNames[check.testName] {
			t.Fatalf("cli tests missing %s for documented output-sidecar guarantee %q", check.testName, check.docPhrase)
		}
	}
}

func TestREADMEOutputGuaranteesLinkDeveloperContract(t *testing.T) {
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	readme := string(readmeBytes)
	for _, want := range []string{
		"[CLI Output Writer Contract](docs/output-writer-contract.md)",
		"command-writer matrix",
		"error taxonomy",
	} {
		if !containsCollapsedText(readme, want) {
			t.Fatalf("README missing output writer contract cross-link phrase %q", want)
		}
	}
}

func TestREADMEOutputGuaranteesDoNotDriftFromDeveloperContract(t *testing.T) {
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	contractBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	readme := string(readmeBytes)
	contract := string(contractBytes)
	for _, phrase := range []string{
		"The parent directory must already exist.",
		"The parent path must be a directory, not a file.",
		"The `--out` target must point to a file path rather than a directory.",
		"Failed path validation must leave stdout empty and must not create output artifacts.",
		"If primary output validation or writing fails, the digest sidecar must not be created.",
		"If the primary artifact is written but the digest sidecar write fails, the writer must rollback the primary artifact",
	} {
		if !containsCollapsedText(contract, phrase) {
			t.Fatalf("output writer contract missing drift-guard phrase %q", phrase)
		}
		if !containsCollapsedText(readme, phrase) {
			t.Fatalf("README missing drift-guard phrase %q", phrase)
		}
	}
}

func TestDeveloperOutputWriterContractDocumentsSharedGuarantees(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "output-writer-contract.md")
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, want := range []string{
		"# CLI Output Writer Contract",
		"writeOutputFileBytes",
		"writeNamedOutputFile",
		"writeOutputPairWithRollback",
		"outputPairErrorStage",
		"parent directory must already exist",
		"must point to a file path rather than a directory",
		"digest sidecar",
		"rollback",
		"append or merge modes must validate existing input before writing",
		"Do not call os.WriteFile directly from command handlers",
	} {
		if !containsCollapsedText(doc, want) {
			t.Fatalf("output writer contract missing %q", want)
		}
	}
}

func TestOutputWriterErrorTaxonomyDocumentsAllCategories(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, want := range []string{
		"missing-parent",
		"parent-inspect",
		"parent-not-directory",
		"target-directory",
		"target-inspect",
		"write-failed",
	} {
		if !containsCollapsedText(doc, want) {
			t.Fatalf("output writer contract missing taxonomy label %q", want)
		}
	}
}

func TestOutputWriterContractDocumentsCommandWriterTable(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, check := range cliFileOutputCommandWriters(t) {
		row := "| `" + check.Command + "` | `" + check.Function + "` | `" + check.Writer + "` | " + check.Contract + " |"
		if !containsCollapsedText(doc, row) {
			t.Fatalf("output writer contract missing command-writer row %q", row)
		}
	}
}

func TestOutputWriterContractCommandWriterMatrixRenderingMatchesFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	got := extractMarkedMarkdownBlock(t, string(docBytes), "output-command-writer-matrix")
	want := renderCommandWriterMatrixMarkdown(t)
	if got != want {
		t.Fatalf("rendered command writer matrix mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

func renderCommandWriterMatrixMarkdown(t *testing.T) string {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("| Command | CLI function | Shared writer | Output contract |\n")
	builder.WriteString("| --- | --- | --- | --- |\n")
	for _, command := range cliFileOutputCommandWriters(t) {
		builder.WriteString("| `" + command.Command + "` | `" + command.Function + "` | `" + command.Writer + "` | " + command.Contract + " |\n")
	}
	return builder.String()
}

func extractMarkedMarkdownBlock(t *testing.T, doc string, name string) string {
	t.Helper()
	startMarker := "<!-- " + name + ":start -->"
	endMarker := "<!-- " + name + ":end -->"
	start := strings.Index(doc, startMarker)
	if start < 0 {
		t.Fatalf("markdown block %s missing start marker %q", name, startMarker)
	}
	start += len(startMarker)
	end := strings.Index(doc[start:], endMarker)
	if end < 0 {
		t.Fatalf("markdown block %s missing end marker %q", name, endMarker)
	}
	block := strings.ReplaceAll(doc[start:start+end], "\r\n", "\n")
	return strings.TrimPrefix(block, "\n")
}

func TestOutputWriterContractReferencesCommandWriterMatrixFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, want := range []string{
		"internal/cli/testdata/output-command-writer-matrix.json",
		"ao-covenant.output-command-writer-matrix.v1",
	} {
		if !containsCollapsedText(doc, want) {
			t.Fatalf("output writer contract missing command matrix fixture reference %q", want)
		}
	}
}

func TestOutputWriterContractReferencesFailureFixtureIndexFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, want := range []string{
		"internal/cli/testdata/output-failure-fixture-index.json",
		"ao-covenant.output-failure-fixture-index.v1",
	} {
		if !containsCollapsedText(doc, want) {
			t.Fatalf("output writer contract missing failure fixture source reference %q", want)
		}
	}
}

func TestOutputWriterContractReferencesOutputPairFixtureIndexFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, want := range []string{
		"internal/cli/testdata/output-pair-failure-fixture-index.json",
		"ao-covenant.output-pair-failure-fixture-index.v1",
	} {
		if !containsCollapsedText(doc, want) {
			t.Fatalf("output writer contract missing output-pair fixture source reference %q", want)
		}
	}
}

func TestOutputWriterContractDocumentsFailureFixtureIndex(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, fixture := range cliFileOutputFailureFixtureMatrix(t) {
		row := "| `" + fixture.Command + "` | `" + fixture.MissingParent + "` | `" + fixture.ParentFile + "` | `" + fixture.DirectoryTarget + "` |"
		if !containsCollapsedText(doc, row) {
			t.Fatalf("output writer contract missing failure fixture row %q", row)
		}
	}
}

func TestOutputWriterContractFailureFixtureIndexRenderingMatchesFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	got := extractMarkedMarkdownBlock(t, string(docBytes), "output-failure-fixture-index")
	want := renderOutputFailureFixtureIndexMarkdown(t)
	if got != want {
		t.Fatalf("rendered output failure fixture index mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

func renderOutputFailureFixtureIndexMarkdown(t *testing.T) string {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("| Command | Missing parent fixture | Parent file fixture | Directory target fixture |\n")
	builder.WriteString("| --- | --- | --- | --- |\n")
	for _, fixture := range cliFileOutputFailureFixtureMatrix(t) {
		builder.WriteString("| `" + fixture.Command + "` | `" + fixture.MissingParent + "` | `" + fixture.ParentFile + "` | `" + fixture.DirectoryTarget + "` |\n")
	}
	return builder.String()
}

func TestOutputWriterContractDocumentsOutputPairFailureFixtureIndex(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	doc := string(docBytes)
	for _, fixture := range cliOutputPairFailureFixtureIndex(t) {
		row := "| " + fixture.Guarantee + " | `" + fixture.HelperFixture + "` | `" + fixture.CompileFixture + "` | `" + fixture.AttachFixture + "` |"
		if !containsCollapsedText(doc, row) {
			t.Fatalf("output writer contract missing output-pair fixture row %q", row)
		}
	}
}

func TestOutputWriterContractOutputPairFailureFixtureIndexRenderingMatchesFixture(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "output-writer-contract.md"))
	if err != nil {
		t.Fatalf("read output writer contract: %v", err)
	}
	got := extractMarkedMarkdownBlock(t, string(docBytes), "output-pair-failure-fixture-index")
	want := renderOutputPairFailureFixtureIndexMarkdown(t)
	if got != want {
		t.Fatalf("rendered output-pair failure fixture index mismatch\n got:\n%s\nwant:\n%s", got, want)
	}
}

func renderOutputPairFailureFixtureIndexMarkdown(t *testing.T) string {
	t.Helper()
	var builder strings.Builder
	builder.WriteString("| Guarantee | Helper fixture | Compile fixture | Approval attach fixture |\n")
	builder.WriteString("| --- | --- | --- | --- |\n")
	for _, fixture := range cliOutputPairFailureFixtureIndex(t) {
		builder.WriteString("| " + fixture.Guarantee + " | `" + fixture.HelperFixture + "` | `" + fixture.CompileFixture + "` | `" + fixture.AttachFixture + "` |\n")
	}
	return builder.String()
}

func containsCollapsedText(text string, phrase string) bool {
	return strings.Contains(strings.Join(strings.Fields(text), " "), strings.Join(strings.Fields(phrase), " "))
}

func TestFileOutputCommandPathFixtureMatrixStaysComplete(t *testing.T) {
	testNames := cliTestFunctionNames(t)
	for _, check := range cliFileOutputFailureFixtureMatrix(t) {
		for _, testName := range []string{check.MissingParent, check.ParentFile, check.DirectoryTarget} {
			if !testNames[testName] {
				t.Fatalf("%s missing output-path fixture %s", check.Command, testName)
			}
		}
	}
}

func TestOutputFailureFixtureIndexParserRejectsUnknownFields(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-failure-fixture-index.v1",
		"fixtures": [
			{
				"command": "compile --out",
				"missing_parent": "TestCompileCommandRejectsOutputFileWithMissingParent",
				"parent_file": "TestCompileCommandRejectsOutputFileWithParentFile",
				"directory_target": "TestCompileCommandRejectsOutputFileDirectoryTarget",
				"unexpected": "ignored by json.Unmarshal"
			}
		]
	}`)

	_, err := parseCLIFileOutputFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output failure fixture index succeeded with unknown fixture field")
	}
	if !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("error = %v, want unknown field", err)
	}
}

func TestOutputFailureFixtureIndexParserRejectsBlankFields(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-failure-fixture-index.v1",
		"fixtures": [
			{
				"command": "compile --out",
				"missing_parent": "",
				"parent_file": "TestCompileCommandRejectsOutputFileWithParentFile",
				"directory_target": "TestCompileCommandRejectsOutputFileDirectoryTarget"
			}
		]
	}`)

	_, err := parseCLIFileOutputFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output failure fixture index succeeded with blank required field")
	}
	if !strings.Contains(err.Error(), "fixtures[0].missing_parent is empty") {
		t.Fatalf("error = %v, want missing_parent validation", err)
	}
}

func TestOutputFailureFixtureIndexParserRejectsDuplicateCommand(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-failure-fixture-index.v1",
		"fixtures": [
			{
				"command": "compile --out",
				"missing_parent": "TestCompileCommandRejectsOutputFileWithMissingParent",
				"parent_file": "TestCompileCommandRejectsOutputFileWithParentFile",
				"directory_target": "TestCompileCommandRejectsOutputFileDirectoryTarget"
			},
			{
				"command": "compile --out",
				"missing_parent": "TestSchemaValidateCommandJSONRejectsOutputFileWithMissingParent",
				"parent_file": "TestSchemaValidateCommandJSONRejectsOutputFileWithParentFile",
				"directory_target": "TestSchemaValidateCommandJSONRejectsOutputFileDirectoryTarget"
			}
		]
	}`)

	_, err := parseCLIFileOutputFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output failure fixture index succeeded with duplicate command")
	}
	if !strings.Contains(err.Error(), `fixtures[1].command duplicates fixtures[0].command "compile --out"`) {
		t.Fatalf("error = %v, want duplicate command validation", err)
	}
}

func TestOutputFailureFixtureIndexParserRejectsDuplicateReferencedTest(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-failure-fixture-index.v1",
		"fixtures": [
			{
				"command": "compile --out",
				"missing_parent": "TestCompileCommandRejectsOutputFileWithMissingParent",
				"parent_file": "TestCompileCommandRejectsOutputFileWithParentFile",
				"directory_target": "TestCompileCommandRejectsOutputFileDirectoryTarget"
			},
			{
				"command": "schema validate --out",
				"missing_parent": "TestCompileCommandRejectsOutputFileWithMissingParent",
				"parent_file": "TestSchemaValidateCommandJSONRejectsOutputFileWithParentFile",
				"directory_target": "TestSchemaValidateCommandJSONRejectsOutputFileDirectoryTarget"
			}
		]
	}`)

	_, err := parseCLIFileOutputFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output failure fixture index succeeded with duplicate referenced test")
	}
	if !strings.Contains(err.Error(), `fixtures[1].missing_parent duplicates fixtures[0].missing_parent "TestCompileCommandRejectsOutputFileWithMissingParent"`) {
		t.Fatalf("error = %v, want duplicate referenced test validation", err)
	}
}

func TestOutputFailureFixtureIndexSchemaValidatesFixture(t *testing.T) {
	requireFixtureSchemaValidatesFile(t,
		filepath.Join("testdata", "output-failure-fixture-index.schema.json"),
		filepath.Join("testdata", "output-failure-fixture-index.json"),
	)
}

func TestOutputFailureFixtureIndexSchemaRejectsIncompleteFixture(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-failure-fixture-index.v1",
		"fixtures": [
			{
				"command": "compile --out",
				"missing_parent": "TestCompileCommandRejectsOutputFileWithMissingParent",
				"parent_file": "TestCompileCommandRejectsOutputFileWithParentFile"
			}
		]
	}`)

	err := validateFixtureJSONAgainstSchema(t, filepath.Join("testdata", "output-failure-fixture-index.schema.json"), payload)
	if err == nil {
		t.Fatalf("output failure fixture schema accepted incomplete fixture")
	}
	if !strings.Contains(err.Error(), "directory_target") {
		t.Fatalf("error = %v, want directory_target validation", err)
	}
}

type cliFileOutputFailureFixtures struct {
	Command         string `json:"command"`
	MissingParent   string `json:"missing_parent"`
	ParentFile      string `json:"parent_file"`
	DirectoryTarget string `json:"directory_target"`
}

type cliFileOutputFailureFixtureIndex struct {
	SchemaVersion string                         `json:"schema_version"`
	Fixtures      []cliFileOutputFailureFixtures `json:"fixtures"`
}

func cliFileOutputFailureFixtureMatrix(t *testing.T) []cliFileOutputFailureFixtures {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "output-failure-fixture-index.json"))
	if err != nil {
		t.Fatalf("read output failure fixture index: %v", err)
	}
	fixtures, err := parseCLIFileOutputFailureFixtureIndex(bytes)
	if err != nil {
		t.Fatalf("decode output failure fixture index: %v", err)
	}
	return fixtures
}

func parseCLIFileOutputFailureFixtureIndex(data []byte) ([]cliFileOutputFailureFixtures, error) {
	var index cliFileOutputFailureFixtureIndex
	if err := decodeStrictFixtureJSON(data, &index); err != nil {
		return nil, err
	}
	if index.SchemaVersion != "ao-covenant.output-failure-fixture-index.v1" {
		return nil, fmt.Errorf("output failure fixture index schema_version = %q", index.SchemaVersion)
	}
	if len(index.Fixtures) == 0 {
		return nil, errors.New("output failure fixture index has no fixtures")
	}
	commands := map[string]fixtureValueLocation{}
	testNames := map[string]fixtureValueLocation{}
	for i, fixture := range index.Fixtures {
		for _, check := range []struct {
			name  string
			value string
		}{
			{"command", fixture.Command},
			{"missing_parent", fixture.MissingParent},
			{"parent_file", fixture.ParentFile},
			{"directory_target", fixture.DirectoryTarget},
		} {
			if strings.TrimSpace(check.value) == "" {
				return nil, fmt.Errorf("fixtures[%d].%s is empty", i, check.name)
			}
		}
		if err := rejectDuplicateFixtureValue(commands, fixture.Command, i, "command"); err != nil {
			return nil, err
		}
		for _, check := range []struct {
			name  string
			value string
		}{
			{"missing_parent", fixture.MissingParent},
			{"parent_file", fixture.ParentFile},
			{"directory_target", fixture.DirectoryTarget},
		} {
			if err := rejectDuplicateFixtureValue(testNames, check.value, i, check.name); err != nil {
				return nil, err
			}
		}
	}
	return index.Fixtures, nil
}

func TestOutputPairFailureFixtureIndexStaysComplete(t *testing.T) {
	testNames := cliTestFunctionNames(t)
	for _, fixture := range cliOutputPairFailureFixtureIndex(t) {
		for _, testName := range []string{fixture.HelperFixture, fixture.CompileFixture, fixture.AttachFixture} {
			if !testNames[testName] {
				t.Fatalf("%s missing output-pair fixture %s", fixture.Guarantee, testName)
			}
		}
	}
}

func TestOutputPairFailureFixtureIndexParserRejectsUnknownFields(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-pair-failure-fixture-index.v1",
		"fixtures": [
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "TestCompileCommandRemovesNewContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachRemovesNewContractWhenDigestSidecarFails",
				"unexpected": "ignored by json.Unmarshal"
			}
		]
	}`)

	_, err := parseCLIOutputPairFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output-pair failure fixture index succeeded with unknown fixture field")
	}
	if !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("error = %v, want unknown field", err)
	}
}

func TestOutputPairFailureFixtureIndexParserRejectsBlankFields(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-pair-failure-fixture-index.v1",
		"fixtures": [
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "",
				"attach_fixture": "TestApprovalAttachRemovesNewContractWhenDigestSidecarFails"
			}
		]
	}`)

	_, err := parseCLIOutputPairFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output-pair failure fixture index succeeded with blank required field")
	}
	if !strings.Contains(err.Error(), "fixtures[0].compile_fixture is empty") {
		t.Fatalf("error = %v, want compile_fixture validation", err)
	}
}

func TestOutputPairFailureFixtureIndexParserRejectsDuplicateGuarantee(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-pair-failure-fixture-index.v1",
		"fixtures": [
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "TestCompileCommandRemovesNewContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachRemovesNewContractWhenDigestSidecarFails"
			},
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRestoresExistingOutputContentOnSidecarFailure",
				"compile_fixture": "TestCompileCommandPreservesExistingContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachPreservesExistingContractWhenDigestSidecarFails"
			}
		]
	}`)

	_, err := parseCLIOutputPairFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output-pair failure fixture index succeeded with duplicate guarantee")
	}
	if !strings.Contains(err.Error(), `fixtures[1].guarantee duplicates fixtures[0].guarantee "sidecar failure removes new primary"`) {
		t.Fatalf("error = %v, want duplicate guarantee validation", err)
	}
}

func TestOutputPairFailureFixtureIndexParserRejectsDuplicateReferencedTest(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-pair-failure-fixture-index.v1",
		"fixtures": [
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "TestCompileCommandRemovesNewContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachRemovesNewContractWhenDigestSidecarFails"
			},
			{
				"guarantee": "sidecar failure restores existing primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "TestCompileCommandPreservesExistingContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachPreservesExistingContractWhenDigestSidecarFails"
			}
		]
	}`)

	_, err := parseCLIOutputPairFailureFixtureIndex(payload)
	if err == nil {
		t.Fatalf("parse output-pair failure fixture index succeeded with duplicate referenced test")
	}
	if !strings.Contains(err.Error(), `fixtures[1].helper_fixture duplicates fixtures[0].helper_fixture "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure"`) {
		t.Fatalf("error = %v, want duplicate referenced test validation", err)
	}
}

func TestOutputPairFailureFixtureIndexSchemaValidatesFixture(t *testing.T) {
	requireFixtureSchemaValidatesFile(t,
		filepath.Join("testdata", "output-pair-failure-fixture-index.schema.json"),
		filepath.Join("testdata", "output-pair-failure-fixture-index.json"),
	)
}

func TestOutputPairFailureFixtureIndexSchemaRejectsUnknownFixtureField(t *testing.T) {
	payload := []byte(`{
		"schema_version": "ao-covenant.output-pair-failure-fixture-index.v1",
		"fixtures": [
			{
				"guarantee": "sidecar failure removes new primary",
				"helper_fixture": "TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure",
				"compile_fixture": "TestCompileCommandRemovesNewContractWhenDigestSidecarFails",
				"attach_fixture": "TestApprovalAttachRemovesNewContractWhenDigestSidecarFails",
				"unexpected": "blocked"
			}
		]
	}`)

	err := validateFixtureJSONAgainstSchema(t, filepath.Join("testdata", "output-pair-failure-fixture-index.schema.json"), payload)
	if err == nil {
		t.Fatalf("output-pair failure fixture schema accepted unknown fixture field")
	}
	if !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("error = %v, want unexpected field validation", err)
	}
}

type cliOutputPairFailureFixture struct {
	Guarantee      string `json:"guarantee"`
	HelperFixture  string `json:"helper_fixture"`
	CompileFixture string `json:"compile_fixture"`
	AttachFixture  string `json:"attach_fixture"`
}

type cliOutputPairFailureFixtureIndexDocument struct {
	SchemaVersion string                        `json:"schema_version"`
	Fixtures      []cliOutputPairFailureFixture `json:"fixtures"`
}

func cliOutputPairFailureFixtureIndex(t *testing.T) []cliOutputPairFailureFixture {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "output-pair-failure-fixture-index.json"))
	if err != nil {
		t.Fatalf("read output-pair failure fixture index: %v", err)
	}
	fixtures, err := parseCLIOutputPairFailureFixtureIndex(bytes)
	if err != nil {
		t.Fatalf("decode output-pair failure fixture index: %v", err)
	}
	return fixtures
}

func parseCLIOutputPairFailureFixtureIndex(data []byte) ([]cliOutputPairFailureFixture, error) {
	var index cliOutputPairFailureFixtureIndexDocument
	if err := decodeStrictFixtureJSON(data, &index); err != nil {
		return nil, err
	}
	if index.SchemaVersion != "ao-covenant.output-pair-failure-fixture-index.v1" {
		return nil, fmt.Errorf("output-pair failure fixture index schema_version = %q", index.SchemaVersion)
	}
	if len(index.Fixtures) == 0 {
		return nil, errors.New("output-pair failure fixture index has no fixtures")
	}
	guarantees := map[string]fixtureValueLocation{}
	testNames := map[string]fixtureValueLocation{}
	for i, fixture := range index.Fixtures {
		for _, check := range []struct {
			name  string
			value string
		}{
			{"guarantee", fixture.Guarantee},
			{"helper_fixture", fixture.HelperFixture},
			{"compile_fixture", fixture.CompileFixture},
			{"attach_fixture", fixture.AttachFixture},
		} {
			if strings.TrimSpace(check.value) == "" {
				return nil, fmt.Errorf("fixtures[%d].%s is empty", i, check.name)
			}
		}
		if err := rejectDuplicateFixtureValue(guarantees, fixture.Guarantee, i, "guarantee"); err != nil {
			return nil, err
		}
		for _, check := range []struct {
			name  string
			value string
		}{
			{"helper_fixture", fixture.HelperFixture},
			{"compile_fixture", fixture.CompileFixture},
			{"attach_fixture", fixture.AttachFixture},
		} {
			if err := rejectDuplicateFixtureValue(testNames, check.value, i, check.name); err != nil {
				return nil, err
			}
		}
	}
	return index.Fixtures, nil
}

type fixtureValueLocation struct {
	index int
	field string
}

func rejectDuplicateFixtureValue(seen map[string]fixtureValueLocation, value string, index int, field string) error {
	if prior, ok := seen[value]; ok {
		return fmt.Errorf("fixtures[%d].%s duplicates fixtures[%d].%s %q", index, field, prior.index, prior.field, value)
	}
	seen[value] = fixtureValueLocation{index: index, field: field}
	return nil
}

func decodeStrictFixtureJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("fixture JSON contains multiple documents")
		}
		return err
	}
	return nil
}

func requireFixtureSchemaValidatesFile(t *testing.T, schemaPath string, fixturePath string) {
	t.Helper()
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	if err := validateFixtureJSONAgainstSchema(t, schemaPath, payload); err != nil {
		t.Fatalf("validate %s against %s: %v", fixturePath, schemaPath, err)
	}
}

func validateFixtureJSONAgainstSchema(t *testing.T, schemaPath string, payload []byte) error {
	t.Helper()
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema %s: %w", schemaPath, err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		return fmt.Errorf("parse schema %s: %w", schemaPath, err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaPath, schemaDocument); err != nil {
		return fmt.Errorf("register schema %s: %w", schemaPath, err)
	}
	compiled, err := compiler.Compile(schemaPath)
	if err != nil {
		return fmt.Errorf("compile schema %s: %w", schemaPath, err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		return fmt.Errorf("parse fixture payload: %w", err)
	}
	if err := compiled.Validate(document); err != nil {
		return err
	}
	return nil
}

func TestApprovalOutputPathFixturesUseSharedAssertions(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli_test.go")
	if err != nil {
		t.Fatalf("read cli tests: %v", err)
	}
	source := string(sourceBytes)
	checks := []struct {
		testName string
		helpers  []string
	}{
		{"TestApprovalCreateRejectsOutputPathWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestApprovalCreateRejectsOutputPathWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent"}},
		{"TestApprovalCreateRejectsOutputPathDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
		{"TestApprovalAttachRejectsOutputPathWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated", "requirePathNotCreated"}},
		{"TestApprovalAttachRejectsOutputPathWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent", "requirePathNotCreated"}},
		{"TestApprovalAttachRejectsOutputPathDirectoryTarget", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestApprovalRevokeRejectsOutputPathWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestApprovalRevokeRejectsOutputPathWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent"}},
		{"TestApprovalRevokeRejectsOutputPathDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
	}
	for _, check := range checks {
		body := cliFunctionBody(t, source, check.testName)
		for _, helper := range check.helpers {
			if !strings.Contains(body, helper+"(") {
				t.Fatalf("%s should use %s for output-path assertions", check.testName, helper)
			}
		}
	}
}

func TestOutputPathFixturesUseSharedAssertions(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli_test.go")
	if err != nil {
		t.Fatalf("read cli tests: %v", err)
	}
	source := string(sourceBytes)
	checks := []struct {
		testName string
		helpers  []string
	}{
		{"TestSchemaValidateCommandJSONRejectsOutputFileWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestSchemaValidateCommandJSONRejectsOutputFileWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent"}},
		{"TestSchemaValidateCommandJSONRejectsOutputFileDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
		{"TestCompileCommandRejectsOutputFileWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestCompileCommandRejectsOutputFileWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent", "requirePathNotCreated"}},
		{"TestCompileCommandRejectsOutputFileDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
		{"TestReleaseDiffCommandRejectsOutputFileWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestReleaseDiffCommandRejectsOutputFileWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent"}},
		{"TestReleaseDiffCommandRejectsOutputFileDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
		{"TestReleaseReportCommandRejectsOutputFileWithMissingParent", []string{"requireFailedOutputPathCommand", "requirePathNotCreated"}},
		{"TestReleaseReportCommandRejectsOutputFileWithParentFile", []string{"requireFailedOutputPathCommand", "requireFileContent"}},
		{"TestReleaseReportCommandRejectsOutputFileDirectoryTarget", []string{"requireFailedOutputPathCommand", "requireDirectoryTarget"}},
	}
	for _, check := range checks {
		body := cliFunctionBody(t, source, check.testName)
		for _, helper := range check.helpers {
			if !strings.Contains(body, helper+"(") {
				t.Fatalf("%s should use %s for output-path assertions", check.testName, helper)
			}
		}
	}
}

func TestAppendModeOutputContractsStayCovered(t *testing.T) {
	testNames := cliTestFunctionNames(t)
	checks := []struct {
		command  string
		testName string
	}{
		{
			command:  "approval revoke --append missing existing",
			testName: "TestApprovalRevokeAppendCreatesRevocationListWhenOutputIsMissing",
		},
		{
			command:  "approval revoke --append invalid existing",
			testName: "TestApprovalRevokeAppendRejectsInvalidExistingRevocationListWithoutOverwrite",
		},
		{
			command:  "approval revoke --append duplicate ticket",
			testName: "TestApprovalRevokeAppendRejectsDuplicateTicketWithoutOverwrite",
		},
	}
	for _, check := range checks {
		if !testNames[check.testName] {
			t.Fatalf("%s missing append-mode contract test %s", check.command, check.testName)
		}
	}
}

func TestReleaseOutputFormatFixtureMatrixStaysComplete(t *testing.T) {
	testNames := cliTestFunctionNames(t)
	checks := []struct {
		command  string
		format   string
		testName string
	}{
		{"release report", "text", "TestReleaseReportCommandWritesTextOutputFile"},
		{"release report", "markdown", "TestReleaseReportCommandWritesMarkdownOutputFile"},
		{"release report", "json", "TestReleaseReportCommandWritesJSONOutputFile"},
		{"release report", "invalid json", "TestReleaseReportCommandWritesInvalidJSONOutputFileBeforeNonZeroExit"},
		{"release report", "sarif", "TestReleaseReportCommandWritesSARIFOutputFile"},
		{"release report", "sarif-baseline", "TestReleaseReportCommandWritesSARIFBaselineOutputFile"},
		{"release diff", "json", "TestReleaseDiffCommandWritesJSONOutputFile"},
		{"release diff", "redacted json", "TestReleaseDiffCommandWritesRedactedJSONOutputFileWithPolicyProfile"},
		{"release diff", "sarif", "TestReleaseDiffCommandWritesSARIFOutputFile"},
		{"release diff", "sarif baseline", "TestReleaseDiffCommandWritesSARIFOutputFileWithAcceptedBaseline"},
	}
	for _, check := range checks {
		if !testNames[check.testName] {
			t.Fatalf("%s format %s missing output-file fixture %s", check.command, check.format, check.testName)
		}
	}
}

func cliTestFunctionNames(t *testing.T) map[string]bool {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "cli_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse cli tests: %v", err)
	}
	names := make(map[string]bool)
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && strings.HasPrefix(fn.Name.Name, "Test") {
			names[fn.Name.Name] = true
		}
	}
	return names
}

func TestRollbackOutputFileForWriteOverrideUsesTestGuard(t *testing.T) {
	testBytes, err := os.ReadFile("cli_test.go")
	if err != nil {
		t.Fatalf("read cli tests: %v", err)
	}
	forbidden := "rollbackOutputFileForWrite" + " ="
	if strings.Contains(string(testBytes), forbidden) {
		t.Fatalf("cli tests directly assign rollbackOutputFileForWrite; use overrideRollbackOutputFileForWriteForTest")
	}
}

func TestOutputPairHelperNamesStayFocused(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("read cli source: %v", err)
	}
	source := string(sourceBytes)
	for _, forbidden := range []string{
		"writeOutputFileWithSidecarRollback",
		"outputFileWithSidecarError",
		"outputFileWithSidecarErrorStage",
		"outputFileWithSidecarStageMain",
		"outputFileWithSidecarStageSidecar",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("cli source still uses old output-sidecar helper name %q; use output-pair naming", forbidden)
		}
	}
}

func TestCLIFileOutputCommandsUseSharedWriters(t *testing.T) {
	sourceBytes, parsed, fileSet := parseCLISource(t)
	functions := cliFunctionSources(t, sourceBytes, parsed, fileSet)
	allowedDirectWriteFileFunctions := map[string]bool{
		"writeOutputFileBytes": true,
		"rollbackOutputFile":   true,
	}
	for _, fn := range parsed.Decls {
		funcDecl, ok := fn.(*ast.FuncDecl)
		if !ok || funcDecl.Body == nil {
			continue
		}
		if !functionCallsOSWriteFile(funcDecl) {
			continue
		}
		if !allowedDirectWriteFileFunctions[funcDecl.Name.Name] {
			t.Fatalf("function %s calls os.WriteFile directly; route CLI file outputs through shared output writers", funcDecl.Name.Name)
		}
	}

	for _, check := range cliFileOutputCommandWriters(t) {
		source, ok := functions[check.Function]
		if !ok {
			t.Fatalf("missing expected CLI function %s", check.Function)
		}
		if !strings.Contains(source, check.Call) {
			t.Fatalf("%s does not call shared output writer %q", check.Function, check.Call)
		}
	}
}

type cliFileOutputCommandWriter struct {
	Command  string `json:"command"`
	Function string `json:"function"`
	Writer   string `json:"writer"`
	Contract string `json:"contract"`
	Call     string `json:"call"`
}

type cliFileOutputCommandWriterMatrix struct {
	SchemaVersion string                       `json:"schema_version"`
	Commands      []cliFileOutputCommandWriter `json:"commands"`
}

func cliFileOutputCommandWriters(t *testing.T) []cliFileOutputCommandWriter {
	t.Helper()
	bytes, err := os.ReadFile(filepath.Join("testdata", "output-command-writer-matrix.json"))
	if err != nil {
		t.Fatalf("read output command writer matrix: %v", err)
	}
	var matrix cliFileOutputCommandWriterMatrix
	if err := json.Unmarshal(bytes, &matrix); err != nil {
		t.Fatalf("decode output command writer matrix: %v", err)
	}
	if matrix.SchemaVersion != "ao-covenant.output-command-writer-matrix.v1" {
		t.Fatalf("output command writer matrix schema_version = %q", matrix.SchemaVersion)
	}
	if len(matrix.Commands) == 0 {
		t.Fatalf("output command writer matrix has no commands")
	}
	return matrix.Commands
}

func TestOutputPairTerminologyDocumentsInternalAndUserFacingBoundary(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("read cli source: %v", err)
	}
	source := string(sourceBytes)
	for _, want := range []string{
		"Internal code calls this an output pair",
		"User-facing diagnostics and README text call the second artifact a digest sidecar",
		"writeOutputPairWithRollback writes a primary artifact and sidecar as one output pair",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("cli source missing output-pair terminology comment %q", want)
		}
	}

	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	readme := string(readmeBytes)
	for _, want := range []string{
		"contract and digest sidecar are treated as one output pair",
		"primary artifact plus a digest sidecar",
		"output-sidecar guarantees",
	} {
		if !containsCollapsedText(readme, want) {
			t.Fatalf("README missing user-facing digest-sidecar wording %q", want)
		}
	}
}

func parseCLISource(t *testing.T) ([]byte, *ast.File, *token.FileSet) {
	t.Helper()
	sourceBytes, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("read cli source: %v", err)
	}
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "cli.go", sourceBytes, 0)
	if err != nil {
		t.Fatalf("parse cli source: %v", err)
	}
	return sourceBytes, parsed, fileSet
}

func cliFunctionSources(t *testing.T, sourceBytes []byte, parsed *ast.File, fileSet *token.FileSet) map[string]string {
	t.Helper()
	functions := make(map[string]string)
	for _, fn := range parsed.Decls {
		funcDecl, ok := fn.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fileSet.Position(funcDecl.Pos()).Offset
		end := fileSet.Position(funcDecl.End()).Offset
		functions[funcDecl.Name.Name] = string(sourceBytes[start:end])
	}
	return functions
}

func functionCallsOSWriteFile(funcDecl *ast.FuncDecl) bool {
	callsWriteFile := false
	ast.Inspect(funcDecl.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "WriteFile" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if ok && receiver.Name == "os" {
			callsWriteFile = true
			return false
		}
		return true
	})
	return callsWriteFile
}

func TestWriteNamedOutputFileValidatesPathAndWritesMarker(t *testing.T) {
	missingParentPath := filepath.Join(t.TempDir(), "missing", "release-report.txt")
	var stdout bytes.Buffer
	err := writeNamedOutputFile(&stdout, "release report", "release_report", missingParentPath, []byte("report\n"))
	if err == nil || !strings.Contains(err.Error(), "release report --out parent directory does not exist") {
		t.Fatalf("err = %v, want release report missing parent diagnostic", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty after failed write", stdout.String())
	}
	if _, statErr := os.Stat(missingParentPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output file stat error = %v, want file not created", statErr)
	}

	stdout.Reset()
	dirPath := t.TempDir()
	err = writeNamedOutputFile(&stdout, "release diff", "release_diff", dirPath, []byte("diff\n"))
	if err == nil || !strings.Contains(err.Error(), "release diff --out points to a directory") {
		t.Fatalf("err = %v, want release diff directory target diagnostic", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty after failed write", stdout.String())
	}

	stdout.Reset()
	outPath := filepath.Join(t.TempDir(), "release-report.txt")
	err = writeNamedOutputFile(&stdout, "release report", "release_report", outPath, []byte("report\n"))
	if err != nil {
		t.Fatalf("write named output file: %v", err)
	}
	if stdout.String() != "release_report="+outPath+"\n" {
		t.Fatalf("stdout = %q, want output marker", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(bytes) != "report\n" {
		t.Fatalf("output file = %q, want report body", string(bytes))
	}
}

func TestWriteOutputFileBytesErrorTaxonomy(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "missing", "artifact.txt")

		err := writeOutputFileBytes("helper command", outPath, []byte("artifact\n"))

		if err == nil || !strings.Contains(err.Error(), "helper command --out parent directory does not exist") {
			t.Fatalf("err = %v, want missing-parent diagnostic", err)
		}
	})

	t.Run("parent is file", func(t *testing.T) {
		parentFile := filepath.Join(t.TempDir(), "artifact-parent")
		if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		outPath := filepath.Join(parentFile, "artifact.txt")

		err := writeOutputFileBytes("helper command", outPath, []byte("artifact\n"))

		if err == nil || !strings.Contains(err.Error(), "helper command --out parent path is not a directory") {
			t.Fatalf("err = %v, want parent-not-directory diagnostic", err)
		}
	})

	t.Run("target is directory", func(t *testing.T) {
		outPath := t.TempDir()

		err := writeOutputFileBytes("helper command", outPath, []byte("artifact\n"))

		if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
			t.Fatalf("err = %v, want target-directory diagnostic", err)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows access control semantics differ from POSIX mode bits")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatalf("chmod read-only dir: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(dir, 0o755)
		})
		outPath := filepath.Join(dir, "artifact.txt")

		err := writeOutputFileBytes("helper command", outPath, []byte("artifact\n"))

		if err == nil || !strings.Contains(err.Error(), "helper command --out write failed") {
			t.Fatalf("err = %v, want write-failed diagnostic", err)
		}
	})
}

func TestWriteOutputFileBytesInspectErrorWordingStaysDocumented(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("read cli source: %v", err)
	}
	source := string(sourceBytes)
	for _, want := range []string{
		"--out parent path cannot be inspected",
		"--out path cannot be inspected",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("cli source missing inspect diagnostic %q", want)
		}
	}
}

func TestWriteNamedOutputFileWrapsTargetInspectionErrors(t *testing.T) {
	var stdout bytes.Buffer
	outPath := filepath.Join(t.TempDir(), "release\x00report.txt")

	err := writeNamedOutputFile(&stdout, "release report", "release_report", outPath, []byte("report\n"))

	if err == nil {
		t.Fatalf("write named output file returned nil error for invalid path")
	}
	if !strings.Contains(err.Error(), "release report --out path cannot be inspected") {
		t.Fatalf("err = %v, want command-specific stat context", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty after failed inspection", stdout.String())
	}
}

func TestWriteNamedOutputFileWrapsWritePermissionErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod write-denial semantics are not portable on Windows")
	}
	parentDir := t.TempDir()
	outPath := filepath.Join(parentDir, "release-report.txt")
	if err := os.Chmod(parentDir, 0o500); err != nil {
		t.Fatalf("chmod parent dir read-only: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(parentDir, 0o700)
	})

	var stdout bytes.Buffer
	err := writeNamedOutputFile(&stdout, "release report", "release_report", outPath, []byte("report\n"))
	if err == nil {
		t.Skip("filesystem permitted write despite removed directory write bit")
	}
	if !strings.Contains(err.Error(), "release report --out write failed") {
		t.Fatalf("err = %v, want command-specific write context", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty after failed write", stdout.String())
	}
}

func outputSidecarTestPaths(t *testing.T) (string, string) {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "artifact.json")
	return outPath, outPath + ".sha256"
}

func makeTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("create directory %s: %v", path, err)
	}
}

func writeTestFileBytes(t *testing.T, path string, bytes []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, bytes, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

var rollbackOutputFileForWriteTestMu sync.Mutex

func overrideRollbackOutputFileForWriteForTest(t *testing.T, rollback rollbackOutputFileFunc) {
	t.Helper()
	rollbackOutputFileForWriteTestMu.Lock()
	previous := replaceRollbackOutputFileForWrite(rollback)
	t.Cleanup(func() {
		replaceRollbackOutputFileForWrite(previous)
		rollbackOutputFileForWriteTestMu.Unlock()
	})
}

func TestWriteOutputPairWithRollbackWritesOutputAndSidecar(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("artifact body\n"), sidecarPath, []byte("digest\n"))

	if err != nil {
		t.Fatalf("write output with sidecar: %v", err)
	}
	bytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read output file: %v", readErr)
	}
	if string(bytes) != "artifact body\n" {
		t.Fatalf("output file = %q, want artifact body", string(bytes))
	}
	sidecarBytes, readErr := os.ReadFile(sidecarPath)
	if readErr != nil {
		t.Fatalf("read sidecar file: %v", readErr)
	}
	if string(sidecarBytes) != "digest\n" {
		t.Fatalf("sidecar file = %q, want digest", string(sidecarBytes))
	}
}

func TestWriteOutputPairWithRollbackUsesCommandNameInDiagnostics(t *testing.T) {
	for _, commandName := range []string{"compile", "approval attach", "future export"} {
		t.Run(commandName+"/main", func(t *testing.T) {
			outPath, sidecarPath := outputSidecarTestPaths(t)
			makeTestDirectory(t, outPath)

			err := writeOutputPairWithRollback(commandName, outPath, []byte("artifact body\n"), sidecarPath, []byte("digest\n"))

			if err == nil {
				t.Fatalf("write output with sidecar returned nil error")
			}
			if got := outputPairErrorStage(err); got != outputPairStageMain {
				t.Fatalf("error stage = %q, want %q", got, outputPairStageMain)
			}
			want := commandName + " --out points to a directory"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})

		t.Run(commandName+"/sidecar", func(t *testing.T) {
			outPath, sidecarPath := outputSidecarTestPaths(t)
			makeTestDirectory(t, sidecarPath)

			err := writeOutputPairWithRollback(commandName, outPath, []byte("artifact body\n"), sidecarPath, []byte("digest\n"))

			if err == nil {
				t.Fatalf("write output with sidecar returned nil error")
			}
			if got := outputPairErrorStage(err); got != outputPairStageSidecar {
				t.Fatalf("error stage = %q, want %q", got, outputPairStageSidecar)
			}
			want := commandName + " --out points to a directory"
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
}

func TestWriteOutputPairWithRollbackDoesNotWriteSidecarWhenOutputWriteFails(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	makeTestDirectory(t, outPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("artifact body\n"), sidecarPath, []byte("digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want output write diagnostic", err)
	}
	if got := outputPairErrorStage(err); got != outputPairStageMain {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageMain)
	}
	if _, statErr := os.Stat(sidecarPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("sidecar file stat error = %v, want not created", statErr)
	}
}

func TestWriteOutputPairWithRollbackReportsSidecarErrorStage(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	makeTestDirectory(t, sidecarPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("artifact body\n"), sidecarPath, []byte("digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want sidecar write diagnostic", err)
	}
	if got := outputPairErrorStage(err); got != outputPairStageSidecar {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageSidecar)
	}
}

func TestWriteOutputPairWithRollbackPreservesExistingSidecarWhenOutputWriteFails(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	previousSidecar := []byte("previous digest\n")
	makeTestDirectory(t, outPath)
	writeTestFileBytes(t, sidecarPath, previousSidecar, 0o600)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("artifact body\n"), sidecarPath, []byte("new digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want output write diagnostic", err)
	}
	if got := outputPairErrorStage(err); got != outputPairStageMain {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageMain)
	}
	bytes, readErr := os.ReadFile(sidecarPath)
	if readErr != nil {
		t.Fatalf("read sidecar file: %v", readErr)
	}
	if string(bytes) != string(previousSidecar) {
		t.Fatalf("sidecar file = %q, want previous %q", string(bytes), string(previousSidecar))
	}
}

func TestWriteOutputPairWithRollbackPreservesExistingSidecarArtifactWhenSidecarWriteFails(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	previousOutput := []byte("previous artifact\n")
	writeTestFileBytes(t, outPath, previousOutput, 0o600)
	makeTestDirectory(t, sidecarPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("new artifact\n"), sidecarPath, []byte("new digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want sidecar write diagnostic", err)
	}
	if got := outputPairErrorStage(err); got != outputPairStageSidecar {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageSidecar)
	}
	bytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read restored output: %v", readErr)
	}
	if string(bytes) != string(previousOutput) {
		t.Fatalf("output file = %q, want previous %q", string(bytes), string(previousOutput))
	}
	info, statErr := os.Stat(sidecarPath)
	if statErr != nil {
		t.Fatalf("stat sidecar artifact: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("sidecar artifact is directory = false, want true")
	}
}

func TestWriteOutputPairWithRollbackReportsRollbackFailure(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	writeTestFileBytes(t, outPath, []byte("previous artifact\n"), 0o600)
	makeTestDirectory(t, sidecarPath)
	overrideRollbackOutputFileForWriteForTest(t, func(string, outputFileSnapshot) error {
		return errors.New("restore failed")
	})

	err := writeOutputPairWithRollback("helper command", outPath, []byte("new artifact\n"), sidecarPath, []byte("digest\n"))

	if err == nil {
		t.Fatalf("write output with sidecar returned nil error")
	}
	if got := outputPairErrorStage(err); got != outputPairStageSidecar {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageSidecar)
	}
	for _, want := range []string{
		"helper command --out points to a directory",
		"rollback output: restore failed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %v, want %q", err, want)
		}
	}
}

func TestRollbackOutputFileReportsRestoreErrors(t *testing.T) {
	err := rollbackOutputFile(filepath.Join(t.TempDir(), "artifact\x00.json"), outputFileSnapshot{
		Exists: true,
		Bytes:  []byte("previous artifact\n"),
		Mode:   0o600,
	})

	if err == nil || !strings.Contains(err.Error(), "restore output") {
		t.Fatalf("err = %v, want restore output diagnostic", err)
	}
}

func TestRollbackOutputFileReportsRemoveErrors(t *testing.T) {
	err := rollbackOutputFile(filepath.Join(t.TempDir(), "artifact\x00.json"), outputFileSnapshot{})

	if err == nil || !strings.Contains(err.Error(), "remove output") {
		t.Fatalf("err = %v, want remove output diagnostic", err)
	}
}

func TestOutputPairErrorStageDefaultsPlainErrorsToMain(t *testing.T) {
	err := errors.New("plain write failure")

	if got := outputPairErrorStage(err); got != outputPairStageMain {
		t.Fatalf("error stage = %q, want %q", got, outputPairStageMain)
	}
}

func TestWriteOutputPairWithRollbackRemovesNewOutputOnSidecarFailure(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	makeTestDirectory(t, sidecarPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("new artifact\n"), sidecarPath, []byte("digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want sidecar write diagnostic", err)
	}
	if _, statErr := os.Stat(outPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output file stat error = %v, want removed", statErr)
	}
}

func TestWriteOutputPairWithRollbackRestoresExistingOutputContentOnSidecarFailure(t *testing.T) {
	outPath, sidecarPath := outputSidecarTestPaths(t)
	previous := []byte("previous artifact\n")
	writeTestFileBytes(t, outPath, previous, 0o600)
	makeTestDirectory(t, sidecarPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("new artifact\n"), sidecarPath, []byte("digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want sidecar write diagnostic", err)
	}
	bytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read restored output: %v", readErr)
	}
	if string(bytes) != string(previous) {
		t.Fatalf("output file = %q, want previous %q", string(bytes), string(previous))
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, statErr := os.Stat(outPath)
	if statErr != nil {
		t.Fatalf("stat restored output: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("restored mode = %v, want 0600", got)
	}
}

func TestWriteOutputPairWithRollbackPreservesExistingOutputModeOnSidecarFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bit restoration policy is not portable on Windows")
	}
	outPath, sidecarPath := outputSidecarTestPaths(t)
	previous := []byte("previous artifact\n")
	writeTestFileBytes(t, outPath, previous, 0o600)
	if err := os.Chmod(outPath, 0o640); err != nil {
		t.Fatalf("chmod previous output: %v", err)
	}
	makeTestDirectory(t, sidecarPath)

	err := writeOutputPairWithRollback("helper command", outPath, []byte("new artifact\n"), sidecarPath, []byte("digest\n"))

	if err == nil || !strings.Contains(err.Error(), "helper command --out points to a directory") {
		t.Fatalf("err = %v, want sidecar write diagnostic", err)
	}
	bytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read restored output: %v", readErr)
	}
	if string(bytes) != string(previous) {
		t.Fatalf("output file = %q, want previous %q", string(bytes), string(previous))
	}
	info, statErr := os.Stat(outPath)
	if statErr != nil {
		t.Fatalf("stat restored output: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("restored mode = %v, want 0640", got)
	}
}

func TestSnapshotOutputFileReportsInspectionErrors(t *testing.T) {
	_, err := snapshotOutputFile(filepath.Join(t.TempDir(), "artifact\x00.json"))

	if err == nil {
		t.Fatalf("snapshotOutputFile returned nil error for invalid path")
	}
}

func TestSnapshotOutputFileReportsReadErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-denial semantics are not portable on Windows")
	}
	outPath := filepath.Join(t.TempDir(), "artifact.json")
	if err := os.WriteFile(outPath, []byte("previous artifact\n"), 0o600); err != nil {
		t.Fatalf("write output: %v", err)
	}
	if err := os.Chmod(outPath, 0o000); err != nil {
		t.Fatalf("chmod output unreadable: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(outPath, 0o600)
	})

	_, err := snapshotOutputFile(outPath)

	if err == nil {
		t.Skip("filesystem permitted read despite removed file permissions")
	}
}

func TestVersionCommandPrintsMetadata(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"version=", "commit=", "date=", "go_version=", "os=", "arch="} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestVersionCommandPrintsJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "version", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Date          string `json:"date"`
		GoVersion     string `json:"go_version"`
		OS            string `json:"os"`
		Arch          string `json:"arch"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode version json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.VersionResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.VersionResultSchemaID)
	}
	if decoded.Version == "" || decoded.Commit == "" || decoded.Date == "" || decoded.GoVersion == "" || decoded.OS == "" || decoded.Arch == "" {
		t.Fatalf("decoded version = %+v, want all fields", decoded)
	}
	if err := schema.ValidateBytes(schema.VersionResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("version result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaBackedJSONOutputsUseValidatedWriter(t *testing.T) {
	sourceBytes, err := os.ReadFile("cli.go")
	if err != nil {
		t.Fatalf("read cli.go: %v", err)
	}
	source := string(sourceBytes)
	tests := []struct {
		name     string
		function string
		call     string
		minCount int
	}{
		{"version json", "runVersion", "writeSchemaJSON(stdout, schema.VersionResultSchemaID, info)", 1},
		{"compile result json", "runCompile", "writeSchemaJSON(stdout, schema.CompileResultSchemaID, jsonResult)", 1},
		{"compile summary json", "runCompile", "writeSchemaJSON(stdout, schema.CompileSummarySchemaID, compileSummary)", 1},
		{"lint result json", "runLint", "writeSchemaJSON(stdout, schema.LintResultSchemaID, result)", 1},
		{"verify result json", "printVerifyResult", "writeSchemaJSON(stdout, schema.VerifyResultSchemaID, result)", 1},
		{"release package json", "runReleasePackage", "writeSchemaJSON(stdout, schema.ReleasePackageResultSchemaID, jsonResult)", 1},
		{"release verify json", "runReleaseVerify", "writeSchemaJSON(stdout, schema.ReleaseVerifyResultSchemaID, jsonResult)", 1},
		{"release inspect json", "runReleaseInspect", "writeSchemaJSON(stdout, schema.ReleaseInspectResultSchemaID, result)", 1},
		{"bundle inspect json", "runBundleInspect", "writeSchemaJSON(stdout, schema.BundleInspectResultSchemaID, result)", 1},
		{"bundle report json", "runBundleReport", "writeSchemaJSON(stdout, schema.BundleReportResultSchemaID, result)", 1},
		{"bundle keygen json", "runBundleKeygen", "writeSchemaJSON(stdout, schema.BundleKeygenResultSchemaID, jsonResult)", 1},
		{"schema catalog json", "runSchemaCatalog", "writeSchemaJSON(stdout, schema.SchemaCatalogResultSchemaID, report)", 1},
		{"schema export json", "runSchemaExport", "writeSchemaJSON(stdout, schema.SchemaExportResultSchemaID, report)", 1},
		{"schema validate aggregate json", "runSchemaValidate", "writeSchemaValidationJSON(stdout, selectedOutPath, report)", 1},
		{"schema validate single json", "printSingleSchemaValidationReport", "writeSchemaValidationJSON(stdout, outPath, report)", 1},
		{"policy explain json", "runPolicyExplain", "writeSchemaJSON(stdout, schema.PolicyExplainResultSchemaID, report)", 1},
		{"policy index json", "runPolicyIndex", "writeSchemaJSON(stdout, schema.PolicyIndexResultSchemaID, report)", 1},
		{"policy spine json", "runPolicySpine", "writeSchemaJSON(stdout, schema.PolicySpineResultSchemaID, report)", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := cliFunctionBody(t, source, tt.function)
			if count := strings.Count(body, tt.call); count < tt.minCount {
				t.Fatalf("%s is not written through validated schema writer; found %d calls to %q, want at least %d", tt.function, count, tt.call, tt.minCount)
			}
		})
	}
}

func cliFunctionBody(t *testing.T, source string, name string) string {
	t.Helper()
	start := strings.Index(source, "func "+name+"(")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	openOffset := strings.Index(source[start:], "{")
	if openOffset < 0 {
		t.Fatalf("function %s body not found", name)
	}
	open := start + openOffset
	depth := 0
	for i := open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open : i+1]
			}
		}
	}
	t.Fatalf("function %s body did not close", name)
	return ""
}

func requireFailedOutputPathCommand(t *testing.T, code int, stdout *bytes.Buffer, stderr *bytes.Buffer, wantDiagnostic string) {
	t.Helper()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), wantDiagnostic) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), wantDiagnostic)
	}
}

func requirePathNotCreated(t *testing.T, path string, description string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s exists at %s, want not created", description, path)
	}
}

func requireFileContent(t *testing.T, path string, want string) {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(bytes) != want {
		t.Fatalf("%s = %q, want %q", path, string(bytes), want)
	}
}

func requireDirectoryTarget(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output directory stat: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("output path is directory = false, want true")
	}
}

func TestSchemaCatalogCommandPrintsText(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "catalog"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=covenant.contract.v1.schema.json path=schemas/covenant.contract.v1.schema.json",
		"schema=covenant.evidence-pack.v1 file=covenant.evidence-pack.v1.schema.json path=schemas/covenant.evidence-pack.v1.schema.json",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaCatalogCommandPrintsJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "catalog", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Schemas       []struct {
			ID         string `json:"id"`
			FileName   string `json:"file_name"`
			SchemaPath string `json:"schema_path"`
		} `json:"schemas"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema catalog json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.SchemaCatalogResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.SchemaCatalogResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.SchemaCatalogResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("schema catalog result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if len(decoded.Schemas) == 0 {
		t.Fatalf("decoded schemas empty")
	}
	first := decoded.Schemas[0]
	if first.ID != "covenant.contract.v1" || first.FileName != "covenant.contract.v1.schema.json" || first.SchemaPath != "schemas/covenant.contract.v1.schema.json" {
		t.Fatalf("first schema = %+v, want contract schema entry", first)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaExportCommandWritesSchemas(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "schemas")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "export", "--out", outDir}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	exportedPath := filepath.Join(outDir, "covenant.contract.v1.schema.json")
	bytes, err := os.ReadFile(exportedPath)
	if err != nil {
		t.Fatalf("read exported schema: %v", err)
	}
	var decoded struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode exported schema: %v", err)
	}
	if decoded.ID != "covenant.contract.v1" {
		t.Fatalf("exported schema id = %q, want covenant.contract.v1", decoded.ID)
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file=covenant.contract.v1.schema.json written="+filepath.ToSlash(exportedPath)) {
		t.Fatalf("stdout = %q, want exported schema line", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaExportCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "schemas")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "export", "--out", outDir, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Schemas       []struct {
			ID          string `json:"id"`
			FileName    string `json:"file_name"`
			SchemaPath  string `json:"schema_path"`
			WrittenPath string `json:"written_path"`
		} `json:"schemas"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema export json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.SchemaExportResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.SchemaExportResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.SchemaExportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("schema export result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if len(decoded.Schemas) == 0 {
		t.Fatalf("decoded schemas empty")
	}
	first := decoded.Schemas[0]
	if first.ID != "covenant.contract.v1" || first.FileName != "covenant.contract.v1.schema.json" || first.SchemaPath != "schemas/covenant.contract.v1.schema.json" {
		t.Fatalf("first schema = %+v, want contract schema entry", first)
	}
	if first.WrittenPath != filepath.ToSlash(filepath.Join(outDir, "covenant.contract.v1.schema.json")) {
		t.Fatalf("written_path = %q, want exported contract schema path", first.WrittenPath)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaExportCommandRequiresOutputDirectory(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "export"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--out is required") {
		t.Fatalf("stderr = %q, want --out requirement", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandAcceptsValidDocument(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file="+filepath.ToSlash(contractPath)+" valid=true") {
		t.Fatalf("stdout = %q, want valid schema line", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandAcceptsValidStdinDocument(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := RunWithInput([]string{"covenant", "schema", "validate", "--stdin"}, strings.NewReader(validCLIContractJSON()), &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file=- valid=true") {
		t.Fatalf("stdout = %q, want valid stdin schema line", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandRejectsInvalidDocument(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file="+filepath.ToSlash(contractPath)+" valid=false") {
		t.Fatalf("stdout = %q, want invalid schema line", stdout.String())
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func TestSchemaValidateCommandRejectsInvalidStdinDocumentJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := RunWithInput([]string{"covenant", "schema", "validate", "--stdin", "--json"}, strings.NewReader(`{"schema_version":"covenant.contract.v1"}`), &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want validation failure", code)
	}
	var decoded schemaValidationReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode validation report: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaID != "covenant.contract.v1" || decoded.File != "-" || decoded.Valid || decoded.Location != "/" {
		t.Fatalf("decoded report = %+v, want invalid stdin contract report", decoded)
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.contract.v1") || !strings.Contains(stderr.String(), "location=/") {
		t.Fatalf("stderr = %q, want validation diagnostic", stderr.String())
	}
}

func TestSchemaValidateCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaID string `json:"schema_id"`
		File     string `json:"file"`
		Valid    bool   `json:"valid"`
		Error    string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode validation json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaID != "covenant.contract.v1" || decoded.File != filepath.ToSlash(contractPath) || !decoded.Valid || decoded.Error != "" {
		t.Fatalf("decoded report = %+v, want valid contract report", decoded)
	}
	requireSchemaValidationReportSchema(t, stdout.Bytes())
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func requireSchemaValidationReportSchema(t *testing.T, data []byte) {
	t.Helper()
	if err := schema.ValidateBytes(schema.SchemaValidationReportSchemaID, data); err != nil {
		t.Fatalf("schema validation report did not match published schema: %v\njson:\n%s", err, string(data))
	}
}

func TestSchemaValidateCommandFileJSONIncludesReportMetadata(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode validation json: %v; stdout = %q", err, stdout.String())
	}
	want := &schemaValidationReportMetadata{
		Command:          "schema validate",
		InputMode:        "file",
		Source:           contractPath,
		ExplicitSchemaID: "covenant.contract.v1",
	}
	if !reflect.DeepEqual(decoded.Metadata, want) {
		t.Fatalf("metadata = %+v, want %+v", decoded.Metadata, want)
	}
	requireSchemaValidationReportSchema(t, stdout.Bytes())
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandJSONWritesOutputFile(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	outPath := filepath.Join(dir, "validation.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json", "--out", outPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "schema_validation_report="+outPath {
		t.Fatalf("stdout = %q, want output file path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read validation output: %v", err)
	}
	var decoded schemaValidationReport
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode validation output: %v; bytes = %q", err, string(bytes))
	}
	if decoded.SchemaID != "covenant.contract.v1" || decoded.File != filepath.ToSlash(contractPath) || !decoded.Valid {
		t.Fatalf("decoded report = %+v, want valid contract report", decoded)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandJSONRejectsOutputFileWithMissingParent(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	outPath := filepath.Join(dir, "missing", "validation.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json", "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "schema validate --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "output file")
}

func TestSchemaValidateCommandJSONRejectsOutputFileWithParentFile(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	parentFile := filepath.Join(dir, "reports")
	outPath := filepath.Join(parentFile, "validation.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json", "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "schema validate --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
}

func TestSchemaValidateCommandJSONRejectsOutputFileDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	outPath := t.TempDir()
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json", "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "schema validate --out points to a directory")
	requireDirectoryTarget(t, outPath)
}

func TestSchemaValidateCommandJSONIncludesLocation(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schemaValidationReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode validation report: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Location != "/" {
		t.Fatalf("location = %q, want root pointer", decoded.Location)
	}
	if !strings.Contains(stderr.String(), "location=/") {
		t.Fatalf("stderr = %q, want location", stderr.String())
	}
}

func TestSchemaValidateCommandPrintsSARIF(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath, "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation sarif: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("sarif = %+v, want one SARIF result", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if result.RuleID != "SCHEMA_VALIDATION_FAILED" || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != filepath.ToSlash(contractPath) {
		t.Fatalf("result = %+v, want schema validation failure for %s", result, contractPath)
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryPrintsSARIF(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("sarif = %+v, want one result for invalid file only", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "invalid-contract.json" {
		t.Fatalf("result location = %+v, want relative invalid path", result.Locations)
	}
	if strings.Contains(stdout.String(), validPath) {
		t.Fatalf("stdout = %q, want valid file omitted from SARIF results", stdout.String())
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectorySARIFWritesOutputFile(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	outPath := filepath.Join(dir, "validation.sarif")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--sarif", "--out", outPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want validation failure", code)
	}
	if strings.TrimSpace(stdout.String()) != "schema_validation_report="+outPath {
		t.Fatalf("stdout = %q, want output file path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read SARIF output: %v", err)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode SARIF output: %v; bytes = %q", err, string(bytes))
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("sarif = %+v, want one invalid result", decoded)
	}
	if decoded.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "invalid-contract.json" {
		t.Fatalf("result = %+v, want relative invalid path", decoded.Runs[0].Results[0])
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want validation diagnostic", stderr.String())
	}
}

func TestSchemaValidateCommandDirectorySARIFReportsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	invalidPath := filepath.Join(nestedDir, "invalid-contract.json")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation sarif: %v; stdout = %q", err, stdout.String())
	}
	uri := decoded.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "nested/invalid-contract.json" {
		t.Fatalf("uri = %q, want relative file path", uri)
	}
	if strings.Contains(stdout.String(), invalidPath) {
		t.Fatalf("stdout = %q, want no absolute file path", stdout.String())
	}
	if !strings.Contains(stderr.String(), "nested/invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want relative invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandSARIFBaselineSuppressesAcceptedFailures(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "SCHEMA_VALIDATION_FAILED",
      "source_uri": "`+filepath.ToSlash(contractPath)+`",
      "justification": "accepted generated fixture drift"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--sarif", "--sarif-baseline", baselinePath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want accepted baseline success; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("decoded sarif = %+v, want one result", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if result.RuleID != "SCHEMA_VALIDATION_FAILED" || len(result.Suppressions) != 1 {
		t.Fatalf("sarif result = %+v, want schema suppression", result)
	}
	if result.Suppressions[0].Kind != "external" || result.Suppressions[0].Justification != "accepted generated fixture drift" {
		t.Fatalf("suppression = %+v, want external justification", result.Suppressions[0])
	}
}

func TestSchemaValidateCommandDirectorySARIFBaselineKeepsUnacceptedFailureFailing(t *testing.T) {
	dir := t.TempDir()
	acceptedPath := filepath.Join(dir, "accepted-contract.json")
	unacceptedPath := filepath.Join(dir, "unaccepted-contract.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	for _, path := range []string{acceptedPath, unacceptedPath} {
		if err := os.WriteFile(path, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
			t.Fatalf("write invalid contract %s: %v", path, err)
		}
	}
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "SCHEMA_VALIDATION_FAILED",
      "source_uri": "accepted-contract.json",
      "justification": "accepted generated fixture drift"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--sarif", "--sarif-baseline", baselinePath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want unaccepted failure; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				Suppressions []struct {
					Kind string `json:"kind"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 2 {
		t.Fatalf("decoded sarif = %+v, want two results", decoded)
	}
	suppressed := 0
	for _, result := range decoded.Runs[0].Results {
		if len(result.Suppressions) == 1 {
			suppressed++
		}
	}
	if suppressed != 1 {
		t.Fatalf("suppressed results = %d, want one", suppressed)
	}
}

func TestSchemaValidateCommandDirectoryFailFastSARIFStopsAfterFirstInvalid(t *testing.T) {
	dir := t.TempDir()
	firstInvalidPath := filepath.Join(dir, "01-invalid-contract.json")
	secondInvalidPath := filepath.Join(dir, "02-invalid-contract.json")
	if err := os.WriteFile(firstInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write first invalid contract: %v", err)
	}
	if err := os.WriteFile(secondInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write second invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--fail-fast", "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation sarif: %v; stdout = %q", err, stdout.String())
	}
	results := decoded.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("results = %+v, want one first invalid result", results)
	}
	if results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "01-invalid-contract.json" {
		t.Fatalf("result = %+v, want first invalid file", results[0])
	}
	if strings.Contains(stdout.String(), "02-invalid-contract.json") {
		t.Fatalf("stdout = %q, want no second invalid result", stdout.String())
	}
	if !strings.Contains(stderr.String(), "01-invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want first invalid file error", stderr.String())
	}
	if strings.Contains(stderr.String(), "02-invalid-contract.json") {
		t.Fatalf("stderr = %q, want no second invalid output", stderr.String())
	}
}

func TestSchemaValidateCommandSARIFIncludesLocation(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	document := validCLIContractMap()
	tasks := document["tasks"].([]any)
	task := tasks[0].(map[string]any)
	task["timeout_seconds"] = "slow"
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal invalid contract: %v", err)
	}
	if err := os.WriteFile(contractPath, documentBytes, 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation sarif: %v; stdout = %q", err, stdout.String())
	}
	if got := decoded.Runs[0].Results[0].Properties.Location; got != "/tasks/0/timeout_seconds" {
		t.Fatalf("location = %q, want nested pointer", got)
	}
}

func TestSchemaValidateCommandPrintsJUnit(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--schema", "covenant.contract.v1", "--file", contractPath, "--junit"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.JUnitTestSuites
	if err := xml.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation junit: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Tests != 1 || decoded.Failures != 1 || len(decoded.TestSuites) != 1 {
		t.Fatalf("junit = %+v, want one failing test suite", decoded)
	}
	testCase := decoded.TestSuites[0].TestCases[0]
	if testCase.ClassName != "covenant.contract.v1" || testCase.Name != filepath.ToSlash(contractPath) || testCase.Failure == nil {
		t.Fatalf("test case = %+v, want failed contract validation test", testCase)
	}
	if !strings.Contains(testCase.Failure.Text, "schema validation failed for covenant.contract.v1") {
		t.Fatalf("failure = %+v, want validation error", testCase.Failure)
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryPrintsJUnit(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--junit"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.JUnitTestSuites
	if err := xml.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation junit: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Tests != 2 || decoded.Failures != 1 || len(decoded.TestSuites) != 1 {
		t.Fatalf("junit = %+v, want two tests and one failure", decoded)
	}
	cases := decoded.TestSuites[0].TestCases
	if len(cases) != 2 {
		t.Fatalf("test cases = %+v, want two cases", cases)
	}
	if cases[0].Name != "invalid-contract.json" || cases[0].Failure == nil {
		t.Fatalf("first case = %+v, want invalid file failure", cases[0])
	}
	if cases[1].Name != "valid-contract.json" || cases[1].Failure != nil {
		t.Fatalf("second case = %+v, want valid file without failure", cases[1])
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJUnitWritesOutputFile(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	outPath := filepath.Join(dir, "validation.xml")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--junit", "--out", outPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want validation failure", code)
	}
	if strings.TrimSpace(stdout.String()) != "schema_validation_report="+outPath {
		t.Fatalf("stdout = %q, want output file path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read JUnit output: %v", err)
	}
	var decoded schema.JUnitTestSuites
	if err := xml.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode JUnit output: %v; bytes = %q", err, string(bytes))
	}
	if decoded.Tests != 1 || decoded.Failures != 1 || decoded.TestSuites[0].TestCases[0].Name != "invalid-contract.json" {
		t.Fatalf("junit = %+v, want one relative invalid test case", decoded)
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want validation diagnostic", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJUnitReportsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	invalidPath := filepath.Join(nestedDir, "invalid-contract.json")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--junit"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.JUnitTestSuites
	if err := xml.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation junit: %v; stdout = %q", err, stdout.String())
	}
	if decoded.TestSuites[0].TestCases[0].Name != "nested/invalid-contract.json" {
		t.Fatalf("test case = %+v, want relative file path", decoded.TestSuites[0].TestCases[0])
	}
	if strings.Contains(stdout.String(), invalidPath) {
		t.Fatalf("stdout = %q, want no absolute file path", stdout.String())
	}
	if !strings.Contains(stderr.String(), "nested/invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want relative invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryFailFastJUnitStopsAfterFirstInvalid(t *testing.T) {
	dir := t.TempDir()
	firstInvalidPath := filepath.Join(dir, "01-invalid-contract.json")
	secondInvalidPath := filepath.Join(dir, "02-invalid-contract.json")
	if err := os.WriteFile(firstInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write first invalid contract: %v", err)
	}
	if err := os.WriteFile(secondInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write second invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--fail-fast", "--junit"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schema.JUnitTestSuites
	if err := xml.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation junit: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Tests != 1 || decoded.Failures != 1 || len(decoded.TestSuites[0].TestCases) != 1 {
		t.Fatalf("junit = %+v, want one first invalid test case", decoded)
	}
	if decoded.TestSuites[0].TestCases[0].Name != "01-invalid-contract.json" {
		t.Fatalf("test case = %+v, want first invalid file", decoded.TestSuites[0].TestCases[0])
	}
	if strings.Contains(stdout.String(), "02-invalid-contract.json") {
		t.Fatalf("stdout = %q, want no second invalid test case", stdout.String())
	}
	if !strings.Contains(stderr.String(), "01-invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want first invalid file error", stderr.String())
	}
	if strings.Contains(stderr.String(), "02-invalid-contract.json") {
		t.Fatalf("stderr = %q, want no second invalid output", stderr.String())
	}
}

func TestSchemaValidateCommandRejectsSchemaFilterWithExplicitSchema(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--schema", "covenant.contract.v1", "--schema-filter", "covenant.contract.v1"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "--schema-filter cannot be combined with --schema") {
		t.Fatalf("stderr = %q, want schema-filter conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsUnknownSchemaFilter(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--schema-filter", "covenant.unknown.v1"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), `unknown schema filter "covenant.unknown.v1"`) {
		t.Fatalf("stderr = %q, want unknown filter diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandSchemaFilterFailsWhenNothingMatches(t *testing.T) {
	dir := t.TempDir()
	taskPath := filepath.Join(dir, "task.json")
	if err := os.WriteFile(taskPath, []byte(`{"schema_version":"covenant.task.v1"}`), 0o644); err != nil {
		t.Fatalf("write task: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--schema-filter", "covenant.contract.v1", "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want no-match failure", code)
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation set: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Total != 0 || decoded.SkippedCount != 1 || len(decoded.Validations) != 0 {
		t.Fatalf("decoded = %+v, want only skipped document", decoded)
	}
	if !strings.Contains(stderr.String(), "no schema documents matched --schema-filter") {
		t.Fatalf("stderr = %q, want no-match diagnostic", stderr.String())
	}
}

func TestSchemaValidateCommandRejectsMultipleStructuredFormats(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	for _, args := range [][]string{
		{"covenant", "schema", "validate", "--file", contractPath, "--json", "--junit"},
		{"covenant", "schema", "validate", "--file", contractPath, "--sarif", "--junit"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run(args, &stdout, &stderr)

		if code != 2 {
			t.Fatalf("args %v exit code = %d, want 2", args, code)
		}
		if !strings.Contains(stderr.String(), "--json, --sarif, and --junit are mutually exclusive") {
			t.Fatalf("args %v stderr = %q, want format conflict", args, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("args %v stdout = %q, want empty", args, stdout.String())
		}
	}
}

func TestSchemaValidateCommandRejectsJSONAndSARIF(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--json", "--sarif"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--json, --sarif, and --junit are mutually exclusive") {
		t.Fatalf("stderr = %q, want format conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsSARIFBaselineWithoutSARIF(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte(`{"schema_version":"covenant.lint-sarif-baseline.v1","accepted":[]}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--sarif-baseline", baselinePath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "--sarif-baseline requires --sarif") {
		t.Fatalf("stderr = %q, want sarif baseline diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsInvalidSARIFBaseline(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("{"), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--sarif", "--sarif-baseline", baselinePath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want baseline read failure", code)
	}
	if !strings.Contains(stderr.String(), "read sarif baseline") {
		t.Fatalf("stderr = %q, want read sarif baseline diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandInfersSchemaFromDocument(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file="+filepath.ToSlash(contractPath)+" valid=true") {
		t.Fatalf("stdout = %q, want inferred valid schema line", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandReportsInferenceError(t *testing.T) {
	dir := t.TempDir()
	documentPath := filepath.Join(dir, "document.json")
	if err := os.WriteFile(documentPath, []byte(`{"id":"contract_demo"}`), 0o644); err != nil {
		t.Fatalf("write document: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", documentPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "infer schema: schema_version is required when --schema is omitted") {
		t.Fatalf("stderr = %q, want inference error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandValidatesDirectory(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	revocationPath := filepath.Join(nestedDir, "revocations.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	writeRevocationList(t, revocationPath, "approval-demo")
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write ignored text file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=contract.json valid=true",
		"schema=covenant.approval-revocations.v1 file=nested/revocations.json valid=true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if strings.Contains(output, "notes.txt") {
		t.Fatalf("stdout = %q, want non-JSON files ignored", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryIgnoresPathPrefixes(t *testing.T) {
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, "generated")
	vendorNestedDir := filepath.Join(dir, "vendor", "nested")
	for _, path := range []string{generatedDir, vendorNestedDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create directory %s: %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write generated invalid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendorNestedDir, "invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write vendor invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", "generated", "--ignore", "vendor"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=contract.json valid=true",
		"ignored=generated/invalid-contract.json pattern=generated",
		"ignored=vendor/nested/invalid-contract.json pattern=vendor",
		"valid=true total=1 valid_count=1 invalid_count=0 ignored_count=2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryIgnorePrintsIgnoredText(t *testing.T) {
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, "generated")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		t.Fatalf("create generated dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write generated invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", "generated"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=contract.json valid=true",
		"ignored=generated/invalid-contract.json pattern=generated",
		"valid=true total=1 valid_count=1 invalid_count=0 ignored_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryIgnoreAppliesBeforeFailFast(t *testing.T) {
	dir := t.TempDir()
	ignoredDir := filepath.Join(dir, "01-generated")
	if err := os.MkdirAll(ignoredDir, 0o755); err != nil {
		t.Fatalf("create ignored dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ignoredDir, "invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write ignored invalid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02-valid-contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", "01-generated", "--fail-fast", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	if !decoded.Valid || decoded.Total != 1 || decoded.ValidCount != 1 || decoded.InvalidCount != 0 {
		t.Fatalf("summary = valid:%t total:%d valid_count:%d invalid_count:%d, want true/1/1/0", decoded.Valid, decoded.Total, decoded.ValidCount, decoded.InvalidCount)
	}
	if len(decoded.Validations) != 1 || decoded.Validations[0].File != "02-valid-contract.json" || !decoded.Validations[0].Valid {
		t.Fatalf("validations = %+v, want only unignored valid contract", decoded.Validations)
	}
	wantIgnored := []schemaValidationIgnoredDocument{{File: "01-generated/invalid-contract.json", Pattern: "01-generated"}}
	if decoded.IgnoredCount != 1 || !reflect.DeepEqual(decoded.Ignored, wantIgnored) {
		t.Fatalf("ignored_count=%d ignored=%+v, want %+v", decoded.IgnoredCount, decoded.Ignored, wantIgnored)
	}
	if strings.Contains(stderr.String(), "01-generated") {
		t.Fatalf("stderr = %q, want ignored failing path omitted from diagnostics", stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryIgnoreReportsIgnoredJSON(t *testing.T) {
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, "generated")
	vendorNestedDir := filepath.Join(dir, "vendor", "nested")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		t.Fatalf("create generated dir: %v", err)
	}
	if err := os.MkdirAll(vendorNestedDir, 0o755); err != nil {
		t.Fatalf("create vendor dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write generated invalid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendorNestedDir, "revocations.json"), []byte(`{"schema_version":"covenant.approval-revocations.v1"}`), 0o644); err != nil {
		t.Fatalf("write vendor revocations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendorNestedDir, "notes.txt"), []byte("not json"), 0o644); err != nil {
		t.Fatalf("write ignored non-json: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", "generated", "--ignore", "vendor", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	wantIgnored := []schemaValidationIgnoredDocument{
		{File: "generated/invalid-contract.json", Pattern: "generated"},
		{File: "vendor/nested/revocations.json", Pattern: "vendor"},
	}
	if decoded.IgnoredCount != len(wantIgnored) || !reflect.DeepEqual(decoded.Ignored, wantIgnored) {
		t.Fatalf("ignored_count=%d ignored=%+v, want %d %+v", decoded.IgnoredCount, decoded.Ignored, len(wantIgnored), wantIgnored)
	}
	if decoded.Total != 1 || decoded.ValidCount != 1 || decoded.InvalidCount != 0 || len(decoded.Validations) != 1 {
		t.Fatalf("decoded = %+v, want one validated document plus ignored report", decoded)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryFiltersByEmbeddedSchema(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	taskPath := filepath.Join(dir, "task.json")
	notePath := filepath.Join(dir, "note.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(taskPath, []byte(`{"schema_version":"covenant.task.v1"}`), 0o644); err != nil {
		t.Fatalf("write task: %v", err)
	}
	if err := os.WriteFile(notePath, []byte(`{"schema_version":"outside.v1","name":"ignored"}`), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--schema-filter", "covenant.contract.v1"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "schema=covenant.contract.v1 file=contract.json valid=true") {
		t.Fatalf("stdout = %q, want contract validation", output)
	}
	if strings.Contains(output, "task.json") || strings.Contains(output, "note.json") {
		t.Fatalf("stdout = %q, want non-matching schemas skipped", output)
	}
	if !strings.Contains(output, "valid=true total=1 valid_count=1 invalid_count=0 skipped_count=2") {
		t.Fatalf("stdout = %q, want skipped count summary", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandFilesFromSchemaFilterReportsSkippedCountJSON(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	taskPath := filepath.Join(dir, "task.json")
	manifestPath := filepath.Join(dir, "manifest.txt")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(taskPath, []byte(`{"schema_version":"covenant.task.v1"}`), 0o644); err != nil {
		t.Fatalf("write task: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("contract.json\ntask.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath, "--schema-filter", "covenant.contract.v1", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation set: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Total != 1 || decoded.ValidCount != 1 || decoded.InvalidCount != 0 || decoded.SkippedCount != 1 || len(decoded.Validations) != 1 {
		t.Fatalf("decoded = %+v, want one validated contract and one skipped task", decoded)
	}
	if decoded.Validations[0].File != "contract.json" || decoded.Validations[0].SchemaID != "covenant.contract.v1" {
		t.Fatalf("validation = %+v, want contract validation", decoded.Validations[0])
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJSONIncludesSchemaBreakdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "01-valid-contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02-invalid-contract.json"), []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	writeRevocationList(t, filepath.Join(dir, "03-revocations.json"), "approval-demo")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded struct {
		Schemas []schemaValidationSchemaSummary `json:"schemas"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	want := []schemaValidationSchemaSummary{
		{SchemaID: "covenant.approval-revocations.v1", Total: 1, ValidCount: 1},
		{SchemaID: "covenant.contract.v1", Total: 2, ValidCount: 1, InvalidCount: 1},
	}
	if !reflect.DeepEqual(decoded.Schemas, want) {
		t.Fatalf("schemas = %+v, want %+v", decoded.Schemas, want)
	}
}

func TestSchemaValidateCommandFilesFromSchemaFilterJSONIncludesSkippedBreakdown(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	taskPath := filepath.Join(dir, "task.json")
	notePath := filepath.Join(dir, "note.json")
	manifestPath := filepath.Join(dir, "manifest.txt")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(taskPath, []byte(`{"schema_version":"covenant.task.v1"}`), 0o644); err != nil {
		t.Fatalf("write task: %v", err)
	}
	if err := os.WriteFile(notePath, []byte(`{"schema_version":"outside.v1"}`), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("contract.json\ntask.json\nnote.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath, "--schema-filter", "covenant.contract.v1", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Schemas []schemaValidationSchemaSummary `json:"schemas"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode schema validation set: %v; stdout = %q", err, stdout.String())
	}
	want := []schemaValidationSchemaSummary{
		{SchemaID: "covenant.contract.v1", Total: 1, ValidCount: 1},
		{SchemaID: "covenant.task.v1", SkippedCount: 1},
		{SchemaID: "unknown", SkippedCount: 1},
	}
	if !reflect.DeepEqual(decoded.Schemas, want) {
		t.Fatalf("schemas = %+v, want %+v", decoded.Schemas, want)
	}
}

func TestSchemaValidateCommandValidatesFilesFromManifest(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	revocationPath := filepath.Join(nestedDir, "revocations.json")
	manifestPath := filepath.Join(dir, "schema-files.txt")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	writeRevocationList(t, revocationPath, "approval-demo")
	manifest := "valid-contract.json\n# comment\n\nnested/revocations.json\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=valid-contract.json valid=true",
		"schema=covenant.approval-revocations.v1 file=nested/revocations.json valid=true",
		"valid=true total=2 valid_count=2 invalid_count=0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if strings.Contains(output, manifestPath) || strings.Contains(output, dir) {
		t.Fatalf("stdout = %q, want manifest-relative display paths", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandFilesFromManifestReportsJSONFailures(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	validPath := filepath.Join(dir, "valid-contract.json")
	manifestPath := filepath.Join(dir, "schema-files.txt")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("invalid-contract.json\nvalid-contract.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want validation failure", code)
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode files-from validation json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Valid || decoded.Total != 2 || decoded.ValidCount != 1 || decoded.InvalidCount != 1 {
		t.Fatalf("summary = valid:%t total:%d valid_count:%d invalid_count:%d, want false/2/1/1", decoded.Valid, decoded.Total, decoded.ValidCount, decoded.InvalidCount)
	}
	if len(decoded.Validations) != 2 || decoded.Validations[0].File != "invalid-contract.json" || decoded.Validations[0].Valid || decoded.Validations[1].File != "valid-contract.json" || !decoded.Validations[1].Valid {
		t.Fatalf("validations = %+v, want manifest order invalid then valid reports", decoded.Validations)
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want manifest-scoped validation error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJSONReportsFailures(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded struct {
		Valid       bool `json:"valid"`
		Validations []struct {
			SchemaID string `json:"schema_id"`
			File     string `json:"file"`
			Valid    bool   `json:"valid"`
			Error    string `json:"error,omitempty"`
		} `json:"validations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Valid {
		t.Fatalf("decoded valid = true, want false")
	}
	if len(decoded.Validations) != 2 {
		t.Fatalf("validations = %+v, want two entries", decoded.Validations)
	}
	if decoded.Validations[0].File != "invalid-contract.json" || decoded.Validations[0].Valid || !strings.Contains(decoded.Validations[0].Error, "schema validation failed for covenant.contract.v1") {
		t.Fatalf("first validation = %+v, want invalid contract report", decoded.Validations[0])
	}
	if decoded.Validations[1].File != "valid-contract.json" || !decoded.Validations[1].Valid || decoded.Validations[1].Error != "" {
		t.Fatalf("second validation = %+v, want valid contract report", decoded.Validations[1])
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want file-scoped validation error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJSONIncludesReportMetadata(t *testing.T) {
	dir := t.TempDir()
	generatedDir := filepath.Join(dir, "generated")
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		t.Fatalf("create generated dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "task.json"), []byte(`{"schema_version":"covenant.task.v1"}`), 0o644); err != nil {
		t.Fatalf("write ignored task: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", "generated", "--schema-filter", "covenant.contract.v1", "--fail-fast", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	want := &schemaValidationReportMetadata{
		Command:        "schema validate",
		InputMode:      "dir",
		Source:         dir,
		SchemaFilters:  []string{"covenant.contract.v1"},
		IgnorePatterns: []string{"generated"},
		FailFast:       true,
	}
	if !reflect.DeepEqual(decoded.Metadata, want) {
		t.Fatalf("metadata = %+v, want %+v", decoded.Metadata, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryTextPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=invalid-contract.json valid=false",
		"schema=covenant.contract.v1 file=valid-contract.json valid=true",
		"valid=false total=2 valid_count=1 invalid_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryTextPrintsSchemaBreakdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "01-valid-contract.json"), []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	writeRevocationList(t, filepath.Join(dir, "02-revocations.json"), "approval-demo")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"schema_summary=covenant.approval-revocations.v1 total=1 valid_count=1 invalid_count=0",
		"schema_summary=covenant.contract.v1 total=1 valid_count=1 invalid_count=0",
		"valid=true total=2 valid_count=2 invalid_count=0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestSchemaValidateCommandDirectoryFailFastStopsAfterFirstInvalidText(t *testing.T) {
	dir := t.TempDir()
	firstInvalidPath := filepath.Join(dir, "01-invalid-contract.json")
	secondValidPath := filepath.Join(dir, "02-valid-contract.json")
	if err := os.WriteFile(firstInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write first invalid contract: %v", err)
	}
	if err := os.WriteFile(secondValidPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write second valid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--fail-fast"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	output := stdout.String()
	for _, want := range []string{
		"schema=covenant.contract.v1 file=01-invalid-contract.json valid=false",
		"valid=false total=1 valid_count=0 invalid_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if strings.Contains(output, "02-valid-contract.json") {
		t.Fatalf("stdout = %q, want validation to stop before second document", output)
	}
	if !strings.Contains(stderr.String(), "01-invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want first invalid file error", stderr.String())
	}
	if strings.Contains(stderr.String(), "02-valid-contract.json") {
		t.Fatalf("stderr = %q, want no second document output", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryTextIncludesLocation(t *testing.T) {
	dir := t.TempDir()
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file=invalid-contract.json valid=false location=/") {
		t.Fatalf("stdout = %q, want validation location", stdout.String())
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") || !strings.Contains(stderr.String(), "location=/") {
		t.Fatalf("stderr = %q, want location", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJSONIncludesSummaryCounts(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid-contract.json")
	invalidPath := filepath.Join(dir, "invalid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded struct {
		Valid        bool `json:"valid"`
		Total        int  `json:"total"`
		ValidCount   int  `json:"valid_count"`
		InvalidCount int  `json:"invalid_count"`
		Validations  []struct {
			File  string `json:"file"`
			Valid bool   `json:"valid"`
		} `json:"validations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Valid || decoded.Total != 2 || decoded.ValidCount != 1 || decoded.InvalidCount != 1 {
		t.Fatalf("summary = valid:%t total:%d valid_count:%d invalid_count:%d, want false/2/1/1", decoded.Valid, decoded.Total, decoded.ValidCount, decoded.InvalidCount)
	}
	if len(decoded.Validations) != 2 || decoded.Validations[0].File != "invalid-contract.json" || decoded.Validations[0].Valid || decoded.Validations[1].File != "valid-contract.json" || !decoded.Validations[1].Valid {
		t.Fatalf("validations = %+v, want stable invalid then valid reports", decoded.Validations)
	}
	if !strings.Contains(stderr.String(), "invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want invalid file error", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryFailFastJSONStopsAfterFirstInvalid(t *testing.T) {
	dir := t.TempDir()
	firstInvalidPath := filepath.Join(dir, "01-invalid-contract.json")
	secondInvalidPath := filepath.Join(dir, "02-invalid-contract.json")
	if err := os.WriteFile(firstInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write first invalid contract: %v", err)
	}
	if err := os.WriteFile(secondInvalidPath, []byte(`{"schema_version":"covenant.contract.v1"}`), 0o644); err != nil {
		t.Fatalf("write second invalid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--fail-fast", "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Valid || decoded.Total != 1 || decoded.ValidCount != 0 || decoded.InvalidCount != 1 {
		t.Fatalf("summary = valid:%t total:%d valid_count:%d invalid_count:%d, want false/1/0/1", decoded.Valid, decoded.Total, decoded.ValidCount, decoded.InvalidCount)
	}
	if len(decoded.Validations) != 1 || decoded.Validations[0].File != "01-invalid-contract.json" || decoded.Validations[0].Valid {
		t.Fatalf("validations = %+v, want only first invalid report", decoded.Validations)
	}
	if strings.Contains(stdout.String(), "02-invalid-contract.json") {
		t.Fatalf("stdout = %q, want no second invalid report", stdout.String())
	}
	if !strings.Contains(stderr.String(), "01-invalid-contract.json: schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want first invalid file error", stderr.String())
	}
	if strings.Contains(stderr.String(), "02-invalid-contract.json") {
		t.Fatalf("stderr = %q, want no second invalid output", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryReportsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	validPath := filepath.Join(nestedDir, "valid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "schema=covenant.contract.v1 file=nested/valid-contract.json valid=true") {
		t.Fatalf("stdout = %q, want relative file path", stdout.String())
	}
	if strings.Contains(stdout.String(), dir) {
		t.Fatalf("stdout = %q, want no absolute directory prefix", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandDirectoryJSONReportsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	validPath := filepath.Join(nestedDir, "valid-contract.json")
	if err := os.WriteFile(validPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write valid contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded schemaValidationSetReport
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode directory validation json: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Validations) != 1 || decoded.Validations[0].File != "nested/valid-contract.json" {
		t.Fatalf("validations = %+v, want relative file path", decoded.Validations)
	}
	if strings.Contains(stdout.String(), validPath) {
		t.Fatalf("stdout = %q, want no absolute file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSchemaValidateCommandRequiresExactlyOneInput(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(filePath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", filePath, "--dir", dir}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --file, --dir, --stdin, or --files-from") {
		t.Fatalf("stderr = %q, want exactly-one input error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRequiresInput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --file, --dir, --stdin, or --files-from") {
		t.Fatalf("stderr = %q, want exactly-one input error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsMultipleInputModesWithStdin(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := RunWithInput([]string{"covenant", "schema", "validate", "--stdin", "--file", contractPath}, strings.NewReader(validCLIContractJSON()), &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --file, --dir, --stdin, or --files-from") {
		t.Fatalf("stderr = %q, want input mode conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsMultipleInputModesWithFilesFrom(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	manifestPath := filepath.Join(dir, "schema-files.txt")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("contract.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--files-from", manifestPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --file, --dir, --stdin, or --files-from") {
		t.Fatalf("stderr = %q, want input mode conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsIgnoreWithoutDirectory(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--ignore", "generated"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "--ignore can only be used with --dir") {
		t.Fatalf("stderr = %q, want --ignore directory-only diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandRejectsUnsafeIgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	for _, pattern := range []string{"../outside", "nested\\generated", "/absolute"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"covenant", "schema", "validate", "--dir", dir, "--ignore", pattern}, &stdout, &stderr)

		if code != 2 {
			t.Fatalf("pattern %q exit code = %d, want usage error", pattern, code)
		}
		if !strings.Contains(stderr.String(), "invalid ignore pattern") || !strings.Contains(stderr.String(), strconv.Quote(pattern)) {
			t.Fatalf("pattern %q stderr = %q, want invalid ignore diagnostic", pattern, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("pattern %q stdout = %q, want empty", pattern, stdout.String())
		}
	}
}

func TestSchemaValidateCommandFilesFromRejectsPathEscapes(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "schema-files.txt")
	if err := os.WriteFile(manifestPath, []byte("../outside.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want manifest failure", code)
	}
	if !strings.Contains(stderr.String(), `invalid manifest entry on line 1: "../outside.json"`) {
		t.Fatalf("stderr = %q, want path escape diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandFilesFromRejectsBackslashPaths(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "schema-files.txt")
	if err := os.WriteFile(manifestPath, []byte("nested\\contract.json\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--files-from", manifestPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want manifest failure", code)
	}
	if !strings.Contains(stderr.String(), `invalid manifest entry on line 1: "nested\\contract.json"`) {
		t.Fatalf("stderr = %q, want backslash path diagnostic", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSchemaValidateCommandOutRequiresStructuredFormat(t *testing.T) {
	dir := t.TempDir()
	contractPath := filepath.Join(dir, "contract.json")
	outPath := filepath.Join(dir, "validation.txt")
	if err := os.WriteFile(contractPath, []byte(validCLIContractJSON()), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "validate", "--file", contractPath, "--out", outPath}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "--out requires --json, --sarif, or --junit") {
		t.Fatalf("stderr = %q, want --out structured format requirement", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("output file exists or stat error = %v, want no output file", err)
	}
}

func TestSchemaCommandRejectsUnknownSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "schema", "unknown"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown schema command "unknown"`) || !strings.Contains(stderr.String(), "usage: covenant schema <command>") {
		t.Fatalf("stderr = %q, want unknown schema command usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestCompileWritesContractAndDigest(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create demo-output/report.txt"), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("contract output missing: %v", err)
	}
	if _, err := os.Stat(outPath + ".sha256"); err != nil {
		t.Fatalf("digest output missing: %v", err)
	}
	if !strings.Contains(stdout.String(), "contract_digest=") {
		t.Fatalf("stdout = %q, want contract_digest", stdout.String())
	}
	contractBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var decoded struct {
		Workspace struct {
			Reads []string `json:"reads"`
		} `json:"workspace"`
	}
	if err := json.Unmarshal(contractBytes, &decoded); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if len(decoded.Workspace.Reads) != 1 || decoded.Workspace.Reads[0] != "brief.md" {
		t.Fatalf("workspace reads = %v, want brief.md", decoded.Workspace.Reads)
	}
}

func TestCompileCommandRejectsOutputFileWithMissingParent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := filepath.Join("missing", "contract.json")
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "compile --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "output file")
}

func TestCompileCommandRejectsOutputFileWithParentFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	parentFile := "contracts"
	outPath := filepath.Join(parentFile, "contract.json")
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "compile --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
	requirePathNotCreated(t, outPath+".sha256", "digest sidecar")
}

func TestCompileCommandRejectsOutputFileDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract-output"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	if err := os.Mkdir(outPath, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "compile --out points to a directory")
	requireDirectoryTarget(t, outPath)
}

func TestCompileCommandRemovesNewContractWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "write digest: compile --out points to a directory") {
		t.Fatalf("stderr = %q, want digest sidecar diagnostic", stderr.String())
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contract output stat error = %v, want removed after digest failure", err)
	}
	if info, err := os.Stat(outPath + ".sha256"); err != nil {
		t.Fatalf("digest sidecar path stat: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("digest sidecar path is directory = false, want true")
	}
}

func TestCompileCommandPreservesExistingContractWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	previousContract := []byte("previous contract bytes\n")
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	if err := os.WriteFile(outPath, previousContract, 0o644); err != nil {
		t.Fatalf("write previous contract: %v", err)
	}
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "write digest: compile --out points to a directory") {
		t.Fatalf("stderr = %q, want digest sidecar diagnostic", stderr.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read contract output: %v", err)
	}
	if string(bytes) != string(previousContract) {
		t.Fatalf("contract output = %q, want previous contents %q", string(bytes), string(previousContract))
	}
	if info, err := os.Stat(outPath + ".sha256"); err != nil {
		t.Fatalf("digest sidecar path stat: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("digest sidecar path is directory = false, want true")
	}
}

func TestCompileCommandReportsRollbackFailureWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	overrideRollbackOutputFileForWriteForTest(t, func(string, outputFileSnapshot) error {
		return errors.New("restore failed")
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "compile", "--brief", briefPath, "--out", outPath}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{
		"write digest: compile --out points to a directory",
		"rollback output: restore failed",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestCompileCommandAcceptsWriteFlags(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
		"--write", "reports/summary.txt",
		"--write", "reports/audit.txt",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	contractBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var decoded contract.Contract
	if err := json.Unmarshal(contractBytes, &decoded); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if len(decoded.Workspace.Writes) != 2 || decoded.Workspace.Writes[0] != "reports/summary.txt" || decoded.Workspace.Writes[1] != "reports/audit.txt" {
		t.Fatalf("workspace writes = %v, want authored reports", decoded.Workspace.Writes)
	}
	if len(decoded.Tasks[0].DeclaredSideEffects) != 2 {
		t.Fatalf("side effects len = %d, want 2", len(decoded.Tasks[0].DeclaredSideEffects))
	}
}

func TestCompileCommandPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
		"--write", "reports/summary.txt",
		"--summary",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"contract=contract.json",
		"contract_digest=",
		"read=brief.md",
		"write=reports/summary.txt",
		"task=scripted_change kind=scripted",
		"obligation=obl_requested_file required=true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestCompileCommandAcceptsStructuredTaskBrief(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte(structuredCompileBrief()), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
		"--summary",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"task=draft_release_report kind=scripted",
		"task=verify_release_report kind=verify",
		"write=reports/release.md",
		"obligation=obl_release_report required=true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	contractBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var decoded contract.Contract
	if err := json.Unmarshal(contractBytes, &decoded); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if len(decoded.Tasks) != 2 || decoded.Tasks[0].ID != "draft_release_report" || decoded.Tasks[1].ID != "verify_release_report" {
		t.Fatalf("tasks = %+v, want authored task ids", decoded.Tasks)
	}
	if len(decoded.Workspace.Writes) != 1 || decoded.Workspace.Writes[0] != "reports/release.md" {
		t.Fatalf("workspace writes = %v, want structured write", decoded.Workspace.Writes)
	}
}

func TestCompileCommandPrintsStructuredDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	brief := `# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	output := stderr.String()
	for _, want := range []string{
		"compile brief: STRUCTURED_TASK_FIELD_UNKNOWN line 8",
		`unsupported task field "writess"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stderr = %q, want %s", output, want)
		}
	}
}

func TestCompileCommandPrintsSummaryJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
		"--write", "reports/summary.txt",
		"--summary-json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion  string   `json:"schema_version"`
		Contract       string   `json:"contract"`
		ContractDigest string   `json:"contract_digest"`
		Reads          []string `json:"reads"`
		Writes         []string `json:"writes"`
		Tasks          []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"tasks"`
		Obligations []struct {
			ID       string `json:"id"`
			Required bool   `json:"required"`
		} `json:"obligations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode summary json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.CompileSummarySchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.CompileSummarySchemaID)
	}
	if decoded.Contract != "contract.json" || decoded.ContractDigest == "" {
		t.Fatalf("decoded summary = %+v", decoded)
	}
	if len(decoded.Reads) != 1 || decoded.Reads[0] != "brief.md" {
		t.Fatalf("reads = %v, want brief.md", decoded.Reads)
	}
	if len(decoded.Writes) != 1 || decoded.Writes[0] != "reports/summary.txt" {
		t.Fatalf("writes = %v, want reports/summary.txt", decoded.Writes)
	}
	if len(decoded.Tasks) != 3 || decoded.Tasks[0].ID != "scripted_change" {
		t.Fatalf("tasks = %+v", decoded.Tasks)
	}
	if len(decoded.Obligations) != 3 || decoded.Obligations[0].ID != "obl_requested_file" || !decoded.Obligations[0].Required {
		t.Fatalf("obligations = %+v", decoded.Obligations)
	}
	if err := schema.ValidateBytes(schema.CompileSummarySchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("compile summary did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestCompileCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	outPath := "contract.json"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", outPath,
		"--write", "reports/summary.txt",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion      string `json:"schema_version"`
		ContractPath       string `json:"contract_path"`
		ContractDigest     string `json:"contract_digest"`
		ContractDigestFile string `json:"contract_digest_file"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode compile json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.CompileResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.CompileResultSchemaID)
	}
	if decoded.ContractPath != outPath || decoded.ContractDigestFile != outPath+".sha256" {
		t.Fatalf("decoded compile paths = %+v", decoded)
	}
	if len(decoded.ContractDigest) != 64 {
		t.Fatalf("contract_digest len = %d, want 64", len(decoded.ContractDigest))
	}
	if _, err := os.Stat(decoded.ContractPath); err != nil {
		t.Fatalf("expected contract path %s: %v", decoded.ContractPath, err)
	}
	if _, err := os.Stat(decoded.ContractDigestFile); err != nil {
		t.Fatalf("expected digest path %s: %v", decoded.ContractDigestFile, err)
	}
	if err := schema.ValidateBytes(schema.CompileResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("compile result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestCompileCommandRejectsJSONWithSummaryJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("brief.md", []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", "brief.md",
		"--out", "contract.json",
		"--json",
		"--summary-json",
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--json cannot be combined with --summary-json") {
		t.Fatalf("stderr = %q, want JSON flag conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestCompileCommandRejectsEscapingWriteFlag(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	if err := os.WriteFile(briefPath, []byte("Create authored reports."), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"compile",
		"--brief", briefPath,
		"--out", "contract.json",
		"--write", "../outside.txt",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), `workspace write "../outside.txt" escapes workspace`) {
		t.Fatalf("stderr = %q, want escaping write", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestLintBriefCommandPrintsValidSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	if err := os.WriteFile(briefPath, []byte(structuredCompileBrief()), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"valid=true", "diagnostic_count=0"} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestLintBriefCommandPrintsJSONDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	brief := `# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string                    `json:"schema_version"`
		Valid         bool                      `json:"valid"`
		Diagnostics   []contract.LintDiagnostic `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode lint json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.LintResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.LintResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.LintResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("lint result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if decoded.Valid || len(decoded.Diagnostics) != 1 {
		t.Fatalf("decoded lint = %+v, want invalid with one diagnostic", decoded)
	}
	diagnostic := decoded.Diagnostics[0]
	if diagnostic.Code != "STRUCTURED_TASK_FIELD_UNKNOWN" || diagnostic.Line != 8 {
		t.Fatalf("diagnostic = %+v", diagnostic)
	}
}

func TestLintBriefCommandPrintsValidJSONWithSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	if err := os.WriteFile(briefPath, []byte(structuredCompileBrief()), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string                    `json:"schema_version"`
		Valid         bool                      `json:"valid"`
		Diagnostics   []contract.LintDiagnostic `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode lint json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.LintResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.LintResultSchemaID)
	}
	if !decoded.Valid || len(decoded.Diagnostics) != 0 {
		t.Fatalf("decoded lint = %+v, want valid result without diagnostics", decoded)
	}
	if err := schema.ValidateBytes(schema.LintResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("lint result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestLintBriefCommandPrintsSARIFDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	brief := `# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--sarif"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode sarif: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 {
		t.Fatalf("decoded sarif = %+v", decoded)
	}
	run := decoded.Runs[0]
	if run.Tool.Driver.Name != "AO Covenant" || len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != "STRUCTURED_TASK_FIELD_UNKNOWN" || result.Level != "error" {
		t.Fatalf("sarif result = %+v", result)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "brief.md" || result.Locations[0].PhysicalLocation.Region.StartLine != 8 {
		t.Fatalf("locations = %+v", result.Locations)
	}
}

func TestLintBriefCommandPrintsSARIFBaselineSuppression(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	brief := `# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

# Tasks
## Task: draft_release_report
writess:
- reports/release.md
obligations:
- obl_release_report
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	mustWriteTestFile(t, "baseline.json", `{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "STRUCTURED_TASK_FIELD_UNKNOWN",
      "source_uri": "brief.md",
      "line": 8,
      "justification": "accepted until structured brief fixture is migrated"
    }
  ]
}`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--sarif", "--sarif-baseline", "baseline.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				RuleID       string `json:"ruleId"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
		t.Fatalf("decoded sarif = %+v, want one result", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if result.RuleID != "STRUCTURED_TASK_FIELD_UNKNOWN" || len(result.Suppressions) != 1 {
		t.Fatalf("sarif result = %+v, want suppression", result)
	}
	if result.Suppressions[0].Kind != "external" || result.Suppressions[0].Justification != "accepted until structured brief fixture is migrated" {
		t.Fatalf("suppression = %+v, want external justification", result.Suppressions[0])
	}
}

func TestLintBriefCommandRejectsInvalidSARIFBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "brief.md", "# Tasks\n")
	mustWriteTestFile(t, "baseline.json", "{")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", "brief.md", "--sarif", "--sarif-baseline", "baseline.json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read sarif baseline") {
		t.Fatalf("stderr = %q, want read sarif baseline", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestLintBriefCommandRejectsSchemaInvalidSARIFBaseline(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "brief.md", "# Tasks\n")
	mustWriteTestFile(t, "baseline.json", `{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "STRUCTURED_TASK_FIELD_UNKNOWN",
      "justification": "accepted until the source brief is migrated",
      "expires_after": "2026-07-01"
    }
  ]
}`)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", "brief.md", "--sarif", "--sarif-baseline", "baseline.json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.lint-sarif-baseline.v1") {
		t.Fatalf("stderr = %q, want schema validation failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestReadLintSARIFBaselineRejectsSchemaInvalidRuleID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	mustWriteTestFile(t, path, `{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [
    {
      "rule_id": "structured_task_field_unknown",
      "justification": "accepted until the source brief is migrated"
    }
  ]
}`)

	_, err := readLintSARIFBaseline(path)

	if err == nil || !strings.Contains(err.Error(), "schema validation failed for covenant.lint-sarif-baseline.v1") {
		t.Fatalf("readLintSARIFBaseline error = %v, want schema validation failure", err)
	}
}

func TestLintCommandRejectsJSONAndSARIF(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("brief.md", []byte(structuredCompileBrief()), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", "brief.md", "--json", "--sarif"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--json cannot be combined with --sarif") {
		t.Fatalf("stderr = %q, want format conflict", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestLintBriefCommandPrintsMultipleJSONDiagnostics(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	brief := `# Writes
- reports/declared.md

# Obligations
## Obligation: obl_release_report
required: true

# Tasks
## Task: draft_release_report
depends_on:
- missing_task
obligations:
- obl_missing
writes:
- reports/not-declared.md
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	var decoded contract.LintResult
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode lint json: %v; stdout = %q", err, stdout.String())
	}
	wantCodes := []string{
		"STRUCTURED_TASK_DEP_UNKNOWN",
		"STRUCTURED_TASK_OBLIGATION_UNKNOWN",
		"STRUCTURED_TASK_WRITE_UNDECLARED",
	}
	if got := lintResultCodes(decoded); strings.Join(got, ",") != strings.Join(wantCodes, ",") {
		t.Fatalf("decoded lint codes = %v, want %v; decoded = %+v", got, wantCodes, decoded)
	}
}

func TestLintBriefCommandPrintsJSONDiagnosticHint(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	briefPath := "brief.md"
	brief := `# Writes
- reports/declared.md

# Obligations
## Obligation: obl_release_report
required: true

# Tasks
## Task: draft_release_report
writes:
- reports/not-declared.md
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", briefPath, "--json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Diagnostics []struct {
			Code string `json:"code"`
			Hint string `json:"hint"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode lint json: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Diagnostics) != 1 {
		t.Fatalf("diagnostics len = %d, want 1; stdout = %q", len(decoded.Diagnostics), stdout.String())
	}
	diagnostic := decoded.Diagnostics[0]
	if diagnostic.Code != "STRUCTURED_TASK_WRITE_UNDECLARED" {
		t.Fatalf("diagnostic code = %s, want STRUCTURED_TASK_WRITE_UNDECLARED", diagnostic.Code)
	}
	if diagnostic.Hint != `Add "reports/not-declared.md" under # Writes or pass --write reports/not-declared.md.` {
		t.Fatalf("diagnostic hint = %q", diagnostic.Hint)
	}
}

func TestLintContractCommandReportsSemanticDiagnostic(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DependsOn = []string{"missing_task"}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--contract", "contract.json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"valid=false",
		"diagnostic_count=1",
		`diagnostic=CONTRACT_TASK_DEPENDENCY_UNKNOWN severity=error field=tasks.depends_on message=task "scripted_change" depends on unknown task "missing_task"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestLintContractCommandPrintsDiagnosticHint(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DependsOn = []string{"missing_task"}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--contract", "contract.json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	want := `hint=Define task "missing_task" or remove it from depends_on.`
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout = %q, want %s", stdout.String(), want)
	}
}

func TestLintContractCommandReportsMultipleSemanticDiagnostics(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].Obligations = []string{"missing_obligation"}
	c.Tasks[0].DependsOn = []string{"missing_task"}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--contract", "contract.json"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"valid=false",
		"diagnostic_count=2",
		`diagnostic=CONTRACT_TASK_OBLIGATION_UNKNOWN severity=error field=tasks.obligations message=task "scripted_change" references unknown obligation "missing_obligation"`,
		`diagnostic=CONTRACT_TASK_DEPENDENCY_UNKNOWN severity=error field=tasks.depends_on message=task "scripted_change" depends on unknown task "missing_task"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestLintCommandRejectsMultipleTargets(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("brief.md", []byte("Create demo-output/report.txt"), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "lint", "--brief", "brief.md", "--contract", "contract.json"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --brief or --contract") {
		t.Fatalf("stderr = %q, want target error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunCommandWritesEvidencePack(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-cli",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"run_dir=", "ledger=", "evidence_pack="} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), want)
		}
	}
	if _, err := os.Stat(".covenant/runs/run-cli/evidence-pack.json"); err != nil {
		t.Fatalf("evidence pack missing: %v", err)
	}
}

func TestRunCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-json",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion    string `json:"schema_version"`
		RunID            string `json:"run_id"`
		RunDir           string `json:"run_dir"`
		LedgerPath       string `json:"ledger_path"`
		EvidencePackPath string `json:"evidence_pack_path"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode run json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.RunResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.RunResultSchemaID)
	}
	if decoded.RunID != "run-json" || !strings.HasSuffix(decoded.RunDir, ".covenant/runs/run-json") || !strings.HasSuffix(decoded.LedgerPath, ".covenant/runs/run-json/events.ndjson") || !strings.HasSuffix(decoded.EvidencePackPath, ".covenant/runs/run-json/evidence-pack.json") {
		t.Fatalf("decoded run result = %+v", decoded)
	}
	if _, err := os.Stat(decoded.LedgerPath); err != nil {
		t.Fatalf("ledger path missing: %v", err)
	}
	if _, err := os.Stat(decoded.EvidencePackPath); err != nil {
		t.Fatalf("evidence pack path missing: %v", err)
	}
	if err := schema.ValidateBytes(schema.RunResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("run result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunCommandRecordsFileReadArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = append([]contract.ActionRef{
		{Type: "file.read", Resource: "examples/risky-change/brief.md"},
	}, c.Tasks[0].DeclaredSideEffects...)
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-read",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	evidenceBytes, err := os.ReadFile(".covenant/runs/run-read/evidence-pack.json")
	if err != nil {
		t.Fatalf("read evidence pack: %v", err)
	}
	var evidence struct {
		ArtifactManifest []struct {
			ArtifactID string `json:"artifact_id"`
			Path       string `json:"path"`
			Digest     string `json:"digest"`
		} `json:"artifact_manifest"`
	}
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("decode evidence pack: %v", err)
	}
	foundReadArtifact := false
	for _, artifact := range evidence.ArtifactManifest {
		if artifact.ArtifactID == "scripted_change-read-1" && artifact.Path == "examples/risky-change/brief.md" && artifact.Digest != "" {
			foundReadArtifact = true
		}
	}
	if !foundReadArtifact {
		t.Fatalf("read artifact not found in %+v", evidence.ArtifactManifest)
	}
}

func TestRunCommandAllowsApprovedProcessEffect(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	writeApprovalContractForProcess(t, "contract.json", "go version")
	writeProcessTicketForResource(t, "ticket.json", "go version")

	var attachStdout bytes.Buffer
	var attachStderr bytes.Buffer
	attachCode := Run([]string{"covenant", "approval", "attach", "--contract", "contract.json", "--ticket", "ticket.json", "--out", "approved-contract.json"}, &attachStdout, &attachStderr)
	if attachCode != 0 {
		t.Fatalf("attach exit code = %d, stderr = %q", attachCode, attachStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "approved-contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-process",
		"--allow-process", "go version",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	processOutput, err := os.ReadFile(".covenant/process/scripted_change-process-1-stdout.txt")
	if err != nil {
		t.Fatalf("read process stdout artifact: %v", err)
	}
	if !strings.Contains(string(processOutput), "go version") {
		t.Fatalf("process stdout = %q, want go version", string(processOutput))
	}
}

func TestRunCommandDeniesRevokedApprovalTicket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	writeApprovalContractForProcess(t, "contract.json", "go version")
	writeProcessTicketForResource(t, "ticket.json", "go version")
	writeRevocationList(t, "revocations.json", "approval-scripted_change-process_spawn-go-version")

	var attachStdout bytes.Buffer
	var attachStderr bytes.Buffer
	attachCode := Run([]string{"covenant", "approval", "attach", "--contract", "contract.json", "--ticket", "ticket.json", "--out", "approved-contract.json"}, &attachStdout, &attachStderr)
	if attachCode != 0 {
		t.Fatalf("attach exit code = %d, stderr = %q", attachCode, attachStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "approved-contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-revoked",
		"--allow-process", "go version",
		"--revocations", "revocations.json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `approval ticket "approval-scripted_change-process_spawn-go-version" is revoked`) {
		t.Fatalf("stderr = %q, want revoked approval", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestPolicyExplainCommandPrintsDecisionSummaries(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeDeniedProcessEvidence(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"explain",
		"--evidence", ".covenant/runs/policy-explain-denied/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"policy=policy-scripted_change-1 task=scripted_change decision=deny effect=process.spawn resource=make-test summary=denied process.spawn on make-test",
		"policy_action=policy-scripted_change-1 action=attach an approved ticket matching task, effect, and resource",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestPolicyExplainCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeDeniedProcessEvidence(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"explain",
		"--json",
		"--evidence", ".covenant/runs/policy-explain-denied/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion      string `json:"schema_version"`
		PolicyExplanations []struct {
			DecisionID     string `json:"decision_id"`
			Decision       string `json:"decision"`
			Summary        string `json:"summary"`
			OperatorAction string `json:"operator_action"`
		} `json:"policy_explanations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode policy explain json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.PolicyExplainResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.PolicyExplainResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.PolicyExplainResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("policy explain result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if len(decoded.PolicyExplanations) != 1 {
		t.Fatalf("policy explanations len = %d, want 1", len(decoded.PolicyExplanations))
	}
	explanation := decoded.PolicyExplanations[0]
	if explanation.DecisionID != "policy-scripted_change-1" || explanation.Decision != "deny" || explanation.Summary != "denied process.spawn on make-test" || explanation.OperatorAction == "" {
		t.Fatalf("explanation = %+v", explanation)
	}
}

func TestPolicyIndexCommandFiltersTextOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeDeniedProcessEvidence(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"index",
		"--evidence", ".covenant/runs/policy-explain-denied/evidence-pack.json",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--decision", "deny",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"policy_count=1",
		"policy=policy-scripted_change-1 task=scripted_change decision=deny effect=process.spawn resource=make-test summary=denied process.spawn on make-test",
		"policy_action=policy-scripted_change-1 action=attach an approved ticket matching task, effect, and resource",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestPolicyIndexCommandFiltersJSONByApprovalTicket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovedProcessEvidence(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"index",
		"--json",
		"--evidence", ".covenant/runs/policy-index-approved/evidence-pack.json",
		"--approval", "with-ticket",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion   string `json:"schema_version"`
		PolicyCount     int    `json:"policy_count"`
		PolicyDecisions []struct {
			DecisionID       string `json:"decision_id"`
			Decision         string `json:"decision"`
			ApprovalTicketID string `json:"approval_ticket_id"`
		} `json:"policy_decisions"`
		PolicyExplanations []struct {
			DecisionID string `json:"decision_id"`
			Summary    string `json:"summary"`
		} `json:"policy_explanations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode policy index json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.PolicyIndexResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.PolicyIndexResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.PolicyIndexResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("policy index result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if decoded.PolicyCount != 1 || len(decoded.PolicyDecisions) != 1 || len(decoded.PolicyExplanations) != 1 {
		t.Fatalf("decoded = %+v, want one indexed policy", decoded)
	}
	decision := decoded.PolicyDecisions[0]
	if decision.DecisionID != "policy-scripted_change-1" || decision.Decision != "allow" || decision.ApprovalTicketID == "" {
		t.Fatalf("decision = %+v, want approved allow decision", decision)
	}
}

func TestPolicySpineCommandPrintsAO2FirstGovernanceJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"spine",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Stack         string `json:"stack"`
		Status        string `json:"status"`
		Scope         struct {
			ActiveRepositories []string `json:"active_repositories"`
			ReplacedBy         []string `json:"replaced_by"`
		} `json:"scope"`
		Responsibilities []struct {
			Name  string   `json:"name"`
			Owner string   `json:"owner"`
			Gates []string `json:"gates"`
		} `json:"responsibilities"`
		OutOfBounds []string `json:"out_of_bounds"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode policy spine json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.PolicySpineResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.PolicySpineResultSchemaID)
	}
	if err := schema.ValidateBytes(schema.PolicySpineResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("policy spine result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if decoded.Stack != "ao2-first" || decoded.Status != "ready" {
		t.Fatalf("stack/status = %q/%q, want ao2-first/ready", decoded.Stack, decoded.Status)
	}
	for _, want := range []string{"ao2", "ao2-control-plane", "ao-foundry", "ao-forge", "ao-command", "ao-covenant"} {
		if !containsString(decoded.Scope.ActiveRepositories, want) {
			t.Fatalf("active repositories = %#v, missing %q", decoded.Scope.ActiveRepositories, want)
		}
	}
	if !containsString(decoded.Scope.ReplacedBy, "ao2") || !containsString(decoded.Scope.ReplacedBy, "ao2-control-plane") {
		t.Fatalf("replaced_by = %#v, want ao2 and ao2-control-plane", decoded.Scope.ReplacedBy)
	}
	for _, forbidden := range []string{"ao-operator", "ao-runtime", "ao-control-plane", "ao-conductor", "agy-swarms"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("policy spine output contains out-of-scope repository %q:\n%s", forbidden, stdout.String())
		}
	}
	if len(decoded.Responsibilities) < 4 {
		t.Fatalf("responsibilities len = %d, want policy spine coverage", len(decoded.Responsibilities))
	}
	if len(decoded.OutOfBounds) == 0 {
		t.Fatalf("out_of_bounds is empty; want explicit non-ownership guardrails")
	}
}

func TestPolicyClaimPublishGateDeniesFullRSIFromAO2RetainedReadbackEvidence(t *testing.T) {
	dir := t.TempDir()
	claimReadinessPath := filepath.Join(dir, "claim-readiness.json")
	readbackIndexPath := filepath.Join(dir, "readback-index.json")
	writeJSONFileForTest(t, claimReadinessPath, map[string]any{
		"schema_version": "ao2.rsi-claim-readiness-audit.v1",
		"status":         "claim_boundary_enforced",
		"claims": map[string]any{
			"full_autonomous_self_mutating_rsi": map[string]any{
				"decision":       "denied",
				"evidence_state": "missing_required_evidence",
				"partial_evidence": map[string]any{
					"live_self_change_readback_index": map[string]any{
						"evidence_state":                       "present",
						"schema_version":                       "ao2.rsi-live-self-change-readback-evidence-index.v1",
						"status":                               "passed",
						"control_plane_readback_status":        "passed",
						"retained_claim_level_evidence_status": "present",
						"claim_publish_approved":               false,
					},
				},
				"blockers": []map[string]any{
					{
						"id":                "covenant_claim_publish_approval",
						"evidence_state":    "missing",
						"required_evidence": "Covenant approval to publish the full autonomous self-mutating RSI claim",
					},
				},
			},
		},
	})
	writeJSONFileForTest(t, readbackIndexPath, map[string]any{
		"schema_version": "ao2.rsi-live-self-change-readback-evidence-index.v1",
		"status":         "passed",
		"retained_claim_level_evidence": map[string]any{
			"status":         "present",
			"schema_version": "ao2.cp-ao2-rsi-live-self-change-rehearsal-readback.v1",
		},
		"sources": map[string]any{
			"control_plane_readback": map[string]any{
				"status": "passed",
			},
		},
		"full_claim_boundary": map[string]any{
			"decision": "denied",
			"remaining_blockers": []string{
				"covenant_claim_publish_approval",
				"rehearsal_not_claim_publish_evidence",
			},
		},
		"trust_boundary": map[string]any{
			"local_only":                      true,
			"uses_network":                    false,
			"stores_credentials":              false,
			"requires_provider_api_key":       false,
			"mutates_repositories":            false,
			"mutates_control_plane_artifacts": false,
			"publishes_claims":                false,
			"approves_rsi_claims":             false,
		},
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"claim-publish-gate",
		"--json",
		"--claim-readiness", claimReadinessPath,
		"--readback-index", readbackIndexPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion        string `json:"schema_version"`
		ClaimLevel           string `json:"claim_level"`
		ClaimPublishResource string `json:"claim_publish_resource"`
		Status               string `json:"status"`
		Decision             string `json:"decision"`
		PublishAuthority     bool   `json:"publish_authority"`
		BlockerCount         int    `json:"blocker_count"`
		Blockers             []struct {
			ID string `json:"id"`
		} `json:"blockers"`
		ObservedEvidence struct {
			ClaimReadiness struct {
				Status               string `json:"status"`
				FullClaimDecision    string `json:"full_claim_decision"`
				ClaimPublishApproved bool   `json:"claim_publish_approved"`
			} `json:"claim_readiness"`
			LiveSelfChangeReadbackIndex struct {
				Status                           string `json:"status"`
				ControlPlaneReadbackStatus       string `json:"control_plane_readback_status"`
				RetainedClaimLevelEvidenceStatus string `json:"retained_claim_level_evidence_status"`
			} `json:"live_self_change_readback_index"`
		} `json:"observed_evidence"`
		TrustBoundary struct {
			LocalOnly           bool `json:"local_only"`
			UsesNetwork         bool `json:"uses_network"`
			MutatesRepositories bool `json:"mutates_repositories"`
			PublishesClaims     bool `json:"publishes_claims"`
			ApprovesRSIClaims   bool `json:"approves_rsi_claims"`
			StoresCredentials   bool `json:"stores_credentials"`
		} `json:"trust_boundary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode policy claim-publish gate json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != "covenant.rsi-claim-publish-gate.v1" {
		t.Fatalf("schema_version = %q, want covenant.rsi-claim-publish-gate.v1", decoded.SchemaVersion)
	}
	if err := schema.ValidateBytes("covenant.rsi-claim-publish-gate.v1", stdout.Bytes()); err != nil {
		t.Fatalf("policy claim-publish gate result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if decoded.ClaimLevel != "full_autonomous_self_mutating_rsi" || decoded.ClaimPublishResource != "full-autonomous-self-mutating-rsi" {
		t.Fatalf("claim target = %q/%q", decoded.ClaimLevel, decoded.ClaimPublishResource)
	}
	if decoded.Status != "denied" || decoded.Decision != "deny" || decoded.PublishAuthority {
		t.Fatalf("gate decision = status %q decision %q publish_authority %t, want denied deny false", decoded.Status, decoded.Decision, decoded.PublishAuthority)
	}
	if decoded.BlockerCount < 2 || !claimGateHasBlocker(decoded.Blockers, "covenant_claim_publish_approval") || !claimGateHasBlocker(decoded.Blockers, "rehearsal_not_claim_publish_evidence") {
		t.Fatalf("blockers = %+v, want covenant approval and rehearsal boundary blockers", decoded.Blockers)
	}
	if decoded.ObservedEvidence.ClaimReadiness.Status != "claim_boundary_enforced" ||
		decoded.ObservedEvidence.ClaimReadiness.FullClaimDecision != "denied" ||
		decoded.ObservedEvidence.ClaimReadiness.ClaimPublishApproved {
		t.Fatalf("claim readiness observation = %+v", decoded.ObservedEvidence.ClaimReadiness)
	}
	if decoded.ObservedEvidence.LiveSelfChangeReadbackIndex.Status != "passed" ||
		decoded.ObservedEvidence.LiveSelfChangeReadbackIndex.ControlPlaneReadbackStatus != "passed" ||
		decoded.ObservedEvidence.LiveSelfChangeReadbackIndex.RetainedClaimLevelEvidenceStatus != "present" {
		t.Fatalf("readback index observation = %+v", decoded.ObservedEvidence.LiveSelfChangeReadbackIndex)
	}
	if !decoded.TrustBoundary.LocalOnly ||
		decoded.TrustBoundary.UsesNetwork ||
		decoded.TrustBoundary.MutatesRepositories ||
		decoded.TrustBoundary.PublishesClaims ||
		decoded.TrustBoundary.ApprovesRSIClaims ||
		decoded.TrustBoundary.StoresCredentials {
		t.Fatalf("trust boundary = %+v, want local read-only non-publishing gate", decoded.TrustBoundary)
	}
}

func writeJSONFileForTest(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal json fixture: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write json fixture: %v", err)
	}
}

func claimGateHasBlocker(blockers []struct {
	ID string `json:"id"`
}, id string) bool {
	for _, blocker := range blockers {
		if blocker.ID == id {
			return true
		}
	}
	return false
}

func TestPolicyIndexCommandFiltersBundleTextOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeBundleInspectFixture(t, false)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"index",
		"--bundle", "bundle.zip",
		"--task", "scripted_change",
		"--effect", "file.write",
		"--resource", "demo-output/report.txt",
		"--decision", "allow",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"policy_count=1",
		"policy=policy-scripted_change-1 task=scripted_change decision=allow effect=file.write resource=demo-output/report.txt summary=allowed file.write on demo-output/report.txt",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestPolicyIndexCommandFiltersSignedBundleJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	publicKeyPath := writeBundleInspectFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"index",
		"--json",
		"--bundle", "bundle.zip",
		"--public-key", publicKeyPath,
		"--decision", "allow",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		PolicyCount     int `json:"policy_count"`
		PolicyDecisions []struct {
			DecisionID string `json:"decision_id"`
			Decision   string `json:"decision"`
			EffectType string `json:"effect_type"`
			Resource   string `json:"resource"`
		} `json:"policy_decisions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode policy index json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.PolicyCount != 1 || len(decoded.PolicyDecisions) != 1 {
		t.Fatalf("decoded = %+v, want one policy decision", decoded)
	}
	decision := decoded.PolicyDecisions[0]
	if decision.DecisionID != "policy-scripted_change-1" || decision.Decision != "allow" || decision.EffectType != "file.write" || decision.Resource != "demo-output/report.txt" {
		t.Fatalf("decision = %+v, want bundled file.write allow", decision)
	}
}

func TestPolicyIndexCommandRejectsEvidenceAndBundle(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeBundleInspectFixture(t, false)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"policy",
		"index",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--bundle", "bundle.zip",
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "provide exactly one of --evidence or --bundle") {
		t.Fatalf("stderr = %q, want source validation error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunCommandRejectsContractWithAdditionalProperty(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(contractBytes, &document); err != nil {
		t.Fatalf("decode contract map: %v", err)
	}
	document["unexpected"] = true
	changed, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode changed contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(changed, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-schema-extra",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "schema validation failed for covenant.contract.v1") {
		t.Fatalf("stderr = %q, want schema validation failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunCommandRejectsMissingContractFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "run", "--workspace", ".", "--out", ".covenant/runs"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--contract is required") {
		t.Fatalf("stderr = %q, want missing contract", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestVerifyCommandAcceptsGeneratedRun(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--ledger", ".covenant/runs/run-verify/events.ndjson",
		"--evidence", ".covenant/runs/run-verify/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"verified=true", "run_id=run-verify", "event_count=", "failure_count=0"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), want)
		}
	}
}

func TestVerifyCommandPrintsArtifactCount(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify-artifacts",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--ledger", ".covenant/runs/run-verify-artifacts/events.ndjson",
		"--evidence", ".covenant/runs/run-verify-artifacts/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "artifact_count=1") {
		t.Fatalf("stdout = %q, want artifact_count=1", stdout.String())
	}
}

func TestVerifyCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify-json",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--json",
		"--ledger", ".covenant/runs/run-verify-json/events.ndjson",
		"--evidence", ".covenant/runs/run-verify-json/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		Verified      bool              `json:"verified"`
		RunID         string            `json:"run_id"`
		EventCount    int               `json:"event_count"`
		ArtifactCount int               `json:"artifact_count"`
		FailureCount  int               `json:"failure_count"`
		Failures      []json.RawMessage `json:"failures"`
		LedgerDigest  string            `json:"ledger_digest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode verify json: %v; stdout = %q", err, stdout.String())
	}
	if !decoded.Verified || decoded.RunID != "run-verify-json" || decoded.EventCount == 0 || decoded.FailureCount != 0 {
		t.Fatalf("decoded json = %+v", decoded)
	}
	if decoded.ArtifactCount != 1 {
		t.Fatalf("artifact count = %d, want 1", decoded.ArtifactCount)
	}
	if decoded.Failures == nil || len(decoded.Failures) != 0 {
		t.Fatalf("failures = %v, want empty array", decoded.Failures)
	}
	if decoded.LedgerDigest == "" {
		t.Fatalf("ledger digest is empty")
	}
}

func TestVerifyCommandAcceptsBundle(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}
	var exportStdout bytes.Buffer
	var exportStderr bytes.Buffer
	exportCode := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--workspace", ".",
		"--out", "bundle.zip",
	}, &exportStdout, &exportStderr)
	if exportCode != 0 {
		t.Fatalf("export exit code = %d, stderr = %q", exportCode, exportStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--bundle", "bundle.zip",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"verified=true",
		"run_id=bundle-cli",
		"artifact_count=1",
		"input_snapshot_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestVerifyCommandRejectsTamperedArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify-tampered-artifact",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}
	if err := os.WriteFile("demo-output/report.txt", []byte("tampered artifact\n"), 0o644); err != nil {
		t.Fatalf("tamper report: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--workspace", ".",
		"--ledger", ".covenant/runs/run-verify-tampered-artifact/events.ndjson",
		"--evidence", ".covenant/runs/run-verify-tampered-artifact/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "artifact digest mismatch") {
		t.Fatalf("stderr = %q, want artifact digest mismatch", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestVerifyCommandRejectsRevokedApprovalTicket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovedProcessEvidence(t)
	writeRevocationList(t, "revocations.json", "approval-scripted_change-process_spawn-go-version")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--ledger", ".covenant/runs/policy-index-approved/events.ndjson",
		"--evidence", ".covenant/runs/policy-index-approved/evidence-pack.json",
		"--revocations", "revocations.json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `references revoked approval ticket "approval-scripted_change-process_spawn-go-version"`) {
		t.Fatalf("stderr = %q, want revoked approval", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestVerifyCommandPrintsFailureSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "network.request", Resource: "api.example.test"},
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify-failed",
	}, &runStdout, &runStderr)
	if runCode != 1 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--ledger", ".covenant/runs/run-verify-failed/events.ndjson",
		"--evidence", ".covenant/runs/run-verify-failed/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"failure_count=1",
		"failure=failure-000001",
		"line=",
		"task=scripted_change",
		"phase=policy",
		"reason=policy denied task",
		"policy=policy-scripted_change-1 task=scripted_change decision=deny effect=network.request resource=api.example.test summary=denied network.request on api.example.test",
		"policy_action=policy-scripted_change-1 action=attach an approved ticket matching task, effect, and resource",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
}

func TestVerifyCommandPrintsPolicyExplanationsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "network.request", Resource: "api.example.test"},
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "run-verify-policy-json",
	}, &runStdout, &runStderr)
	if runCode != 1 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"verify",
		"--json",
		"--ledger", ".covenant/runs/run-verify-policy-json/events.ndjson",
		"--evidence", ".covenant/runs/run-verify-policy-json/evidence-pack.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		PolicyExplanations []struct {
			DecisionID     string `json:"decision_id"`
			Decision       string `json:"decision"`
			Summary        string `json:"summary"`
			OperatorAction string `json:"operator_action"`
		} `json:"policy_explanations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode verify json: %v; stdout = %q", err, stdout.String())
	}
	if err := schema.ValidateBytes(schema.VerifyResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("verify policy result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if len(decoded.PolicyExplanations) != 1 {
		t.Fatalf("policy explanations len = %d, want 1", len(decoded.PolicyExplanations))
	}
	explanation := decoded.PolicyExplanations[0]
	if explanation.DecisionID != "policy-scripted_change-1" || explanation.Decision != "deny" || explanation.Summary != "denied network.request on api.example.test" || explanation.OperatorAction == "" {
		t.Fatalf("policy explanation = %+v", explanation)
	}
}

func TestVerifyCommandRejectsMissingLedgerFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{"covenant", "verify", "--evidence", "evidence-pack.json"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--ledger is required") {
		t.Fatalf("stderr = %q, want missing ledger", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSelfRunCommandWritesVerifiedEvidence(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/self-run/brief.md", "Produce AO Covenant self-run evidence for this repository.")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"self-run",
		"--workspace", ".",
		"--out", ".covenant/self-run",
		"--run-id", "self-run-cli",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"contract=.covenant/self-run/contract.json",
		"contract_digest=",
		"contract_digest_file=.covenant/self-run/contract.json.sha256",
		"run_dir=",
		"ledger=",
		"evidence_pack=",
		"verified=true",
		"failure_count=0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	for _, path := range []string{
		".covenant/self-run/contract.json",
		".covenant/self-run/contract.json.sha256",
		".covenant/self-run/runs/self-run-cli/events.ndjson",
		".covenant/self-run/runs/self-run-cli/evidence-pack.json",
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
}

func TestSelfRunCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/self-run/brief.md", "Produce AO Covenant self-run evidence for this repository.")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"self-run",
		"--workspace", ".",
		"--out", ".covenant/self-run",
		"--run-id", "self-run-json",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion      string `json:"schema_version"`
		ContractPath       string `json:"contract_path"`
		ContractDigest     string `json:"contract_digest"`
		ContractDigestFile string `json:"contract_digest_file"`
		RunID              string `json:"run_id"`
		RunDir             string `json:"run_dir"`
		LedgerPath         string `json:"ledger_path"`
		EvidencePackPath   string `json:"evidence_pack_path"`
		Verified           bool   `json:"verified"`
		FailureCount       int    `json:"failure_count"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode self-run json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.SelfRunResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.SelfRunResultSchemaID)
	}
	if decoded.ContractPath != ".covenant/self-run/contract.json" || decoded.ContractDigestFile != ".covenant/self-run/contract.json.sha256" {
		t.Fatalf("decoded contract paths = %+v", decoded)
	}
	if len(decoded.ContractDigest) != 64 {
		t.Fatalf("contract_digest len = %d, want 64", len(decoded.ContractDigest))
	}
	if decoded.RunID != "self-run-json" || !strings.HasSuffix(decoded.RunDir, ".covenant/self-run/runs/self-run-json") || !strings.HasSuffix(decoded.LedgerPath, ".covenant/self-run/runs/self-run-json/events.ndjson") || !strings.HasSuffix(decoded.EvidencePackPath, ".covenant/self-run/runs/self-run-json/evidence-pack.json") {
		t.Fatalf("decoded run paths = %+v", decoded)
	}
	if _, err := os.Stat(decoded.LedgerPath); err != nil {
		t.Fatalf("expected ledger path %s: %v", decoded.LedgerPath, err)
	}
	if _, err := os.Stat(decoded.EvidencePackPath); err != nil {
		t.Fatalf("expected evidence pack path %s: %v", decoded.EvidencePackPath, err)
	}
	if !decoded.Verified || decoded.FailureCount != 0 {
		t.Fatalf("decoded verification = %+v", decoded)
	}
	if err := schema.ValidateBytes(schema.SelfRunResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("self-run result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleasePackageCommandBuildsOneTarget(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "abc123",
		"--date", "2026-06-11T00:00:00Z",
		"--target", "linux/amd64",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"manifest=", "checksums=", "artifact="} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	for _, path := range []string{
		filepath.Join(outDir, "manifest.json"),
		filepath.Join(outDir, "SHA256SUMS"),
		filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(outDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read release manifest: %v", err)
	}
	var manifest struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode release manifest: %v; manifest = %q", err, string(manifestBytes))
	}
	if manifest.SchemaVersion != schema.ReleaseManifestSchemaID {
		t.Fatalf("manifest schema_version = %q, want %q", manifest.SchemaVersion, schema.ReleaseManifestSchemaID)
	}
	if err := schema.ValidateBytes(schema.ReleaseManifestSchemaID, manifestBytes); err != nil {
		t.Fatalf("release manifest did not match published schema: %v\njson:\n%s", err, string(manifestBytes))
	}
}

func TestReleasePackageCommandPrintsJSON(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v9.1.0",
		"--commit", "slice91",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string              `json:"schema_version"`
		ManifestPath  string              `json:"manifest_path"`
		ChecksumsPath string              `json:"checksums_path"`
		ArtifactPaths []string            `json:"artifact_paths"`
		Manifest      releasepkg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release package json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleasePackageResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleasePackageResultSchemaID)
	}
	if decoded.ManifestPath != filepath.Join(outDir, "manifest.json") || decoded.ChecksumsPath != filepath.Join(outDir, "SHA256SUMS") {
		t.Fatalf("decoded package paths = %+v", decoded)
	}
	if len(decoded.ArtifactPaths) != 1 || decoded.ArtifactPaths[0] != filepath.Join(outDir, "ao-covenant_v9.1.0_linux_amd64") {
		t.Fatalf("artifact_paths = %+v", decoded.ArtifactPaths)
	}
	if decoded.Manifest.SchemaVersion != schema.ReleaseManifestSchemaID || decoded.Manifest.Version != "v9.1.0" || decoded.Manifest.Commit != "slice91" || decoded.Manifest.Date != "2026-06-12T00:00:00Z" {
		t.Fatalf("decoded manifest metadata = %+v", decoded.Manifest)
	}
	if len(decoded.Manifest.Artifacts) != 1 || decoded.Manifest.Artifacts[0].Path != "ao-covenant_v9.1.0_linux_amd64" {
		t.Fatalf("decoded manifest artifacts = %+v", decoded.Manifest.Artifacts)
	}
	if _, err := os.Stat(decoded.ManifestPath); err != nil {
		t.Fatalf("expected manifest path %s: %v", decoded.ManifestPath, err)
	}
	if _, err := os.Stat(decoded.ChecksumsPath); err != nil {
		t.Fatalf("expected checksums path %s: %v", decoded.ChecksumsPath, err)
	}
	if _, err := os.Stat(decoded.ArtifactPaths[0]); err != nil {
		t.Fatalf("expected artifact path %s: %v", decoded.ArtifactPaths[0], err)
	}
	if err := schema.ValidateBytes(schema.ReleasePackageResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release package result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleasePackageCommandIncludesSupplementalArtifacts(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	provenancePath := filepath.Join(inputDir, "provenance.intoto.json")
	if err := os.WriteFile(sbomPath, []byte(`{"spdxVersion":"SPDX-2.3"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	if err := os.WriteFile(provenancePath, []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "supplemental123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sbom", sbomPath,
		"--provenance", provenancePath,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string              `json:"schema_version"`
		Manifest      releasepkg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release package json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleasePackageResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleasePackageResultSchemaID)
	}
	if len(decoded.Manifest.SupplementalArtifacts) != 2 {
		t.Fatalf("supplemental artifacts = %+v, want 2", decoded.Manifest.SupplementalArtifacts)
	}
	if decoded.Manifest.SupplementalArtifacts[0].Kind != "sbom" || decoded.Manifest.SupplementalArtifacts[0].Path != "sbom.spdx.json" {
		t.Fatalf("sbom supplemental = %+v", decoded.Manifest.SupplementalArtifacts[0])
	}
	if decoded.Manifest.SupplementalArtifacts[1].Kind != "provenance" || decoded.Manifest.SupplementalArtifacts[1].Path != "provenance.intoto.json" {
		t.Fatalf("provenance supplemental = %+v", decoded.Manifest.SupplementalArtifacts[1])
	}
	for _, path := range []string{
		filepath.Join(outDir, "sbom.spdx.json"),
		filepath.Join(outDir, "provenance.intoto.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected supplemental file %s: %v", path, err)
		}
	}
	if err := schema.ValidateBytes(schema.ReleasePackageResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release package result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseVerifyCommandReportsSupplementalArtifactsJSON(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	sbomBytes := []byte(`{"spdxVersion":"SPDX-2.3"}` + "\n")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "verify-supplemental-json",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sbom", sbomPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stdout = %q stderr = %q", packageCode, packageStdout.String(), packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("verify exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion         string                                `json:"schema_version"`
		Verified              bool                                  `json:"verified"`
		SupplementalArtifacts []releasepkg.SupplementalVerifyReport `json:"supplemental_artifacts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release verify json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseVerifyResultSchemaID || !decoded.Verified {
		t.Fatalf("decoded = %+v, want verified %s", decoded, schema.ReleaseVerifyResultSchemaID)
	}
	if len(decoded.SupplementalArtifacts) != 1 {
		t.Fatalf("supplemental artifacts = %+v, want 1", decoded.SupplementalArtifacts)
	}
	supplemental := decoded.SupplementalArtifacts[0]
	if supplemental.Kind != "sbom" || supplemental.Name != "sbom.spdx.json" || supplemental.Path != "sbom.spdx.json" {
		t.Fatalf("supplemental identity = %+v, want sbom.spdx.json", supplemental)
	}
	if !supplemental.Verified || !supplemental.PathValid || !supplemental.DigestVerified || !supplemental.SizeVerified || !supplemental.ChecksumVerified {
		t.Fatalf("supplemental status = %+v, want fully verified", supplemental)
	}
	if supplemental.SizeBytes != int64(len(sbomBytes)) || supplemental.ActualSizeBytes != int64(len(sbomBytes)) {
		t.Fatalf("supplemental sizes = declared %d actual %d, want %d", supplemental.SizeBytes, supplemental.ActualSizeBytes, len(sbomBytes))
	}
	if supplemental.SHA256 == "" || supplemental.ActualSHA256 != supplemental.SHA256 {
		t.Fatalf("supplemental digests = declared %q actual %q, want matching digest", supplemental.SHA256, supplemental.ActualSHA256)
	}
	if len(supplemental.Problems) != 0 {
		t.Fatalf("supplemental problems = %+v, want none", supplemental.Problems)
	}
	if err := schema.ValidateBytes(schema.ReleaseVerifyResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release verify result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if packageStderr.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stderr package=%q verify=%q, want empty", packageStderr.String(), stderr.String())
	}
}

func TestReleasePackageCommandIncludesArtifactAttestations(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "attestation.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "attestation123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--attestation", "linux/amd64=" + attestationPath,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string              `json:"schema_version"`
		Manifest      releasepkg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release package json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleasePackageResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleasePackageResultSchemaID)
	}
	if len(decoded.Manifest.Artifacts) != 1 || len(decoded.Manifest.Artifacts[0].Attestations) != 1 {
		t.Fatalf("manifest artifacts = %+v, want one attestation", decoded.Manifest.Artifacts)
	}
	attestation := decoded.Manifest.Artifacts[0].Attestations[0]
	if attestation.Name != "attestation.intoto.json" || attestation.Path != "ao-covenant_v0.1.0_linux_amd64.attestation.intoto.json" {
		t.Fatalf("attestation = %+v", attestation)
	}
	if _, err := os.Stat(filepath.Join(outDir, attestation.Path)); err != nil {
		t.Fatalf("expected attestation file %s: %v", attestation.Path, err)
	}
	if err := schema.ValidateBytes(schema.ReleasePackageResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release package result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleasePackageCommandIncludesArtifactAttestationKind(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "slsa.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "attestation-kind",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--attestation", "kind:slsa,target:linux/amd64=" + attestationPath,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string              `json:"schema_version"`
		Manifest      releasepkg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release package json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleasePackageResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleasePackageResultSchemaID)
	}
	if len(decoded.Manifest.Artifacts) != 1 || len(decoded.Manifest.Artifacts[0].Attestations) != 1 {
		t.Fatalf("manifest artifacts = %+v, want one attestation", decoded.Manifest.Artifacts)
	}
	if got := decoded.Manifest.Artifacts[0].Attestations[0].Kind; got != "slsa" {
		t.Fatalf("attestation kind = %q, want slsa", got)
	}
	if err := schema.ValidateBytes(schema.ReleasePackageResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release package result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleasePackageCommandReportsAttestationSelectorChoices(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	attestationPath := filepath.Join(inputDir, "attestation.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "attestation-selector",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--attestation", "target:windows/amd64=" + attestationPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{
		`release package: attestation selector "target:windows/amd64" did not match a release artifact`,
		"available selectors:",
		"name:ao-covenant_v0.1.0_linux_amd64",
		"target:linux/amd64",
		"path:ao-covenant_v0.1.0_linux_amd64",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %s", stderr.String(), want)
		}
	}
}

func TestReleaseDiffCommandReportsArtifactDrift(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-to")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"AO Covenant Release Diff\n",
		"from: " + fromDir,
		"to: " + toDir,
		"status: changed",
		"artifacts:",
		"- removed ao-covenant_v0.1.0_linux_amd64 (linux/amd64)",
		"- added ao-covenant_v0.2.0_linux_amd64 (linux/amd64)",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandReturnsZeroForMatchingRelease(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	releaseDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, releaseDir, "v0.1.0", "diff-same")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", releaseDir,
		"--to", releaseDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"AO Covenant Release Diff\n",
		"from: " + releaseDir,
		"to: " + releaseDir,
		"status: unchanged",
		"changes: none",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandPrintsJSONForChangedRelease(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-json-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-json-to")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string                 `json:"schema_version"`
		FromDir       string                 `json:"from_dir"`
		ToDir         string                 `json:"to_dir"`
		Changed       bool                   `json:"changed"`
		Entries       []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseDiffResultSchemaID || decoded.FromDir != fromDir || decoded.ToDir != toDir || !decoded.Changed {
		t.Fatalf("decoded = %+v, want changed release diff", decoded)
	}
	if len(decoded.Entries) == 0 {
		t.Fatalf("entries empty, want release drift entries")
	}
	if err := schema.ValidateBytes(schema.ReleaseDiffResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release diff result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if strings.Contains(stdout.String(), "AO Covenant Release Diff") {
		t.Fatalf("stdout = %q, want JSON without text heading", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandPrintsRedactedJSONWithPolicyProfile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	rootDir := t.TempDir()
	fromDir := filepath.Join(rootDir, "from")
	toDir := filepath.Join(rootDir, "to")
	fromPrivateKeyPath := filepath.Join(rootDir, "from-private.json")
	fromPublicKeyPath := filepath.Join(rootDir, "from-public.json")
	toPrivateKeyPath := filepath.Join(rootDir, "to-private.json")
	toPublicKeyPath := filepath.Join(rootDir, "to-public.json")
	policyPath := filepath.Join(rootDir, "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	var fromKeygenStdout bytes.Buffer
	var fromKeygenStderr bytes.Buffer
	fromKeygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", fromPrivateKeyPath,
		"--public", fromPublicKeyPath,
	}, &fromKeygenStdout, &fromKeygenStderr)
	if fromKeygenCode != 0 {
		t.Fatalf("from keygen exit code = %d, stderr = %q", fromKeygenCode, fromKeygenStderr.String())
	}
	var toKeygenStdout bytes.Buffer
	var toKeygenStderr bytes.Buffer
	toKeygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", toPrivateKeyPath,
		"--public", toPublicKeyPath,
	}, &toKeygenStdout, &toKeygenStderr)
	if toKeygenCode != 0 {
		t.Fatalf("to keygen exit code = %d, stderr = %q", toKeygenCode, toKeygenStderr.String())
	}
	fromFingerprint := stdoutValue(t, fromKeygenStdout.String(), "public_key_sha256")
	toFingerprint := stdoutValue(t, toKeygenStdout.String(), "public_key_sha256")

	var fromPackageStdout bytes.Buffer
	var fromPackageStderr bytes.Buffer
	fromPackageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", fromDir,
		"--version", "v0.1.0",
		"--commit", "diff-redact-from",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", fromPrivateKeyPath,
	}, &fromPackageStdout, &fromPackageStderr)
	if fromPackageCode != 0 {
		t.Fatalf("from package exit code = %d, stderr = %q", fromPackageCode, fromPackageStderr.String())
	}
	var toPackageStdout bytes.Buffer
	var toPackageStderr bytes.Buffer
	toPackageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", toDir,
		"--version", "v0.2.0",
		"--commit", "diff-redact-to",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", toPrivateKeyPath,
	}, &toPackageStdout, &toPackageStderr)
	if toPackageCode != 0 {
		t.Fatalf("to package exit code = %d, stderr = %q", toPackageCode, toPackageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--public-key", toPublicKeyPath,
		"--json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion    string                 `json:"schema_version"`
		FromDir          string                 `json:"from_dir"`
		ToDir            string                 `json:"to_dir"`
		Changed          bool                   `json:"changed"`
		Redacted         bool                   `json:"redacted"`
		Redactions       []string               `json:"redactions"`
		RedactionProfile string                 `json:"redaction_profile"`
		Entries          []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseDiffResultSchemaID || decoded.FromDir != "[REDACTED_PATH]" || decoded.ToDir != "[REDACTED_PATH]" || !decoded.Changed || !decoded.Redacted {
		t.Fatalf("decoded = %+v, want changed redacted release diff", decoded)
	}
	if !reflect.DeepEqual(decoded.Redactions, []string{"paths", "digests"}) || decoded.RedactionProfile != "partner" {
		t.Fatalf("redaction metadata = %+v/%q, want paths+digests partner", decoded.Redactions, decoded.RedactionProfile)
	}
	if len(decoded.Entries) == 0 {
		t.Fatalf("entries empty, want release drift entries")
	}
	if err := schema.ValidateBytes(schema.ReleaseDiffResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release diff result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	for _, forbidden := range []string{fromDir, toDir, fromFingerprint, toFingerprint} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", stdout.String(), forbidden)
		}
	}
	if !strings.Contains(stdout.String(), "[REDACTED_DIGEST]") {
		t.Fatalf("stdout = %q, want redacted signature digest detail", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandPrintsJSONForMatchingRelease(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	releaseDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, releaseDir, "v0.1.0", "diff-json-same")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", releaseDir,
		"--to", releaseDir,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string                 `json:"schema_version"`
		FromDir       string                 `json:"from_dir"`
		ToDir         string                 `json:"to_dir"`
		Changed       bool                   `json:"changed"`
		Entries       []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseDiffResultSchemaID || decoded.FromDir != releaseDir || decoded.ToDir != releaseDir || decoded.Changed || len(decoded.Entries) != 0 {
		t.Fatalf("decoded = %+v, want unchanged release diff", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseDiffResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release diff result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandWritesJSONOutputFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-json-out-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-json-out-to")
	outPath := filepath.Join(t.TempDir(), "release-diff.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_diff="+outPath+"\n" {
		t.Fatalf("stdout = %q, want release diff path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read release diff JSON: %v", err)
	}
	var decoded struct {
		SchemaVersion string                 `json:"schema_version"`
		FromDir       string                 `json:"from_dir"`
		ToDir         string                 `json:"to_dir"`
		Changed       bool                   `json:"changed"`
		Entries       []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release diff json: %v; file = %q", err, string(bytes))
	}
	if decoded.SchemaVersion != schema.ReleaseDiffResultSchemaID || decoded.FromDir != fromDir || decoded.ToDir != toDir || !decoded.Changed || len(decoded.Entries) == 0 {
		t.Fatalf("decoded = %+v, want changed release diff JSON", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseDiffResultSchemaID, bytes); err != nil {
		t.Fatalf("release diff result did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	if strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandRejectsOutputFileWithMissingParent(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-out-missing-parent-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-out-missing-parent-to")
	outPath := filepath.Join(t.TempDir(), "missing", "release-diff.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release diff --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "output file")
}

func TestReleaseDiffCommandRejectsOutputFileWithParentFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-out-parent-file-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-out-parent-file-to")
	parentFile := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	outPath := filepath.Join(parentFile, "release-diff.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release diff --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
}

func TestReleaseDiffCommandRejectsOutputFileDirectoryTarget(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-out-directory-target-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-out-directory-target-to")
	outPath := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release diff --out points to a directory")
	requireDirectoryTarget(t, outPath)
}

func TestReleaseDiffCommandWritesRedactedJSONOutputFileWithPolicyProfile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	rootDir := t.TempDir()
	fromDir := filepath.Join(rootDir, "from")
	toDir := filepath.Join(rootDir, "to")
	fromPrivateKeyPath := filepath.Join(rootDir, "from-private.json")
	fromPublicKeyPath := filepath.Join(rootDir, "from-public.json")
	toPrivateKeyPath := filepath.Join(rootDir, "to-private.json")
	toPublicKeyPath := filepath.Join(rootDir, "to-public.json")
	policyPath := filepath.Join(rootDir, "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	var fromKeygenStdout bytes.Buffer
	var fromKeygenStderr bytes.Buffer
	fromKeygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", fromPrivateKeyPath,
		"--public", fromPublicKeyPath,
	}, &fromKeygenStdout, &fromKeygenStderr)
	if fromKeygenCode != 0 {
		t.Fatalf("from keygen exit code = %d, stderr = %q", fromKeygenCode, fromKeygenStderr.String())
	}
	var toKeygenStdout bytes.Buffer
	var toKeygenStderr bytes.Buffer
	toKeygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", toPrivateKeyPath,
		"--public", toPublicKeyPath,
	}, &toKeygenStdout, &toKeygenStderr)
	if toKeygenCode != 0 {
		t.Fatalf("to keygen exit code = %d, stderr = %q", toKeygenCode, toKeygenStderr.String())
	}
	fromFingerprint := stdoutValue(t, fromKeygenStdout.String(), "public_key_sha256")
	toFingerprint := stdoutValue(t, toKeygenStdout.String(), "public_key_sha256")

	var fromPackageStdout bytes.Buffer
	var fromPackageStderr bytes.Buffer
	fromPackageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", fromDir,
		"--version", "v0.1.0",
		"--commit", "diff-redact-out-from",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", fromPrivateKeyPath,
	}, &fromPackageStdout, &fromPackageStderr)
	if fromPackageCode != 0 {
		t.Fatalf("from package exit code = %d, stderr = %q", fromPackageCode, fromPackageStderr.String())
	}
	var toPackageStdout bytes.Buffer
	var toPackageStderr bytes.Buffer
	toPackageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", toDir,
		"--version", "v0.2.0",
		"--commit", "diff-redact-out-to",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", toPrivateKeyPath,
	}, &toPackageStdout, &toPackageStderr)
	if toPackageCode != 0 {
		t.Fatalf("to package exit code = %d, stderr = %q", toPackageCode, toPackageStderr.String())
	}
	outPath := filepath.Join(rootDir, "release-diff-redacted.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--public-key", toPublicKeyPath,
		"--json",
		"--out", outPath,
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_diff="+outPath+"\n" {
		t.Fatalf("stdout = %q, want release diff path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read release diff JSON: %v", err)
	}
	var decoded struct {
		SchemaVersion    string                 `json:"schema_version"`
		FromDir          string                 `json:"from_dir"`
		ToDir            string                 `json:"to_dir"`
		Changed          bool                   `json:"changed"`
		Redacted         bool                   `json:"redacted"`
		Redactions       []string               `json:"redactions"`
		RedactionProfile string                 `json:"redaction_profile"`
		Entries          []releasepkg.DiffEntry `json:"entries"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release diff json: %v; file = %q", err, string(bytes))
	}
	if decoded.SchemaVersion != schema.ReleaseDiffResultSchemaID || decoded.FromDir != "[REDACTED_PATH]" || decoded.ToDir != "[REDACTED_PATH]" || !decoded.Changed || !decoded.Redacted {
		t.Fatalf("decoded = %+v, want changed redacted release diff", decoded)
	}
	if !reflect.DeepEqual(decoded.Redactions, []string{"paths", "digests"}) || decoded.RedactionProfile != "partner" {
		t.Fatalf("redaction metadata = %+v/%q, want paths+digests partner", decoded.Redactions, decoded.RedactionProfile)
	}
	if len(decoded.Entries) == 0 {
		t.Fatalf("entries empty, want release drift entries")
	}
	if err := schema.ValidateBytes(schema.ReleaseDiffResultSchemaID, bytes); err != nil {
		t.Fatalf("release diff result did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	for _, forbidden := range []string{fromDir, toDir, fromFingerprint, toFingerprint} {
		if strings.Contains(string(bytes), forbidden) {
			t.Fatalf("release diff file = %q, want %q redacted", string(bytes), forbidden)
		}
	}
	if !strings.Contains(string(bytes), "[REDACTED_DIGEST]") {
		t.Fatalf("release diff file = %q, want redacted signature digest detail", string(bytes))
	}
	if strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandPrintsSARIFForChangedRelease(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-sarif-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-sarif-to")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--sarif",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff sarif: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 {
		t.Fatalf("sarif = %+v, want one SARIF 2.1.0 run", decoded)
	}
	if decoded.Runs[0].Tool.Driver.Name != "AO Covenant Release Diff" {
		t.Fatalf("driver = %+v", decoded.Runs[0].Tool.Driver)
	}
	if len(decoded.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v, want release drift results", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if !strings.HasPrefix(result.RuleID, "RELEASE_DIFF_") || result.Level != "warning" {
		t.Fatalf("result = %+v, want release diff warning", result)
	}
	if result.Properties.Component == "" || result.Properties.Kind == "" || result.Properties.Name == "" || result.Properties.Location == "" || result.Properties.ReleaseDir != toDir {
		t.Fatalf("properties = %+v, want release diff properties", result.Properties)
	}
	if strings.Contains(stdout.String(), "AO Covenant Release Diff\n") {
		t.Fatalf("stdout = %q, want SARIF without text heading", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandWritesSARIFOutputFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-sarif-out-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-sarif-out-to")
	outPath := filepath.Join(t.TempDir(), "release-diff.sarif")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--sarif",
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_diff="+outPath+"\n" {
		t.Fatalf("stdout = %q, want release diff path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read release diff SARIF: %v", err)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release diff sarif: %v; file = %q", err, string(bytes))
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v, want changed release diff SARIF", decoded)
	}
	if strings.Contains(stdout.String(), `"version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandWritesSARIFOutputFileWithAcceptedBaseline(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-sarif-out-baseline-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-sarif-out-baseline-to")
	baselinePath := filepath.Join(t.TempDir(), "release-diff-sarif-baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [{
    "rule_id": "RELEASE_DIFF_ARTIFACT",
    "justification": "accepted release artifact replacement"
  }, {
    "rule_id": "RELEASE_DIFF_METADATA",
    "justification": "accepted release metadata drift"
  }]
}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "release-diff.sarif")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--sarif",
		"--sarif-baseline", baselinePath,
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_diff="+outPath+"\n" {
		t.Fatalf("stdout = %q, want release diff path", stdout.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read release diff SARIF: %v", err)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release diff sarif: %v; file = %q", err, string(bytes))
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v, want suppressed release diff SARIF results", decoded)
	}
	for _, result := range decoded.Runs[0].Results {
		if len(result.Suppressions) != 1 || result.Suppressions[0].Kind != "external" || !strings.HasPrefix(result.Suppressions[0].Justification, "accepted release ") {
			t.Fatalf("suppressions = %+v, want external accepted suppression", result.Suppressions)
		}
	}
	if strings.Contains(stdout.String(), `"version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandPrintsSARIFForMatchingRelease(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	releaseDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, releaseDir, "v0.1.0", "diff-sarif-same")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", releaseDir,
		"--to", releaseDir,
		"--sarif",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff sarif: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 0 {
		t.Fatalf("sarif = %+v, want unchanged release diff without results", decoded)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandSARIFBaselineSuppressesAcceptedDrift(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	fromDir := filepath.Join(t.TempDir(), "from")
	toDir := filepath.Join(t.TempDir(), "to")
	packageReleaseForDiffTest(t, sourceDir, fromDir, "v0.1.0", "diff-sarif-baseline-from")
	packageReleaseForDiffTest(t, sourceDir, toDir, "v0.2.0", "diff-sarif-baseline-to")
	baselinePath := filepath.Join(t.TempDir(), "release-diff-sarif-baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [{
    "rule_id": "RELEASE_DIFF_ARTIFACT",
    "justification": "accepted release artifact replacement"
  }, {
    "rule_id": "RELEASE_DIFF_METADATA",
    "justification": "accepted release metadata drift"
  }]
}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", fromDir,
		"--to", toDir,
		"--sarif",
		"--sarif-baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release diff sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v, want suppressed drift results", decoded)
	}
	for _, result := range decoded.Runs[0].Results {
		if len(result.Suppressions) != 1 || result.Suppressions[0].Kind != "external" || !strings.HasPrefix(result.Suppressions[0].Justification, "accepted release ") {
			t.Fatalf("suppressions = %+v, want external accepted suppression", result.Suppressions)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseDiffCommandRejectsSARIFBaselineWithoutSARIF(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "release-diff-sarif-baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{"schema_version":"covenant.lint-sarif-baseline.v1","accepted":[]}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", filepath.Join(t.TempDir(), "old-release"),
		"--to", filepath.Join(t.TempDir(), "new-release"),
		"--sarif-baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--sarif-baseline requires --sarif") {
		t.Fatalf("stderr = %q, want SARIF baseline diagnostic", stderr.String())
	}
	if strings.Contains(stderr.String(), "read from manifest") {
		t.Fatalf("stderr = %q, want flag validation before release diff", stderr.String())
	}
}

func TestReleaseDiffCommandRejectsJSONAndSARIF(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"diff",
		"--from", "old-dist",
		"--to", "new-dist",
		"--json",
		"--sarif",
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--json and --sarif are mutually exclusive") {
		t.Fatalf("stderr = %q, want mutually exclusive diagnostic", stderr.String())
	}
	if strings.Contains(stderr.String(), "read from manifest") {
		t.Fatalf("stderr = %q, want flag validation before release diff", stderr.String())
	}
}

func TestReleaseDiffCommandRequiresBothDirectories(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing from", args: []string{"covenant", "release", "diff", "--to", "new-dist"}, want: "--from is required"},
		{name: "missing to", args: []string{"covenant", "release", "diff", "--from", "old-dist"}, want: "--to is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want %s", stderr.String(), tt.want)
			}
		})
	}
}

func packageReleaseForDiffTest(t *testing.T, sourceDir string, outDir string, version string, commit string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", version,
		"--commit", commit,
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("package %s exit code = %d, stdout = %q stderr = %q", version, code, stdout.String(), stderr.String())
	}
}

func packageReleaseForProvenanceSummaryTest(t *testing.T, commit string) (string, string) {
	t.Helper()
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"spdxVersion":"SPDX-2.3"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	provenancePath := filepath.Join(inputDir, "provenance.intoto.json")
	if err := os.WriteFile(provenancePath, []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write provenance: %v", err)
	}
	attestationPath := filepath.Join(inputDir, "slsa.intoto.json")
	if err := os.WriteFile(attestationPath, []byte(`{"_type":"https://in-toto.io/Statement/v1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", commit,
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sbom", sbomPath,
		"--provenance", provenancePath,
		"--attestation", "kind:slsa,target:linux/amd64=" + attestationPath,
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	return outDir, publicKeyPath
}

func TestReleaseVerifyCommandAcceptsPackage(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "verify123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"verified=true",
		"manifest=" + filepath.Join(outDir, "manifest.json"),
		"checksums=" + filepath.Join(outDir, "SHA256SUMS"),
		"artifact_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseVerifyCommandPrintsJSON(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "verify-json",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string   `json:"schema_version"`
		Verified      bool     `json:"verified"`
		ManifestPath  string   `json:"manifest_path"`
		ChecksumsPath string   `json:"checksums_path"`
		ArtifactCount int      `json:"artifact_count"`
		Problems      []string `json:"problems"`
		Artifacts     []struct {
			Name             string   `json:"name"`
			Path             string   `json:"path"`
			Verified         bool     `json:"verified"`
			PathValid        bool     `json:"path_valid"`
			DigestVerified   bool     `json:"digest_verified"`
			SizeVerified     bool     `json:"size_verified"`
			ChecksumVerified bool     `json:"checksum_verified"`
			MetadataVerified bool     `json:"metadata_verified"`
			Problems         []string `json:"problems"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release verify json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseVerifyResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleaseVerifyResultSchemaID)
	}
	if !decoded.Verified {
		t.Fatalf("verified = false, want true; decoded = %+v", decoded)
	}
	if decoded.ManifestPath != filepath.Join(outDir, "manifest.json") || decoded.ChecksumsPath != filepath.Join(outDir, "SHA256SUMS") {
		t.Fatalf("decoded verify paths = %+v", decoded)
	}
	if decoded.ArtifactCount != 1 {
		t.Fatalf("artifact_count = %d, want 1", decoded.ArtifactCount)
	}
	if len(decoded.Problems) != 0 {
		t.Fatalf("problems = %+v, want empty", decoded.Problems)
	}
	if len(decoded.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1", len(decoded.Artifacts))
	}
	artifact := decoded.Artifacts[0]
	if artifact.Name != "ao-covenant_v0.1.0_linux_amd64" || artifact.Path != "ao-covenant_v0.1.0_linux_amd64" {
		t.Fatalf("artifact identity = %+v", artifact)
	}
	if !artifact.Verified || !artifact.PathValid || !artifact.DigestVerified || !artifact.SizeVerified || !artifact.ChecksumVerified || !artifact.MetadataVerified {
		t.Fatalf("artifact status = %+v, want all verification booleans true", artifact)
	}
	if len(artifact.Problems) != 0 {
		t.Fatalf("artifact problems = %+v, want empty", artifact.Problems)
	}
	if err := schema.ValidateBytes(schema.ReleaseVerifyResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release verify result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseVerifyCommandRejectsTamperedPackage(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "verify123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	if err := os.WriteFile(filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64"), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "verified=false") || !strings.Contains(output, "problem=") || !strings.Contains(output, "sha256 mismatch") {
		t.Fatalf("stdout = %q, want tamper problem", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseVerifyCommandRejectsHostBinaryMetadataMismatch(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "embedded123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", runtime.GOOS + "/" + runtime.GOARCH,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	manifestPath := filepath.Join(outDir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest releasepkg.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.Commit = "manifest-drift"
	if err := schema.WriteJSONFile(manifestPath, schema.ReleaseManifestSchemaID, manifest, 0o644); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "commit metadata mismatch") {
		t.Fatalf("stdout = %q, want commit metadata mismatch", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleasePackageAndVerifySignedManifest(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint = %q, want 64 hex chars", fingerprint)
	}

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "signed123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", runtime.GOOS + "/" + runtime.GOARCH,
		"--sign-key", privateKeyPath,
		"--json",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	var packageResult struct {
		SchemaVersion   string `json:"schema_version"`
		SignaturePath   string `json:"signature_path"`
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(packageStdout.Bytes(), &packageResult); err != nil {
		t.Fatalf("decode package json: %v; stdout = %q", err, packageStdout.String())
	}
	if packageResult.SchemaVersion != schema.ReleasePackageResultSchemaID {
		t.Fatalf("package schema_version = %q, want %q", packageResult.SchemaVersion, schema.ReleasePackageResultSchemaID)
	}
	if packageResult.SignaturePath != filepath.Join(outDir, "release-signature.json") {
		t.Fatalf("signature_path = %q, want release-signature.json", packageResult.SignaturePath)
	}
	if packageResult.PublicKeySHA256 != fingerprint {
		t.Fatalf("package public key sha256 = %q, want %q", packageResult.PublicKeySHA256, fingerprint)
	}
	if err := schema.ValidateBytes(schema.ReleasePackageResultSchemaID, packageStdout.Bytes()); err != nil {
		t.Fatalf("release package result did not match published schema: %v\njson:\n%s", err, packageStdout.String())
	}

	var verifyStdout bytes.Buffer
	var verifyStderr bytes.Buffer
	verifyCode := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--json",
	}, &verifyStdout, &verifyStderr)
	if verifyCode != 0 {
		t.Fatalf("verify exit code = %d, stdout = %q stderr = %q", verifyCode, verifyStdout.String(), verifyStderr.String())
	}
	var verifyResult struct {
		SchemaVersion   string `json:"schema_version"`
		Verified        bool   `json:"verified"`
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(verifyStdout.Bytes(), &verifyResult); err != nil {
		t.Fatalf("decode verify json: %v; stdout = %q", err, verifyStdout.String())
	}
	if verifyResult.SchemaVersion != schema.ReleaseVerifyResultSchemaID || !verifyResult.Verified {
		t.Fatalf("verify result = %+v, want verified release verify result", verifyResult)
	}
	if verifyResult.PublicKeySHA256 != fingerprint {
		t.Fatalf("verify public key sha256 = %q, want %q", verifyResult.PublicKeySHA256, fingerprint)
	}
	if err := schema.ValidateBytes(schema.ReleaseVerifyResultSchemaID, verifyStdout.Bytes()); err != nil {
		t.Fatalf("release verify result did not match published schema: %v\njson:\n%s", err, verifyStdout.String())
	}
	if packageStderr.Len() != 0 || verifyStderr.Len() != 0 {
		t.Fatalf("stderr package=%q verify=%q, want empty", packageStderr.String(), verifyStderr.String())
	}
}

func TestReleaseVerifyCommandPrintsProvenanceJSON(t *testing.T) {
	outDir := t.TempDir()
	inputDir := t.TempDir()
	sbomPath := filepath.Join(inputDir, "sbom.spdx.json")
	sbomBytes := []byte(`{"spdxVersion":"SPDX-2.3"}` + "\n")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	attestationPath := filepath.Join(inputDir, "slsa.intoto.json")
	attestationBytes := []byte(`{"_type":"https://in-toto.io/Statement/v1"}` + "\n")
	if err := os.WriteFile(attestationPath, attestationBytes, 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "provenance123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", runtime.GOOS + "/" + runtime.GOARCH,
		"--sbom", sbomPath,
		"--attestation", "kind:slsa,target:" + runtime.GOOS + "/" + runtime.GOARCH + "=" + attestationPath,
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Provenance    struct {
			Version           string `json:"version"`
			Commit            string `json:"commit"`
			Date              string `json:"date"`
			PublicKeySHA256   string `json:"public_key_sha256"`
			SignatureVerified bool   `json:"signature_verified"`
			Artifacts         []struct {
				Name               string `json:"name"`
				VerificationStatus string `json:"verification_status"`
				MetadataVerified   bool   `json:"metadata_verified"`
				Attestations       []struct {
					Kind               string `json:"kind"`
					Name               string `json:"name"`
					Path               string `json:"path"`
					VerificationStatus string `json:"verification_status"`
					SHA256             string `json:"sha256"`
					SizeBytes          int64  `json:"size_bytes"`
				} `json:"attestations"`
				BinaryMetadata struct {
					Version string `json:"version"`
					Commit  string `json:"commit"`
					OS      string `json:"os"`
					Arch    string `json:"arch"`
				} `json:"binary_metadata"`
			} `json:"artifacts"`
			SupplementalArtifacts []struct {
				Kind               string `json:"kind"`
				Name               string `json:"name"`
				Path               string `json:"path"`
				VerificationStatus string `json:"verification_status"`
				SHA256             string `json:"sha256"`
				SizeBytes          int64  `json:"size_bytes"`
			} `json:"supplemental_artifacts"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release verify json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseVerifyResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleaseVerifyResultSchemaID)
	}
	if decoded.Provenance.Version != "v0.1.0" || decoded.Provenance.Commit != "provenance123" || decoded.Provenance.Date != "2026-06-12T00:00:00Z" {
		t.Fatalf("provenance release metadata = %+v", decoded.Provenance)
	}
	if !decoded.Provenance.SignatureVerified || decoded.Provenance.PublicKeySHA256 != fingerprint {
		t.Fatalf("provenance signature = %+v, want fingerprint %s", decoded.Provenance, fingerprint)
	}
	if len(decoded.Provenance.Artifacts) != 1 {
		t.Fatalf("provenance artifacts len = %d, want 1", len(decoded.Provenance.Artifacts))
	}
	artifact := decoded.Provenance.Artifacts[0]
	if artifact.VerificationStatus != "verified" || !artifact.MetadataVerified || artifact.BinaryMetadata.Version != "v0.1.0" || artifact.BinaryMetadata.Commit != "provenance123" || artifact.BinaryMetadata.OS != runtime.GOOS || artifact.BinaryMetadata.Arch != runtime.GOARCH {
		t.Fatalf("artifact provenance = %+v", artifact)
	}
	if len(artifact.Attestations) != 1 {
		t.Fatalf("artifact provenance attestations = %+v, want one", artifact.Attestations)
	}
	attestation := artifact.Attestations[0]
	if attestation.Kind != "slsa" || attestation.Name != "slsa.intoto.json" || attestation.VerificationStatus != "verified" {
		t.Fatalf("attestation provenance = %+v, want verified slsa attestation", attestation)
	}
	if attestation.SHA256 == "" || attestation.SizeBytes != int64(len(attestationBytes)) {
		t.Fatalf("attestation provenance digest/size = %+v, want digest and size %d", attestation, len(attestationBytes))
	}
	if len(decoded.Provenance.SupplementalArtifacts) != 1 {
		t.Fatalf("supplemental provenance len = %d, want 1", len(decoded.Provenance.SupplementalArtifacts))
	}
	supplemental := decoded.Provenance.SupplementalArtifacts[0]
	if supplemental.Kind != "sbom" || supplemental.Name != "sbom.spdx.json" || supplemental.Path != "sbom.spdx.json" || supplemental.VerificationStatus != "verified" {
		t.Fatalf("supplemental provenance = %+v, want verified sbom", supplemental)
	}
	if supplemental.SizeBytes != int64(len(sbomBytes)) || supplemental.SHA256 == "" {
		t.Fatalf("supplemental provenance digest/size = %+v, want digest and size %d", supplemental, len(sbomBytes))
	}
	if err := schema.ValidateBytes(schema.ReleaseVerifyResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release verify result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseInspectCommandReportsSignedManifest(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "inspect123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"inspect",
		"--dir", outDir,
		"--public-key", publicKeyPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"manifest_valid=true",
		"checksum_status=verified",
		"signature=verified",
		"public_key_sha256=" + fingerprint,
		"artifact_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseInspectCommandPrintsJSON(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "inspect123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"inspect",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion  string `json:"schema_version"`
		ManifestValid  bool   `json:"manifest_valid"`
		ChecksumStatus string `json:"checksum_status"`
		Signature      struct {
			Status          string `json:"status"`
			PublicKeySHA256 string `json:"public_key_sha256"`
		} `json:"signature"`
		ArtifactCount int `json:"artifact_count"`
		Artifacts     []struct {
			Verified bool `json:"verified"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release inspect json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseInspectResultSchemaID || !decoded.ManifestValid || decoded.ChecksumStatus != "verified" || decoded.Signature.Status != "verified" || decoded.ArtifactCount != 1 {
		t.Fatalf("decoded = %+v, want verified release inspection", decoded)
	}
	if len(decoded.Artifacts) != 1 || !decoded.Artifacts[0].Verified {
		t.Fatalf("artifacts = %+v, want one verified artifact", decoded.Artifacts)
	}
	if len(decoded.Signature.PublicKeySHA256) != 64 {
		t.Fatalf("public_key_sha256 = %q, want 64 hex chars", decoded.Signature.PublicKeySHA256)
	}
	if err := schema.ValidateBytes(schema.ReleaseInspectResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release inspect result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseInspectCommandRedactsTextForExternalAudience(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "redact-inspect",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"inspect",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--audience", "external",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"manifest=[REDACTED_PATH]",
		"checksums=[REDACTED_PATH]",
		"signature=verified",
		"public_key_sha256=[REDACTED_DIGEST]",
		"signature_public_key_sha256=[REDACTED_DIGEST]",
		"artifact_count=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	for _, forbidden := range []string{outDir, filepath.Join(outDir, "manifest.json"), fingerprint} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", output, forbidden)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseInspectCommandPrintsRedactedJSONWithPolicyProfile(t *testing.T) {
	rootDir := t.TempDir()
	outDir := filepath.Join(rootDir, "dist")
	privateKeyPath := filepath.Join(rootDir, "private.json")
	publicKeyPath := filepath.Join(rootDir, "public.json")
	policyPath := filepath.Join(rootDir, "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "inspect-json-redacted",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	unredacted, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("inspect unredacted release: %v", err)
	}
	if len(unredacted.Artifacts) != 1 || unredacted.Artifacts[0].SHA256 == "" || unredacted.Signature.PublicKeySHA256 == "" {
		t.Fatalf("unredacted inspection = %+v, want signed release with one artifact digest", unredacted)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"inspect",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded releasepkg.InspectResult
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release inspect json: %v; stdout = %q", err, stdout.String())
	}
	zeroSHA256 := strings.Repeat("0", 64)
	if decoded.SchemaVersion != schema.ReleaseInspectResultSchemaID ||
		decoded.ReleaseDir != "[REDACTED_PATH]" ||
		decoded.ManifestPath != "[REDACTED_PATH]" ||
		decoded.ChecksumsPath != "[REDACTED_PATH]" ||
		decoded.SignaturePath != "[REDACTED_PATH]" ||
		decoded.Signature.PublicKeySHA256 != zeroSHA256 ||
		len(decoded.Artifacts) != 1 ||
		decoded.Artifacts[0].Path != "[REDACTED_PATH]" ||
		decoded.Artifacts[0].SHA256 != zeroSHA256 ||
		decoded.Artifacts[0].ActualSHA256 != zeroSHA256 {
		t.Fatalf("decoded = %+v, want schema-valid redacted release inspection", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseInspectResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release inspect result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	for _, forbidden := range []string{outDir, unredacted.ManifestPath, unredacted.Signature.PublicKeySHA256, unredacted.Artifacts[0].SHA256} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", stdout.String(), forbidden)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandSummarizesSignedPackage(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report123",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"AO Covenant Release Report\n",
		"release_dir: " + outDir,
		"manifest: " + filepath.Join(outDir, "manifest.json") + " (valid)",
		"checksums: " + filepath.Join(outDir, "SHA256SUMS") + " (verified)",
		"signature: verified",
		"signature_file: " + filepath.Join(outDir, "release-signature.json"),
		"public_key_sha256: " + fingerprint,
		"artifacts: 1",
		"- ao-covenant_v0.1.0_linux_amd64 (linux/amd64): verified",
		"  digest: verified",
		"  size: verified",
		"  checksum: verified",
		"  metadata: not_checked",
		"problems: none",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsProvenanceSummary(t *testing.T) {
	outDir, publicKeyPath := packageReleaseForProvenanceSummaryTest(t, "report-provenance-summary")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"provenance_summary:\n",
		"  signature: verified",
		"  attestations: 1 verified, 0 invalid",
		"  supplemental_sbom: 1 verified, 0 invalid",
		"  supplemental_provenance: 1 verified, 0 invalid",
		"  invalid_evidence: 0",
		"problems: none",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesTextOutputFile(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-out-text",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	reportPath := filepath.Join(t.TempDir(), "release-report.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read release report: %v", err)
	}
	output := string(bytes)
	for _, want := range []string{"AO Covenant Release Report\n", "release_dir: " + outDir, "problems: none"} {
		if !strings.Contains(output, want) {
			t.Fatalf("report file = %q, want %s", output, want)
		}
	}
	if strings.Contains(stdout.String(), "AO Covenant Release Report") {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesMarkdownOutputFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	outDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, outDir, "v0.1.0", "report-out-markdown")
	reportPath := filepath.Join(t.TempDir(), "release-report.md")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "markdown",
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read release report markdown: %v", err)
	}
	output := string(bytes)
	for _, want := range []string{"# AO Covenant Release Report\n", "## Summary", "## Artifacts", "## Problems", "No problems."} {
		if !strings.Contains(output, want) {
			t.Fatalf("report file = %q, want %s", output, want)
		}
	}
	if strings.Contains(stdout.String(), "# AO Covenant Release Report") {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesJSONOutputFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	outDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, outDir, "v0.1.0", "report-out-json-valid")
	reportPath := filepath.Join(t.TempDir(), "release-report.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "json",
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read release report json: %v", err)
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Valid         bool   `json:"valid"`
		Format        string `json:"format"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release report json: %v; file = %q", err, string(bytes))
	}
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || !decoded.Valid || decoded.Format != "json" {
		t.Fatalf("decoded = %+v, want valid release report JSON", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, bytes); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	if strings.Contains(stdout.String(), "{") {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandRejectsOutputFileWithMissingParent(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	outDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, outDir, "v0.1.0", "report-out-missing-parent")
	reportPath := filepath.Join(t.TempDir(), "missing", "release-report.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--out", reportPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release report --out parent directory does not exist")
	requirePathNotCreated(t, reportPath, "output file")
}

func TestReleaseReportCommandRejectsOutputFileWithParentFile(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	outDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, outDir, "v0.1.0", "report-out-parent-file")
	parentFile := filepath.Join(t.TempDir(), "reports")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	reportPath := filepath.Join(parentFile, "release-report.txt")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--out", reportPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release report --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
}

func TestReleaseReportCommandRejectsOutputFileDirectoryTarget(t *testing.T) {
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	outDir := filepath.Join(t.TempDir(), "release")
	packageReleaseForDiffTest(t, sourceDir, outDir, "v0.1.0", "report-out-directory-target")
	reportPath := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--out", reportPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "release report --out points to a directory")
	requireDirectoryTarget(t, reportPath)
}

func TestReleaseReportCommandPrintsMarkdownFormat(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-markdown",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--format", "markdown",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"# AO Covenant Release Report\n",
		"## Summary",
		"| Field | Value |",
		"| Release directory | " + outDir + " |",
		"| Manifest | " + filepath.Join(outDir, "manifest.json") + " (valid) |",
		"| Checksums | " + filepath.Join(outDir, "SHA256SUMS") + " (verified) |",
		"| Signature | verified |",
		"| Public key SHA256 | " + fingerprint + " |",
		"## Artifacts",
		"| Name | Target | Status | Digest | Size | Checksum | Metadata | Path |",
		"| ao-covenant_v0.1.0_linux_amd64 | linux/amd64 | verified | verified | verified | verified | not_checked | ao-covenant_v0.1.0_linux_amd64 |",
		"## Problems",
		"No problems.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if strings.Contains(output, "release_dir:") {
		t.Fatalf("stdout = %q, want markdown output without text report labels", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsMarkdownProvenanceSummary(t *testing.T) {
	outDir, publicKeyPath := packageReleaseForProvenanceSummaryTest(t, "report-markdown-provenance-summary")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--format", "markdown",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"## Provenance Summary",
		"| Field | Value |",
		"| Signature | verified |",
		"| Artifact attestations | 1 verified, 0 invalid |",
		"| Supplemental SBOMs | 1 verified, 0 invalid |",
		"| Supplemental provenance | 1 verified, 0 invalid |",
		"| Invalid provenance evidence | 0 |",
		"## Problems",
		"No problems.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsJSONProvenanceSummary(t *testing.T) {
	outDir, publicKeyPath := packageReleaseForProvenanceSummaryTest(t, "report-json-provenance-summary")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion     string                         `json:"schema_version"`
		ProvenanceSummary releaseProvenanceSummaryFields `json:"provenance_summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleaseReportResultSchemaID)
	}
	if decoded.ProvenanceSummary.SignatureStatus != "verified" ||
		decoded.ProvenanceSummary.AttestationVerifiedCount != 1 ||
		decoded.ProvenanceSummary.AttestationInvalidCount != 0 ||
		decoded.ProvenanceSummary.SBOMVerifiedCount != 1 ||
		decoded.ProvenanceSummary.SBOMInvalidCount != 0 ||
		decoded.ProvenanceSummary.SupplementalProvenanceVerifiedCount != 1 ||
		decoded.ProvenanceSummary.SupplementalProvenanceInvalidCount != 0 ||
		decoded.ProvenanceSummary.InvalidEvidenceCount != 0 {
		t.Fatalf("provenance_summary = %+v, want verified release evidence counts", decoded.ProvenanceSummary)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsJSONFormatForValidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-json-valid",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string                   `json:"schema_version"`
		Valid         bool                     `json:"valid"`
		Format        string                   `json:"format"`
		Audience      string                   `json:"audience"`
		Redacted      bool                     `json:"redacted"`
		Inspection    releasepkg.InspectResult `json:"inspection"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || !decoded.Valid || decoded.Format != "json" || decoded.Audience != "internal" || decoded.Redacted {
		t.Fatalf("decoded = %+v, want valid internal JSON report", decoded)
	}
	if decoded.Inspection.SchemaVersion != schema.ReleaseInspectResultSchemaID || decoded.Inspection.ReleaseDir != outDir || decoded.Inspection.ArtifactCount != 1 || decoded.Inspection.ChecksumStatus != "verified" {
		t.Fatalf("inspection = %+v, want release inspection summary", decoded.Inspection)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if strings.Contains(stdout.String(), "AO Covenant Release Report") {
		t.Fatalf("stdout = %q, want JSON without text heading", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsJSONFormatForInvalidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-json-invalid",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactPath := filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64")
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string                   `json:"schema_version"`
		Valid         bool                     `json:"valid"`
		Inspection    releasepkg.InspectResult `json:"inspection"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || decoded.Valid || decoded.Inspection.ChecksumStatus != "invalid" || len(decoded.Inspection.Problems) == 0 {
		t.Fatalf("decoded = %+v, want invalid release JSON report", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesInvalidJSONOutputFileBeforeNonZeroExit(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-out-json-invalid",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactPath := filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64")
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	reportPath := filepath.Join(t.TempDir(), "release-report.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "json",
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read release report: %v", err)
	}
	var decoded struct {
		SchemaVersion string                   `json:"schema_version"`
		Valid         bool                     `json:"valid"`
		Inspection    releasepkg.InspectResult `json:"inspection"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release report json: %v; file = %q", err, string(bytes))
	}
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || decoded.Valid || decoded.Inspection.ChecksumStatus != "invalid" {
		t.Fatalf("decoded = %+v, want invalid release report JSON", decoded)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, bytes); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	if strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsJSONWithRedactionPolicyProfile(t *testing.T) {
	rootDir := t.TempDir()
	outDir := filepath.Join(rootDir, "dist")
	policyPath := filepath.Join(rootDir, "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-json-redacted",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	unredacted, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: outDir})
	if err != nil {
		t.Fatalf("inspect unredacted release: %v", err)
	}
	if len(unredacted.Artifacts) != 1 || unredacted.Artifacts[0].SHA256 == "" {
		t.Fatalf("unredacted artifacts = %+v, want one artifact with digest", unredacted.Artifacts)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion    string                   `json:"schema_version"`
		Valid            bool                     `json:"valid"`
		Format           string                   `json:"format"`
		Audience         string                   `json:"audience"`
		Redacted         bool                     `json:"redacted"`
		Redactions       []string                 `json:"redactions"`
		RedactionProfile string                   `json:"redaction_profile"`
		Inspection       releasepkg.InspectResult `json:"inspection"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report json: %v; stdout = %q", err, stdout.String())
	}
	zeroSHA256 := strings.Repeat("0", 64)
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || !decoded.Valid || decoded.Format != "json" || decoded.Audience != "internal" || !decoded.Redacted {
		t.Fatalf("decoded = %+v, want valid redacted internal JSON report", decoded)
	}
	if !reflect.DeepEqual(decoded.Redactions, []string{"paths", "digests"}) || decoded.RedactionProfile != "partner" {
		t.Fatalf("redaction metadata = %+v/%q, want paths+digests partner", decoded.Redactions, decoded.RedactionProfile)
	}
	if decoded.Inspection.ReleaseDir != "[REDACTED_PATH]" ||
		decoded.Inspection.ManifestPath != "[REDACTED_PATH]" ||
		decoded.Inspection.ChecksumsPath != "[REDACTED_PATH]" ||
		len(decoded.Inspection.Artifacts) != 1 ||
		decoded.Inspection.Artifacts[0].Path != "[REDACTED_PATH]" ||
		decoded.Inspection.Artifacts[0].SHA256 != zeroSHA256 ||
		decoded.Inspection.Artifacts[0].ActualSHA256 != zeroSHA256 {
		t.Fatalf("inspection = %+v, want redacted paths and schema-valid digests", decoded.Inspection)
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	for _, forbidden := range []string{outDir, unredacted.ManifestPath, unredacted.Artifacts[0].SHA256} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", stdout.String(), forbidden)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsJSONWithProvenanceRedactionPolicyProfile(t *testing.T) {
	outDir, publicKeyPath := packageReleaseForProvenanceSummaryTest(t, "report-json-provenance-redacted")
	policyPath := filepath.Join(t.TempDir(), "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	unredacted, err := releasepkg.Inspect(releasepkg.InspectOptions{Dir: outDir, PublicKeyPath: publicKeyPath})
	if err != nil {
		t.Fatalf("inspect unredacted release: %v", err)
	}
	if len(unredacted.Artifacts) != 1 ||
		len(unredacted.Artifacts[0].Attestations) != 1 ||
		len(unredacted.SupplementalArtifacts) != 2 ||
		unredacted.Signature.PublicKeySHA256 == "" {
		t.Fatalf("unredacted inspection = %+v, want signed release with attestation and supplemental evidence", unredacted)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--format", "json",
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion     string                         `json:"schema_version"`
		Valid             bool                           `json:"valid"`
		Redacted          bool                           `json:"redacted"`
		Redactions        []string                       `json:"redactions"`
		RedactionProfile  string                         `json:"redaction_profile"`
		ProvenanceSummary releaseProvenanceSummaryFields `json:"provenance_summary"`
		Inspection        releasepkg.InspectResult       `json:"inspection"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report json: %v; stdout = %q", err, stdout.String())
	}
	zeroSHA256 := strings.Repeat("0", 64)
	if decoded.SchemaVersion != schema.ReleaseReportResultSchemaID || !decoded.Valid || !decoded.Redacted {
		t.Fatalf("decoded = %+v, want valid redacted release report", decoded)
	}
	if !reflect.DeepEqual(decoded.Redactions, []string{"paths", "digests"}) || decoded.RedactionProfile != "partner" {
		t.Fatalf("redaction metadata = %+v/%q, want paths+digests partner", decoded.Redactions, decoded.RedactionProfile)
	}
	if decoded.ProvenanceSummary.SignatureStatus != "verified" ||
		decoded.ProvenanceSummary.AttestationVerifiedCount != 1 ||
		decoded.ProvenanceSummary.SBOMVerifiedCount != 1 ||
		decoded.ProvenanceSummary.SupplementalProvenanceVerifiedCount != 1 ||
		decoded.ProvenanceSummary.InvalidEvidenceCount != 0 {
		t.Fatalf("provenance_summary = %+v, want verified signature, attestation, SBOM, and provenance counts", decoded.ProvenanceSummary)
	}
	inspection := decoded.Inspection
	if inspection.ReleaseDir != "[REDACTED_PATH]" ||
		inspection.ManifestPath != "[REDACTED_PATH]" ||
		inspection.ChecksumsPath != "[REDACTED_PATH]" ||
		inspection.SignaturePath != "[REDACTED_PATH]" ||
		inspection.Signature.PublicKeySHA256 != zeroSHA256 {
		t.Fatalf("inspection summary = %+v, want redacted release paths and signature digest", inspection)
	}
	if len(inspection.Artifacts) != 1 || len(inspection.Artifacts[0].Attestations) != 1 {
		t.Fatalf("artifacts = %+v, want one artifact with one attestation", inspection.Artifacts)
	}
	artifact := inspection.Artifacts[0]
	if artifact.Path != "[REDACTED_PATH]" || artifact.SHA256 != zeroSHA256 || artifact.ActualSHA256 != zeroSHA256 {
		t.Fatalf("artifact = %+v, want redacted path and digests", artifact)
	}
	attestation := artifact.Attestations[0]
	if attestation.Path != "[REDACTED_PATH]" || attestation.SHA256 != zeroSHA256 || attestation.ActualSHA256 != zeroSHA256 {
		t.Fatalf("attestation = %+v, want redacted path and digests", attestation)
	}
	if len(inspection.SupplementalArtifacts) != 2 {
		t.Fatalf("supplemental_artifacts = %+v, want SBOM and provenance evidence", inspection.SupplementalArtifacts)
	}
	for _, supplemental := range inspection.SupplementalArtifacts {
		if supplemental.Path != "[REDACTED_PATH]" || supplemental.SHA256 != zeroSHA256 || supplemental.ActualSHA256 != zeroSHA256 {
			t.Fatalf("supplemental = %+v, want redacted path and digests", supplemental)
		}
	}
	if err := schema.ValidateBytes(schema.ReleaseReportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release report result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	for _, forbidden := range []string{
		outDir,
		unredacted.ManifestPath,
		unredacted.ChecksumsPath,
		unredacted.SignaturePath,
		unredacted.Signature.PublicKeySHA256,
		unredacted.Artifacts[0].SHA256,
		unredacted.Artifacts[0].Attestations[0].SHA256,
		unredacted.SupplementalArtifacts[0].SHA256,
		unredacted.SupplementalArtifacts[1].SHA256,
	} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", stdout.String(), forbidden)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseSARIFBaselineTemplateIncludesRuleSourceFieldAndPlaceholder(t *testing.T) {
	sarif := schema.SARIFLog{
		Runs: []schema.SARIFRun{{
			Results: []schema.SARIFResult{{
				RuleID: "RELEASE_ARTIFACT_PROBLEM",
				Locations: []schema.SARIFLocation{{
					PhysicalLocation: schema.SARIFPhysicalLocation{
						ArtifactLocation: schema.SARIFArtifactLocation{URI: "ao-covenant_v0.1.0_linux_amd64"},
					},
				}},
				Properties: schema.SARIFResultProperties{Location: "artifact:ao-covenant_v0.1.0_linux_amd64"},
			}},
		}},
	}

	baseline := releaseSARIFBaselineTemplate(sarif)

	if baseline.SchemaVersion != "covenant.lint-sarif-baseline.v1" {
		t.Fatalf("schema_version = %q", baseline.SchemaVersion)
	}
	if len(baseline.Accepted) != 1 {
		t.Fatalf("accepted = %+v, want one entry", baseline.Accepted)
	}
	entry := baseline.Accepted[0]
	if entry.RuleID != "RELEASE_ARTIFACT_PROBLEM" ||
		entry.SourceURI != "ao-covenant_v0.1.0_linux_amd64" ||
		entry.Field != "artifact:ao-covenant_v0.1.0_linux_amd64" ||
		entry.Justification != "REVIEW: explain why this release finding is accepted" {
		t.Fatalf("entry = %+v, want release SARIF baseline template entry", entry)
	}
	if err := schema.ValidateValue(schema.LintSARIFBaselineSchemaID, baseline); err != nil {
		t.Fatalf("baseline template did not validate: %v", err)
	}
}

func TestReleaseSARIFBaselineTemplateDeduplicatesFindings(t *testing.T) {
	result := schema.SARIFResult{
		RuleID: "RELEASE_ARTIFACT_PROBLEM",
		Locations: []schema.SARIFLocation{{
			PhysicalLocation: schema.SARIFPhysicalLocation{
				ArtifactLocation: schema.SARIFArtifactLocation{URI: "app"},
			},
		}},
		Properties: schema.SARIFResultProperties{Location: "artifact:app"},
	}
	sarif := schema.SARIFLog{Runs: []schema.SARIFRun{{
		Results: []schema.SARIFResult{result, result},
	}}}

	baseline := releaseSARIFBaselineTemplate(sarif)

	if len(baseline.Accepted) != 1 {
		t.Fatalf("accepted = %+v, want duplicate findings collapsed", baseline.Accepted)
	}
}

func TestReleaseReportCommandPrintsSARIFFormatForValidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-valid",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report sarif: %v; stdout = %q", err, stdout.String())
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 {
		t.Fatalf("sarif = %+v, want one SARIF 2.1.0 run", decoded)
	}
	if decoded.Runs[0].Tool.Driver.Name != "AO Covenant Release Inspector" {
		t.Fatalf("driver = %+v", decoded.Runs[0].Tool.Driver)
	}
	if len(decoded.Runs[0].Results) != 0 {
		t.Fatalf("results = %+v, want no findings for valid release", decoded.Runs[0].Results)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsSARIFFormatForInvalidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-invalid",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactPath := filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64")
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) < 1 {
		t.Fatalf("sarif = %+v, want invalid artifact results", decoded)
	}
	result := decoded.Runs[0].Results[0]
	if result.RuleID != "RELEASE_ARTIFACT_PROBLEM" || result.Level != "error" {
		t.Fatalf("result = %+v, want artifact error", result)
	}
	if !strings.Contains(result.Message.Text, "sha256 mismatch") {
		t.Fatalf("message = %q, want sha256 mismatch", result.Message.Text)
	}
	if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "ao-covenant_v0.1.0_linux_amd64" {
		t.Fatalf("locations = %+v, want artifact path", result.Locations)
	}
	if result.Properties.Component != "artifact" || result.Properties.Name != "ao-covenant_v0.1.0_linux_amd64" || result.Properties.ReleaseDir != outDir {
		t.Fatalf("properties = %+v, want artifact properties", result.Properties)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesSARIFOutputFile(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-out",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactPath := filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64")
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	reportPath := filepath.Join(t.TempDir(), "release-report.sarif")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif",
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read SARIF report: %v", err)
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release report SARIF: %v; file = %q", err, string(bytes))
	}
	if decoded.Version != "2.1.0" || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) == 0 {
		t.Fatalf("sarif = %+v, want invalid release SARIF findings", decoded)
	}
	if strings.Contains(stdout.String(), `"version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandSARIFBaselineSuppressesAcceptedFindings(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-baseline",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactName := "ao-covenant_v0.1.0_linux_amd64"
	artifactPath := filepath.Join(outDir, artifactName)
	if err := os.WriteFile(artifactPath, []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	baselinePath := filepath.Join(t.TempDir(), "release-sarif-baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{
  "schema_version": "covenant.lint-sarif-baseline.v1",
  "accepted": [{
    "rule_id": "RELEASE_ARTIFACT_PROBLEM",
    "source_uri": "ao-covenant_v0.1.0_linux_amd64",
    "field": "artifact:ao-covenant_v0.1.0_linux_amd64",
    "justification": "accepted release fixture drift"
  }]
}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif",
		"--sarif-baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded schema.SARIFLog
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release report sarif: %v; stdout = %q", err, stdout.String())
	}
	if len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) < 1 {
		t.Fatalf("sarif = %+v, want accepted invalid artifact results", decoded)
	}
	for _, result := range decoded.Runs[0].Results {
		if result.RuleID != "RELEASE_ARTIFACT_PROBLEM" {
			t.Fatalf("result = %+v, want artifact-only baseline fixture result", result)
		}
		if result.Properties.Location != "artifact:"+artifactName {
			t.Fatalf("properties = %+v, want artifact location", result.Properties)
		}
		if len(result.Suppressions) != 1 || result.Suppressions[0].Kind != "external" || result.Suppressions[0].Justification != "accepted release fixture drift" {
			t.Fatalf("suppressions = %+v, want external accepted suppression", result.Suppressions)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandWritesSARIFBaselineOutputFile(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-baseline-out",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactName := "ao-covenant_v0.1.0_linux_amd64"
	if err := os.WriteFile(filepath.Join(outDir, artifactName), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	reportPath := filepath.Join(t.TempDir(), "release-sarif-baseline.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif-baseline",
		"--out", reportPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "release_report="+reportPath+"\n" {
		t.Fatalf("stdout = %q, want release report path", stdout.String())
	}
	bytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read SARIF baseline report: %v", err)
	}
	var decoded contract.LintSARIFBaseline
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode release report SARIF baseline: %v; file = %q", err, string(bytes))
	}
	if decoded.SchemaVersion != "covenant.lint-sarif-baseline.v1" || len(decoded.Accepted) != 1 {
		t.Fatalf("decoded = %+v, want one baseline template entry", decoded)
	}
	if decoded.Accepted[0].RuleID != "RELEASE_ARTIFACT_PROBLEM" ||
		decoded.Accepted[0].SourceURI != artifactName ||
		decoded.Accepted[0].Field != "artifact:"+artifactName {
		t.Fatalf("accepted = %+v, want artifact baseline template entry", decoded.Accepted)
	}
	if err := schema.ValidateBytes(schema.LintSARIFBaselineSchemaID, bytes); err != nil {
		t.Fatalf("SARIF baseline template did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	if strings.Contains(stdout.String(), `"schema_version"`) {
		t.Fatalf("stdout = %q, want only output file path", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsSARIFBaselineTemplateForInvalidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-baseline-template",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	artifactName := "ao-covenant_v0.1.0_linux_amd64"
	if err := os.WriteFile(filepath.Join(outDir, artifactName), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif-baseline",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded contract.LintSARIFBaseline
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode SARIF baseline template: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != "covenant.lint-sarif-baseline.v1" || len(decoded.Accepted) != 1 {
		t.Fatalf("decoded = %+v, want one baseline template entry", decoded)
	}
	entry := decoded.Accepted[0]
	if entry.RuleID != "RELEASE_ARTIFACT_PROBLEM" ||
		entry.SourceURI != artifactName ||
		entry.Field != "artifact:"+artifactName ||
		entry.Justification != "REVIEW: explain why this release finding is accepted" {
		t.Fatalf("entry = %+v, want accepted release artifact template entry", entry)
	}
	if err := schema.ValidateBytes(schema.LintSARIFBaselineSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("SARIF baseline template did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandPrintsEmptySARIFBaselineTemplateForValidRelease(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-sarif-baseline-template-empty",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--format", "sarif-baseline",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded contract.LintSARIFBaseline
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode SARIF baseline template: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != "covenant.lint-sarif-baseline.v1" || len(decoded.Accepted) != 0 {
		t.Fatalf("decoded = %+v, want empty baseline template", decoded)
	}
	if err := schema.ValidateBytes(schema.LintSARIFBaselineSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("SARIF baseline template did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandRejectsSARIFBaselineWithoutSARIF(t *testing.T) {
	baselinePath := filepath.Join(t.TempDir(), "release-sarif-baseline.json")
	if err := os.WriteFile(baselinePath, []byte(`{"schema_version":"covenant.lint-sarif-baseline.v1","accepted":[]}`), 0o644); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", filepath.Join(t.TempDir(), "missing-release"),
		"--sarif-baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--sarif-baseline requires --format sarif") {
		t.Fatalf("stderr = %q, want SARIF baseline diagnostic", stderr.String())
	}
	if strings.Contains(stderr.String(), "read manifest") {
		t.Fatalf("stderr = %q, want flag validation before release inspect", stderr.String())
	}
}

func TestReleaseReportCommandRejectsSARIFRedaction(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", filepath.Join(t.TempDir(), "missing-release"),
		"--format", "sarif",
		"--redact", "paths",
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "release report redaction is only supported for text, markdown, and JSON output") {
		t.Fatalf("stderr = %q, want SARIF redaction diagnostic", stderr.String())
	}
	if strings.Contains(stderr.String(), "read manifest") {
		t.Fatalf("stderr = %q, want redaction validation before release inspect", stderr.String())
	}
}

func TestReleaseReportCommandRejectsUnknownFormatBeforeInspect(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", filepath.Join(t.TempDir(), "missing-release"),
		"--format", "html",
	}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unsupported release report format "html"`) {
		t.Fatalf("stderr = %q, want unsupported format error", stderr.String())
	}
	if strings.Contains(stderr.String(), "read manifest") {
		t.Fatalf("stderr = %q, want format validation before release inspect", stderr.String())
	}
}

func TestReleaseReportCommandRedactsTextOutputWithPolicyProfile(t *testing.T) {
	outDir := t.TempDir()
	privateKeyPath := filepath.Join(outDir, "private.json")
	publicKeyPath := filepath.Join(outDir, "public.json")
	policyPath := filepath.Join(outDir, "redaction-policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": "covenant.report-redaction-policy.v1",
  "profiles": {
    "partner": {
      "redact": ["paths", "digests"]
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write redaction policy: %v", err)
	}
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privateKeyPath,
		"--public", publicKeyPath,
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	fingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")

	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "redact-report",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--sign-key", privateKeyPath,
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
		"--public-key", publicKeyPath,
		"--redaction-policy", policyPath,
		"--redaction-profile", "partner",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"release_dir: [REDACTED_PATH]",
		"manifest: [REDACTED_PATH] (valid)",
		"checksums: [REDACTED_PATH] (verified)",
		"signature: verified",
		"signature_file: [REDACTED_PATH]",
		"public_key_sha256: [REDACTED_DIGEST]",
		"- ao-covenant_v0.1.0_linux_amd64 (linux/amd64): verified",
		"  path: [REDACTED_PATH]",
		"problems: none",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	for _, forbidden := range []string{outDir, filepath.Join(outDir, "manifest.json"), fingerprint} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("stdout = %q, want %q redacted", output, forbidden)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReportCommandFailsForTamperedPackage(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "report-tamper",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	if err := os.WriteFile(filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64"), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"report",
		"--dir", outDir,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"checksums: " + filepath.Join(outDir, "SHA256SUMS") + " (invalid)",
		"- ao-covenant_v0.1.0_linux_amd64 (linux/amd64): invalid",
		"  digest: invalid",
		"problem: artifact \"ao-covenant_v0.1.0_linux_amd64\" sha256 mismatch",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %s", output, want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseVerifyCommandPrintsTamperedPackageJSON(t *testing.T) {
	outDir := t.TempDir()
	sourceDir := filepath.Clean(filepath.Join("..", ".."))
	var packageStdout bytes.Buffer
	var packageStderr bytes.Buffer
	packageCode := Run([]string{
		"covenant",
		"release",
		"package",
		"--source", sourceDir,
		"--out", outDir,
		"--version", "v0.1.0",
		"--commit", "verify-json",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
	}, &packageStdout, &packageStderr)
	if packageCode != 0 {
		t.Fatalf("package exit code = %d, stderr = %q", packageCode, packageStderr.String())
	}
	if err := os.WriteFile(filepath.Join(outDir, "ao-covenant_v0.1.0_linux_amd64"), []byte("tampered\n"), 0o755); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"release",
		"verify",
		"--dir", outDir,
		"--json",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	var decoded struct {
		SchemaVersion string   `json:"schema_version"`
		Verified      bool     `json:"verified"`
		ManifestPath  string   `json:"manifest_path"`
		ChecksumsPath string   `json:"checksums_path"`
		ArtifactCount int      `json:"artifact_count"`
		Problems      []string `json:"problems"`
		Artifacts     []struct {
			Name             string   `json:"name"`
			Verified         bool     `json:"verified"`
			DigestVerified   bool     `json:"digest_verified"`
			SizeVerified     bool     `json:"size_verified"`
			ChecksumVerified bool     `json:"checksum_verified"`
			Problems         []string `json:"problems"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode release verify json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ReleaseVerifyResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ReleaseVerifyResultSchemaID)
	}
	if decoded.Verified {
		t.Fatalf("verified = true, want false; decoded = %+v", decoded)
	}
	if decoded.ArtifactCount != 1 {
		t.Fatalf("artifact_count = %d, want 1", decoded.ArtifactCount)
	}
	if len(decoded.Problems) == 0 || !strings.Contains(decoded.Problems[0], "sha256 mismatch") {
		t.Fatalf("problems = %+v, want sha256 mismatch", decoded.Problems)
	}
	if len(decoded.Artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1", len(decoded.Artifacts))
	}
	if decoded.Artifacts[0].Verified || decoded.Artifacts[0].DigestVerified || decoded.Artifacts[0].SizeVerified || !decoded.Artifacts[0].ChecksumVerified {
		t.Fatalf("artifact status = %+v, want failed digest/size and matching checksum entry", decoded.Artifacts[0])
	}
	if len(decoded.Artifacts[0].Problems) == 0 || !strings.Contains(strings.Join(decoded.Artifacts[0].Problems, "\n"), "sha256 mismatch") {
		t.Fatalf("artifact problems = %+v, want sha256 mismatch", decoded.Artifacts[0].Problems)
	}
	if err := schema.ValidateBytes(schema.ReleaseVerifyResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("release verify result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestReleaseReadinessWorkflowValidatesPublicArtifacts(t *testing.T) {
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	sourceDir := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	if err := os.MkdirAll("artifacts", 0o755); err != nil {
		t.Fatalf("create artifacts directory: %v", err)
	}

	runJSON := func(name string, args ...string) []byte {
		t.Helper()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%s exit code = %d, stderr = %q", name, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s stderr = %q, want empty", name, stderr.String())
		}
		path := filepath.Join("artifacts", name+".json")
		if err := os.WriteFile(path, stdout.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return stdout.Bytes()
	}

	versionJSON := runJSON("version",
		"covenant", "version", "--json",
	)
	var versionResult struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(versionJSON, &versionResult); err != nil {
		t.Fatalf("decode version json: %v; json = %q", err, string(versionJSON))
	}
	if versionResult.SchemaVersion != schema.VersionResultSchemaID {
		t.Fatalf("version schema_version = %q, want %q", versionResult.SchemaVersion, schema.VersionResultSchemaID)
	}

	compileJSON := runJSON("compile",
		"covenant", "compile",
		"--brief", "examples/risky-change/brief.md",
		"--out", "contract.json",
		"--json",
	)
	var compileResult struct {
		ContractPath string `json:"contract_path"`
	}
	if err := json.Unmarshal(compileJSON, &compileResult); err != nil {
		t.Fatalf("decode compile json: %v; json = %q", err, string(compileJSON))
	}
	if compileResult.ContractPath != "contract.json" {
		t.Fatalf("compile contract path = %q, want contract.json", compileResult.ContractPath)
	}

	runJSON("lint-brief",
		"covenant", "lint",
		"--brief", "examples/risky-change/brief.md",
		"--json",
	)
	runJSON("lint-contract",
		"covenant", "lint",
		"--contract", "contract.json",
		"--json",
	)

	runResultJSON := runJSON("run",
		"covenant", "run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "release-ready",
		"--json",
	)
	var runResult struct {
		LedgerPath       string `json:"ledger_path"`
		EvidencePackPath string `json:"evidence_pack_path"`
	}
	if err := json.Unmarshal(runResultJSON, &runResult); err != nil {
		t.Fatalf("decode run json: %v; json = %q", err, string(runResultJSON))
	}
	if runResult.LedgerPath == "" || runResult.EvidencePackPath == "" {
		t.Fatalf("run result paths = %+v", runResult)
	}

	runJSON("verify",
		"covenant", "verify",
		"--ledger", runResult.LedgerPath,
		"--evidence", runResult.EvidencePackPath,
		"--json",
	)
	runJSON("policy-explain",
		"covenant", "policy", "explain",
		"--evidence", runResult.EvidencePackPath,
		"--json",
	)
	runJSON("policy-index",
		"covenant", "policy", "index",
		"--evidence", runResult.EvidencePackPath,
		"--json",
	)
	runJSON("policy-spine",
		"covenant", "policy", "spine",
		"--json",
	)

	keygenJSON := runJSON("bundle-keygen",
		"covenant", "bundle", "keygen",
		"--private", "covenant-private-key.json",
		"--public", "covenant-public-key.json",
		"--json",
	)
	var keygenResult struct {
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(keygenJSON, &keygenResult); err != nil {
		t.Fatalf("decode keygen json: %v; json = %q", err, string(keygenJSON))
	}
	if len(keygenResult.PublicKeySHA256) != 64 {
		t.Fatalf("public key fingerprint = %q, want 64 hex chars", keygenResult.PublicKeySHA256)
	}

	bundleExportJSON := runJSON("bundle-export",
		"covenant", "bundle", "export",
		"--contract", "contract.json",
		"--ledger", runResult.LedgerPath,
		"--evidence", runResult.EvidencePackPath,
		"--workspace", ".",
		"--out", "release-ready-bundle.zip",
		"--sign-key", "covenant-private-key.json",
		"--json",
	)
	var bundleExportResult struct {
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(bundleExportJSON, &bundleExportResult); err != nil {
		t.Fatalf("decode bundle export json: %v; json = %q", err, string(bundleExportJSON))
	}
	if bundleExportResult.PublicKeySHA256 != keygenResult.PublicKeySHA256 {
		t.Fatalf("bundle export public key = %q, want %q", bundleExportResult.PublicKeySHA256, keygenResult.PublicKeySHA256)
	}

	runJSON("bundle-verify",
		"covenant", "verify",
		"--bundle", "release-ready-bundle.zip",
		"--public-key", "covenant-public-key.json",
		"--json",
	)
	runJSON("bundle-inspect",
		"covenant", "bundle", "inspect",
		"--bundle", "release-ready-bundle.zip",
		"--public-key", "covenant-public-key.json",
		"--json",
	)
	runJSON("bundle-report",
		"covenant", "bundle", "report",
		"--bundle", "release-ready-bundle.zip",
		"--public-key", "covenant-public-key.json",
		"--json",
	)

	releaseJSON := runJSON("release-package",
		"covenant", "release", "package",
		"--source", sourceDir,
		"--out", "release",
		"--version", "v0.1.0-readiness",
		"--commit", "release-readiness",
		"--date", "2026-06-12T00:00:00Z",
		"--target", "linux/amd64",
		"--json",
	)
	var releaseResult struct {
		ManifestPath  string   `json:"manifest_path"`
		ArtifactPaths []string `json:"artifact_paths"`
	}
	if err := json.Unmarshal(releaseJSON, &releaseResult); err != nil {
		t.Fatalf("decode release package json: %v; json = %q", err, string(releaseJSON))
	}
	if releaseResult.ManifestPath != filepath.Join("release", "manifest.json") || len(releaseResult.ArtifactPaths) != 1 {
		t.Fatalf("release result = %+v", releaseResult)
	}
	manifestEntry := func(path string) string {
		t.Helper()
		if filepath.IsAbs(path) {
			relative, err := filepath.Rel(dir, path)
			if err != nil {
				t.Fatalf("make %s relative to %s: %v", path, dir, err)
			}
			path = relative
		}
		return filepath.ToSlash(filepath.Clean(path))
	}

	manifest := strings.Join([]string{
		"contract.json",
		manifestEntry(runResult.EvidencePackPath),
		"covenant-private-key.json",
		"covenant-public-key.json",
		manifestEntry(releaseResult.ManifestPath),
		"artifacts/version.json",
		"artifacts/compile.json",
		"artifacts/lint-brief.json",
		"artifacts/lint-contract.json",
		"artifacts/run.json",
		"artifacts/verify.json",
		"artifacts/policy-explain.json",
		"artifacts/policy-index.json",
		"artifacts/policy-spine.json",
		"artifacts/bundle-keygen.json",
		"artifacts/bundle-export.json",
		"artifacts/bundle-verify.json",
		"artifacts/bundle-inspect.json",
		"artifacts/bundle-report.json",
		"artifacts/release-package.json",
	}, "\n") + "\n"
	if err := os.WriteFile("schema-files.txt", []byte(manifest), 0o644); err != nil {
		t.Fatalf("write schema-files.txt: %v", err)
	}

	var validationStdout bytes.Buffer
	var validationStderr bytes.Buffer
	validationCode := Run([]string{
		"covenant", "schema", "validate",
		"--files-from", "schema-files.txt",
		"--json",
		"--out", "artifacts/schema-validation.json",
	}, &validationStdout, &validationStderr)
	if validationCode != 0 {
		t.Fatalf("schema validation exit code = %d, stdout = %q, stderr = %q", validationCode, validationStdout.String(), validationStderr.String())
	}
	if validationStdout.String() != "schema_validation_report=artifacts/schema-validation.json\n" {
		t.Fatalf("schema validation stdout = %q", validationStdout.String())
	}

	var finalValidationStdout bytes.Buffer
	var finalValidationStderr bytes.Buffer
	finalValidationCode := Run([]string{
		"covenant", "schema", "validate",
		"--file", "artifacts/schema-validation.json",
		"--json",
	}, &finalValidationStdout, &finalValidationStderr)
	if finalValidationCode != 0 {
		t.Fatalf("final schema validation exit code = %d, stdout = %q, stderr = %q", finalValidationCode, finalValidationStdout.String(), finalValidationStderr.String())
	}
	requireSchemaValidationReportSchema(t, finalValidationStdout.Bytes())
}

func TestBundleExportCommandWritesArchive(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--workspace", ".",
		"--out", "bundle.zip",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle=bundle.zip") || !strings.Contains(stdout.String(), "entry_count=") {
		t.Fatalf("stdout = %q, want bundle path and entry count", stdout.String())
	}
	if _, err := os.Stat("bundle.zip"); err != nil {
		t.Fatalf("bundle stat: %v", err)
	}
}

func TestBundleExportCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli-json",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli-json/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli-json/evidence-pack.json",
		"--workspace", ".",
		"--out", "bundle.zip",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string             `json:"schema_version"`
		BundlePath    string             `json:"bundle_path"`
		EntryCount    int                `json:"entry_count"`
		Manifest      bundlepkg.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode bundle export json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.BundleExportResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.BundleExportResultSchemaID)
	}
	if decoded.BundlePath != "bundle.zip" || decoded.EntryCount != len(decoded.Manifest.Entries) || decoded.Manifest.RunID != "bundle-cli-json" {
		t.Fatalf("decoded export result = %+v", decoded)
	}
	if err := schema.ValidateBytes(schema.BundleExportResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("bundle export result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestBundleExportCommandAttachesRevocations(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli-revocations",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}
	writeRevocationList(t, "revocations.json", "approval-not-used")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli-revocations/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli-revocations/evidence-pack.json",
		"--workspace", ".",
		"--revocations", "revocations.json",
		"--out", "bundle.zip",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle=bundle.zip") {
		t.Fatalf("stdout = %q, want bundle path", stdout.String())
	}
	if !zipContainsEntry(t, "bundle.zip", "revocations/revocations.json") {
		t.Fatalf("bundle.zip missing revocations/revocations.json")
	}
}

func TestBundleKeygenCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "covenant-private-key.json")
	publicPath := filepath.Join(dir, "covenant-public-key.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", privatePath,
		"--public", publicPath,
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion   string `json:"schema_version"`
		PrivateKeyPath  string `json:"private_key_path"`
		PublicKeyPath   string `json:"public_key_path"`
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode keygen json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.BundleKeygenResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.BundleKeygenResultSchemaID)
	}
	if decoded.PrivateKeyPath != privatePath || decoded.PublicKeyPath != publicPath {
		t.Fatalf("decoded paths = %q %q, want %q %q", decoded.PrivateKeyPath, decoded.PublicKeyPath, privatePath, publicPath)
	}
	if len(decoded.PublicKeySHA256) != 64 {
		t.Fatalf("public_key_sha256 = %q, want 64 hex chars", decoded.PublicKeySHA256)
	}
	if err := schema.ValidateBytes(schema.BundleKeygenResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("bundle keygen result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestBundleKeygenExportAndVerifySignedBundle(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var keygenStdout bytes.Buffer
	var keygenStderr bytes.Buffer
	keygenCode := Run([]string{
		"covenant",
		"bundle",
		"keygen",
		"--private", "covenant-private-key.json",
		"--public", "covenant-public-key.json",
	}, &keygenStdout, &keygenStderr)
	if keygenCode != 0 {
		t.Fatalf("keygen exit code = %d, stderr = %q", keygenCode, keygenStderr.String())
	}
	if !strings.Contains(keygenStdout.String(), "private_key=covenant-private-key.json") || !strings.Contains(keygenStdout.String(), "public_key=covenant-public-key.json") {
		t.Fatalf("keygen stdout = %q, want key paths", keygenStdout.String())
	}
	keyFingerprint := stdoutValue(t, keygenStdout.String(), "public_key_sha256")
	if len(keyFingerprint) != 64 {
		t.Fatalf("keygen public key sha256 = %q, want 64 hex chars", keyFingerprint)
	}

	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}

	var exportStdout bytes.Buffer
	var exportStderr bytes.Buffer
	exportCode := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--workspace", ".",
		"--out", "bundle.zip",
		"--sign-key", "covenant-private-key.json",
	}, &exportStdout, &exportStderr)
	if exportCode != 0 {
		t.Fatalf("export exit code = %d, stderr = %q", exportCode, exportStderr.String())
	}
	if stdoutValue(t, exportStdout.String(), "public_key_sha256") != keyFingerprint {
		t.Fatalf("export stdout = %q, want key fingerprint %s", exportStdout.String(), keyFingerprint)
	}

	var verifyStdout bytes.Buffer
	var verifyStderr bytes.Buffer
	verifyCode := Run([]string{
		"covenant",
		"verify",
		"--bundle", "bundle.zip",
		"--public-key", "covenant-public-key.json",
	}, &verifyStdout, &verifyStderr)
	if verifyCode != 0 {
		t.Fatalf("verify exit code = %d, stderr = %q", verifyCode, verifyStderr.String())
	}
	output := verifyStdout.String()
	for _, want := range []string{
		"verified=true",
		"run_id=bundle-cli",
		"public_key_sha256=" + keyFingerprint,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("verify stdout = %q, want %s", output, want)
		}
	}

	var verifyJSONStdout bytes.Buffer
	var verifyJSONStderr bytes.Buffer
	verifyJSONCode := Run([]string{
		"covenant",
		"verify",
		"--json",
		"--bundle", "bundle.zip",
		"--public-key", "covenant-public-key.json",
	}, &verifyJSONStdout, &verifyJSONStderr)
	if verifyJSONCode != 0 {
		t.Fatalf("verify json exit code = %d, stderr = %q", verifyJSONCode, verifyJSONStderr.String())
	}
	var verifyJSON struct {
		PublicKeySHA256 string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(verifyJSONStdout.Bytes(), &verifyJSON); err != nil {
		t.Fatalf("decode verify json: %v; stdout = %q", err, verifyJSONStdout.String())
	}
	if verifyJSON.PublicKeySHA256 != keyFingerprint {
		t.Fatalf("verify json public key sha256 = %q, want %q", verifyJSON.PublicKeySHA256, keyFingerprint)
	}
}

func TestBundleInspectCommandPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeBundleInspectFixture(t, false)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"inspect",
		"--bundle", "bundle.zip",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("inspect exit code = %d, stderr = %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"run_id=bundle-cli",
		"checksums=verified",
		"signature=unsigned",
		"artifact_count=1",
		"input_snapshot_count=1",
		"policy=policy-scripted_change-1 task=scripted_change decision=allow effect=file.write resource=demo-output/report.txt summary=allowed file.write on demo-output/report.txt",
		"artifact=scripted_change-artifact-1 path=demo-output/report.txt",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("inspect stdout = %q, want %s", output, want)
		}
	}
}

func TestBundleInspectCommandPrintsJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	publicKeyPath := writeBundleInspectFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"inspect",
		"--json",
		"--bundle", "bundle.zip",
		"--public-key", publicKeyPath,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("inspect exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		RunID          string `json:"run_id"`
		ChecksumStatus string `json:"checksum_status"`
		Signature      struct {
			Status      string `json:"status"`
			SignedEntry string `json:"signed_entry"`
		} `json:"signature"`
		ArtifactCount      int `json:"artifact_count"`
		PolicyExplanations []struct {
			Summary string `json:"summary"`
		} `json:"policy_explanations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode inspect json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.RunID != "bundle-cli" || decoded.ChecksumStatus != "verified" || decoded.Signature.Status != "verified" || decoded.Signature.SignedEntry != "bundle-manifest.json" || decoded.ArtifactCount != 1 {
		t.Fatalf("decoded inspect = %+v", decoded)
	}
	if len(decoded.PolicyExplanations) != 1 || decoded.PolicyExplanations[0].Summary != "allowed file.write on demo-output/report.txt" {
		t.Fatalf("policy explanations = %+v", decoded.PolicyExplanations)
	}
}

func TestApprovalCreateWritesTicket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"create",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--reason", "operator approved local test command",
		"--operator", "operator_alice",
		"--expires-at", "2099-01-02T03:04:05Z",
		"--out", "ticket.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ticket=ticket.json") {
		t.Fatalf("stdout = %q, want ticket path", stdout.String())
	}
	if !strings.Contains(stdout.String(), "operator_id=operator_alice") || !strings.Contains(stdout.String(), "expires_at=2099-01-02T03:04:05Z") {
		t.Fatalf("stdout = %q, want operator and expiration", stdout.String())
	}
	bytes, err := os.ReadFile("ticket.json")
	if err != nil {
		t.Fatalf("read ticket: %v", err)
	}
	var decoded struct {
		TicketID   string `json:"ticket_id"`
		TaskID     string `json:"task_id"`
		EffectType string `json:"effect_type"`
		Resource   string `json:"resource"`
		Approved   bool   `json:"approved"`
		OperatorID string `json:"operator_id"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode ticket: %v", err)
	}
	if decoded.TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("ticket id = %q", decoded.TicketID)
	}
	if decoded.TaskID != "scripted_change" || decoded.EffectType != "process.spawn" || decoded.Resource != "make-test" || !decoded.Approved {
		t.Fatalf("decoded ticket = %+v", decoded)
	}
	if decoded.OperatorID != "operator_alice" || decoded.ExpiresAt != "2099-01-02T03:04:05Z" {
		t.Fatalf("decoded ticket metadata = %+v", decoded)
	}
}

func TestApprovalCreatePrintsJSONResult(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"create",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--reason", "operator approved local test command",
		"--operator", "operator_alice",
		"--expires-at", "2099-01-02T03:04:05Z",
		"--out", "ticket.json",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		TicketPath    string `json:"ticket_path"`
		Ticket        struct {
			SchemaVersion string `json:"schema_version"`
			TicketID      string `json:"ticket_id"`
			OperatorID    string `json:"operator_id"`
			ExpiresAt     string `json:"expires_at"`
		} `json:"ticket"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode approval create json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalCreateResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ApprovalCreateResultSchemaID)
	}
	if decoded.TicketPath != "ticket.json" || decoded.Ticket.TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("decoded create result = %+v", decoded)
	}
	if decoded.Ticket.SchemaVersion != schema.ApprovalTicketSchemaID || decoded.Ticket.OperatorID != "operator_alice" || decoded.Ticket.ExpiresAt != "2099-01-02T03:04:05Z" {
		t.Fatalf("decoded ticket = %+v", decoded.Ticket)
	}
	if err := schema.ValidateBytes(schema.ApprovalCreateResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval create result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestApprovalCreateRejectsOutputPathWithMissingParent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	outPath := filepath.Join("missing", "ticket.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "create",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--reason", "operator approved local test command",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval create --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "ticket output")
}

func TestApprovalCreateRejectsOutputPathWithParentFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	parentFile := "tickets"
	outPath := filepath.Join(parentFile, "ticket.json")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "create",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--reason", "operator approved local test command",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval create --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
}

func TestApprovalCreateRejectsOutputPathDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	outPath := "ticket.json"
	if err := os.Mkdir(outPath, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "create",
		"--task", "scripted_change",
		"--effect", "process.spawn",
		"--resource", "make-test",
		"--reason", "operator approved local test command",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval create --out points to a directory")
	requireDirectoryTarget(t, outPath)
}

func TestApprovalInspectPrintsTicketSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "inspect", "--ticket", "ticket.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"ticket_id=approval-scripted_change-process_spawn-make-test", "task_id=scripted_change", "effect_type=process.spawn", "approved=true", "operator_id=operator_alice", "expires_at=2099-01-02T03:04:05Z"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), want)
		}
	}
}

func TestApprovalInspectPrintsJSONTicket(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "inspect", "--ticket", "ticket.json", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		TicketID      string `json:"ticket_id"`
		TaskID        string `json:"task_id"`
		OperatorID    string `json:"operator_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode approval inspect json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalTicketSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ApprovalTicketSchemaID)
	}
	if decoded.TicketID != "approval-scripted_change-process_spawn-make-test" || decoded.TaskID != "scripted_change" || decoded.OperatorID != "operator_alice" {
		t.Fatalf("decoded ticket = %+v", decoded)
	}
	if err := schema.ValidateBytes(schema.ApprovalTicketSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval inspect ticket did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestApprovalValidateChecksContractMatch(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "validate", "--contract", "contract.json", "--ticket", "ticket.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "valid=true") {
		t.Fatalf("stdout = %q, want valid=true", stdout.String())
	}
}

func TestApprovalValidatePrintsJSONResult(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "validate", "--contract", "contract.json", "--ticket", "ticket.json", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Valid         bool   `json:"valid"`
		TicketID      string `json:"ticket_id"`
		ContractPath  string `json:"contract_path"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode approval validate json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalValidateResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ApprovalValidateResultSchemaID)
	}
	if !decoded.Valid || decoded.TicketID != "approval-scripted_change-process_spawn-make-test" || decoded.ContractPath != "contract.json" {
		t.Fatalf("decoded validate result = %+v", decoded)
	}
	if err := schema.ValidateBytes(schema.ApprovalValidateResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval validate result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestApprovalAttachWritesApprovedContractAndDigest(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "attach", "--contract", "contract.json", "--ticket", "ticket.json", "--out", "approved-contract.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "approvals=1") {
		t.Fatalf("stdout = %q, want approvals=1", stdout.String())
	}
	if _, err := os.Stat("approved-contract.json.sha256"); err != nil {
		t.Fatalf("digest stat: %v", err)
	}
	bytes, err := os.ReadFile("approved-contract.json")
	if err != nil {
		t.Fatalf("read approved contract: %v", err)
	}
	var decoded struct {
		Approvals []struct {
			TicketID string `json:"ticket_id"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode approved contract: %v", err)
	}
	if len(decoded.Approvals) != 1 || decoded.Approvals[0].TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("approvals = %+v", decoded.Approvals)
	}
}

func TestApprovalAttachPrintsJSONResult(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "attach", "--contract", "contract.json", "--ticket", "ticket.json", "--out", "approved-contract.json", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	var decoded struct {
		SchemaVersion  string `json:"schema_version"`
		ContractPath   string `json:"contract_path"`
		ContractDigest string `json:"contract_digest"`
		ApprovalCount  int    `json:"approval_count"`
		TicketID       string `json:"ticket_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode approval attach json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalAttachResultSchemaID {
		t.Fatalf("schema_version = %q, want %q", decoded.SchemaVersion, schema.ApprovalAttachResultSchemaID)
	}
	if decoded.ContractPath != "approved-contract.json" || decoded.ContractDigest == "" || decoded.ApprovalCount != 1 || decoded.TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("decoded attach result = %+v", decoded)
	}
	if err := schema.ValidateBytes(schema.ApprovalAttachResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval attach result did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
}

func TestApprovalAttachRejectsOutputPathWithMissingParent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	outPath := filepath.Join("missing", "approved-contract.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "write contract: approval attach --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "approved contract")
	requirePathNotCreated(t, outPath+".sha256", "digest sidecar")
}

func TestApprovalAttachRejectsOutputPathWithParentFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	parentFile := "approved"
	outPath := filepath.Join(parentFile, "approved-contract.json")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "write contract: approval attach --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
	requirePathNotCreated(t, outPath+".sha256", "digest sidecar")
}

func TestApprovalAttachRejectsOutputPathDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	outPath := "approved-contract.json"
	if err := os.Mkdir(outPath, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval attach --out points to a directory")
	requirePathNotCreated(t, outPath+".sha256", "digest sidecar")
}

func TestApprovalAttachRemovesNewContractWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	outPath := "approved-contract.json"
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "write digest: approval attach --out points to a directory") {
		t.Fatalf("stderr = %q, want digest sidecar diagnostic", stderr.String())
	}
	if _, err := os.Stat(outPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("approved contract stat error = %v, want removed after digest failure", err)
	}
	if info, err := os.Stat(outPath + ".sha256"); err != nil {
		t.Fatalf("digest sidecar path stat: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("digest sidecar path is directory = false, want true")
	}
}

func TestApprovalAttachPreservesExistingContractWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	outPath := "approved-contract.json"
	previousContract := []byte("previous approved contract bytes\n")
	if err := os.WriteFile(outPath, previousContract, 0o600); err != nil {
		t.Fatalf("write previous approved contract: %v", err)
	}
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "write digest: approval attach --out points to a directory") {
		t.Fatalf("stderr = %q, want digest sidecar diagnostic", stderr.String())
	}
	bytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read restored approved contract: %v", err)
	}
	if string(bytes) != string(previousContract) {
		t.Fatalf("approved contract = %q, want previous %q", string(bytes), string(previousContract))
	}
	if info, err := os.Stat(outPath + ".sha256"); err != nil {
		t.Fatalf("digest sidecar path stat: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("digest sidecar path is directory = false, want true")
	}
}

func TestApprovalAttachReportsRollbackFailureWhenDigestSidecarFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeApprovalContract(t, "contract.json")
	writeProcessTicket(t, "ticket.json")
	outPath := "approved-contract.json"
	if err := os.Mkdir(outPath+".sha256", 0o755); err != nil {
		t.Fatalf("create digest sidecar directory: %v", err)
	}
	overrideRollbackOutputFileForWriteForTest(t, func(string, outputFileSnapshot) error {
		return errors.New("restore failed")
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "attach",
		"--contract", "contract.json",
		"--ticket", "ticket.json",
		"--out", outPath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{
		"write digest: approval attach --out points to a directory",
		"rollback output: restore failed",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestApprovalRevokeWritesSchemaValidRevocationList(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-scripted_change-process_spawn-make-test",
		"--reason", "operator revoked local process approval",
		"--out", "revocations.json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"revocations=revocations.json",
		"revoked_ticket_count=1",
		"ticket_id=approval-scripted_change-process_spawn-make-test",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), want)
		}
	}
	bytes, err := os.ReadFile("revocations.json")
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	if err := schema.ValidateBytes(schema.ApprovalRevocationsSchemaID, bytes); err != nil {
		t.Fatalf("revocation list did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	var decoded approval.RevocationList
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode revocations: %v", err)
	}
	if decoded.SchemaVersion != schema.ApprovalRevocationsSchemaID || len(decoded.RevokedTickets) != 1 {
		t.Fatalf("decoded revocations = %+v", decoded)
	}
	if decoded.RevokedTickets[0].TicketID != "approval-scripted_change-process_spawn-make-test" || decoded.RevokedTickets[0].Reason != "operator revoked local process approval" {
		t.Fatalf("decoded revoked ticket = %+v", decoded.RevokedTickets[0])
	}
}

func TestApprovalRevokeAppendsToExistingRevocationList(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeRevocationList(t, "revocations.json", "approval-existing")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-new",
		"--reason", "operator revoked another approval",
		"--out", "revocations.json",
		"--append",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "revoked_ticket_count=2") {
		t.Fatalf("stdout = %q, want two revoked tickets", stdout.String())
	}
	list, err := approval.ReadRevocationList("revocations.json")
	if err != nil {
		t.Fatalf("ReadRevocationList: %v", err)
	}
	if len(list.RevokedTickets) != 2 || list.RevokedTickets[0].TicketID != "approval-existing" || list.RevokedTickets[1].TicketID != "approval-new" {
		t.Fatalf("revoked tickets = %+v", list.RevokedTickets)
	}
}

func TestApprovalRevokeAppendCreatesRevocationListWhenOutputIsMissing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-new",
		"--reason", "operator revoked another approval",
		"--out", "revocations.json",
		"--append",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "revoked_ticket_count=1") {
		t.Fatalf("stdout = %q, want one revoked ticket", stdout.String())
	}
	bytes, err := os.ReadFile("revocations.json")
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	if err := schema.ValidateBytes(schema.ApprovalRevocationsSchemaID, bytes); err != nil {
		t.Fatalf("revocation list did not match published schema: %v\njson:\n%s", err, string(bytes))
	}
	list, err := approval.ReadRevocationList("revocations.json")
	if err != nil {
		t.Fatalf("ReadRevocationList: %v", err)
	}
	if len(list.RevokedTickets) != 1 || list.RevokedTickets[0].TicketID != "approval-new" {
		t.Fatalf("revoked tickets = %+v", list.RevokedTickets)
	}
}

func TestApprovalRevokeAppendRejectsInvalidExistingRevocationListWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	original := []byte(`{"schema_version":"covenant.approval-revocations.v1","revoked_tickets":[`)
	if err := os.WriteFile("revocations.json", original, 0o644); err != nil {
		t.Fatalf("write invalid existing revocations: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-new",
		"--reason", "operator revoked another approval",
		"--out", "revocations.json",
		"--append",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "read approval revocation list:") {
		t.Fatalf("stderr = %q, want read diagnostic", stderr.String())
	}
	current, err := os.ReadFile("revocations.json")
	if err != nil {
		t.Fatalf("read revocations after failed append: %v", err)
	}
	if !bytes.Equal(current, original) {
		t.Fatalf("revocations changed after failed append: got %q want %q", string(current), string(original))
	}
}

func TestApprovalRevokeAppendRejectsDuplicateTicketWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeRevocationList(t, "revocations.json", "approval-existing")
	original, err := os.ReadFile("revocations.json")
	if err != nil {
		t.Fatalf("read original revocations: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-existing",
		"--reason", "operator revoked duplicate approval",
		"--out", "revocations.json",
		"--append",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %q stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `validate approval revocation list: duplicate revoked ticket id "approval-existing"`) {
		t.Fatalf("stderr = %q, want duplicate ticket diagnostic", stderr.String())
	}
	current, err := os.ReadFile("revocations.json")
	if err != nil {
		t.Fatalf("read revocations after failed append: %v", err)
	}
	if !bytes.Equal(current, original) {
		t.Fatalf("revocations changed after failed append: got %q want %q", string(current), string(original))
	}
}

func TestApprovalRevokePrintsJSONRevocationList(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"approval",
		"revoke",
		"--ticket-id", "approval-scripted_change-process_spawn-make-test",
		"--reason", "operator revoked local process approval",
		"--out", "revocations.json",
		"--json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if err := schema.ValidateBytes(schema.ApprovalRevokeResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval revoke json did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	var decoded struct {
		SchemaVersion      string                  `json:"schema_version"`
		RevocationsPath    string                  `json:"revocations_path"`
		RevokedTicketCount int                     `json:"revoked_ticket_count"`
		TicketID           string                  `json:"ticket_id"`
		Revocations        approval.RevocationList `json:"revocations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode revoke json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalRevokeResultSchemaID || decoded.RevocationsPath != "revocations.json" || decoded.RevokedTicketCount != 1 || decoded.TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("decoded revoke result = %+v", decoded)
	}
	if decoded.Revocations.SchemaVersion != schema.ApprovalRevocationsSchemaID || len(decoded.Revocations.RevokedTickets) != 1 || decoded.Revocations.RevokedTickets[0].TicketID != "approval-scripted_change-process_spawn-make-test" {
		t.Fatalf("decoded nested revocations = %+v", decoded.Revocations)
	}
}

func TestApprovalRevokeRejectsOutputPathWithMissingParent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	outPath := filepath.Join("missing", "revocations.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "revoke",
		"--ticket-id", "approval-scripted_change-process_spawn-make-test",
		"--reason", "operator revoked local process approval",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval revoke --out parent directory does not exist")
	requirePathNotCreated(t, outPath, "revocations output")
}

func TestApprovalRevokeRejectsOutputPathWithParentFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	parentFile := "revocations"
	outPath := filepath.Join(parentFile, "revocations.json")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "revoke",
		"--ticket-id", "approval-scripted_change-process_spawn-make-test",
		"--reason", "operator revoked local process approval",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval revoke --out parent path is not a directory")
	requireFileContent(t, parentFile, "not a directory")
}

func TestApprovalRevokeRejectsOutputPathDirectoryTarget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	outPath := "revocations.json"
	if err := os.Mkdir(outPath, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run([]string{
		"covenant", "approval", "revoke",
		"--ticket-id", "approval-scripted_change-process_spawn-make-test",
		"--reason", "operator revoked local process approval",
		"--out", outPath,
	}, &stdout, &stderr)

	requireFailedOutputPathCommand(t, code, &stdout, &stderr, "approval revoke --out points to a directory")
	requireDirectoryTarget(t, outPath)
}

func TestApprovalRevocationsInspectPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeRevocationList(t, "revocations.json", "approval-scripted_change-process_spawn-make-test")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "revocations", "inspect", "--file", "revocations.json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"schema_version=covenant.approval-revocations.v1",
		"revoked_ticket_count=1",
		"ticket_id=approval-scripted_change-process_spawn-make-test reason=operator revoked local approval",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), want)
		}
	}
}

func TestApprovalRevocationsInspectPrintsJSONList(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeRevocationList(t, "revocations.json", "approval-scripted_change-process_spawn-make-test")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"covenant", "approval", "revocations", "inspect", "--file", "revocations.json", "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if err := schema.ValidateBytes(schema.ApprovalRevocationsInspectResultSchemaID, stdout.Bytes()); err != nil {
		t.Fatalf("approval revocations inspect json did not match published schema: %v\njson:\n%s", err, stdout.String())
	}
	var decoded struct {
		SchemaVersion      string                  `json:"schema_version"`
		RevocationsPath    string                  `json:"revocations_path"`
		RevokedTicketCount int                     `json:"revoked_ticket_count"`
		Revocations        approval.RevocationList `json:"revocations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode revocations inspect json: %v; stdout = %q", err, stdout.String())
	}
	if decoded.SchemaVersion != schema.ApprovalRevocationsInspectResultSchemaID || decoded.RevocationsPath != "revocations.json" || decoded.RevokedTicketCount != 1 {
		t.Fatalf("decoded revocations inspect result = %+v", decoded)
	}
	if decoded.Revocations.SchemaVersion != schema.ApprovalRevocationsSchemaID || len(decoded.Revocations.RevokedTickets) != 1 {
		t.Fatalf("decoded nested revocations = %+v", decoded.Revocations)
	}
}

func mustWriteTestFile(t *testing.T, path string, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepathDir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func stdoutValue(t *testing.T, output string, key string) string {
	t.Helper()
	prefix := key + "="
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("output = %q, want key %s", output, key)
	return ""
}

func filepathDir(path string) string {
	index := strings.LastIndex(path, "/")
	if index == -1 {
		return "."
	}
	return path[:index]
}

func structuredCompileBrief() string {
	return `# Objective
Create a release report.

# Writes
- reports/release.md

# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

## Obligation: obl_verify_passes
required: true
text: Verification passes.

# Tasks
## Task: draft_release_report
kind: scripted
writes:
- reports/release.md
obligations:
- obl_release_report

## Task: verify_release_report
kind: verify
depends_on:
- draft_release_report
obligations:
- obl_verify_passes
`
}

func writeApprovalContract(t *testing.T, path string) {
	t.Helper()
	writeApprovalContractForProcess(t, path, "make-test")
}

func writeApprovalContractForProcess(t *testing.T, path string, resource string) {
	t.Helper()
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	c.Tasks[0].DeclaredSideEffects = []contract.ActionRef{
		{Type: "process.spawn", Resource: resource},
	}
	c.Workspace.Writes = []string{}
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile(path, append(bytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
}

func writeDeniedProcessEvidence(t *testing.T) {
	t.Helper()
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	writeApprovalContractForProcess(t, "contract.json", "make-test")

	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "policy-explain-denied",
	}, &runStdout, &runStderr)
	if runCode != 1 {
		t.Fatalf("run exit code = %d, want 1; stderr = %q", runCode, runStderr.String())
	}
	if !strings.Contains(runStderr.String(), "process.spawn requires an approved ticket") {
		t.Fatalf("run stderr = %q, want policy denial", runStderr.String())
	}
	if _, err := os.Stat(".covenant/runs/policy-explain-denied/evidence-pack.json"); err != nil {
		t.Fatalf("evidence pack missing: %v", err)
	}
}

func TestFullRSIClaimBoundaryExamplesDocumentPolicyDecisions(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "examples", "full-rsi-claim-boundary")
	for _, required := range []string{
		"brief.md",
		"live-self-change-authority.packet.json",
		"denied.contract.json",
		"generic-approval.contract.json",
		"rollback-retained.contract.json",
		"evidence-approved.contract.json",
		"generic-approval-ticket.json",
		"rollback-retained-ticket.json",
		"evidence-approval-ticket.json",
	} {
		if _, err := os.Stat(filepath.Join(fixtureDir, required)); err != nil {
			t.Fatalf("full RSI claim boundary fixture %s missing: %v", required, err)
		}
	}
	authorityPacket := filepath.Join(fixtureDir, "live-self-change-authority.packet.json")
	var validateStdout bytes.Buffer
	var validateStderr bytes.Buffer
	validateCode := Run([]string{
		"covenant",
		"schema",
		"validate",
		"--schema", "covenant.live-self-change-authority.v1",
		"--file", authorityPacket,
		"--json",
	}, &validateStdout, &validateStderr)
	if validateCode != 0 {
		t.Fatalf("authority packet schema validation exit=%d stderr=%s stdout=%s", validateCode, validateStderr.String(), validateStdout.String())
	}
	for _, want := range []string{
		`"schema_id": "covenant.live-self-change-authority.v1"`,
		`"valid": true`,
	} {
		if !strings.Contains(validateStdout.String(), want) {
			t.Fatalf("authority packet validation stdout missing %q:\n%s", want, validateStdout.String())
		}
	}

	tests := []struct {
		name                 string
		contractFile         string
		wantDecision         string
		wantApprovalTicketID string
		wantReason           []string
	}{
		{
			name:         "denied-without-approval",
			contractFile: "denied.contract.json",
			wantDecision: "deny",
			wantReason:   []string{"claim_level=full_autonomous_self_mutating_rsi", "claim_level=bounded_governed_rsi", "mutation authority", "rollback", "live self-change"},
		},
		{
			name:                 "denied-with-generic-approval",
			contractFile:         "generic-approval.contract.json",
			wantDecision:         "deny",
			wantApprovalTicketID: "ticket-full-rsi-generic",
			wantReason:           []string{"approval ticket", "missing", "claim_level=full_autonomous_self_mutating_rsi", "claim_level=bounded_governed_rsi", "mutation authority", "rollback", "live self-change"},
		},
		{
			name:                 "denied-with-retained-rollback-rehearsal",
			contractFile:         "rollback-retained.contract.json",
			wantDecision:         "deny",
			wantApprovalTicketID: "ticket-full-rsi-rollback-retained",
			wantReason:           []string{"approval ticket", "retained rollback rehearsal", "insufficient", "claim_level=full_autonomous_self_mutating_rsi", "claim_level=bounded_governed_rsi", "mutation authority", "live self-change"},
		},
		{
			name:                 "allowed-with-evidence-approval",
			contractFile:         "evidence-approved.contract.json",
			wantDecision:         "allow",
			wantApprovalTicketID: "ticket-full-rsi-evidence",
			wantReason:           []string{"approved full RSI claim evidence", "claim_level=full_autonomous_self_mutating_rsi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runID := "full-rsi-" + tt.name
			outDir := filepath.Join(t.TempDir(), "runs")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run([]string{
				"covenant",
				"run",
				"--contract", filepath.Join(fixtureDir, tt.contractFile),
				"--workspace", fixtureDir,
				"--out", outDir,
				"--run-id", runID,
				"--json",
			}, &stdout, &stderr)
			if code == 2 {
				t.Fatalf("run exit code = %d, want executable fixture; stderr = %q", code, stderr.String())
			}

			decision := fullRSIClaimPolicyDecision(t, filepath.Join(outDir, runID, "evidence-pack.json"))
			if decision.Decision != tt.wantDecision {
				t.Fatalf("decision = %q, want %q; stderr = %q", decision.Decision, tt.wantDecision, stderr.String())
			}
			if decision.ApprovalTicketID != tt.wantApprovalTicketID {
				t.Fatalf("approval_ticket_id = %q, want %q", decision.ApprovalTicketID, tt.wantApprovalTicketID)
			}
			if !containsAllSubstrings(decision.Reason, tt.wantReason) {
				t.Fatalf("reason = %q, want tokens %v", decision.Reason, tt.wantReason)
			}
		})
	}
}

type testPolicyDecision struct {
	Decision         string `json:"decision"`
	EffectType       string `json:"effect_type"`
	Resource         string `json:"resource"`
	Reason           string `json:"reason"`
	ApprovalTicketID string `json:"approval_ticket_id"`
}

func fullRSIClaimPolicyDecision(t *testing.T, evidencePath string) testPolicyDecision {
	t.Helper()
	bytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence pack: %v", err)
	}
	var decoded struct {
		PolicyDecisions []testPolicyDecision `json:"policy_decisions"`
	}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode evidence pack: %v", err)
	}
	for _, decision := range decoded.PolicyDecisions {
		if decision.EffectType == "claim.publish" && decision.Resource == "full-autonomous-self-mutating-rsi" {
			return decision
		}
	}
	t.Fatalf("evidence pack %s did not contain full RSI claim policy decision", evidencePath)
	return testPolicyDecision{}
}

func containsAllSubstrings(value string, substrings []string) bool {
	for _, substring := range substrings {
		if !strings.Contains(value, substring) {
			return false
		}
	}
	return true
}

func writeApprovedProcessEvidence(t *testing.T) {
	t.Helper()
	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	writeApprovalContractForProcess(t, "contract.json", "go version")
	writeProcessTicketForResource(t, "ticket.json", "go version")

	var attachStdout bytes.Buffer
	var attachStderr bytes.Buffer
	attachCode := Run([]string{"covenant", "approval", "attach", "--contract", "contract.json", "--ticket", "ticket.json", "--out", "approved-contract.json"}, &attachStdout, &attachStderr)
	if attachCode != 0 {
		t.Fatalf("attach exit code = %d, stderr = %q", attachCode, attachStderr.String())
	}

	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "approved-contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "policy-index-approved",
		"--allow-process", "go version",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}
	if _, err := os.Stat(".covenant/runs/policy-index-approved/evidence-pack.json"); err != nil {
		t.Fatalf("evidence pack missing: %v", err)
	}
}

func writeBundleInspectFixture(t *testing.T, signed bool) string {
	t.Helper()
	publicKeyPath := ""
	signArgs := []string{}
	if signed {
		var keygenStdout bytes.Buffer
		var keygenStderr bytes.Buffer
		code := Run([]string{
			"covenant",
			"bundle",
			"keygen",
			"--private", "covenant-private-key.json",
			"--public", "covenant-public-key.json",
		}, &keygenStdout, &keygenStderr)
		if code != 0 {
			t.Fatalf("keygen exit code = %d, stderr = %q", code, keygenStderr.String())
		}
		publicKeyPath = "covenant-public-key.json"
		signArgs = []string{"--sign-key", "covenant-private-key.json"}
	}

	mustWriteTestFile(t, "examples/risky-change/brief.md", "Create demo-output/report.txt")
	c, err := contract.CompileBriefWithSource("Create demo-output/report.txt", "examples/risky-change/brief.md")
	if err != nil {
		t.Fatalf("CompileBriefWithSource error: %v", err)
	}
	contractBytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("encode contract: %v", err)
	}
	if err := os.WriteFile("contract.json", append(contractBytes, '\n'), 0o644); err != nil {
		t.Fatalf("write contract: %v", err)
	}
	var runStdout bytes.Buffer
	var runStderr bytes.Buffer
	runCode := Run([]string{
		"covenant",
		"run",
		"--contract", "contract.json",
		"--workspace", ".",
		"--out", ".covenant/runs",
		"--run-id", "bundle-cli",
	}, &runStdout, &runStderr)
	if runCode != 0 {
		t.Fatalf("run exit code = %d, stderr = %q", runCode, runStderr.String())
	}
	exportArgs := []string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--workspace", ".",
		"--out", "bundle.zip",
	}
	exportArgs = append(exportArgs, signArgs...)
	var exportStdout bytes.Buffer
	var exportStderr bytes.Buffer
	exportCode := Run(exportArgs, &exportStdout, &exportStderr)
	if exportCode != 0 {
		t.Fatalf("export exit code = %d, stderr = %q", exportCode, exportStderr.String())
	}
	return publicKeyPath
}

func writeBundleInspectFixtureWithRevocations(t *testing.T) {
	t.Helper()
	writeBundleInspectFixture(t, false)
	writeRevocationList(t, "revocations.json", "approval-not-used")
	var exportStdout bytes.Buffer
	var exportStderr bytes.Buffer
	code := Run([]string{
		"covenant",
		"bundle",
		"export",
		"--contract", "contract.json",
		"--ledger", ".covenant/runs/bundle-cli/events.ndjson",
		"--evidence", ".covenant/runs/bundle-cli/evidence-pack.json",
		"--workspace", ".",
		"--revocations", "revocations.json",
		"--out", "bundle.zip",
	}, &exportStdout, &exportStderr)
	if code != 0 {
		t.Fatalf("revocation export exit code = %d, stderr = %q", code, exportStderr.String())
	}
}

func writeProcessTicket(t *testing.T, path string) {
	t.Helper()
	writeProcessTicketForResource(t, path, "make-test")
}

func writeProcessTicketForResource(t *testing.T, path string, resource string) {
	t.Helper()
	ticket, err := approval.Create(approval.CreateInput{
		TaskID:     "scripted_change",
		EffectType: "process.spawn",
		Resource:   resource,
		Approved:   true,
		Reason:     "operator approved local test command",
		OperatorID: "operator_alice",
		ExpiresAt:  "2099-01-02T03:04:05Z",
	})
	if err != nil {
		t.Fatalf("Create approval ticket: %v", err)
	}
	if err := approval.WriteTicket(path, ticket); err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
}

func writeRevocationList(t *testing.T, path string, ticketID string) {
	t.Helper()
	if err := approval.WriteRevocationList(path, approval.RevocationList{
		SchemaVersion: approval.RevocationListSchemaVersion,
		RevokedTickets: []approval.RevokedTicket{
			{
				TicketID: ticketID,
				Reason:   "operator revoked local approval",
			},
		},
	}); err != nil {
		t.Fatalf("WriteRevocationList: %v", err)
	}
}

func zipContainsEntry(t *testing.T, zipPath string, entryName string) bool {
	t.Helper()
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip %s: %v", zipPath, err)
	}
	defer reader.Close()
	for _, file := range reader.File {
		if file.Name == entryName {
			return true
		}
	}
	return false
}

func lintResultCodes(result contract.LintResult) []string {
	codes := make([]string, 0, len(result.Diagnostics))
	for _, diagnostic := range result.Diagnostics {
		codes = append(codes, diagnostic.Code)
	}
	return codes
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validCLIContractJSON() string {
	return `{
  "schema_version": "covenant.contract.v1",
  "objective": "Create a schema validation demo contract.",
  "workspace": {
    "root": ".",
    "reads": ["brief.md"],
    "writes": ["reports/demo.txt"]
  },
  "tasks": [
    {
      "id": "task_demo",
      "kind": "scripted",
      "adapter": "process",
      "depends_on": [],
      "obligations": ["obl_demo"],
      "declared_side_effects": [
        {
          "type": "file.write",
          "resource": "reports/demo.txt"
        }
      ],
      "timeout_seconds": 60
    }
  ],
  "obligations": [
    {
      "id": "obl_demo",
      "text": "Create reports/demo.txt",
      "required": true
    }
  ],
  "policy": {
    "mode": "strict"
  },
  "approvals": [],
  "evaluator": {
    "required_obligations": ["obl_demo"]
  }
}`
}

func validCLIContractMap() map[string]any {
	var document map[string]any
	if err := json.Unmarshal([]byte(validCLIContractJSON()), &document); err != nil {
		panic(err)
	}
	return document
}
