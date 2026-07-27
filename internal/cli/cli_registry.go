package cli

import (
	"fmt"
	"io"
	"os"
)

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	return RunWithInput(args, os.Stdin, stdout, stderr)
}

func RunWithInput(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 2 {
		printUsage(stderr)
		return 2
	}

	switch args[1] {
	case "version":
		return runVersion(args[2:], stdout, stderr)
	case "compile":
		return runCompile(args[2:], stdout, stderr)
	case "lint":
		return runLint(args[2:], stdout, stderr)
	case "run":
		return runContract(args[2:], stdout, stderr)
	case "verify":
		return runVerify(args[2:], stdout, stderr)
	case "self-run":
		return runSelfRun(args[2:], stdout, stderr)
	case "release":
		return runRelease(args[2:], stdout, stderr)
	case "bundle":
		return runBundle(args[2:], stdout, stderr)
	case "approval":
		return runApproval(args[2:], stdout, stderr)
	case "policy":
		return runPolicy(args[2:], stdout, stderr)
	case "schema":
		return runSchema(args[2:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[1])
		printUsage(stderr)
		return 2
	}
}

func runRelease(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printReleaseUsage(stderr)
		return 2
	}
	switch args[0] {
	case "package":
		return runReleasePackage(args[1:], stdout, stderr)
	case "verify":
		return runReleaseVerify(args[1:], stdout, stderr)
	case "inspect":
		return runReleaseInspect(args[1:], stdout, stderr)
	case "report":
		return runReleaseReport(args[1:], stdout, stderr)
	case "diff":
		return runReleaseDiff(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown release command %q\n", args[0])
		printReleaseUsage(stderr)
		return 2
	}
}

func runApproval(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printApprovalUsage(stderr)
		return 2
	}
	switch args[0] {
	case "create":
		return runApprovalCreate(args[1:], stdout, stderr)
	case "inspect":
		return runApprovalInspect(args[1:], stdout, stderr)
	case "live-docs":
		return runApprovalLiveDocs(args[1:], stdout, stderr)
	case "mutation-class":
		return runApprovalMutationClass(args[1:], stdout, stderr)
	case "low-risk-code-live":
		return runApprovalLowRiskCodeLive(args[1:], stdout, stderr)
	case "validate":
		return runApprovalValidate(args[1:], stdout, stderr)
	case "attach":
		return runApprovalAttach(args[1:], stdout, stderr)
	case "revoke":
		return runApprovalRevoke(args[1:], stdout, stderr)
	case "revocations":
		return runApprovalRevocations(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown approval command %q\n", args[0])
		printApprovalUsage(stderr)
		return 2
	}
}

func runPolicy(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printPolicyUsage(stderr)
		return 2
	}
	switch args[0] {
	case "explain":
		return runPolicyExplain(args[1:], stdout, stderr)
	case "index":
		return runPolicyIndex(args[1:], stdout, stderr)
	case "spine":
		return runPolicySpine(args[1:], stdout, stderr)
	case "credential-checklist":
		return runPolicyCredentialChecklist(args[1:], stdout, stderr)
	case "claim-publish-gate":
		return runPolicyClaimPublishGate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown policy command %q\n", args[0])
		printPolicyUsage(stderr)
		return 2
	}
}

func runSchema(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 1 {
		printSchemaUsage(stderr)
		return 2
	}
	switch args[0] {
	case "catalog":
		return runSchemaCatalog(args[1:], stdout, stderr)
	case "export":
		return runSchemaExport(args[1:], stdout, stderr)
	case "validate":
		return runSchemaValidate(args[1:], stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown schema command %q\n", args[0])
		printSchemaUsage(stderr)
		return 2
	}
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant <command>")
	fmt.Fprintln(stderr, "commands: version, compile, lint, run, verify, self-run, release, bundle, approval, policy, schema")
}

func printApprovalUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval <command>")
	fmt.Fprintln(stderr, "commands: create, inspect, live-docs, mutation-class, low-risk-code-live, validate, attach, revoke, revocations")
}

func printApprovalLiveDocsUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval live-docs <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalMutationClassUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval mutation-class <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalLowRiskCodeLiveUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval low-risk-code-live <command>")
	fmt.Fprintln(stderr, "commands: validate")
}

func printApprovalRevocationsUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant approval revocations <command>")
	fmt.Fprintln(stderr, "commands: inspect")
}

func printPolicyUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant policy <command>")
	fmt.Fprintln(stderr, "commands: explain, index, spine, credential-checklist, claim-publish-gate")
}

func printSchemaUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant schema <command>")
	fmt.Fprintln(stderr, "commands: catalog, export, validate")
}

func printReleaseUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant release <command>")
	fmt.Fprintln(stderr, "commands: package, verify")
}

func printBundleUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: covenant bundle <command>")
	fmt.Fprintln(stderr, "commands: export, inspect, report, keygen")
}
