# AO Covenant Security Advisory Maintainer Checklist

Use this checklist when a private report may affect AO Covenant contracts,
evidence bundles, signing keys, release metadata, verification results, local
execution behavior, or public documentation. Pair it with the
[security policy](../SECURITY.md), [threat model](threat-model.md), and
[security advisory routing guide](security-advisory-routing.md). Use the
[release note template](release-note-template.md) when public release notes or
replacement notices need security-sensitive wording.

## Scope

This checklist is for maintainers handling private vulnerability reports and
security-sensitive public issues. It does not replace GitHub Security
Advisories, legal disclosure requirements, or incident response for services
outside this repository.

Do not request or copy private keys, credentials, customer data, production evidence bundles, unreleased bundles, or local machine paths into public issues, public pull requests, comments, screenshots, logs, release assets, or workflow artifacts.

## 1. Intake And Routing

- Keep reports private in GitHub Security Advisories when they include exploit
  details, signing material, production evidence, unreleased bundles, customer
  data, credentials, or local paths.
- If the report arrived through a public issue, reply with routing guidance
  only and avoid confirming exploitability in public.
- Record the affected command, schema, workflow, release asset, documentation
  page, operating system, version, and commit in private maintainer notes.
- Ask for a minimal synthetic reproducer when the report depends on sensitive
  evidence.

## 2. Containment And Evidence Safety

- Stop sharing sensitive material outside the private advisory.
- If signing material, credentials, release assets, or attestations may be
  affected, treat related releases as suspect until verified or replaced.
- Preserve only the minimum private evidence needed for triage.
- Use redacted summaries for public pull requests and do not repeat exploit details or secret values.

## 3. Triage And Severity

- Classify severity with the security policy: Critical, High, Moderate, or Low.
- Decide whether the issue affects supported code on `main`, release assets,
  generated bundles, schemas, documentation, or only unsupported local
  experiments.
- Identify user impact, affected versions or commits, and whether users need a
  workaround before a fix is released.
- Document non-applicability decisions in the private advisory when the report
  does not affect AO Covenant.

## 4. Fix And Verification

- Reproduce with synthetic data before changing code or docs.
- Add or update tests for the affected behavior before implementing the fix.
- Keep public PR text at a safe impact level and reference the private advisory
  only when needed.
- Run the relevant focused tests, then run:

```sh
go test -count=1 ./...
go vet ./...
./scripts/release-readiness.sh
git diff --check
```

- Confirm required GitHub checks pass on Ubuntu, macOS, and Windows before
  merging.

## 5. Disclosure And Release Notes

- Publish only the detail needed for users to assess impact and take action.
- Draft public release notes with the [release note template](release-note-template.md).
- Do not include exploit payloads, private keys, credentials, customer data,
  production evidence, unreleased bundles, or local paths.
- If a release artifact, signature, checksum, attestation, or provenance report
  was affected, state the affected versions and verification steps.
- If keys or credentials were exposed, document rotation or revocation status
  without repeating secret values.

## 6. Closure

- Confirm the fix or documentation update is merged to protected `main`.
- Confirm public release notes, advisory text, or issue summaries do not repeat
  exploit details or secret values.
- Close the private advisory only after the public user action is documented or
  a non-applicability decision is recorded.
- If follow-up hardening remains, open a non-sensitive public issue or tracked
  task with sanitized scope.
