# AO Covenant Security Advisory Routing

AO Covenant handles contracts, evidence bundles, signatures, release metadata,
and local execution evidence. Security-sensitive reports should start private
unless it is clear that the issue contains no exploit details or sensitive
material.

Use this guide with the [security policy](../SECURITY.md), the
[threat model](threat-model.md), and the security-sensitive GitHub issue
template.

## Private-First Rule

Use GitHub Security Advisories for private disclosure when a report may involve
exploitation, secret exposure, release integrity, signing material, local
execution, provenance, or confidential evidence.

Private advisory URL:

```text
https://github.com/uesugitorachiyo/ao-covenant/security/advisories/new
```

When unsure, choose the private path first. Maintainers can later publish a
minimal public issue, release note, or advisory summary when disclosure is safe.

## When To Use A Private Advisory

Use a private advisory for reports involving:

- release signature bypass, checksum mismatch, attestation bypass, or
  provenance manipulation
- unauthorized local command execution or policy bypass
- private keys, signing material, credentials, access tokens, cookies, or API
  keys
- production evidence bundles, customer data, unreleased bundles, or local
  machine paths
- schema, redaction, or verification behavior that could mislead an operator
- actionable exploit steps that have not been triaged

## Minimal Public Report

If GitHub Security Advisories are unavailable, or if a public issue is needed
only to reserve a tracking number, open a minimal non-sensitive routing note.
The public issue should say only that a security-sensitive report exists and
that details will be shared privately.

Acceptable public summary:

```text
There may be a security-sensitive issue affecting release verification. I will
provide details privately.
```

Do not include reproduction steps, proof-of-concept details, exploit payloads,
private identifiers, or real evidence in the public issue.

## What To Include Privately

Private advisories should include enough detail for maintainers to reproduce
and assess the report safely:

- affected command, file, schema, workflow, release asset, or documentation
- AO Covenant version, commit, operating system, and install source
- expected behavior, observed behavior, and security impact
- minimal synthetic reproducer that avoids real secrets and confidential data
- whether private keys, credentials, production evidence bundles, unreleased
  bundles, customer data, or local paths may have been exposed
- whether any released artifact, signature, checksum, attestation, or
  provenance report may be affected

## What Not To Post Publicly

Do not post exploit details, private keys, tokens, customer data, production
evidence bundles, unreleased bundles, or local paths in public issues, pull
requests, comments, logs, screenshots, or workflow artifacts.

Do not paste full private advisory details into a public pull request. Security
fix pull requests should describe the public impact at a safe level and refer
to the private advisory or maintainer notes for sensitive details.

## Maintainer Handling

Maintainers should:

- acknowledge private reports when seen
- reproduce with synthetic data when possible
- keep sensitive details in the private advisory until disclosure is safe
- avoid requesting secrets, production evidence, or local paths in public
  threads
- land fixes through protected `main` with required CI
- publish a mitigation, release note, or advisory summary when public users
  need action

If sensitive material appears in a public issue, comment only with routing
instructions, remove or minimize the exposed material when possible, and follow
the secret leakage guidance in the security policy.
