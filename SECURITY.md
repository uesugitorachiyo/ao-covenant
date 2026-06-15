# Security Policy

AO Covenant handles contracts, evidence bundles, signatures, release metadata,
and local execution evidence. Treat suspected vulnerabilities as sensitive until
triaged.

The public [Threat Model](docs/threat-model.md) defines protected assets, trust
boundaries, mitigated threats, operator responsibilities, and non-goals. The
[security advisory routing guide](docs/security-advisory-routing.md) defines
when to use a private advisory and how to keep public reports minimal.

## Reporting

Use GitHub Security Advisories for private disclosure when available. Follow the
[security advisory routing guide](docs/security-advisory-routing.md) when a
report may include exploit details, private keys, tokens, customer data,
production evidence bundles, unreleased bundles, or local paths. Include:

- affected command, file, schema, workflow, or release asset
- AO Covenant version, commit, operating system, and install source
- minimal reproducer using synthetic data
- expected behavior, observed behavior, and security impact
- whether private keys, credentials, production evidence, or local paths may
  have been exposed

If advisories are unavailable, open a public issue with a minimal description
only. Do not post exploit details, private keys, tokens, customer data,
production evidence bundles, unreleased bundles, or local paths in public
issues.

## Response Expectations

This project is pre-1.0 and maintained on a best-effort basis. Security reports
are triaged on the `main` branch. Maintainers should:

- acknowledge private reports when they are seen
- confirm whether the report affects supported code or documentation
- reproduce the issue with synthetic data when possible
- prepare a fix, mitigation, documentation change, or non-applicability note
- avoid publishing exploit details before a fix or mitigation is available

Security fixes are expected to land through the normal protected-branch process:
pull request, required CI, and merge to `main`.

## Severity Guidance

Use the highest matching severity when reporting:

- **Critical:** remote or unauthenticated compromise of signing material,
  release artifacts, verification results, or arbitrary host execution.
- **High:** local privilege escalation, signature bypass, release verification
  bypass, unauthorized write execution, or exposure of private signing keys.
- **Moderate:** integrity drift in contracts, bundles, evidence packs, approval
  material, schema validation, or redaction behavior that can mislead an
  operator.
- **Low:** hardening gaps, incomplete diagnostics, documentation ambiguity, or
  denial-of-service issues without evidence integrity impact.

## Public Issue Guidance

Public issues are acceptable for non-sensitive hardening requests,
documentation gaps, dependency updates, and reproducible bugs that do not expose
exploit details or confidential data.

Do not post exploit details publicly until maintainers have had a reasonable
opportunity to triage and publish a fix or mitigation. When unsure, file a
private advisory or keep the public issue intentionally minimal.

## Sensitive Material

Do not commit:

- Private keys or signing material
- Access tokens, API keys, cookies, or credentials
- Real production evidence bundles containing confidential data
- Local machine paths or user-specific environment files

Use synthetic fixtures for tests and examples.

## Secret Leakage

If a private key, access token, production evidence bundle, unreleased bundle,
or local path is accidentally committed or posted:

- revoke or rotate the affected credential or signing key before relying on it
  again
- remove the material from the public report, branch, release, or artifact when
  possible
- treat any signed artifact produced after exposure as suspect until it is
  re-signed with trusted material
- disclose the impact in the relevant advisory, issue, or release note without
  repeating the secret value

## Supported Versions

This project is pre-1.0. Security fixes target the `main` branch until formal
version support is defined. Older commits, unpublished branches, local
experiments, and generated evidence fixtures are not supported security release
lines.
