# Security Policy

AO Covenant handles contracts, evidence bundles, signatures, and release metadata. Treat suspected vulnerabilities as sensitive until triaged.

The public [Threat Model](docs/threat-model.md) defines protected assets, trust
boundaries, mitigated threats, operator responsibilities, and non-goals.

## Reporting

Use GitHub Security Advisories for private disclosure when available. If advisories are unavailable, open an issue with a minimal description and avoid posting exploit details, private keys, tokens, customer data, or unreleased evidence bundles.

## Sensitive Material

Do not commit:

- Private keys or signing material
- Access tokens, API keys, cookies, or credentials
- Real production evidence bundles containing confidential data
- Local machine paths or user-specific environment files

Use synthetic fixtures for tests and examples.

## Supported Versions

This project is pre-1.0. Security fixes target the `main` branch until formal version support is defined.
