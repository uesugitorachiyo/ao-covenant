# Governance

AO Covenant is currently a pre-1.0 project maintained through small,
reviewable slices on protected `main`. Governance is intentionally lightweight
until the project has a larger maintainer set and stable release cadence.

## Project Status

AO Covenant is pre-1.0. Public schemas, release artifacts, security posture, and
verification workflows are treated carefully, but the project may still change
behavior, CLI surfaces, and documentation as the design hardens.

The repository currently uses:

- protected `main`
- pull requests for changes
- required CI on Ubuntu, macOS, and Windows
- squash merges for slice work
- public documentation guards for important contributor and user docs

## Maintainer Decision Scope

Maintainers decide:

- whether a change fits the current project scope
- whether a public behavior is stable enough to document
- whether a release should be tagged or delayed
- whether security, provenance, or repository hygiene concerns block a change
- whether an issue or pull request should be closed, narrowed, or deferred

Maintainer decisions should favor evidence, tests, clear public documentation,
and the threat model over speed or breadth.

## Contribution Decisions

Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md). Maintainers may
request smaller pull requests, additional tests, documentation updates, schema
validation, release-readiness evidence, or public-readiness updates before
merge.

A contribution may be declined if it expands scope without enough evidence,
weakens verification, increases public API ambiguity, risks publishing sensitive
material, or conflicts with the [threat model](docs/threat-model.md).

## Release Decisions

Release decisions must follow the release operations and verification docs:

- [release operations](docs/release.md)
- [release verification walkthrough](docs/release-verification.md)
- [public readiness index](docs/public-readiness.md)

Maintainers should not publish release artifacts when required verification,
signing, provenance, repository hygiene, or disclosure expectations are not met.

## Pre-1.0 Expectations

Before 1.0, users and contributors should expect conservative changes to
contracts, schemas, CLI output, release artifacts, and documentation. Changes
that affect automation consumers should be documented and tested in the same
pull request.

Compatibility promises should be explicit. If a surface is not documented as
stable by the [public API stability policy](docs/public-api-stability.md),
treat it as subject to change before 1.0.
