# AO Covenant Branch Protection

This runbook records the required GitHub branch protection settings for the
public AO Covenant repository. It keeps the policy-spine repository aligned
with the same public-readiness expectations documented in `CONTRIBUTING.md`,
`docs/public-readiness.md`, and the release threat model.

## Required Settings

Configure a branch protection rule or ruleset for `main` with these controls:

- Require a pull request before merging.
- Dismiss stale pull request approvals when new commits are pushed.
- Require status checks to pass before merging.
- Require branches to be up to date before merging when GitHub offers that
  control for the rule or ruleset.
- Require linear history.
- Restrict force pushes.
- Do not allow deletions.
- Include administrators in enforcement.

## Required Checks

Require these status checks before merge:

- `License policy`
- `Go ubuntu-latest`
- `Go macos-latest`
- `Go windows-latest`

These checks come from `.github/workflows/ci.yml`. `License policy` verifies
the canonical Apache-2.0 root license, NOTICE, and package metadata. The Go
matrix runs tests and vet on Ubuntu, macOS, and Windows, then checks diff
whitespace.

`Release Readiness` is a scheduled/manual smoke gate, not a pull-request
required check. It should stay green for public release confidence, but it does
not run on every pull request and should not block ordinary protected-branch
merges.

## Live Verification

Run the read-only verifier after changing branch protection or renaming CI
jobs:

```sh
scripts/verify-branch-protection.sh
```

The verifier uses `gh api` to inspect live protection for `main`, confirms the
required checks and protection toggles, and emits
`ao.covenant.branch-protection-audit.v1` JSON.

The `Production Readiness Ops` workflow in
`.github/workflows/production-readiness-ops.yml` runs the same
`scripts/verify-branch-protection.sh` drift check on a daily schedule and by
manual dispatch. It has read-only repository permissions and uses the workflow
`GH_TOKEN` only for live branch-protection inspection.

## Local Fallback

Before pushing public changes, run:

```sh
scripts/check-license-policy.sh
go test -count=1 ./...
go vet ./...
ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path); puts path }' .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/release-readiness.yml .github/workflows/production-readiness-ops.yml
git diff --check
```

For release-facing changes, also run:

```sh
tmpdir="$(mktemp -d)"
COVENANT_RELEASE_READINESS_DIR="$tmpdir" ./scripts/release-readiness.sh
rm -rf "$tmpdir"
```

Local checks do not replace branch protection. They reduce feedback time before
the required GitHub checks run.
