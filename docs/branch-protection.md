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
- `Go macos-26`
- `Go windows-latest`

The macOS Go check is pinned to an explicit image label so GitHub's moving
`macos-latest` alias cannot silently change the required status context.

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

By default, the verifier runs in full mode. Full mode uses `gh api` to inspect
live protection and rulesets for `main`, confirms the required checks and
protection toggles, and emits `ao.covenant.branch-protection-audit.v1` JSON.
Full mode requires a GitHub token that can read branch-protection and ruleset
details.

The `Production Readiness Ops` workflow in
`.github/workflows/production-readiness-ops.yml` runs the same
`scripts/verify-branch-protection.sh` drift check on a daily schedule and by
manual dispatch. It has read-only repository permissions and uses the workflow
`GH_TOKEN` in limited mode:

```sh
AO_COVENANT_BRANCH_PROTECTION_MODE=limited scripts/verify-branch-protection.sh
```

Limited mode uses the branch metadata API that is visible to the workflow `GH_TOKEN`.
It confirms `main` is protected, verifies the required checks, and
requires status checks to be enforced for everyone. It does not replace the
stricter local full mode when branch-protection settings are changed.

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
