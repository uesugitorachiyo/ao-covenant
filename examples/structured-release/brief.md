# Objective
Create a release report.

# Reads
- examples/risky-change/brief.md

# Writes
- reports/release.md

# Obligations
## Obligation: obl_release_report
required: true
text: Release report exists.

## Obligation: obl_verify_passes
required: true
text: Verification passes.

## Obligation: obl_review_clear
required: true
text: Review is clear.

# Tasks
## Task: draft_release_report
kind: scripted
writes:
- reports/release.md
reads:
- examples/risky-change/brief.md
obligations:
- obl_release_report
timeout_seconds: 45

## Task: verify_release_report
kind: verify
depends_on:
- draft_release_report
obligations:
- obl_verify_passes

## Task: review_release_report
kind: review
depends_on:
- verify_release_report
obligations:
- obl_review_clear
