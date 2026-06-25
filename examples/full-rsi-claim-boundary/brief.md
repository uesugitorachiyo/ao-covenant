# Full RSI Claim Boundary Fixture

Attempt to publish a full autonomous self-mutating RSI claim.

This fixture demonstrates that AO Covenant keeps the public claim
`full-autonomous-self-mutating-rsi` fail-closed unless an approval ticket
explicitly names mutation authority evidence, rollback evidence, and live
self-change evidence.

Retained rollback rehearsal evidence alone is intentionally insufficient. The
`rollback-retained.contract.json` fixture models the AO2, ao2-control-plane, AO
Command, and AO Forge retained rollback proof path while still denying
`claim_level=full_autonomous_self_mutating_rsi` until mutation authority and
live self-change evidence also exist.

Without those evidence classes, the allowed public wording is
`claim_level=bounded_governed_rsi`. The stronger
`claim_level=full_autonomous_self_mutating_rsi` wording remains denied until the
claim-publish policy gate passes.
