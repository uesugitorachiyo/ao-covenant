# Full RSI Claim Boundary Fixture

Attempt to publish a full autonomous self-mutating RSI claim.

This fixture demonstrates that AO Covenant keeps the public claim
`full-autonomous-self-mutating-rsi` fail-closed unless an approval ticket
explicitly names mutation authority evidence, rollback evidence, and live
self-change evidence.

The `live-self-change-authority.packet.json` fixture is a schema-backed example
of the mutation authority packet required before the stronger claim can be
considered. It is validated against `covenant.live-self-change-authority.v1` and
names repository, branch, allowed write surface, approval identity, expiry,
exact digest, rollback evidence, live self-change evidence, and observer
readback.

Retained rollback rehearsal evidence alone is intentionally insufficient. The
`rollback-retained.contract.json` fixture models the AO2, ao2-control-plane, AO
Command, and AO Forge retained rollback proof path while still denying
`claim_level=full_autonomous_self_mutating_rsi` until mutation authority and
live self-change evidence also exist.

Without those evidence classes, the allowed public wording is
`claim_level=bounded_governed_rsi`. The stronger
`claim_level=full_autonomous_self_mutating_rsi` wording remains denied until the
claim-publish policy gate passes.
