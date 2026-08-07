ShieldKit-Groth-54KB: swap ShieldKit-Groth's verifier (PF10-FusedQGenesis: 10 roles, 13-input actions, 90,977 B unlocks) to the pinned bn254-onetx-pf6-a3-r1 verifier (reference: 54,671 script bytes, score 54,949, 6 roles genesis/exec0-3/terminal; actions become 9 inputs = 6 verifier + binding + state + funding) and carry it to a production-readiness declaration.

RULES (hard):
- Work only in /home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/; no writes to ../shieldkit-groth-94kb/, ../verifier.cash/, or ../Groth16-Formal/.
- Execute PLAN.md WP-0..WP-9 in order; never skip, rename, or soften a gate.
- Inherit the BCH privacy mission policy unchanged: chipnet-only, zero mainnet claims, RULE 0 constant gate (bch_constants.lookup before any BCH numeric fact), TOOL-INVENTORY gate (bch_tool_inventory.lookup before building anything).
- Pinned toolchain only: cashc 1c707c1d, libauth 3.1.0-next.8, leanbch 51201015, Node 22.23.1, BCH-2026.
- Dual-VM evidence = libauth AND LeanBCH on identical bytes; every artifact is JSON with schema, sha256, and command.

CEREMONY POLICY: no new ceremony. Reuse the existing single-contributor material — the PRODUCT keys are the beta ceremony's (VK d38f3cfc / beta-proving-key 61683ef2..., verified by the runtime install receipt); the older dev pin (254a7bb2/e52d09c3) is superseded. The phase-2 keys are circuit-bound, not verifier-bound; the circuit is unchanged, so keys and proofs are reused unchanged. (phase-1 ptau randomness is circuit-independent; phase-2 keys are circuit-bound, not verifier-bound; the circuit is unchanged, so keys and proofs are reused unchanged). Record ceremonyQualified=false and d01Qualified=false; never claim ceremony independence. If the reference build's baked VK != e52d09c3, rebake the build with the product VK and re-measure (document byte-for-byte).

COMPLETION REQUIRES ALL OF:
(1) Reference pf6 build materialized: scriptBytes exactly 54671, 6 inputs, 1 tx; dual-VM accept on dense-proof-candidate-25 and reject on the offsubgroup fixture; divergence from the pin => stop and reconcile (pf7-sub62 worktree is the fallback), never proceed silently.
(2) design/ frozen: topology pf6-a3-direct-v1, 9-input layout, digest carrier/offset resolved from the adapter code, VK equality-or-rebake proof.
(3) pool create/deposit/transfer/withdraw/recover green with 9 inputs and exact-topology hard checks.
(4) B-02-final: libauth, BCHN testmempoolaccept, mined BCHN, and LeanBCH accept identical deposit/transfer/withdrawal; tx <=100,000 B, every unlock <=10,000 B, VM <=100%, all measured; tamper corpus fully rejected.
(5) Q-08: two clean hosts complete the full lifecycle incl. erase, recovery, and recovered-note spend. No 30-day soak gate: every live settlement recorded in the evidence ledger with matching count; live evidence bundles as budget allows.
(6) Groth16-Formal diff_* gates extended to the ShieldKit pf6 adapter/binding/packing; forge accepts 0; dual-VM role oracle for the 6 roles.
(7) Red team mandatory: attack matrix executed (forgery, state confusion, carrier substitution, digest mismatch, off-subgroup, dust/1-in-1000, reorg, thread escape, BQ-residual-no-fuel, genesis edge cases, terminal selector abuse); 4 signed audit scopes (protocol, implementation, formal/TCB, ops/release) with blocker-complete closure.
(8) Offline bundle + release pin (exact release ID + manifest SHA-256, no remote publication); fail-closed scans pass: no-seven-carrier, source policy, external-release-gate boundaries; ceremony-reuse evidence under evidence/ceremony-reuse/.
(9) Evidence ledger complete, accepted-risks-only register, maintainer.json, docs deltas, production-readiness declaration scoped to the single-contributor ceremony posture.

If any gate cannot be closed, prove the blocker with host-observable evidence and keep making safe progress; red team is never optional.
