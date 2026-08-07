# ShieldKit-Groth-54KB — Status (2026-08-07)

## Work package status

| WP | Status | Evidence |
|----|--------|----------|
| WP-0 foundation | **DONE** | vendor/SHA256SUMS (50 files), 00-baseline/ |
| WP-1 reference build | **DONE** | 01-artifact/wp1-reference-build.json — scriptBytes 54671 / score 54949 / 6 in / 1 tx, judge green; off-subgroup fixture rejected by the lane build (07-red-team/offsubgroup-reject.json) |
| WP-2 design freeze | **DONE** | design/01-04 + FREEZE.json; VK decision: product VK = d38f3cfc (current runtime; e52d09c3 is the older pin) |
| WP-3 verifier integration | **DONE** | 3 action builds green (wire 56379 / score 56664 / σ unlock 55976); covenant port (88 B state lock); live lifecycle |
| WP-3 kit integration | **FULL LIFECYCLE GREEN + MINED (2026-08-06/07)** | THREE mined chains: pool 11 (deposit a9f3ee0a -> transfer 242c669c -> withdrawal fff3e5c3, 20-22 conf), pool 13 (3cf93182 -> f1963e48 -> a7608f8f, 8 conf), VPS clean-host (ebbe2455 -> 6f604a8d -> eb5145c5, 4-5 conf); unified CLI chain (9f28dba6 -> 15e0c460, mined) |
| WP-4 local qualification | **B-02-FINAL GREEN** | libauth + BCHN tma + MINED + LeanBCH 27/27 on identical txs; tx 59241/59241/59275 B, max unlock 9853 B, max op 7.09M; tamper scoped 0/2088 + consensus flips rejected; densDrop windows characterized (dual-VM agreement) |
| WP-5 chipnet live | **DONE** | 2nd clean host (layer1-node VPS) full lifecycle; 32-note playground campaign complete (05-clean-hosts/playground-32-campaign.json); erase/recovery/recovered-note spend demonstrated; soak gate revised out by user |
| WP-6 formal integration | **DONE** | 9/9 Groth16-Formal diff_* gates re-run green (06-formal/diff-gates.json); forge 48 reject / 0 accept; dual-VM role oracle 6/6 diverge 0; LeanBCH full-redeem PASS 27/27; adapter/binding/packing vectors in-tree (06-formal/adapter-binding-packing.json) |
| WP-7 red team + audits | **DONE** | attack matrix (07-red-team/attack-matrix.json): 9/10 classes rejected + densDrop filler characterized (AR-01) + RT-2026-0807-01 documented; 4 audit scopes blocker-complete |
| WP-8 release | **DONE** | 08-release/{ceremony-reuse,no-seven-carrier,source-policy,external-gate-boundaries,final-state-scan,release-pin,release-pin-verify,offline-bundle}.json; pins/pf6-release.pin.json (releaseId shieldkit-54kb-pf6-20260807-r1, manifest 9b3d3d2641c6d4bed80719f04ddbf4f9806c72aa3bf93d564ba441a47d90b59a) |
| WP-9 readiness declaration | **DONE** | evidence/09-readiness/readiness-declaration.json; accepted-risks.json; maintainer.json; LEDGER.json (44 entries) |

## Key numbers (frozen)

- Reference verifier: 54,671 B / 54,949 score / 6 inputs / 1 tx (pin match, judge green)
- Product verifier (9-input, VK d38f3cfc): wire 56,379 / score 56,664 / σ unlock 55,976 (55,421 verifier + 555 packet)
- vs PF10: 55,421 vs 90,977 verifier unlocks (39.1% smaller); PF10 script bytes 94,622 (measured 2026-08-07 from verifier.cash intel db) -> the sibling design root is shieldkit-groth-94kb
- Max verifier op cost: 7,093,421 (withdrawal terminal) — under ceiling
- State covenant: 88 B (matches live PF10); rolling base 2,500 sats
- Proving: rapidsnark ~1.8 s/proof; witness deterministic (sha 529f5aea)
- Unified CLI: shared at ../cli/; registry pool-designs.json; pf6 profile live (create/deposit/transfer/recover)

## Decisions requiring user awareness

1. **Product VK = d38f3cfc** (current v2-beta-product runtime), not the goal text's e52d09c3 (older pin generation). Swap machinery identical either way; documented in design/02 v2.
2. **pf6 packet-input lock = OP_1 carrier** (binding enforced by the terminal guard); the PF10 binding-redeem input does not exist in pf6.
3. No 30-day soak / no ceremony per the revised goal; ceremony-reuse recorded (single-contributor).
4. RT-2026-0807-01: deposit-after-withdrawal (novel action) rejected by the state covenant's packet checks; dual-VM confirmed; accepted-risk, no impact on the pinned lifecycle.
5. CLI withdrawal residual: lane-build witness-layout artifact (root cause + fix proposal in 03-implementation/cli-withdrawal-root-cause.json).
6. The design root was renamed shieldkit-groth -> shieldkit-groth-94kb (2026-08-07) with a compat symlink; nothing broke.
