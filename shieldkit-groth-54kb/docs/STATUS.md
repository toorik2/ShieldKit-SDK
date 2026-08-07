# ShieldKit-Groth-54KB — Status (2026-08-06)

## Work package status

| WP | Status | Evidence |
|----|--------|----------|
| WP-0 foundation | **DONE** | vendor/SHA256SUMS (50 files), 00-baseline/ |
| WP-1 reference build | **DONE** | 01-artifact/wp1-reference-build.json — scriptBytes 54671 / score 54949 / 6 in / 1 tx, judge green; reconciliation documented (stabilization env) |
| WP-2 design freeze | **DONE** | design/01-04 + FREEZE.json; VK decision: product VK = d38f3cfc (current runtime; e52d09c3 is the older pin) |
| WP-3 verifier integration | **verifier side DONE** | 3 action builds green (56379/56664); material; replays; tamper; prove pipeline; covenant port (88B state lock) |
| WP-3 kit integration | **FULL LIFECYCLE GREEN (2026-08-06)** | deposit a9f3ee0a + transfer 242c669c + withdrawal fff3e5c3 accepted+broadcast on chipnet (pool c0188394, layout verifier@0-5/carrier@6/state@7) |
| WP-4 local qualification | **B-02-FINAL GREEN (2026-08-06)** | libauth + BCHN tma + MINED + LeanBCH 27/27 on identical txs; tx 59241/59241/59275 B, max unlock 9853 B, max op 7.09M; tamper scoped 0/2088 + consensus green |
| WP-5 chipnet live | **OPEN** | clean hosts, lifecycle, settlements |
| WP-6 formal integration | **OPEN** | Groth16-Formal diff_* extension |
| WP-7 red team + audits | **OPEN** | attack matrix foundation exists (tamper classes); 4 signed audits pending |
| WP-8 release | **DONE (2026-08-07)** | 08-release/ceremony-reuse.json; scans 08-release/{no-seven-carrier,source-policy,external-gate-boundaries,final-state-scan}.json; bundle+pin pins/pf6-release.pin.json (releaseId shieldkit-54kb-pf6-20260807-r1; hashes in pin + receipts) |
| WP-9 readiness declaration | **OPEN** | |

## Key numbers (frozen)

- Reference verifier: 54,671 B / 54,949 score / 6 inputs / 1 tx (pin match, judge green)
- Product verifier (9-input, VK d38f3cfc): wire 56,379 / score 56,664 / σ unlock 55,976 (55,421 verifier + 555 packet)
- vs PF10: 55,421 vs 90,977 verifier unlocks (39.1% smaller); 9 vs 13 inputs
- Max verifier op cost: 7,093,421 (withdrawal terminal) — under ceiling
- State covenant: 88 B (matches live PF10); rolling base 2,500 sats
- Proving: rapidsnark ~1.8 s/proof; witness deterministic (sha 529f5aea)

## Decisions requiring user awareness

1. **Product VK = d38f3cfc** (current v2-beta-product runtime), not the goal text's e52d09c3 (older pin generation). Swap machinery identical either way; documented in design/02 v2.
2. **pf6 packet-input lock = OP_1 carrier** (binding enforced by the terminal guard); the PF10 binding-redeem input does not exist in pf6.
3. No 30-day soak / no ceremony per the revised goal; ceremony-reuse recorded (single-contributor).
4. Live deployment (pool-create + actions on chipnet) is the next milestone; hot wallet 9.42 BCH funded.

## How to continue

1. Port packet/transition builders (design/04 v3) -> live deployment (source -> genesis -> deposit/transfer/withdrawal).
2. WP-4: BCHN testmempoolaccept + mined on the deployed pool; LeanBCH full-redeem; every-byte tamper corpus.
3. WP-6: extend Groth16-Formal diff_* to the pf6 adapter/binding/packing.
4. WP-7: attack matrix + 4 signed audit scopes.
5. ~~WP-8: release scans, bundle, pin~~ — DONE 2026-08-07 (scans + bundle + pin recorded under evidence/08-release/ and pins/).
6. WP-9: readiness declaration.
