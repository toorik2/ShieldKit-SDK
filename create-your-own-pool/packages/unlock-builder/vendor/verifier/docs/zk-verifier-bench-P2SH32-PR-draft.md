# P2SH32 PR draft — ready for your review + click (branch already pushed: toorik2:p2sh32-standardness)
# Create-PR URL: https://github.com/mr-zwets/zk-verifier-bench/compare/main...toorik2:p2sh32-standardness?expand=1
# (confirm base = mr-zwets/zk-verifier-bench : main, head = toorik2 : p2sh32-standardness, account = toorik2)

**Title:** Deploy the covenant Groth16 verifiers via P2SH32 (standard-relayable + smaller)

## What this does
Both covenant entries now deploy every chunk under a **P2SH32** envelope — locking = `OP_HASH256 <hash256(redeem)> OP_EQUAL` (35 B); the verifier redeem script moves into the unlocking (libauth executes the P2SH pattern natively). This flips **`fitsBchStandardness` false→true** (relayable under default mempool policy) on the standard VM, **and reduces the score**.

## Results (regenerated via `export-json.ts`)
| entry | was → now | Δ | standard |
|---|---|---|---|
| `bch-groth16-chunked-covenant` (BN254) | 472,510 → **402,287** | −70,223 | now **fits ✓** |
| `bch-groth16-bls12381-chunked-covenant` (BLS12-381) | 634,540 → **555,307** | −79,233 | now **fits ✓** |

Both remain `bch.compatible`, `tokenSafety.enforced`, `runtimeGeneral` (2/2), `inputValidation` (2/2). BN254 holds `frontier.current`.

## Why it's smaller (not just standard)
The 35 B P2SH32 locking replaces the bare per-chunk script (up to 2,793 B) in the output; the redeem moves into the unlocking, where on op-bound chunks it **rides inside the op-cost padding already paid**. Net: Σ-locking drops far more than the unlocking grows. **Zero** chunks exceed the 10,000 B standard unlocking cap (max 9,885 BN254 / 9,727 BLS).

## Soundness preserved (gates re-run independently)
- Forward-chain re-bakes to `hash256(P2SH32(next redeem))` — still uniquely + transitively pins the next chunk (the P2SH32 script embeds `hash256(next redeem)`). Baton-custody (self-P2SH32) unchanged.
- Adversarial covenant gates under P2SH: **BN254 99/0, BLS12-381 120/0** — identical pass-counts to the bare build (honest chain accepts; all forgeries reject: forward-chain redirect, wrong-stage seam, tower/coeffs/single-hash tamper, cross-region, foreign-category, baton-spend, direct-mint, off-curve A, off-subgroup B).

## One note
Padding is sized against the **standard** VM (`createVirtualMachineBch2026(true)`), which charges 3× per hash iteration (192 vs 64 op) — so the heaviest chunks were re-measured to fit with margin.

## Diff
4 files: the two covenant vector JSONs (now P2SH32-wrapped), `results.json`, `score-history.json`. **No harness or implementation change** — the impl reads vectors verbatim and P2SH executes natively.

## Reproduce
`npx tsx src/harness/export-json.ts`
