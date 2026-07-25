# MANIFEST — BN254 Groth16 chunked-covenant native-standard crown, 170,366 B

| field | value |
|---|---|
| crown id | `bn254-native-crown-170366-patha` |
| track | `bn254-native-standard` |
| method | chunked-covenant, reverse-threaded (19 chunks over 348 miller ops) |
| deployment | P2SH32, CashToken-threaded (NFT-commitment `hash256(state)` across every chunk seam) |
| curve | BN254 / alt_bn128 |
| **totalBytes** | **170,366** (Σ locking+unlocking over the 19 verifying steps) |
| totalOperationCost | 135,355,911 |
| maxStepOperationCost | 7,689,046 (budget/input 8,032,800 — margin 343,754; all fit) |
| stageBytes | vkx 6,703 / miller 159,963 / tail 3,700 |
| topology | 1 ECIP vk_x cert (genesis/root) + 17 affine miller + 1 residue tail; **g2check chunk DELETED (T5-1)** |
| lever stack | T2-A+MODSTRIP + T4-KP + T5-1 (g2check-delete / fold+relocate) + T3-2 (ECIP divisor-cert vk_x) |
| P2SH class | **0 P2SH20 (a914)** / 18 P2SH32 (aa20) successor pins (tail terminal, unpinned) |
| status | **a1-certified** |
| beats | mr-zwets #1 native-STANDARD BN254 241,628 by −71,262; #1 non-standard 241,518 by −71,152 |

## Source / provenance

- **Source repo:** github.com/toorik2 verifier.cash (local `/home/toorik/Projects/verifier.cash`),
  branch `path-a-sub200k`.
- **Crown (integration) commit:** `26917cae` — "path-a: FINAL sound crown 170366 B, A1 gates pass"
  (per-lever integration commit `447d46c6`; vectors byte-identical between them).
- **Generator / builder:** `build/chunked/pairing/unified_affine.mjs` — freshly generates + measures
  every chunk under the deployed `buildCovStep` P2SH32 byte convention (rescheduled cashc compile).
  Imports `_millermath.mjs`, `gen_vkx_ecip.mjs` (T3-2), `gen_miller_affine.mjs` (T4-KP/T5-1),
  `gen_miller_residue.mjs` / tail. Default env (`T4KP`, `PEEPHOLE`, `T2A_CSE` all on; `ELIG_INSTANCE`
  unset ⇒ proof#0) reproduces the byte-identical 170,366 crown.
- **Build command:**
  `node build/chunked/pairing/unified_affine.mjs` → prints `TOTAL 170366 / 19 chunks`.
  `SAVE_DIR=<this dir> node build/chunked/pairing/unified_affine.mjs` dumped `chunks.json` + the 19
  `.cash` sources (the `SAVE_DIR` path is inert to the measurement). **NOT rebuilt for this
  certification — bytes are frozen at `26917cae`.**
- **Compiler:** vendored mr-zwets/cashscript rescheduling fork (`build/node_modules/cashc`,
  `vendor/cashc-resched`; registry pin `1c707c1dbf87396b30ba5e0704b1db44475ce893`).
- **VM:** libauth `@bitauth/libauth` 3.1.0-next.8 `createVirtualMachineBch2026(false)` (real BCH-2026
  consensus). Second oracle: LeanBCH Lean-extracted BCH-2026 VM
  (`/home/toorik/Projects/LeanBCH`, `.lake/build/bin/xcheck`).

## Lever stack (integrated, per-lever byte deltas)

| lever | integrated bytes | Δ | what |
|---|---|---|---|
| baseline (working sound crown) | 212,913 | — | 32-chunk g2check+vkx+miller+tail line |
| T2-A + MODSTRIP | 211,034 | −1,879 | InvokeCSE golf (undomint byte-exact-undo cert) + `%Pmod` dead-strip on canonical pass-through limbs |
| T4-KP | 194,550 | −16,484 | miller `k·P` specialization (bake each distinct `k·P` literal; semantics-null / byte-identical to runtime) |
| T5-1 | 179,536 | −15,014 | **delete g2check stage**; G2-subgroup check folded into the final miller window (`R_end == −ψ³(B)`); on-twist / on-G1 / input-canonicality relocated to the vkx genesis (mandatory gate) |
| T3-2 | 170,366 | −9,170 | ECIP divisor-cert vk_x (Liam-Eagen / garaga, CryptoExperts-audited ref) replaces the 8-chunk Jacobian MSM with one divisor-identity chunk |
| T1-A + DP-CLOSE | 170,366 | 0 | non-realizing on the deployed 19-chunk affine topology (score/tx-overhead lever needing OP_INPUTBYTECODE re-arch) |
| **FINAL** | **170,366** | **−42,547** vs baseline | |

## The crown bytes (canonical location)

The frozen witnesses + per-chunk hexes live in this directory in `chunks.json` (self-contained: each
of the 19 entries carries `lockingHex`, `redeemHex`, `unlockingHex`, `inCommit`, `outCommit`,
`operationCost`). Pointer:

| path | sha256 |
|---|---|
| `chunks.json` | `f04f04dff08b10a6bf0a11e01b28e1d3aef0eb2f280c7fa2e7f19a7d6409abaa` |

`steps.json` carries the per-step metadata derived from those hexes (name, stage, locking/unlocking
bytes, real-VM op-cost, `lockingSpk`, `redeemSha256`, `inCommit`/`outCommit`) plus the totals and the
`chunks.json` pointer — sufficient to identify and re-verify every chunk. The 19 `.cash` sources are
under `chunks/` exactly as compiled (reverse-threaded, real successor P2SH32 spks embedded).

## Files in this artifact

| file | sha256 | what |
|---|---|---|
| `MANIFEST.md` | (this file) | provenance + totals + lever stack |
| `A1-CERTIFICATE.md` | — | soundness verdict + full fresh forge table + dual-VM |
| `steps.json` | `03adba3b0cd3871a8012ed51b690f2d4515abe4e99641583433fbf238158491e` | per-step metadata + vectors pointer |
| `chunks.json` | `f04f04dff08b10a6bf0a11e01b28e1d3aef0eb2f280c7fa2e7f19a7d6409abaa` | 19 frozen chunks (locking/redeem/unlock hex + commits + op) |
| `manifest.json` | `12c2c64847e1d2568eb1d20fd52cea49f07f2407e069898cb772cc73b2cc6458` | original build manifest (per-chunk, lever, gates) |
| `measurement.json` | `ddf0312362dcd01e05126b34a3421d316bdfb5267c344f6cb769329c563a8255` | builder final measurement (total 170,366) |
| `a1-certificate.json` | `3b11be09005da63363387c819f503d76e107eaf42dc0dd3cd63bc5c8f9d40604` | original A1 forge-battery verdicts (13 gates) |
| `verify_bn_crown.mjs` | `b30d44734a8a24c7801d8168e30ed14a0f23ff2e84b3474ddb9da04c50b30e59` | from-frozen honest + op-cost + bytes + hash-pin + chain-binding reproducer |
| `forge_battery.mjs` | `c8d7195e2d0da3a51d456fcaa5cdb240d4eec6f553714d65d538c91d5d89d9c8` | from-frozen forge battery (witness / hashpin / covIn-splice / thread-escape / covOut / category) |
| `xcheck_affine_export.mjs` | `db416f75ff11abfe677dc14b91b85ac50ed1b2acbed2ac349db83346e1d1b695` | serialize a frozen chunk for the LeanBCH twin |
| `xcheck_forge.mjs` | `710060731be24f5225d01c5b2234d8ff03d2fbb51f61952c06697435d51d1d55` | serialize a forged chunk for the LeanBCH twin |
| `transcript-harness-verify.log` | `4f130395fb077a44767ff879ad5310730079173abdbaffe83e5d76891f684706` | 19/19 accept, op-cost exact, totalBytes 170,366, 19/19 pins, 18/18 seams |
| `transcript-forge-battery.log` | `b80be49c215a9e28ffbe10afea816548308d1ea7a8f41108b19e8b312b7d560e` | 0 accepting forgeries; every honest control accepts |
| `transcript-dualvm-leanbch.log` | `5b0565185385dbafe3ff43e16f5008a9bee1a1d259215907ca7873837c3f1836` | libauth == LeanBCH (accept + op-cost) on 3 chunks; both reject the forge |
| `transcript-generator-forge-gates.log` | `601f514c258468435eadd89c474b525618865b084beb54c4b0c89f9e41a94ca4` | T5-1 cofactor / T3-2 divisor / miller-slope / residue semantic gates |
| `transcript-rebuild-reproduce.log` | `0855e0b0f97b73099eae3eb2cbf585d356aa8342cb4cc96f63c24a27e73ef7f8` | fresh generator rebuild → TOTAL 170,366 (chunk-identical); proof#1 runtimeGeneral |

The four generator-side semantic scripts (`_atk_cofactor.mjs`, `attack_g2_subgroup.mjs`,
`attack_ecip_vkx.mjs`, `_atk_ecip_deep.mjs`, `_s3_forge.mjs`, `forge_c.mjs`) are committed at repo
`build/chunked/pairing/` on `path-a-sub200k` (they depend on the generator tree; not copied here).

## Reproduce

```
# from-frozen A1 (needs the repo's node_modules with @bitauth/libauth 3.1.0-next.8 on PATH)
node verify_bn_crown.mjs        # -> 19/19 accept; op-cost exact; totalBytes 170,366; 19/19 hash-pin; 18/18 seams
node forge_battery.mjs          # -> 0 accepting forgeries; 19 honest controls accept
# dual-VM (needs the LeanBCH xcheck binary)
node xcheck_affine_export.mjs chunks.json 8   # writes /tmp/xcheck_{tx,srcouts}.hex
( cd /home/toorik/Projects/LeanBCH && .lake/build/bin/xcheck )   # leanVerifyInput + leanFullOpCost
node xcheck_forge.mjs chunks.json 0           # forged bytes; LeanBCH must also reject
# deep semantic gates (from the generator tree)
cd /home/toorik/Projects/verifier.cash/build/chunked/pairing
node _atk_cofactor.mjs ; node attack_g2_subgroup.mjs ; node attack_ecip_vkx.mjs ; node _atk_ecip_deep.mjs
```

The three from-frozen scripts read ONLY `chunks.json` in this directory + `@bitauth/libauth`; they are
read-only w.r.t. the crown.
