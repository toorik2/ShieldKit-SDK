# A1 SOUNDNESS CERTIFICATE — BN254 Groth16 chunked-covenant crown (170,366 B)

**Verdict: SOUND — A1-CERTIFIED.** On the FROZEN artifact, every soundness-critical forgery
rejects; all honest controls accept; the harness reproduces `totalBytes = 170,366` and every
per-chunk op-cost exactly; a machine-checked second VM (LeanBCH) agrees on accept + op-cost and
also rejects the forgery. **No forgery was found.**

- **Crown:** BN254 native-standard chunked-covenant grouped Groth16 verifier — 19 chunks
  (1 ECIP vk_x cert + 17 affine miller + 1 residue tail), 348 miller ops, reverse-threaded via
  CashToken NFT-commitment `hash256(state)` across every seam. **g2check chunk DELETED (T5-1).**
- **Lever stack:** T2-A+MODSTRIP + T4-KP + T5-1 (g2check-delete / fold+relocate) + T3-2 (ECIP
  divisor-cert vk_x). **totalBytes 170,366** (beats mr-zwets #1 standard 241,628 by −71,262;
  #1 non-standard 241,518 by −71,152).
- **Frozen at** verifier.cash `path-a-sub200k` commit `26917cae`.
- **Vectors:** `chunks.json` sha256 `f04f04dff08b10a6bf0a11e01b28e1d3aef0eb2f280c7fa2e7f19a7d6409abaa`.
- **Audit date:** 2026-07-11. Auditor: independent adversarial re-pass on the FROZEN artifact
  (`verify_bn_crown.mjs`, `forge_battery.mjs`, `xcheck_*` — fresh, reading only `chunks.json`), plus
  a fresh re-run of the committed generator-side semantic gates. All runs on the real BCH-2026
  consensus VM `createVirtualMachineBch2026(false)` (libauth 3.1.0-next.8).

This certificate is REPRODUCIBLE: the four `*.mjs` audit scripts and their captured
`transcript-*.log` outputs are banked alongside (see MANIFEST for sha256s).

---

## 1. The forge surface (why it is well-defined)

Each chunk's unlocking is `pushdata(pad) ++ pushdata(stateArgs…) ++ pushdata(redeem)`. The deployment
is **P2SH32**, so the redeem (the verifier logic) is hash-committed: it CANNOT be altered without
breaking the locking's `OP_HASH256 <hash256(redeem)> OP_EQUAL` pin. `verify_bn_crown.mjs` confirms
**all 19 redeems hash256-pin to their P2SH32 lockings and are embedded as the trailing pushdata of
their unlockings** — the on-chain executed logic is exactly the reviewed compiled verifier,
unbypassable. The only forgeable surface is the witness data (state limbs, ECIP hint + sqrt-cert,
miller slopes, residue `c`). The chain is anchored:

- **each seam:** a chunk recomputes its outgoing state and commits `tx.outputs[0].nftCommitment ==
  hash256(outBlob)` and `tokenCategory` continuity; the next chunk pins `tx.inputs[0].nftCommitment
  == hash256(inBlob)`. `outCommit[i] == inCommit[i+1]` for all 18 seams (chain-binding verified).
- **successor locking:** each non-terminal chunk commits `tx.outputs[0].lockingBytecode == <next
  chunk P2SH32 spk>` (OP_OUTPUTBYTECODE) and `OP_TXOUTPUTCOUNT == 1` — the state NFT cannot be
  rerouted or duplicated. The tail is terminal (no successor; verification complete).

## 2. Honest controls (must ACCEPT) — `transcript-harness-verify.log`

| control | VM | result |
|---|---|---|
| all 19 chunks, committed proof | real BCH-2026 consensus | **19/19 ACCEPT** |
| per-chunk op-cost == recorded | real consensus | ✓ every chunk (Σ 135,355,911) |
| every op-cost ≤ budget 8,032,800 | real consensus | ✓ (max 7,689,046; margin 343,754) |
| Σ(locking+unlocking) | measured | **170,366** ✓ |
| fresh generator rebuild (`unified_affine.mjs`, independent of frozen data) | real consensus | **TOTAL 170,366**, chunk-identical, internalChainOk=true (`transcript-rebuild-reproduce.log`) |
| 19 redeems hash256-pinned + embedded | — | 19/19 ✓ |
| chain-binding `outCommit[i]==inCommit[i+1]` | — | 18/18 seams; tail terminal ✓ |
| runtimeGeneral: empty-constructor chunks (same lockings verify any valid proof) | structural + replay | ✓ (see §5) |

## 3. Forge battery (must REJECT) — from-frozen, independent — `transcript-forge-battery.log`

Run on the real consensus VM against the FROZEN `chunks.json`. **165 forgery attempts, 0 accepting.**

| # | attack (surface) | span | expected | result |
|---|---|---|---|---|
| A | witness-tamper: flip the last witness byte (before the redeem push) | every chunk (19) | REJECT | **19/19 REJECT** |
| B | hashpin-tamper: flip a redeem byte → P2SH32 `hash256` pin mismatch | every chunk (19) | REJECT | **19/19 REJECT** |
| F | covIn-splice: wrong input-utxo NFT commitment (chunk spliced onto a wrong predecessor) | every chunk (19) | REJECT | **19/19 REJECT** |
| C1 | thread-escape: reroute `output[0]` → OP_1 (steal state NFT) | every pinned chunk (18) | REJECT | **18/18 REJECT** |
| C2 | thread-escape: reroute `output[0]` → attacker P2SH32 | every pinned chunk (18) | REJECT | **18/18 REJECT** |
| C3 | thread-escape: reroute `output[0]` → a different valid P2SH32 ≠ committed successor | every pinned chunk (18) | REJECT | **18/18 REJECT** |
| C4 | thread-escape: append an extra output after the honest successor (value 0, txValid holds) | every pinned chunk (18) | REJECT | **18/18 REJECT** |
| D | covOut-tamper: flip a byte of `output[0]` token nftCommitment | every pinned chunk (18) | REJECT | **18/18 REJECT** |
| E | category-swap: `output[0]` token category cd→ee (continuity) | every pinned chunk (18) | REJECT | **18/18 REJECT** |

Honest control for all 19 chunks re-confirmed ACCEPT in the same run (0 honest failures).

### Deep semantic gates (corroboration) — `transcript-generator-forge-gates.log`

The subgroup / divisor-cert / slope / residue *semantic* checks are exercised by the committed
generator-side attack scripts, which compile the IDENTICAL check logic hash-pinned into the frozen
redeems (§1) and run it on the real VM against freshly-crafted adversarial witnesses (the frozen
artifact holds only one honest witness per chunk, so a valid-looking-but-false witness must be
generator-crafted). These corroborate the load-bearing from-frozen battery above.

| gate | forgery | result |
|---|---|---|
| **T5-1** on-twist (vkx genesis, surface A) | not-on-twist B (`y+1`, off `y²=x³+3/(9+u)`) | REJECT |
| **T5-1** fold (final miller window `R_end==−ψ³(B)`, surface B) | cofactor B (`[r]·P₀`, on twist, order ∤ r) | REJECT |
| **T5-1** fold | small-subgroup B (order 10069, on twist) | REJECT |
| **T5-1** ladder (`attack_g2_subgroup`) | wrong-subgroup cofactor / small / mix | REJECT @ final chunk |
| — T5-1 verdict — | `allOk = true` (honest on-twist+fold ACCEPT; all 3 adversarial B REJECT) | ✓ |
| **T3-2** vk_x | fake divisor (`a_num0+1`) | REJECT |
| **T3-2** vk_x | wrong vk_x (`Qx+1` in seam2 / witness) | REJECT |
| **T3-2** vk_x | witness limb tamper (`in0/yA0/nfail/gr0/mA0/iad0/t1p`) | REJECT (each) |
| **T3-2** vk_x | `nfail:=0` understate / off-curve C (`x+1`) | REJECT |
| **T3-2** deep | wrong-Q, 6 variants (`Q+ICᵢ`, `2Q`, …) | REJECT (all) |
| **T3-2** deep | FS-grind: 300 linear-solve iters | **0 convergences** |
| **T3-2** deep | non-residue retry inflate / deflate / skip-a-QR | REJECT |
| **T3-2** deep | Q-vs-seam divergence / successor-spk redirect | REJECT |
| — T3-2 verdict — | `ANY FORGERY ACCEPTED = false` | ✓ |
| **miller** (`_s3_forge`) | forged λ[0]+1 / λ[mid] / all-zero slopes | REJECT (each); honest ACCEPT |
| **residue tail** (`forge_c`) | out-of-range / non-canonical `c` (e.g. `c₀+100p`) | commits **NO wrong residue** (BIAS%p==0 ⇒ reduceOutMul(x)≡x mod p); a false residue `fF'` rejects — benign representation malleability only, never a false statement |

## 4. Dual-VM cross-check — libauth (JS) vs LeanBCH (machine-checked) — `transcript-dualvm-leanbch.log`

Each chunk's input tx (the exact frozen bytes from `chunks.json`) is serialized via libauth
`encodeTransaction` and independently verified by the LeanBCH Lean-extracted BCH-2026 VM
(`.lake/build/bin/xcheck`, sha256 `63b868d7…`, LeanBCH commit `565f9255`).

| chunk | role | libauth accept / op-cost | LeanBCH accept / op-cost | match |
|---|---|---|---|---|
| 0 `vkx_ecip` | ECIP vk_x cert + T5-1 relocated gates (genesis root) | true / 5,366,810 | true / 5,366,810 | ✓ |
| 8 `ml_7[146,167)` | mid affine miller | true / 7,687,371 | true / 7,687,371 | ✓ |
| 15 `ml_14[293,314)` | worst-case max-op miller | true / 7,689,046 | true / 7,689,046 | ✓ |
| 0-forge | witness byte flip (attack A) | **false** (OP_VERIFY) | **false** (leanVerifyInput) | ✓ (both REJECT) |

LeanBCH also confirms `txValid=true` and `verifyTokens=true` for every honest chunk. On the honest
path the two VMs agree on op-cost **to the unit**; on the forge path both REJECT (the 1-unit op delta
26,524 vs 26,525 is a failure-path accounting nuance — libauth stops at the failing OP_VERIFY,
LeanBCH sums the three script-phase metrics — and is not load-bearing). **Status: MATCHED.**

## 5. runtimeGeneral (same lockings verify any valid proof)

All 19 chunk contracts have EMPTY constructors (`VkxEcip()`, `MillerAffineChunk()`, `ResidueTailU()`)
— no baked proof data, only the fixed VK — so the identical P2SH32 lockings verify any valid proof
under that VK. The banked `a1-certificate.json` records the replay evidence: a **distinct** proof#1
(public inputs 439832/401604) accepts end-to-end (internalChainOk=true, byte-identical lockings,
maxOp 7,688,654) and a dense near-r worst case (~2²⁵³−1) accepts end-to-end (byte-identical lockings,
maxOp 7,688,990; vkx ECIP op near-constant, no bit-loop blowup). **Re-confirmed fresh (2026-07-11,
`transcript-rebuild-reproduce.log`):** `ELIG_INSTANCE=proof1 node build/chunked/pairing/unified_affine.mjs`
→ all 19 chunks accept end-to-end, internalChainOk=true, byte-identical LOCKINGS (lock=35 P2SH32 every
chunk), maxOp 7,688,654 ≤ 8,032,800.

## 6. Non-soundness observations (token-safety PoC limits — NOT forgeries)

Consistent with the BLS crown's cert: the covenant pins the successor STATE (nftCommitment + category
continuity) and the successor LOCKING (OP_OUTPUTBYTECODE, verified live by battery C1–C3) and the
output COUNT (C4). The genesis inToken is empty and category is enforced for in→out continuity but not
pinned to a global constant, so an attacker running the WHOLE pipeline under their own token category
is accepted — an identity/deployment concern, never a false Groth16/pairing result. No accepting case
verifies a false statement.

---

**CONCLUSION:** No forgery was found. Every soundness-critical attack surface — P2SH32 hash-pin,
witness integrity, covenant state/locking/count binding, T5-1 g2-subgroup fold + on-twist relocation,
T3-2 ECIP divisor-cert, affine miller slopes, and residue final-exp — rejects adversarial witnesses
while honest proofs accept, reproducing `totalBytes = 170,366` exactly and confirmed on two
independent VMs. The 170,366 B crown is **A1-CERTIFIED SOUND**.
