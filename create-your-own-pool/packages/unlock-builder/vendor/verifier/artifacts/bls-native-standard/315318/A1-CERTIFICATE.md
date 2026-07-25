# A1 SOUNDNESS CERTIFICATE — BLS12-381 Groth16 grouped-residue crown (315,318 B)

**Verdict: SOUND — A1-CERTIFIED.** Every soundness forgery rejects; all honest controls
accept; harness score reproduces exactly; a machine-checked second VM (LeanBCH) agrees on
accept + op-cost for all four groups and rejects the forgery.

- **Crown:** grouped-residue BLS12-381 Groth16 verifier, 4 groups `[9,9,9,9]` / 36 inputs.
- **Lever stack:** g2-fold (fused G2-subgroup test) + ECIP divisor-cert vk_x + L10 affine-slope
  offload of pair-0 + L01.
- **totalBytes 315,318 / full score 316,946** (beats mr-zwets #1 339,297 std by −22,351).
- **Frozen at** verifier.cash `bls-crown` commit `afc4bc49` (vectors unchanged since).
- **Vectors:** `harness/src/bch/groth16-bls12381-grouped-residue-vectors.json`
  sha256 `5463649d0d79d9697e1c71deb8db78781681f47b5a86ce846b1eeb388ab54025`.
- **Audit date:** 2026-07-11. Auditor: independent adversarial pass (fresh witnesses, not the
  generator's built-in battery). All runs on the real BCH-2026 consensus VM
  (`createVirtualMachineBch2026(false)`) and the harness loosened VM
  (`createLoosenedVm`, `harness/src/harness/vm.ts`).

This certificate is REPRODUCIBLE: the five `*.mjs` audit scripts and their captured
`transcript-*.log` outputs are banked alongside. Re-run from a machine with the repo's
`node_modules` (`@bitauth/libauth` 3.1.0-next.8) on the frozen vectors.

---

## 1. The forge surface (why it is well-defined)

Each step's unlocking is `pushdata(inBlob) ++ pushdata(extras…) ++ pushdata(pad) ++ pushdata(redeem)`.
The deployment is **P2SH32**, so the redeem (the verifier logic) is hash-committed: it CANNOT be
altered without breaking the locking's `hash256(redeem)` pin. **All 36 redeems were verified to
hash256-pin to their P2SH32 lockings** (`transcript-hashpin.log`) — the on-chain executed logic is
exactly the reviewed compiled verifier, unbypassable. The only forgeable surface is therefore the
witness data: the committed `inBlob` state and the *uncommitted* `extras` (L10 slopes, residue `w`,
ECIP hint + sqrt-cert grblob). The chain is anchored by:

- **within a group** (intra-tx bundle of linked inputs): each non-final chunk recomputes its
  outgoing blob and `require`s it byte-equals the next sibling input's `inBlob`, read via
  `tx.inputs[idx+1].unlockingBytecode` (OP_INPUTBYTECODE) — a forward byte-equality pin;
- **across groups**: the last chunk commits `tx.outputs[0].nftCommitment == hash256(outBlob)` and
  `tx.outputs[0].tokenCategory == tx.inputs[0].tokenCategory`; the next group's first chunk pins
  `tx.inputs[0].nftCommitment == hash256(inBlob)`. State is hash-bound across every boundary.

## 2. Honest controls (must ACCEPT)

| control | VM | result |
|---|---|---|
| committed proof, all 36 steps | loosened + real consensus | ACCEPT (both) |
| extra proof #1 (distinct statement, SAME lockings) | real consensus | ACCEPT — runtime-general |
| every step op-cost ≤ budget 8,032,800 | real consensus | ✓ (max 7,435,167) |
| loosened op-cost == real op-cost, every step | both | ✓ identical |

Σ op-cost 246,630,270 and maxStepOp 7,435,167 both match the vectors' recorded totals.

## 3. Forge battery (must REJECT) — independent, against the FROZEN artifact

Run on the real consensus VM. Full log: `transcript-forge-battery.log`.

| # | attack (surface) | expected | result |
|---|---|---|---|
| A | flip 1 byte of `inBlob` in **every** step (36×) — forward-commitment integrity | REJECT | **36/36 REJECT** |
| B1 | L10 witnessed-slope tamper (step 1, genesis miller window) | REJECT | REJECT |
| B1b | L10 witnessed-slope tamper (step 5, mid-group) | REJECT | REJECT |
| B2 | residue-`w` witness tamper (step 30, residue walk) | REJECT | REJECT |
| B3 | ECIP hint/witness limb tamper (step 0) | REJECT | REJECT |
| B3b | ECIP grblob (sqrt-nonresidue cert) tamper (step 0, 528-B blob) | REJECT | REJECT |
| C1 | cross-instance splice: proof#1 witness → committed run, step 0 (genesis) | REJECT | REJECT |
| C2 | cross-instance splice, step 5 (mid-group) | REJECT | REJECT |
| C3 | cross-instance splice, step 9 (group1 first, token boundary) | REJECT | REJECT |
| C4 | cross-instance splice, step 18 (group2 first) | REJECT | REJECT |
| C5 | cross-instance splice, step 30 (residue) | REJECT | REJECT |
| C6 | splice ENTIRE group1 from proof#1 (NFT-commitment boundary) | REJECT | REJECT |
| D1 | group0 output NFT-commitment tamper (covout `hash256`) | REJECT | REJECT |
| D2 | group1 input NFT-commitment tamper (covInHash `hash256`) | REJECT | REJECT |
| D3 | group0 output token CATEGORY swap (be→cd) — category continuity | REJECT | REJECT |
| D4 | capability escalation mutable→minting (group0 output token) | REJECT | REJECT (token consensus) |

**17/17 soundness-critical forgeries reject. 0 accepting forgeries.**

### Deep semantic checks (generator forge gates — same require()s compiled into the frozen redeems)

The subgroup / slope / divisor-cert *semantic* checks were additionally exercised by the generators'
built-in A1 gates on freshly-compiled chunks carrying the identical check logic
(`transcript-generator-forge-gates.log`). These are corroboration; the frozen-artifact battery above
is the load-bearing evidence (and the hash-pin proves the frozen redeems carry these very checks).

| gate | forgery | result |
|---|---|---|
| miller-residue | off-TWIST B (genesis `y²=x³+(4+4u)` fail) | REJECT |
| miller-residue | on-twist off-SUBGROUP B (final `psi(B) == −[\|x\|]B` fail) | REJECT |
| miller-residue | tampered slope (affDbl/affAdd `lam` require) | REJECT |
| miller-residue | wrong intermediate point (forced-derivation + covOut) | REJECT |
| ECIP vk_x | fake divisor (perturb a_num) | REJECT (×3 instances) |
| ECIP vk_x | wrong Q (Q ≠ IC0+Σinᵢ·ICᵢ) | REJECT (×3) |
| ECIP vk_x | FS-grind a hint coeff | REJECT (×3) |
| ECIP vk_x | tamper a point-challenge term | REJECT (×3) |
| ECIP vk_x | non-canonical in0 = in0+r (≥ r) | REJECT (×3) |
| ECIP vk_x | tamper a sqrt-nonresidue cert in grblob | REJECT |

## 4. Dual-VM cross-check — libauth (JS) vs LeanBCH (machine-checked)

Each group's input-0 tx (the exact frozen bytes) serialized via libauth `encodeTransaction` and
independently verified by the LeanBCH Lean-extracted BCH-2026 VM. Full log:
`transcript-dualvm-leanbch.log` (xcheck binary sha256 recorded therein).

| group | input-0 chunk | libauth accept / op-cost | LeanBCH accept / op-cost | match |
|---|---|---|---|---|
| 0 | ECIP vk_x divisor cert (genesis) | true / 6,362,601 | true / 6,362,601 | ✓ |
| 1 | miller ops[77,87) (covInHash) | true / 7,155,408 | true / 7,155,408 | ✓ |
| 2 | miller ops[167,177) (covInHash) | true / 7,141,936 | true / 7,141,936 | ✓ |
| 3 | miller ops[256,266) (covInHash) | true / 7,358,123 | true / 7,358,123 | ✓ |
| 0-forge | ECIP inBlob flip (false public inputs) | **false** (OP_VERIFY) | **false** (leanVerifyInput) | ✓ |

LeanBCH also confirms `txValid=true` and `verifyTokens=true` for every honest group. Two
independent VMs agree on accept, op-cost, and rejection. **Status: MATCHED.**

## 5. Non-soundness observations (token-safety PoC limits — NOT forgeries)

These accept but do **not** verify a false statement (no false Groth16/pairing result can be
produced); they are the documented token-safety limits of the PoC covenant
(`Implementation.tokenSafetyEnforced` defaults FALSE; see `harness/src/harness/types.ts`), a
deployment concern, not a proof-soundness break. The running state stays hash-bound to the terminal
verdict regardless:

- **Successor LOCKING not pinned:** covout pins the successor *state* (`nftCommitment`) and category,
  but not the output *locking script*, so a group's output token can be redirected to an attacker
  script. This cannot forge a verdict — the next group's covInHash still forces `inBlob` = the
  committed `outBlob`, and its logic is hash-pinned. (Liveness/deployment note.)
- **Output count unconstrained:** an extra attacker output can be appended to a group tx. Fund-safety,
  not proof-soundness.
- **Category not pinned to a constant:** an attacker running the *whole* pipeline under their own
  token category is accepted (genesis inToken is empty; covout only enforces in→out continuity).
  Identity/deployment concern; the proof math is unaffected.

A production deployment should pin the successor locking (self-pin / OP_INPUTBYTECODE on outputs),
constrain the output set, and pin the category constant. None affects the A1 verdict for the
verifier's proof-soundness.

## 6. Harness score confirmation

`transcript-harness-verify.log`: Σ(locking+unlocking) over 36 valid steps = **315,318** (matches
`totalBytes`); Σ tx-overhead (intra-tx model, `stepTxOverhead`) = 1,628; **full score = 316,946**.
Per-group script+overhead bytes match the vectors' `groupBytes` exactly (all four < 100,000 →
standard); all 36 accept on both VMs.

---

**CONCLUSION:** No forgery was found. Every soundness-critical attack surface — g2 subgroup, L10
affine slopes, ECIP divisor-cert, residue final-exp, FS/statement binding, and covenant
state-binding — rejects adversarial witnesses while honest proofs (including a distinct second
statement under the same lockings) accept, confirmed on two independent VMs. The 315,318 B crown is
**A1-CERTIFIED SOUND**.
