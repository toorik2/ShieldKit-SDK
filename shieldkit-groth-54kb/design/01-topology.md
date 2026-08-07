# ShieldKit-Groth-54KB — Design 01: PF6-A3-Direct Topology (FROZEN v1)

Status: **FROZEN** 2026-08-06. Supersedes any earlier topology sketch for the
54KB verifier swap. Source of truth: `vendor/pf6-lane/src/c7/build.ts`
(structural-role sections), `shield-direct-v2-packet-input.mjs`,
`shield-adapter-input.mjs`, `legacy-c7-config.mjs` (all hash-pinned in
`vendor/SHA256SUMS`), plus Groth16-Formal `harness/IR.md` (atom order).

## 1. Topology identity

- **ID:** `pf6-a3-direct-v1`
- **Construction:** bn254-onetx-pf6-a3-r1 (PairFold-6 dens-rich a3)
- **State model:** p2shchain (state flows through carrier inputs)
- **Transaction count:** 1 (single settlement transaction per action)

## 2. Input layout (9 inputs)

| Index | Role | Kind | Carries |
|------:|------|------|---------|
| 0 | exec0 | verifier | Miller windows [1,16) + boundary loaders |
| 1 | exec1 | verifier | Miller windows [16,32) |
| 2 | exec2 | verifier | Miller windows [32,48) |
| 3 | exec3 | verifier | Miller windows [48,64) |
| 4 | genesis | verifier | projection signal `4d e0 01 ∥ ctx[448] ∥ digest[32]` |
| 5 | terminal | verifier | final Groth16 equation + BQ residual + packet digest guard |
| 6 | packet | structural (binding) | `4d 28 02 ∥ SDA2[552]` (exact 552-byte V2 Direct packet) |
| 7 | state | structural | SKS2 128-byte state (product codec; P-02) |
| 8 | fee | structural (funding) | wallet funding input |

- `carrierCount = 6`, `bindingInputIndex = 6`, `stateInputIndex = 7`,
  `fundingInputIndex = 8`, `inputCount = 9` (mirrors product `materialize()`
  rule: binding = carrierCount, state = carrierCount+1, funding =
  carrierCount+2).
- Outputs: deposit/transfer = 9, withdrawal = 10 (carrierCount+3/+4 — the
  withdrawal carries the recovered-note output).

## 3. Role ordering note (tx order ≠ atom order)

- Tx input order: exec0..exec3, genesis, terminal (build assembly order).
- Atom/IR role order (Groth16-Formal `IR.md`): genesis=0, exec0=1, exec1=2,
  exec2=3, exec3=4, terminal=5.
- Any role-index KAT or atom bundle MUST use the IR order; any tx-index guard
  (`ROLEGUARD`, `activeInputGuard`) MUST use the tx order. Documented here so
  the two never get conflated.

## 4. Digest binding (SDA2 V2 Direct ABI)

- Packet: input 6 bytecode is exactly `0x4d 0x28 0x02` (PUSHDATA2, 552 B) +
  the 552-byte SDA2 packet; no trailing bytes (terminal pins the exact length
  555).
- Digest: SHA-256(packet) — 32 bytes carried at genesis input 4, byte offset
  **451** (3-byte push header `4d e0 01` + 448 projection bytes), spanning
  [451, 483).
- Proof public inputs: `directV2PacketPublicInputs(digest)` = two unsigned
  big-endian u128 limbs of the digest: `in0 = digest[0..16]`, `in1 =
  digest[16..32]` — bijectively asserted against the Groth16 proof's public
  inputs at build time (`assertDirectV2PacketPublicInputs`) and bound at
  runtime by the terminal guard.
- Terminal runtime guard: `INPUTBYTECODE(6)` == PUSHDATA2(SDA2[552]);
  `INPUTBYTECODE(4)` == `4d e0 01 ∥ ctx[448] ∥ digest[32]`; `sha256(packet)`
  == digest (single hash, OP_SHA256 on the canonical payload after stripping
  the push header).
- Structural roles (6,7,8) are deliberately unevaluated inside the verifier
  build's reality gate (they are evaluated by the ShieldKit product runtime);
  the 6 verifier roles ARE evaluated in the complete 9-input context.

## 5. Byte layout / size budget (reference build, natural lengths)

| Role | Unlock bytes (reference VK) |
|------|------:|
| exec0 | 9,853 |
| exec1 | 9,848 |
| exec2 | 9,877 |
| exec3 | 8,893 |
| genesis | 7,452 |
| terminal | 8,538 |
| **σ unlock** | **54,461** |
| σ lock (6×35 P2SH) | 210 |
| **scriptBytes (pin accounting)** | **54,671** |
| tx overhead | 278 |
| **score** | **54,949** |

- Judge (tier fast) on the reference build: verdict green, scriptBytes 54671,
  score 54949, 6 inputs, 1 tx, valid 4/4, invalid rejected 6/6,
  worst-case accepted, fitsStandardBudget, maxInputOperationCost 6,933,105
  (≤ 100% ceiling).
- Product build (WP-3) rebakes the VK to verification_key.json `e52d09c3`
  (see Design 02) — per-role sizes will shift; re-measure and record.

## 6. Stabilization policy

- Reference/pin-matching build: `C7_UNLOCK_LENGTH_STABILIZE=0` (natural
  lengths).
- Product build: stabilization ON (default) — genesis pinned to 7,600 B,
  terminal to 9,350 B so multiproof lock identity and executor length pins
  stay stable across prove↔build; product profile records its own measured
  numbers (stabilized wire was 55,699 on the reference VK; re-measure after
  VK rebake).


## Revision v2 (2026-08-06): packet-input lock decision (from live PF10 settlement analysis)

- The pf6 terminal's runtime guard requires input 6's UNLOCKING bytecode to be
  EXACTLY the packet push (555 B = `4d 28 02` + SDA2[552]) — verified in the
  product build (projectionSignalCarrier + packet guard) and the live replay.
- Therefore the pool's binding LOCK for input 6 cannot be a P2SH of the
  PF10-style binding redeem (2,198 B — that redeem requires
  [packet push][redeem] in the unlock, 2,753 B total).
- **Decision: the pf6 packet input (6) lock = bare `OP_1` (51) carrier.**
  Anyone may push a packet; the terminal enforces sha256(packet) == digest at
  genesis offset 451 == proof public inputs. An attacker's packet must be a
  SHA-256 preimage of the bound digest — infeasible. The carrier holds dust
  (1,200 sats class), so the trivial lock is sound. The packet↔digest binding
  moved from the PF10 binding input's redeem INTO the pf6 terminal guard.
- State input (7): the product's state covenant UNCHANGED (state lock + SKS2
  unlock 2,677 B format, from the live PF10 deposit: `4d 72 0a` PUSHDATA2 +
  2,674 B state payload).
- Fee input (8): P2PKH (product format, 100 B signature from the hot wallet).
- Evidence: vendor/chipnet-txs/pf10-deposit.hex (live tx), binding-redeem.bin,
  packet-push-sample.bin.


## Revision v3 (2026-08-06): binding carrier lock corrected — live-test finding

- The first live pool used a bare `OP_1` (51) carrier lock. BCHN rejected the
  deposit: the BCH VM requires the final stack to have EXACTLY ONE item;
  `OP_1` with the 555-B packet push leaves depth 2 -> UNSPENDABLE.
- **Corrected carrier lock: `75 51` (OP_DROP OP_TRUE).** The packet push is
  dropped, then true is pushed -> final stack depth 1. The terminal guard
  (unlock == exactly 555 B) is unaffected. The state covenant pins
  sha256(75 51) for the binding input's UTXO bytecode.
- The first pool (instance b35e2532, genesis dc6634d8) is unusable (its
  carrier UTXO is unspendable; state covenant pins the old lock). Its dust
  (~11K sats) is documented loss on chipnet — the cost of the live test.
- Evidence: evidence/03-implementation/deposit-rejection-OP1.md
