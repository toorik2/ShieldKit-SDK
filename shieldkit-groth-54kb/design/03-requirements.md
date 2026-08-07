# ShieldKit-Groth-54KB — Design 03: State Semantics & Requirement-Matrix Delta (FROZEN v1)

Status: **FROZEN** 2026-08-06.

## 1. State semantics (unchanged from product V2 Direct)

- The structural state input (index 7) carries the product's exact **SKS2
  128-byte state** (P-02): profileId raw-SHA-256, BE canonical roots, LE
  counters/amounts, CashToken category byte order — byte-identical codec to
  the current product (`packages/action/v2/state.mjs`,
  `crates/shieldkit-v2-codec`). The verifier swap does not touch the state
  codec, the NFT category, or the note/nullifier model.
- State flows p2sh-chain: each verifier carrier input spends the previous
  carrier's output; genesis pins the state; terminal finalizes.
- `live = note - nullifier` invariant, capacity/sequence bounds (P-03) are
  enforced by the product runtime + circuit, not by the pf6 verifier — the
  verifier's job is proof acceptance + packet/digest binding only.

## 2. Packet (P-05) — unchanged ABI, new binding location

- SDA2 552-byte packet (flags=0, action-active fields, instance/pre/post
  equality, full SHA-256, two BE u128 public inputs) — same codec.
- NEW: packet rides input 6; digest binds at genesis offset 451; terminal
  hashes packet once at runtime (Design 01 §4).

## 3. Requirement-matrix delta (PF10 → pf6-a3-direct-v1)

| Req | PF10 status | pf6 delta |
|-----|-------------|-----------|
| P-01 one-settlement topology | 13-in/13-14-out | **9-in/9-10-out**; topology id `pf6-a3-direct-v1`; exact-topology hard checks required |
| P-02 SKS2 state | 128 B | unchanged (input 7) |
| P-03 state invariants | runtime+circuit | unchanged |
| P-04 profileId/descriptor | PF10 schema | new `V2_PF6_TOPOLOGY_SPEC_SCHEMA`; instance descriptor pins pf6 roles |
| P-05 SDA2 packet | 552 B | unchanged ABI; binding via genesis offset 451 + terminal guard |
| P-06 action deltas | circuit+covenant | unchanged |
| P-07 witness | PF10 action witness | pf6 witness: per-role unlock packing from pf6 build outputs; BQ shard/reserve semantics per candidate terminal config |
| P-08 covenant | PF10 roles | 6 pf6 role locks + 3 structural (packet/state/fee) |
| P-09 recovery | PF10 | unchanged logic; new topology input/output counts |
| P-10 privacy | unchanged | unchanged |
| P-11 funding | 1 wallet input | unchanged (input 8) |
| P-12 overflow | circuit | unchanged |
| P-13 docs | PF10 docs | this design set + PLAN/GOAL updates |

## 4. Fixed points (no shenanigans)

- 9 inputs, 1 transaction, 6 verifier + packet + state + fee.
- Digest carrier genesis@4 offset 451; packet@6; terminal guard mandatory.
- VK: product `e52d09c3` (rebake; Design 02).
- Stabilization ON for product (genesis 7600 / terminal 9350); measured
  numbers recorded per profile.
- Hard ceilings: tx ≤ 100,000 B, unlock ≤ 10,000 B/input, VM ≤ 100%.
