# V2 Direct verifier-foundation decision

Status: PF11 foundation rejected at the operation ceiling; PF10 has a
provisional local Libauth hard-limit pass on 2026-07-29. Release
qualification remains open.

This document records a rejection, not a qualified verifier. The current legacy seven-carrier verifier pin (out of product scope)
ECIP topology must not be used for a V2 Direct release.

## Decision

The current ECIP `vk_x` construction is not total. For fixed public inputs, the
proof statement fixes `Q`, the ECIP hint, the Fiat-Shamir seed, and the complete
try-and-increment chain. Re-running or rerandomizing a Groth16 proof cannot
change the result. With `C7_MAXTRY=2`, an otherwise valid statement can require
more than two attempts and is rejected.

Increasing `C7_MAXTRY` reduces but never eliminates the reject set. It therefore
does not satisfy the protocol requirements that:

- every valid proof have one deterministic fixed-width encoding; and
- no wallet need change a packet, public input, fee, or proof witness to obtain
  an encodable verifier unlock.

A total hash-to-curve map alone is not a repair. The current ECIP verifier also
depends on nonzero rational-function denominators and has exceptional tangent
and divisor cases. BN254 has no standard RFC 9380 suite that can be substituted
without designing and auditing a new construction.

The selected direction is exact, fixed-round Shamir/Straus MSM over the two
128-bit packet-digest limbs. **PF11 is only the semantic correctness oracle.**
Its totalized five-executor composition exceeds the BCH-2026 operation ceiling,
so PF11 is rejected as a deployable transaction candidate. In particular, it
must not be described as a selected production topology, a fixed fourteen-input
plan, or a fourteen/fifteen-output settlement layout.

`PF10-FusedQGenesis` is the provisional local candidate. Its current local
layout has verifier roles `0..9`, then binding at input `10`, state at `11`,
and the wallet funding input at `12`: thirteen inputs in total. Deposit and
transfer have thirteen outputs; withdrawal has fourteen. This layout is not
frozen for release until all qualification gates below are satisfied.

## Reproduced current behavior

The three development proofs happen to encode under the current bounded ECIP
rule:

```text
deposit     nfail=0
transfer    nfail=0
withdrawal  nfail=1
```

This sample says nothing about totality. A deterministic 16-input probe found
two cases with `nfail > 2`, consistent with the approximate random-oracle reject
probability of `1/8` for a two-retry bound.

The V2 Direct public inputs are exactly the two unsigned big-endian 16-byte
halves of the SHA-256 packet digest. Exactly 128 scalar rounds are therefore
sufficient.

## PF11 MSM frame and canonical encodings

Every direct-MSM carrier consumes and produces one exact 128-byte state frame:

```text
offset  width  field
0       32     rX: Jacobian accumulator X, canonical BE Fp
32      32     rY: Jacobian accumulator Y, canonical BE Fp
64      32     rZ: Jacobian accumulator Z, canonical BE Fp
96      16     in0: first SHA-256 digest half, unsigned BE u128
112     16     in1: second SHA-256 digest half, unsigned BE u128
```

The decoder rejects any frame whose length is not exactly 128 bytes, any
coordinate outside the canonical Fp range, and any noncanonical encoding. The
two digest limbs are exactly sixteen bytes each, unsigned big-endian integers
in `[0, 2^128)`: they have no sign byte, no alternate short form, and no
little-endian interpretation. If a BCH VM numeric operation needs a signed
representation, conversion occurs only after decoding the canonical bytes and
adds a zero sign byte as required by the VM; the protocol frame itself never
uses that representation. `in0` and `in1` are identical in all four MSM
frames and are bound to the packet digest. The final MSM role emits the
canonical affine/identity `Q` used by the separate input-9 Miller genesis.

## PF11 semantic-oracle telemetry and rejection

The measurement prototype was built and run only under a temporary directory;
it did not modify this worktree. It used the repository-pinned CashScript
compiler. These figures are partial semantic-oracle telemetry, not PF11
qualification evidence. The complete PF11 composition exceeds the BCH-2026
operation ceiling and is rejected; no PF11 production topology follows from
this table.

| Role | Scalar bits | Redeem bytes | BCH-2026 operations | Minimum density unlock |
|---|---:|---:|---:|---:|
| MSM0 | 0-37 | 1,491 | 7,989,085 | 9,946 |
| MSM1 | 38-74 | 1,437 | 7,905,772 | 9,842 |
| MSM2 | 75-111 | 1,437 | 7,906,412 | 9,843 |
| MSM3 before separate Miller genesis | 112-127 | 1,609 | 3,611,883 | 4,474 |
| Total | 128 rounds | 5,974 | 27,413,152 | 34,105 |

The isolated MSM implements one canonical total output rule:

```text
Z = 0: zInv = 0 and Q = (0,0)
Z != 0: Z * zInv = 1 and Q is canonical affine and on-curve
```

`(0,0)` is not an affine BN254 G1 point, so it is an unambiguous encoding of
the point at infinity. A synthetic verification key was chosen so maximum
two-u128 public inputs produce infinity; the isolated VM path accepted the
canonical identity branch with `zInv=0`.

That does not qualify the complete verifier. The current PairFold Miller
implementation always folds the `vk_x/gamma` line contribution and has no
identity skip.

## PF10 provisional local hard-limit evidence

`PF10-FusedQGenesis` fuses the final MSM window with identity-aware Miller
genesis. Fresh local Libauth execution measured complete action transactions as
follows. This is a **local-only provisional hard-limit pass**, not release
qualification.

| Action | Serialized transaction | Inputs | Outputs | Ordered unlocking bytecode lengths |
|---|---:|---:|---:|---|
| Deposit | 97,844 B | 13 | 13 | 9411, 8451, 8643, 8642, 9602, 9024, 9009, 9017, 9170, 10000, 2753, 2677, 100 |
| Transfer | 97,844 B | 13 | 13 | 9411, 8451, 8643, 8642, 9602, 9024, 9009, 9017, 9170, 10000, 2753, 2677, 100 |
| Withdrawal | 97,878 B | 13 | 14 | 9411, 8451, 8643, 8642, 9602, 9024, 9009, 9017, 9170, 10000, 2753, 2677, 100 |

The maximum unlocking bytecode is exactly 10,000 bytes, so this local result
passes the stated inclusive byte and unlock ceilings. Fresh execution preserved
the same byte/unlock layout and passed the full local Libauth resource suite;
maximum observed operation usage was 96.79% of the per-input budget and 94.32%
at terminal. It does not prove BCHN mempool or mined acceptance, LeanBCH
agreement, the unmodified maintainer benchmark, final-key proof corpus,
ceremony/reproducibility, audit, clean-host, or release qualification. The only
hard acceptance limits remain serialized transaction `<=100,000` bytes, every
input unlocking bytecode `<=10,000` bytes, and every standard VM resource
`<=100%`; narrower margins are telemetry only.

## Mandatory point-at-infinity semantics

There is no tractable argument that the fixed verification key has no infinity
preimage over all pairs of 128-bit inputs. The input domain is larger than the
prime-order group, and the required discrete-log relation among the IC points
is unavailable. Identity handling is mandatory.

The complete verifier must:

1. Derive `qInf` from `Qx == 0 && Qy == 0`; never accept an independent witness
   bit.
2. Accept only canonical `(0,0)` or canonical affine coordinates satisfying
   `y^2 = x^3 + 3`.
3. Bind `(Qx,Qy)` through each MSM seam and through the genesis and terminal
   transcripts.
4. Replace every `vk_x/gamma` Miller contribution with multiplicative identity
   when `qInf` is true, implementing `e(O,gamma)=1`.
5. Regenerate the offline Miller, S-Z quotient, chain, residue, rolling hash,
   and terminal witnesses under the same identity-aware semantics.
6. Keep fixed widths, fixed rounds, and one topology for affine and identity
   cases.

Zeroing only variable line coefficients is incorrect because the line constant
terms remain.

## Required builder and protocol work

1. Add a V2-specific sibling-read MSM carrier generator with the exact 128-byte
   canonical BE frame and explicit unsigned-u128 decoding.
2. Preserve PF11 only as the independently tested semantic oracle; do not
   revive its rejected production topology.
3. Maintain the separately named PF10 13-input candidate topology and its
   candidate-specific role map, binding, state, and funding semantics.
4. Remove ECIP data, witness packing, merge source, and the ECIP pin gate.
5. Pin every MSM role to its active index, round interval, common parent,
   source index, predecessor/successor lock, state category, and next MSM state.
6. Do not freeze PF10 locks, base values, or a final descriptor until the
   complete candidate passes every required full-transaction gate.
7. Recompute the transaction context, packet digest, public inputs, proof,
   adapters, manifests, and artifact hashes.
8. Build the real binding, state, and funding roles before measuring size or
   claiming qualification.

The packet remains 552 bytes, but its context hash and therefore its proof and
public inputs change when the topology changes.

## Kill tests

- Differential exact MSM against an independent BN254 implementation for zero,
  one, `2^128-1`, every individual scalar bit, and randomized input pairs.
- Full-chain synthetic `Q=O`, inverse-add intermediate infinity, equal-point
  doubling, and leading-zero accumulation.
- Mutation of `zInv`, `Qx`, `Qy`, identity encoding, coordinate aliases,
  bounds, and every intermediate commitment.
- Omitted, duplicated, reordered, and swapped MSM windows and carrier roles.
- Mutated active/source indices, common parent, successor lock, carrier count,
  packet index, token category, and context hash.
- Independent three-pair reference agreement for `qInf`; forcing the identity
  branch for an affine Q must fail.
- Mutation of every gamma-line contribution to prove it is skipped only for
  canonical identity.
- Complete deposit, transfer, and withdrawal transactions under BCH-2026,
  BCHN mempool/mining, LeanBCH, and the unmodified maintainer benchmark.
- Full packet/state/funding mutation matrices and the planned 768 final-key
  transaction corpus.

## Implementation order

1. Retain and differentially test PF11's identity-safe MSM as the semantic
   oracle, without treating its op-ceiling failure as a deployable topology.
2. Keep PF10's fused-Q/genesis implementation under its own candidate identity;
   do not reuse PF11 artifact IDs or a PF11 fixed role map.
3. Complete candidate-specific binding/state/funding covenants and adversarial
   tests for the measured PF10 topology.
4. Re-measure deposit, transfer, and withdrawal with final artifacts and the
   full mutation corpus; the current local pass is not qualification.
5. Obtain BCHN mempool and mined evidence, LeanBCH agreement, and the latest
   unmodified maintainer benchmark for the same final transaction artifacts.
6. Complete ceremony, reproducibility, audits, clean-host, and release gates
   before freezing locks, context, packets, proofs, descriptors, or manifests.

Reference: [ECIP paper](https://eprint.iacr.org/2022/596.pdf).
