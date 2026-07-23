# G2 PF7 settlement slice audit

Status: **design boundary only — no G2 transaction candidate exists**.

Scope: current `shield.cash` HEAD `450ed6ac9cb1f617d8ac0d4d0b08d476fd3538a7`,
local source and recorded BCH-2026/libauth evidence. No transaction was built,
broadcast, submitted to a node, or presented as standardness/Chipnet evidence.

## Result

The smallest semantics-preserving target is a **regenerated ten-input**
transaction: seven PF7 verifier roles plus one binding/action carrier, one
state-NFT carrier, and one transparent fee input. The measured seven-input
PF7 transaction cannot be wrapped with those three inputs: the real terminal
redeem rejects in the expanded context. A byte budget for the missing roles is
therefore not a measurement or feasibility result.

The locked hard limits remain `wire <= 59000` and every unlocking bytecode
`<= 10000`; 54,739 B is only the PF6 fee reference. The approximately 82-KiB
generic adapter is not a fallback.

## What is real now, and what is not

| Item | Evidence | Status relevant to G2 |
| --- | --- | --- |
| Seven-input PF7 verifier | `evidence/G1/verifier-partition/observation.json` | Real BCH-2026 VM/adversarial verifier-only result: 54,296 wire B, 54,541 all-byte score, max unlock 9,176 B. Fixed VK and one `OP_RETURN` output; not a settlement action. |
| Expanded-context falsifier | `evidence/G1/verifier-envelope-integration/ten-input-context-result.json` and `REPORT.md` | Real negative: appending three structural inputs makes the current terminal reject. This rules out wrapping the seven-role fixture. |
| Ten-role structural experiment | `evidence/G1/verifier-ten-role/REPORT.md` | Seven verifier roles accept in a ten-input context, but inputs 7–9 are P2PKH structural placeholders and do not execute binding/state/fee semantics. Its 54,561-B wire figure is descriptive only. |
| Development-v0 ten verifier-role build | `evidence/G1/development-v0-real-proof/pf7-result.json` | All ten are verifier roles, 81,563 wire B and 82,739 score B; it cannot be relabelled as the three protocol roles and does not fit the 59,000-B G2 ceiling. |
| Action relation/reference model | `circuits/g1-relation/CIRCUIT_SCOPE.md`, `packages/core/shielded-transition.mjs` | The 752-B action packet and two SHA-256 limbs are real relation/reference work. The transaction-context digest is still an input, not reconstructed from a BCH transaction. |
| Kernel transaction document | `spec/kernel/G1_TRANSACTION_CANDIDATE.md` | Semantic requirements are useful, but its 0–5/6/7/8 map, 95,000-B target, and `>=10` verifier-role discussion are explicitly G1/falsification history and conflict with the frozen seven-PF7/59,000-B direction. It is not an active builder specification. |

## Required input layout

All inputs use transaction version `2`, sequence `0`, and locktime `0`.
Indices are consensus material, not labels.

| Index | Role | Exact source/output requirement |
| ---: | --- | --- |
| 0 | `exec0` | Profile-authenticated generated PF7 P2SH32 lock. |
| 1 | `exec1` | Profile-authenticated generated PF7 P2SH32 lock. |
| 2 | `exec2` | Profile-authenticated generated PF7 P2SH32 lock. |
| 3 | `exec3` | Profile-authenticated generated PF7 P2SH32 lock. |
| 4 | `exec4` | Profile-authenticated generated PF7 P2SH32 lock. |
| 5 | `genesis` | Profile-authenticated generated PF7 P2SH32 lock. |
| 6 | `terminal` | Regenerated PF7 terminal; derives the two Groth16 public limbs from the canonical input-7 packet, not fixture fields. |
| 7 | `binding` | Bare P2S covenant, canonical packet push only, profile/instance-bound and self-pinned. Its source value is `B + D` for deposit and `B` otherwise. |
| 8 | `state` | Instance-bound bare P2S covenant holding the sole mutable state NFT. Source value/commitment equal packet pre-state. It pins the exact binding lock at input 7. |
| 9 | `fee` | One normal transparent user/sponsor UTXO. Its outpoint, source value, lock hash, sequence, and canonical change script are packet-bound. |

The generated verifier set must make this ten-role map explicit in every
input-index read, sighash/transaction guard, source-lock digest, red-team
mutation, and LeanBCH fixture. Reusing a seven-input `EXPECTED_INPUTS` guard is
incorrect even if the added roles individually evaluate.

## Canonical outputs and conservation

The minimum output layout is action-dependent but deterministic:

| Action | Output 0 | Output 1 | Output 2 |
| --- | --- | --- | --- |
| deposit | successor state NFT under unchanged state lock | canonical transparent change | absent |
| transfer | successor state NFT under unchanged state lock | canonical transparent change | absent |
| withdrawal | successor state NFT under unchanged state lock | exactly `D = 10,000,000` sats under packet-bound recipient lock | canonical transparent change |

The 192-B encrypted record is carried in the canonical input-7 action packet,
which is on-chain transaction data; it must be included in the relation packet
and the binding parser. No protocol/maintainer/relayer output is permitted.

Let `K = sum(verifier carrier values) + B`, `F` be input-9 value, and `C` the
canonical change. The binding and state scripts must jointly enforce:

```
deposit:    input7 = B + D, Rpost = Rpre + D, W = 0
transfer:   input7 = B,     Rpost = Rpre,     W = 0
withdrawal: input7 = B,     Rpost = Rpre - D, W = D
miner fee = K + F - C
```

Thus neither the pool reserve nor a protocol role subsidizes the miner fee.

## Transaction-context preimage to implement

The existing 752-B action packet contains a 32-B `transactionContextDigest`.
For this slice its canonical preimage should be fixed before code generation:

```
"SCCT" || u8(1) || u8(network) || u8(actionKind) || u8(0) ||
profileId[32] || instanceId[32] || u16le(10) || u16le(outputCount) ||
for each input i in 0..9:
  u8(role[i]) || outpointTxidWire[32] || u32le(vout) || u32le(sequence) ||
  u64le(sourceValue) || sha256(sourceLockingBytecode)[32] ||
  sha256(canonicalTokenData)[32] ||
for each output in order:
  u8(role) || u64le(value) || sha256(lockingBytecode)[32] ||
  sha256(canonicalTokenData)[32]
```

This is 1,352 B for deposit/transfer (two outputs) and 1,425 B for withdrawal
(three outputs), before hashing. `canonicalTokenData` must be the exact
CashTokens serialization selected by the BCH-2026 builder, including an
unambiguous no-token encoding; do not substitute JSON or a display format.
The packet digest excludes all unlocking bytecodes, signatures, and proof to
avoid a circular transaction identifier. The binding covenant must recompute
this preimage from BCH introspection, and the terminal must bind the same
canonical input-7 packet to the Groth16 public limbs. An unchecked caller
digest is a kill condition.

## Directed script construction

```
PF7 verifier material -> profileId -> category input + reserve cap -> instanceId
    -> binding lock (pins seven verifier locks, profile, instance)
    -> state lock (pins exact binding lock, NFT category, cap, denomination)
    -> genesis / prepared carriers
```

The binding script must not create a lock-hash cycle by pinning the final state
lock before it is derived. Instead it authenticates input-8's unique state NFT
and transaction context; state self-pins its input/output lock and pins exact
input-7 binding lock. Any substituted accepting verifier, binding, state,
source value, token prefix, index, outpoint, sequence, output, packet byte, or
public limb must reject at least one executed input.

## Byte and execution gates

Known measurements are not additive envelope measurements:

| Measured fixture | Wire B | Remaining to 59,000 B | Why it is not G2 headroom |
| --- | ---: | ---: | --- |
| PF7 seven verifier roles | 54,296 | 4,704 | No binding/state/fee inputs or real outputs; rejects expanded context. |
| Ten-input structural experiment | 54,561 | 4,439 | Roles 7–9 are unevaluated P2PKH structural inputs. |
| Development-v0 ten verifier roles | 81,563 | -22,563 | Wrong role semantics and exceeds the hard ceiling. |

The next implementation must emit all three real action transactions, score all
source locks and all wire bytes, enforce every unlock `<= 10,000 B`, then run
the full BCH-2026 VM, mutation suite, LeanBCH cross-check, and unmodified BCHN
standardness/Chipnet evidence. Until then, none of the figures above is a G2
PASS, feasibility PASS, or assigned byte budget.

## First bounded implementation package

1. Replace positional PF7 generator constants with the ten-role map above and
   regenerate a terminal that parses/binds input 7.
2. Implement the context-preimage encoder and test exact byte offsets/hashes
   from independently constructed transaction fields.
3. Implement binding and state P2S scripts only after their constructor
   graph is fixed; add whole-transaction lock/value/token/index substitutions.
4. Build deposit, transfer, and withdrawal complete transactions with real
   proofs from one typed `development-only` profile; execute every input in the
   BCH-2026 VM.
5. Stop if any complete action exceeds 59,000 B or any unlock exceeds 10,000 B;
   record the measured falsifier rather than repartitioning to the generic
   adapter.
