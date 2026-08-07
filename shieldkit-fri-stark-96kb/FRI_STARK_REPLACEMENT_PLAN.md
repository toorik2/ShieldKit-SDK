# ShieldKit FRI-STARK 98 KB-Lineage Replacement Plan

> **Provenance:** Recovered from OpenAI Codex (sol) session rollout `019fd27e-782f-7e82-aedd-c3b81780ea66` (`<proposed_plan>`). Plan Mode blocked the original write. **Wire correction applied:** native 128-byte `SFS1` NFT commitment and 424-byte `SFP1` (replacing 136-byte state + `SHA256` NFT pointer and 440-byte packet). Filename: `FRI_STARK_REPLACEMENT_PLAN.md` (normative for this package).

## 1. Outcome and immutable release contract

Build a standalone, fresh-genesis ShieldKit product rooted entirely in `/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-fri-stark`. Preserve deposit, transfer, withdraw, recovery, wallet, journal, and zero-conf UX concepts; replace Groth/BN254 relation, proof format, cryptography, state, covenant topology, identifiers, and storage with FRI-native equivalents.

- Package: `shieldkit-fri-stark@0.1.0-beta.1`; CLI: `shieldkit-fri`.
- Release: unaudited, Chipnet-only beta. Mainnet, audited-production, encrypted-note privacy, and Groth-pool compatibility claims are forbidden.
- Compatibility: existing Groth pools remain untouched. Migration is only Groth withdrawal followed by fresh FRI deposit.
- Containment: no edits to parent manifests, lockfiles, workspaces, CI, documentation, or `shieldkit-groth`; no escaping symlinks or runtime imports. External repositories may be read or cloned only into `.private/`.
- Runtime test state and caches use `.private/`; production defaults to `${XDG_DATA_HOME:-$HOME/.local/share}/shieldkit/fri-stark/v1-beta`.
- Actions must each be exactly one standard BCH transaction, accepted and exactly read back at zero confirmation.
- Every worst-case signed action must be `<=100,000` bytes; no engineering reserve. Every input unlock must remain within consensus/policy limits.
- Final effective classical soundness must be `>=100` bits after all algebraic, masking-degree, query-collision, repetition, transcript, hash-binding, and union corrections.
- Reference-host prover SLA, separately for every action: p95 `<=60 s`, peak RSS `<=4 GiB`.
- Horizontal scaling only: one serial state writer per pool instance; concurrency comes from independent instances. No sequencer, batching, remote proving, automatic cross-pool routing, or shared anonymity set.
- No soak test and no confirmation-wait gate.
- Any failed security, ZK, byte, VM, or SLA gate terminates the release path with a measured infeasibility report; never weaken depth, digest width, binding, or security to force a fit.

Freeze the exact current `goldilocks-98k` working-tree specimen as the bootstrap authority, including staged, unstaged, and untracked release-relevant bytes. Record Git status, upstream `a600e828d68eb41840049cb16d0c21850ff9df57`, binary patch, permissions, normalized archive, and SHA-256/BLAKE3 inventory. Independently reproduce:

- `q=7`, blowup `2048`, grind `30`, depth `4`, fold `8`.
- Seventeen roles: blob, seven deep-query, seven aggregate-FRI, composition-transition, composition-final.
- Score `98,776`; exact synthetic transaction `98,181` bytes; aggregate unlock bytes `97,430`; largest unlock `7,897`; measured peak op-cost `6,048,448`.
- The score is not a real production transaction size.
- The baseline relation is a small hash-chain/confidential-transfer demonstration, not ShieldKit’s final relation.
- Existing one-limb application hashes provide at most approximately 32-bit collision security and must not survive into the final profile.
- Treat upstream as research lineage: its own documentation says it is not production-hardened or externally reviewed ([upstream repository](https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier)).
- Public packaging requires an explicit compatible source grant/license naming covered files, modification, redistribution, sublicensing, and binary distribution rights. Absence of a repository license otherwise retains default copyright ([GitHub licensing guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)).

Use a standalone layout containing `spec/`, frozen `vendor/` sources, Rust AIR/prover/verifier crates, TypeScript SDK/CLI packages, qualification tooling/evidence, release artifacts, and ignored mode-`0700` `.private/` data. Pin Node `22.23.1`, npm `10.9.8`, Python `3.14.6`, Rust `1.97.1`, compiler versions, dependency integrity hashes, VM models, and qualification commits.

## 2. Protocol, relation, proof, and covenant design

### FRI-native cryptography

Use Goldilocks `p=0xffffffff00000001` and the frozen baseline Poseidon2 permutation: width `12`, exponent `7`, `RF=8`, `RP=22`, with exact matrices/constants hash-pinned and independently reproduced.

Define only fixed-arity typed hashes:

```text
H4_D(x0..x7):
    state = [x0..x7, IV_D[0..3]]
    state = Poseidon2(state)
    return state[0..3]
```

- Every input is exactly eight field elements; no variable-length sponge or implicit padding.
- Digest encoding is four canonical `<p` limbs, each U64LE, totaling 32 bytes.
- Arbitrary 32-byte data enters as eight U32LE field elements, preserving injectivity.
- Derive each domain IV from `SHA256("ShieldKit/FRI-Poseidon2-IV/v1/" || label || 0x00 || U32BE(counter))`, split into four U64LE values, incrementing `counter` until every limb is nonzero and `<p`. Freeze labels, counters, IVs, and uniqueness tests.
- Allocate distinct domains for profile, instance, identifiers, parameters, pool, owner, nullifier key, rho, note commitment, note leaf, empty note leaf, every note-tree level, nullifier metadata, nullifier keys, nullifier leaf, and every nullifier-tree level.

Canonical derivations:

```text
profile4  = H4_PROFILE_ID(u32le8(profileId32))
instance4 = H4_INSTANCE_ID(u32le8(instanceId32))
ids4      = H4_IDS(profile4 || instance4)

params4 = H4_PARAMS(
  networkId, 1, 10_000_000, 32, 32,
  100_000, 0xffffffff, 0xfffffffe
)

pool4 = H4_POOL(ids4 || params4)

PRK = HKDF-Extract-SHA256(salt=encode(pool4), IKM=seed32)
accountKey32 = HKDF-Expand(
  PRK,
  "ShieldKit/FRI/account-key/v1" || U32BE(counter),
  32
)
owner4 = H4_OWNER(u32le8(accountKey32))
nfKey4 = H4_NULLIFIER_KEY(u32le8(accountKey32))
```

Use the first derivation counter producing nonzero owner and nullifier-key digests. One seed yields one stable address per pool.

Canonical address:

- Binary length 72: magic `SFA1`, network byte, version `1`, zero U16 flags, `pool4`, `owner4`.
- Text: `sfa1:` followed by lowercase hex of all 72 bytes.
- JSON, JCS-canonicalized: `{"schema":"shieldkit-fri-address-v1","networkId":N,"poolDomain":"<64-lowercase-hex>","owner":"<64-lowercase-hex>"}`.
- Anyone receiving an address can scan and link all its receipts. There is no ECDH, encrypted record, tag, memo, or recipient unlinkability claim.

Notes and spends:

```text
rho4  = H4_RHO(pool4 || postSequence || actionKind || 0 || 0)
cm4   = H4_NOTE(owner4 || rho4)
leaf4 = H4_NOTE_LEAF(cm4 || rho4)
nf4   = H4_NULLIFIER(nfKey4 || cm4)
```

- Deposit and transfer append one note; withdrawal appends none.
- Transfer and withdrawal consume one note and publish full `nf4`; deposit publishes zero.
- Spending recomputes account owner, nullifier key, rho, commitment, leaf, membership path, and nullifier.
- Note tree: depth 20 [AMENDED 2026-08-06 from 32 — 2^20 = 1,048,576 notes; measured size flat across depths 4-31 at T=1024 (103,321-103,425 B), depth 32 forced T=2048 and illegal N=2^22 for fold-8; see AMENDMENT-20260806], Digest4 nodes, a typed empty leaf, and separate per-level node domains.
- Indexed nullifier tree: depth 20 [AMENDED 2026-08-06 — nullifier lifetime ~28 years at 100 tx/day; see AMENDMENT-20260806]; lexicographic numeric ordering of four limbs; physical leaf zero is typed `MIN`; end-of-list is a typed `END` successor, never a leaf. `nfCount` counts real nullifiers; a new real leaf uses physical index `nfCount+1`; maximum is `0xfffffffe`.
- Each nullifier leaf commits typed metadata `(type,index,successorIndex-or-END,reserved...)` and `(key4,successorKey4-or-zero)`. Insertion proves predecessor membership, strict ordering, predecessor replacement, empty append position, and new root.

### Normative public wires

**Native state (locked correction):** CashTokens NFT commitment may hold up to 128 bytes directly (May 2026 P2S). The mutable state NFT commitment is exactly the canonical 128-byte `SFS1` state. There is no secondary state hash and no external state preimage. Pool instance identity is the mutable NFT’s category; the packet carries that category as `instanceId`.

State `SFS1`, exactly **128 bytes**:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `SFS1` |
| 4 | 32 | `profileId` |
| 36 | 32 | FRI note root |
| 68 | 32 | FRI nullifier root |
| 100 | 4 | note count, U32LE |
| 104 | 4 | nullifier count, U32LE |
| 108 | 4 | maximum live notes, U32LE |
| 112 | 8 | reserve sats, U64LE |
| 120 | 8 | action sequence, U64LE |
| 128 | — | end |

Covenant checks (state NFT):

```text
sourceNFT.category             == packet.instanceId
successorNFT.category          == packet.instanceId
sourceNFT.capability           == mutable
successorNFT.capability        == mutable
sourceNFT.commitment           == packet.preState
successorNFT.commitment        == packet.postState
sourceNFT.commitment.length    == 128
successorNFT.commitment.length == 128
```

Packet `SFP1`, exactly **424 bytes**:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `SFP1` |
| 4 | 1 | network |
| 5 | 1 | action: deposit `1`, transfer `2`, withdraw `3` |
| 6 | 2 | zero flags |
| 8 | 32 | `instanceId` / NFT category |
| 40 | 128 | complete pre-state (`SFS1`) |
| 168 | 128 | complete post-state (`SFS1`) |
| 296 | 32 | public nullifier |
| 328 | 32 | output note leaf |
| 360 | 32 | withdrawal locking-bytecode SHA-256 |
| 392 | 32 | transaction-context SHA-256 |
| 424 | — | end |

Inactive fields must be all-zero. The public AIR statement is still the packet hash (separate from state persistence):

```text
statementDigest = SHA256(SFP1_bytes)
```

exposed as eight strict U32LE limbs. The transcript absorbs the exact 32 digest bytes after protocol, AIR, and profile domains.

Byte tradeoff vs the earlier hash-pointer design (screening only): packet shrinks by 16 bytes (two 136→128 states); successor NFT commitment grows by 96 bytes (32→128); net signed-transaction increase ≈80 bytes. If those bytes prevent the final FRI verifier from fitting, optimize the verifier or report infeasibility—never silently revert to hashed external state.

Define `SFC1` as the only transaction-context serialization:

```text
magic "SFC1"
network U8
version U8 = 1
action U8
flags U8 = 0
txVersion U32LE
locktime U32LE
inputCount U8 = 18
for input i=0..17:
    role U8
    outpointTxid in BCH wire order, 32 bytes
    outpointIndex U32LE
    sequence U32LE
    sourceValue U64LE
    SHA256(sourceLockingBytecode), 32 bytes
    tokenDataLength U16LE
    exact canonical consensus token-data bytes
outputCount U8 = 18 for deposit/transfer, 19 for withdrawal
for each output in index order:
    role U8
    value U64LE
    serializedOutputLength U16LE
    exact consensus serialization of token prefix plus locking bytecode
```

All lengths are strict-minimal and bounded by consensus limits. Unlocking bytecodes are excluded, removing proof/fee circularity. Input zero reconstructs `SFC1` from transaction introspection and requires its hash to equal the packet field. Fixed proof and funding-unlock lengths make the exact fee and change known before proving.

State rules:

- `post.sequence = pre.sequence + 1`.
- `live = noteCount - nfCount`; `reserve = live * 10,000,000`.
- Deposit: notes `+1`, nullifiers unchanged, reserve `+10,000,000`.
- Transfer: notes `+1`, nullifiers `+1`, reserve unchanged.
- Withdraw: notes unchanged, nullifiers `+1`, reserve `-10,000,000`.
- Enforce count bounds, capacity `live<=100000`, arithmetic range, underflow/overflow rejection, unchanged profile fields, correct active/zero packet fields, and exact tree transitions.
- State output BCH value is `stateCarrierBase + reserve`; `stateCarrierBase` is fixed at genesis and preserved by `input0.value-pre.reserve == output0.value-post.reserve`.
- Genesis chooses the smallest state/role carrier values accepted by the pinned unmodified BCHN standard-policy build for the exact locks, then freezes them in the signed profile manifest. They cannot vary per action.

Freeze identifiers:

```text
relationId    = "shieldkit-pool-action-fri-v1"
publicAbi     = "sha256-u32le8"
topologyId    = "fri17-fused-state-v1"
profileId32   = SHA256(JCS canonical final profile manifest)
instanceId32  = SHA256(canonical genesis descriptor)
```

Every pool uses a fresh CashTokens category, genesis transaction, instance ID, and initial roots.

### Production AIR and proof

Implement one universal production AIR with action selectors; no action-specialized verifier or fixed-context shortcut:

1. Strict packet/state parsing, range checks, inactive-field zeroing, and packet SHA-256.
2. Poseidon2/H4 domain operations.
3. Account ownership and nullifier derivation for spend actions.
4. Note membership for transfer/withdraw.
5. Note append for deposit/transfer.
6. Indexed-nullifier predecessor update and append for transfer/withdraw.
7. State arithmetic and boundary constraints.
8. Public statement binding.

Freeze an AIR manifest containing column names, row schedule, selectors, transition/boundary constraints, maximum degrees, constants, padding rules, witness layout, public-input order, and hashes of generated artifacts.

- Production depth-20 AIR and its actual trace length are authoritative [AMENDED 2026-08-06 — the product config is depth 20 / T=1024 / N=2^21=8^7, measured end-to-end: D/T/W 99,313-99,394 B, 17/17 accept, 0 density fails; see AMENDMENT-20260806]. `T=1024` is the measured product trace, not a bootstrap placeholder.
- Constrain every inverse, carry, selector, lookup, padding row, disabled branch, witness hint, and auxiliary channel.
- Python is an independent reference oracle only. TypeScript model, Python oracle, Rust prover/verifier, AIR evaluator, and on-chain locks must agree byte-for-byte.
- Prove explicit witness zero knowledge across trace, composition, OOD/DEEP openings, FRI folds, and all masking columns. Trace masking alone is insufficient.
- Add leakage canaries and witness-differential transcript tests; empirical tests supplement but cannot replace the masking argument.

Canonical transcript order:

```text
protocol domain
AIR identifier
profile identifier
statement digest
trace commitment
AIR challenges
composition commitment
OOD point and OOD values
DEEP coefficients
"fri"
for each FRI layer: commitment, then fold challenge
final layer/final commitment
grinding nonce
query indices
```

Canonical proof encoding:

- Base elements: U64LE and `<p`; extensions: ordered base-element pairs.
- Root width, counts, nonce length, query count, path depth, role partition, and unlock lengths are fixed by one signed parameter-set manifest.
- Grinding nonce is exactly eight bytes.
- Encode all query slots and paths at fixed lengths; account for repeated-query probability in the security calculation.
- Reject noncanonical limbs, wrong lengths, missing fields, trailing bytes, reordered paths, alternative encodings, and unused nonzero padding.
- One common proof source is committed through input zero; all roles bind the same statement, transcript seed, parameter set, and role partition.
- All three actions use the same proof length.

Perform deterministic parameter search over query count, blowup, grinding, FRI depth/fold factor, repetitions, root truncation width, and partitioning using the actual AIR. Lexicographically minimize:

1. Worst-case exact signed withdrawal transaction bytes.
2. Reference-host prover p95.
3. Grinding work.

Subject to all hard constraints:

- Exact aggregate failure probability `<=2^-100` after union of AIR/DEEP/FRI, masking-degree corrections, repeated or colliding queries, transcript bias, commitment binding, application-hash collision bounds, and all verification roles.
- Poseidon2/H4 and SHA-256 truncation assumptions and margins are explicit. The baseline 25-byte Merkle width does not pass automatically; choose the smallest byte width the calculator proves sufficient.
- Provable zero knowledge.
- Signed deposit, transfer, and withdrawal each `<=100000` bytes.
- Every unlock, stack element, stack depth, opcode count/cost, hash density, and standard-policy condition passes all target VMs.
- Prover SLA passes.
- No reliance on synthetic statements, patched VM policy, omitted transaction binding, fixed paths, or runtime-general false profiles.

Allowed optimizations are soundness-neutral only: column/schedule reuse, proof packing, blob access reduction, role regrouping, common-subexpression elimination, and replay of the measured 80 KB optimization frontier. Never reduce tree depth, Digest4 width, transaction binding, ZK closure, or the effective security target.

### Seventeen-role BCH topology

Use exactly 18 inputs:

- Input 0: mutable state NFT; blob/Fiat–Shamir source; full packet; common proof source; structural and transaction binding.
- Inputs 1–7: deep-query roles.
- Inputs 8–14: aggregate-FRI roles.
- Input 15: composition-transition.
- Input 16: composition-final.
- Input 17: tokenless P2PKH fee/funding lane with exact 100-byte Schnorr unlock and sighash `ALL|UTXOS|FORKID` (`0x61`).

Inputs 0–16 must spend outputs 0–16 of one common parent transaction. Input 17 is independent funding. Leaf roles commit profile/topology/role constants; compile them first. Input zero commits the ordered vector of their locking-bytecode hashes, avoiding a script-hash cycle.

Outputs:

- Deposit/transfer: output 0 state/verifier successor; outputs 1–16 exact verifier successors; output 17 funding change.
- Withdrawal: outputs 0–16 successors; output 17 exact fixed-denomination P2PKH payout; output 18 funding change.
- Output locks 1–16 and their tokenless carrier values exactly equal corresponding source outputs.
- Output zero preserves the state lock/category/capability and updates only the **128-byte** native mutable NFT commitment (`SFS1` bytes) and reserve-backed value.
- Anchor checks exact input/output counts, indexes, roles, common-parent outpoints, source locks/values/token data, successor locks/values/token data, payout, funding lane, `SFC1`, and state commitments.
- Every verifier role executes its assigned checks through its UTXO lock; presence of unlocking bytes alone never satisfies verification.

Use the screening equations, then require exact serialization:

```text
deposit/transfer bytes = Σ role unlocks + 87*r + commitmentBytes + 220
withdrawal bytes       = Σ role unlocks + 87*r + commitmentBytes + 254
```

For the frozen baseline, `r=17`, `ΣU=97430`, and a **128-byte** native state commitment with a **424-byte** `SFP1` packet, provisional screening (using the plan’s earlier ~`99716/99750` hash-pointer estimates plus ≈80 net bytes for native 128) lands near `99796/99830`. Those remain screening estimates only: production AIR, structural binding, and exact signed bytes decide the gate. Do not treat baseline 98 KB golf scores as production sizes.

Chipnet fee policy is **1 sat/byte + 1** (`feeSats = txBytes + 1`). Do not use higher mainnet-style rates on chipnet. Maintain two alternating tokenless P2PKH funding chains. Deposit funding covers denomination plus fee; transfer and withdrawal funding cover fee; withdrawal denomination comes from the state reserve. Each recreated change output must be `>=546` sats. If exact fee/change cannot be fixed before proving, reject the design.

## 3. SDK, runtime, persistence, and scalability

### Product/API surface

Export strict TypeScript interfaces and no Groth fallback:

```ts
type Digest4 = Uint8Array; // runtime length exactly 32
type ActionKind = "deposit" | "transfer" | "withdraw";

interface FriProfile {
  relationId: "shieldkit-pool-action-fri-v1";
  publicAbi: "sha256-u32le8";
  topologyId: "fri17-fused-state-v1";
  profileId: Uint8Array;
  parameterSetId: Uint8Array;
  network: "chipnet";
  denominationSats: 10_000_000n;
  noteDepth: 32;
  nullifierDepth: 32;
  maximumLive: 100_000;
}

interface FriProofResult {
  airId: string;
  profileId: Uint8Array;
  parameterSetId: Uint8Array;
  statementDigest: Uint8Array;
  proofBytes: Uint8Array;
  roleUnlocks: readonly Uint8Array[];
  durationMs: number;
  peakRssBytes: number;
  runtimeArtifactSha256: string;
  provenanceManifestSha256: string;
}
```

Public operations:

```text
createPool
deriveAddress
prepareDeposit / prepareTransfer / prepareWithdrawal
proveAction
assembleAction
verifyAction
executeAction
recoverFromSeed
inspectPool
refreshRuntime
rebroadcastExact
doctor
```

Lifecycle:

1. Acquire per-instance writer lock; load and validate tip, funding lane, state, descriptor, and journal.
2. Reserve wallet notes and one funding lane using compare-and-swap.
3. Derive canonical post-state, packet, outputs, exact transaction context, fixed fee, and change.
4. Build the AIR witness and call the pinned Rust runtime.
5. Validate proof metadata and fixed 17-role encoding.
6. Assemble and sign the exact transaction.
7. Run all-input local VM verification and exact byte/resource checks.
8. Persist pre-broadcast journal and raw transaction atomically with file and directory fsync.
9. Run node policy preflight, broadcast once, then read back exact raw bytes/state at zero confirmation.
10. Commit local tip or retain a resumable/rebroadcastable journal entry. Never wait for a block.

Use a persistent Rust worker binary with a length-prefixed canonical-JSON stdin/stdout protocol for `manifest`, `prove`, and `verify`; binary values are lowercase hex, stdout contains protocol frames only, and stderr contains secret-free diagnostics. The runtime handshake must match the release manifest hash before accepting witnesses. Python is excluded from the shipped runtime.

Stable error codes:

```text
PROFILE_MISMATCH
NON_CANONICAL_WIRE
INSTANCE_BUSY
STALE_TIP
CHAIN_BACKLOG_LIMIT
INSUFFICIENT_FUNDING
PROVER_SLA_EXCEEDED
RESOURCE_LIMIT
PROOF_INVALID
VM_REJECTED
READBACK_MISMATCH
RECOVERY_INCOMPLETE
ARTIFACT_INTEGRITY
```

Store a new schema only: profile/instance/category, genesis descriptor, current state and tip, note records `(rho,cm,leaf,index,spent)`, funding lanes, journal phases, exact raw transactions, proof metadata, runtime provenance, and recovery cursor. Seed/private material is mode `0600`; directories are `0700`; logs and telemetry must never contain seed, account key, nullifier key, witness, proof randomness, or unredacted runtime requests.

### Direct horizontal scaling

- Exactly one active mutating action and at most one queued action per instance. Additional requests fail `INSTANCE_BUSY`.
- Cross-process `flock` plus persisted compare-and-swap on tip outpoint, sequence, state hash, funding outpoint, and journal generation.
- Re-read all CAS fields before signing and before broadcast. A stale proof is discarded and rescheduled from the new state; it is never patched.
- Global local worker count is `min(configuredWorkers, activeInstances, floor(0.80*physicalRAM/observedPeakPerWorker))`.
- Verify CPU affinity and core utilization; use weighted round-robin across instances so one long proof cannot starve another.
- The scheduler is local resource control, not a protocol sequencer. Instances have independent state, carrier sets, funding, anonymity sets, liquidity, data directories, and writer locks.
- No automatic bridging or cross-pool selection. Moving value between instances is an explicit withdrawal/deposit and exposes the ordinary linkability of that flow.
- Publish anonymity/liquidity fragmentation as a scaling cost.

Before proof generation, reject if the instance’s unconfirmed ancestry is `>=20` transactions or `>=2,000,000` serialized bytes, or if live node policy probing predicts rejection. BCHN removed older ancestor/descendant count and byte caps, but provider and mempool policies remain deployment-specific, so runtime probing is authoritative ([BCHN v23 release notes](https://docs.bitcoincashnode.org/doc/release-notes/release-notes-23.0.0/)).

Qualification scalability workload:

- Exactly eight isolated pools and 256 fresh real actions.
- Per pool: eight deposits, sixteen transfers, eight withdrawals.
- Distinct genesis/category/state carriers/funding/keys/data roots; only the signed runtime is shared read-only.
- Primary run uses four prover workers and must complete without cross-instance contamination, lost updates, duplicate nullifiers, or stale-tip acceptance.
- Finite worker benchmarks use 1, 2, and 4 workers. Four-worker throughput must be `>=3.0x` one-worker throughput; single-worker action p95 remains `<=60 s`; four-worker loaded p95 `<=120 s`; per-worker peak RSS `<=4 GiB`; aggregate RSS `<=80%` of physical RAM.
- Capture raw samples, CPU utilization, run queue, RSS, proof/transaction bytes, queue latency, VM metrics, and admission/readback results.

History/recovery scalability:

- Generate 100,000 unique model-valid state transitions through the production state/store codecs and independent oracle. This dataset qualifies scanning/storage only and must not be represented as 100,000 proof or VM samples.
- State application p95 `<=250 ms`.
- Warm recovery of authenticated compact history `<=15 min`, peak RSS `<=2 GiB`, store `<=2.5 GiB`.
- The ratio of warm per-event processing time at 100,000 events versus 1,000 events must be `<=1.10`.
- Recovery scans confirmed chain plus current mempool from the recorded genesis; reconstructs candidate `rho` for the stable owner; verifies packet/state/transaction chaining; and finds zero-conf receipts.
- Chain acquisition latency is reported separately from local recovery performance.

## 4. Gate-ordered implementation, qualification, and release

Expose these authoritative commands:

```text
npm run ci
npm run qualify:bootstrap
npm run qualify:security
npm run qualify:reality
npm run qualify:corpus
npm run qualify:scale
npm run qualify:package
npm run qualify:clean-host
npm run release:verify
```

### P0 — Containment, provenance, and legal gate

- Snapshot parent Git status/tree before work; every resulting tracked/untracked path must remain under `shieldkit-fri-stark/`.
- Route Cargo/npm/Python/temp/data caches into `.private/`; forbid generated writes outside the root.
- Freeze local baseline bytes and reproduce all baseline measurements in an isolated contained copy.
- Replay from clean upstream plus a recorded patch series and prove equality to the frozen specimen.
- Materialize the explicit source grant/license and third-party notices before any public package.
- Emit a signed/JCS provenance manifest and baseline report. Mismatch or insufficient rights blocks public release.

### P1 — Security and one-transaction reality gate

Before porting the full SDK:

- Implement final depth-20 AIR [AMENDED 2026-08-06], independent model/oracle, native prover/verifier, canonical proof codec, 17 role locks, minimal exact assembler, and parameter/security calculator.
- Generate one fresh real proof and one fully signed transaction for each action.
- Run exact byte, unlock, stack, opcode/op-cost, density, standardness, and transaction-context measurements.
- Demonstrate full witness-dependent behavior, runtime-general paths, fixed proof size, and ZK closure.
- Require all security, `<=100000` byte, one-transaction, VM, and prover SLA gates.
- If no parameter tuple passes, stop and emit the complete Pareto frontier, constraint responsible for failure, and smallest measured overage. Do not build the product around a projection.

### P2 — Differential corpus and adversarial gate

Produce 256 distinct proofs and transactions per action, 768 total:

- Unique statements, witnesses, transcript seeds, proofs, outpoints, funding, and state positions.
- Execute on regtest, mining between chains as needed to keep corpus generation bounded; mined qualification does not alter production zero-conf behavior.
- Require identical verdicts and decoded states across TypeScript, Python, Rust, AIR evaluator, covenant model, and raw transaction model.

Mutation matrix must include:

- Every packet/state byte and reserved bit.
- Noncanonical field limbs, truncated/extended/reordered proof data, alternative encodings, nonzero padding, root/path/query changes, transcript reordering, role swapping, duplicated/omitted roles, wrong parameter/profile/AIR identifiers.
- Invalid note ownership, rho, note path/index, output commitment, nullifier, predecessor/successor ordering, repeated nullifier, wrong append index/root, count/capacity/sequence/reserve errors.
- Action-selector crossover and nonzero inactive fields.
- Source-input substitution, common-parent/vout substitution, state NFT/category/capability/commitment changes, carrier value changes, successor lock replacement, output insertion/reordering, payout/change/value/script changes, funding signature/sighash changes.
- Free witness hints, unconstrained inverse/carry/selector/lookup/padding cells, masking removal, OOD/DEEP/FRI fold mutations, repeated-query edge cases, grinding/nonce changes.
- Every invalid case must fail at the earliest appropriate independent layer; no single implementation may provide both test mutation and sole oracle.

### P3 — Independent BCH execution gate

For the identical final raw bytes:

- Pass Libauth using an exact integrity-pinned release.
- Pass the latest unmodified maintainer verifier-bench, with its exact commit recorded.
- Pass unmodified BCHN `testmempoolaccept`, mempool execution, and mined regtest execution.
- Pass LeanBCH cross-checks for every supported opcode/resource model.
- Report exact total bytes, each input unlock, source-lock score contribution, stack maxima, op counts/costs, hash density, and verdicts.
- Resolve any LeanBCH/BCHN/bench op-cost discrepancy or prove, with exact margins, that it cannot change acceptance. A patched harness is supplementary evidence only.

### P4 — Product lifecycle and recovery gate

- Port wallet, two-lane funding, journal, exact rebroadcast, doctor, create, deposit, transfer, withdraw, and seed recovery.
- Inject crashes after every reservation, proof, signature, fsync, broadcast, readback, and commit boundary.
- Test stale tips, conflicting writers, double spends, mempool eviction/replacement, reorgs, partial/corrupt stores, runtime replacement, manifest mismatch, interrupted recovery, and byte-identical rebroadcast.
- Require fail-closed behavior, deterministic restart, no lost spendability, and no secret-bearing logs/core/test artifacts.
- Assert every normal command terminates after zero-conf admission and exact readback without polling for confirmation.

### P5 — Performance and scalability gate

- Pin the reference host by recording exact CPU model, microcode, physical/logical cores, RAM, storage, kernel, governor, swap state, toolchain, and runtime hashes.
- Run three warmups and at least 32 measured proofs per action with CPU affinity and no competing workloads.
- Enforce action-specific p95 `<=60 s` and peak RSS `<=4 GiB`.
- Run the eight-instance/256-action campaign, worker scaling benchmarks, 100,000-event store/recovery benchmark, backlog guards, CAS/concurrency tests, and secret-free metrics checks.
- This is a finite benchmark campaign, not a soak test.

### P6 — Reproducible package and audit-handoff gate

Build twice on independent clean hosts with fixed source-date epoch, locale, timezone, umask, toolchains, dependencies, and offline caches. Require identical source, platform-neutral CLI, Linux x86_64 GNU runtime, generated covenant artifacts, profile manifest, and release-manifest hashes.

Package only an allowlisted inventory:

- CLI/SDK.
- Prebuilt signed runtime; no runtime compilation or downloads.
- Canonical specifications/test vectors.
- Profile, parameter, AIR, topology, runtime, and provenance manifests.
- CycloneDX 1.6 SBOM, licenses, source grant, `THIRD_PARTY_NOTICES`.
- Security calculation, AIR/constraint inventory, threat model, topology/byte report, mutation corpus summary, independent VM evidence, performance/scale reports, recovery/operations guide, incident/revocation procedure, and known limitations.

Reject tampered hashes/signatures, extra files, absolute/escaping paths, symlinks, hardlinks, wrong modes, noncanonical manifests, dependency drift, and secret-bearing artifacts. Require zero known Critical/High findings; document accepted lower-severity findings.

Use a 2-of-3 offline Ed25519 threshold over the JCS release manifest and artifact Merkle root. Installer verifies threshold, inventory, modes, hashes, profile/runtime compatibility, and then performs an atomic install with receipt. Missing two signatures blocks the public candidate.

### P7 — Independent Chipnet release gate

On two independent clean Linux hosts using packed artifacts, distinct host identities, seeds, funding, pool categories, instances, and data roots, each performs:

1. Install offline and verify release.
2. Create fresh Chipnet pool.
3. Deposit to address A.
4. Deposit to address C.
5. Transfer A to B.
6. Withdraw B.
7. Erase wallet/index state while preserving only seed and public genesis descriptor.
8. Recover C from seed by chain plus mempool scan.
9. Withdraw recovered C.

For every transaction require node admission, exact raw-transaction readback, expected tip/state NFT commitment, local VM agreement, and journal/store commit at zero confirmation. Never wait for a block.

Each host emits an Ed25519-signed JCS transcript binding release/runtime/profile hashes, host manifest, commands, timestamps, RPC verdicts, raw transactions, txids, decoded states, and evidence hashes. Both full journeys must pass.

`release:verify` succeeds only when P0–P7 evidence is internally consistent and all signatures/hashes resolve. It produces release-ready artifacts locally but does not create a Git tag, publish npm artifacts, upload binaries, or change parent defaults without separate authorization.

Exact permitted release claim:

> ShieldKit-FRI Beta — unaudited, Chipnet-only, fresh-genesis experimental profile; zero-conf admission/readback; no mainnet, production, encrypted-note privacy, or Groth-pool compatibility claim.

“Transparent” and “no trusted setup” may be added only after provenance/runtime verification. A numeric 100-bit claim may be added only if the final signed security calculation passes.

## 5. Assumptions, stop conditions, rollout, and rollback

- The available source grant is converted into an explicit distributable artifact during P0; otherwise work may remain internal but cannot become a public package.
- The frozen 98 KB specimen is lineage/bootstrap evidence, not immutable production parameters. The final relation, AIR, Merkle width, query count, grinding, and proof bytes are selected only by the deterministic security/byte/SLA search.
- Fixed denomination is 10,000,000 sats; note and nullifier depths are 32; maximum live notes are 100,000.
- Privacy is record-free owner hiding against a passive observer who does not know the address. Address disclosure enables scanning and receipt linkage.
- Public beta requires two clean qualification hosts, Chipnet funding, and two of three release signatures. Missing infrastructure blocks signing, not technical gate reporting.
- No placeholder proof, synthetic transaction, projected byte count, patched policy harness, incomplete provenance, or storage-only workload may satisfy a release claim outside its explicitly limited purpose.
- No soak or confirmation-wait test is added later as an implicit requirement.
- Distribution rollback uses a signed revocation manifest: stop new installs, genesis creation, and ordinary actions; preserve local evidence, seed recovery data, exact raw transactions, and the last known-good runtime. No remote kill switch, silent verifier replacement, or Groth downgrade.
- A verifier/relation defect requires a new profile ID and fresh genesis. Existing pools never mutate profile, locks, category, or verifier in place.
- Parent-package cutover is a separate future authorization after beta evidence: wire the parent binary/workspace/docs, retain Groth recovery tooling, and document withdrawal/deposit migration. It is not part of this contained build.

---

## AMENDMENT-20260806 — note/nullifier tree depth 32 → 20 (ratified)

**Status:** ratified by user decision ("ok depth 20 locked in"). Supersedes every depth-32 pin above.

**Rationale (measured, evidence/production/SIZE_INVESTIGATION_20260806.json):**
- Tx size is FLAT for all depths 4–31 (T=1024, N=2^21=8^7 at blowup 2048): depth 4 = 103,321 B,
  depth 14 = 103,331 B, depth 17 = 103,411 B, depth 20 = 103,425 B — differences are statement-field noise.
- Depth 32 is a cliff: T=2048, N=2^22 NOT 8^m → illegal for the fold-8 loop → blowup pad 2048→8192
  (N=2^24) → measured 124,739 B at nq8 (was the root cause of the >100 KB floor).
- Capacity: 2^20 = 1,048,576 notes; nullifier tree is monotonic → ~28 years at 100 tx/day.
  Depth 17 (100k notes) buys nothing in bytes (14 B) and shortens lifetime 8×.

**Product config (locked, unchanged by this amendment):**
depth=20 · nq=7 · blowup=2048 · grind=30 · fold_step=3 · deep · T=1024 · N=2^21=8^7 · security=100 bit.

**Measured after amendment (evidence/production/WS1_GATE_20260806.json):**
deposit 99,313 B · transfer 99,378 B · withdrawal 99,394 B — all 17/17 accept, 0 density fails,
maxUnlock 7,898 ≤ 10,000, RC 0. All three actions ≤ 100,000 B at the product config.

**Effect on gates:** P1 floor-size and domain-legality gates now measured green at the amended config;
the d32/b8192 "floor" is no longer normative (kept as a density/stress configuration: 122,443 B, 19/20, 0 fails).
