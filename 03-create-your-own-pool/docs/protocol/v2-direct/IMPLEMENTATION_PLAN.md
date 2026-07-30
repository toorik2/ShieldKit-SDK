# ShieldKit Protocol V2 Direct — Native 128-Byte State

## 1. Product and security contract

This is the active V2 Direct implementation plan. Preserve the abandoned batching design under `docs/archive/` as superseded research.

The complete user flow is:

```text
sync public pool history
→ construct one private witness locally
→ generate one Groth16 proof locally
→ sign one wallet-owned transparent funding input
→ broadcast one BCH settlement transaction
```

There is no batching, batcher, coordinator, sponsor, faucet, fee ticket, remote prover, preparation transaction, recursive proof, or root-history accumulator.

The protocol goals are precise:

- Secure: BCH covenants and one Groth16 proof enforce note authority, nullifier uniqueness, state transitions, value conservation, and exact transaction construction.
- Private: a public nullifier does not reveal which qualifying historical note was spent.
- History-scalable: proof size, circuit size, and Merkle-path work do not grow with pool history.
- Not throughput-scalable: the single state NFT remains a serial writer. Concurrent users can race and require re-proving.

V2 requires the post-May-2026 BCH rules that permit 128-byte NFT commitments. See the [P2S specification](https://github.com/bitjson/bch-p2s) and [BCHN releases](https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/releases).

## 2. Exact V2 protocol

### Native 128-byte state NFT

The mutable state NFT commitment is the complete canonical pool state. There is no secondary state hash or external state preimage.

```text
Offset     Size   Field
0          4      ASCII "SKS2"
4          32     profileId
36         32     noteRoot
68         32     nullifierRoot
100        4      noteCount u32le
104        4      nullifierCount u32le
108        4      maximumLiveNotes u32le
112        8      reserveSats u64le
120        8      actionSequence u64le
Total      128
```

Encoding rules:

- `profileId` uses raw SHA-256 byte order.
- Roots are canonical BN254 scalar-field elements encoded as 32-byte big-endian integers.
- Counts and amounts use unsigned little-endian encoding.
- `instanceId` is not duplicated: it is exactly the state NFT's 32-byte CashToken category in token-prefix byte order.
- Explorer/display transaction-ID byte order is only a UI conversion and must never enter consensus encoding.
- `liveNoteCount` is derived as `noteCount - nullifierCount`.
- Denomination is fixed by the profile.
- Both source and successor state NFTs require:
  - category equal to `instanceId`;
  - mutable capability;
  - zero fungible amount;
  - exactly 128 commitment bytes.

Required invariants:

```text
nullifierCount ≤ noteCount

liveNoteCount := noteCount - nullifierCount

reserveSats =
  liveNoteCount × denominationSats

1 ≤ maximumLiveNotes
maximumLiveNotes ≤ floor(MAX_MONEY_SATS / denominationSats)
liveNoteCount ≤ maximumLiveNotes

max(noteCount, nullifierCount)
  ≤ actionSequence
  ≤ noteCount + nullifierCount

noteCount ≤ 0xffffffff
nullifierCount ≤ 0xfffffffe
actionSequence < 2^33
```

The nullifier limit leaves physical tree positions 0 and 1 for sentinels. Deposit/transfer requires `pre.noteCount < 0xffffffff`; transfer/withdrawal requires `pre.nullifierCount < 0xfffffffe`.

The first profile fixes:

```text
denominationSats = 10,000,000
noteTreeDepth = 32
nullifierTreeDepth = 32
```

Instance capacity:

- General qualified instance: `maximumLiveNotes = 210,000,000`.
- Disposable Chipnet playground: `maximumLiveNotes = 32`.
- The playground must warn that 32 deposits can intentionally close admission.
- No expiry, eviction, admin clearing, reusable slots, or inactivity confiscation exists.

### Profile and instance identity

Define:

```text
profileId =
  SHA256("SKP2" || RFC8785(profileCore))
```

`profileCore` includes:

- Network and denomination.
- Circuit relation and R1CS hash.
- Groth16 verification-key hash.
- Tree depths, leaf schemas, curve parameters, and Poseidon domains.
- State, packet, address, proof, and unlock encoding versions.
- Public-input ABI.
- Base verifier artifact hashes.
- Reference software/toolchain versions.

It excludes instantiated scripts containing `profileId` or `instanceId`, preventing a profile-hash cycle.

The instance descriptor separately pins:

- `profileId`.
- State token category/`instanceId`.
- Genesis transaction and exact state outpoint.
- Final instance-specific carrier, binding, and state locks.
- Rolling-output base values.
- Initial 128-byte state.
- Signed artifact manifest.

### Action packet

Use this exact 552-byte packet:

```text
Offset     Size   Field
0          4      ASCII "SDA2"
4          1      networkId
5          1      kind
6          2      flags=0
8          32     instanceId
40         128    preState
168        128    postState
296        32     publicNullifier
328        32     outputNoteLeaf
360        128    encryptedRecord
488        32     withdrawalLockingBytecodeHash
520        32     transactionContextHash
Total      552
```

Kind-specific canonical fields:

| Kind | Nullifier | Output leaf and record | Withdrawal hash |
|---|---|---|---|
| Deposit | inactive zero | active | inactive zero |
| Transfer | active | active | inactive zero |
| Withdrawal | active | inactive zero | active |

Action kind determines whether a field is active. An active field may contain any valid canonical value, including zero; zero must not be globally reserved as an impossible Poseidon result.

`boundaryAmount` is removed. The fixed denomination, state delta, output topology, and transaction context already bind the exact boundary value.

The packet must satisfy:

```text
packet.instanceId
  = source state NFT category
  = successor state NFT category

packet.preState
  = source state NFT commitment

packet.postState
  = successor state NFT commitment
```

Hash the complete packet:

```text
digest = SHA256(ActionPacketV2)

publicInput0 = OS2IP_BE(digest[0..15])
publicInput1 = OS2IP_BE(digest[16..31])
```

Keep both 128-bit public inputs. Do not truncate the digest merely to save one verifier multiplication; verifier fit remains a foundation gate.

### State transitions

Deposit:

```text
actionSequence += 1
noteCount += 1
nullifierCount unchanged
noteRoot = append(outputNoteLeaf)
nullifierRoot unchanged
reserveSats += D
require preLive < maximumLiveNotes
```

Transfer:

```text
actionSequence += 1
noteCount += 1
nullifierCount += 1
noteRoot = append(outputNoteLeaf)
nullifierRoot = insert(publicNullifier)
reserveSats unchanged
liveNoteCount unchanged
```

Withdrawal:

```text
actionSequence += 1
noteCount unchanged
nullifierCount += 1
noteRoot unchanged
nullifierRoot = insert(publicNullifier)
reserveSats -= D
require preLive ≥ 1
```

Every addition and subtraction requires explicit overflow or underflow preconditions. The circuit and state covenant both enforce the public counter, reserve, sequence, capacity, and value deltas.

### Keys, notes, and Faerie resistance

Use one spend secret and one incoming-view secret per HD account:

```text
S = [sk]B8
V = [ivk]B8

authority = Poseidon(
  ADDRESS_DOMAIN,
  profileId limbs,
  instanceId limbs,
  S.x, S.y,
  V.x, V.y
)
```

The recipient address contains network, profile, instance, compressed `S`, compressed `V`, and `authority`.

For each deposit or transfer:

```text
rho = Poseidon(
  RHO_DOMAIN,
  profileId limbs,
  instanceId limbs,
  postActionSequence,
  rhoBlind
)

cm = Poseidon(
  NOTE_DOMAIN,
  profileId limbs,
  instanceId limbs,
  denominationSats,
  authority,
  rho,
  r
)

nf = Poseidon(
  NULLIFIER_DOMAIN,
  profileId limbs,
  instanceId limbs,
  sk,
  rho,
  cm
)
```

`rhoBlind`, `r`, and the encryption ephemeral scalar are fresh, canonical, and nonzero. Instance plus the uniquely accepted action sequence prevents canonical cross-action `rho` reuse without reintroducing a state-hash layer.

Encrypted record:

```text
compressed BabyJub ephemeral point E   32
encrypted rho                           32
encrypted r                             32
Poseidon authentication tag            32
Total                                  128
```

The circuit proves:

- Recipient and ephemeral points are canonical, nonidentity, and in the prime subgroup.
- `E = [esk]B8`.
- Shared secret equals `[esk]V`.
- Domain-separated Poseidon masks correctly encrypt `rho` and `r`.
- The authentication tag binds shared secret, profile, instance, `cm`, `E`, and ciphertext.
- The note leaf binds `cm` and the circuit-derived authentication tag. The tag
  already binds the exact canonical record semantics: pool context, ECDH
  points, `cm`, encrypted `rho`, and encrypted `r`.

```text
outputNoteLeaf =
  Poseidon(NOTE_LEAF_DOMAIN, cm, tag)
```

This circuit-friendly encryption requires a dedicated cryptographic audit and cross-language known-answer vectors.

There is no separate encrypted-record commitment or `RECORD` Poseidon domain.
Every accepted output derives the tag in-circuit, binds the exact tag bytes and
canonical packed ephemeral point in the packet, then derives the leaf. Every
spend recomputes `cm`, supplies the leaf-bound tag, and proves membership.
Security relies on the accepted-output induction from an empty genesis and
Poseidon collision/preimage resistance; a pool must never import note roots
created under another leaf formula. This pre-release relation change requires a
new profile, instance/genesis, vectors, proof artifacts, and verifier evidence.

### Trees

Note tree:

- Depth 32.
- Append-only.
- Deposit and transfer append exactly one leaf.
- Withdrawal leaves it unchanged.
- Persistent frontier and nodes make append/path work fixed-depth.

Indexed nullifier tree:

- Depth 32.
- Full canonical BN254 field nullifiers; no 128-bit truncation.
- Explicit leaf types: empty, minimum sentinel, normal, maximum sentinel.
- Sentinels occupy physical leaves 0 and 1.
- Conceptual ordering is `MIN < every normal field value < MAX`; normal zero and `Fr−1` remain valid.
- A normal leaf commits to type, physical index, nullifier key, successor index, and successor key.
- Insertion proves:
  1. predecessor membership;
  2. strict conceptual ordering;
  3. predecessor successor-pointer replacement;
  4. empty append position;
  5. insertion of the new normal leaf;
  6. exact post-root.
- Duplicate normal nullifiers fail.
- SQLite stores normal keys as canonical 32-byte big-endian blobs for logarithmic predecessor lookup.

There is no historical-root accumulator. A direct proof always binds the current state and must be regenerated after a competing state transition.

## 3. BCH settlement and wallet architecture

### Authenticated covenant DAG

Preserve this security topology:

```text
verifier carriers
  validate the Groth16 proof and packet digest

binding carrier
  validates packet encoding,
  both public inputs,
  transaction context,
  source NFT state,
  successor NFT state,
  profile/instance identity

state covenant
  pins the exact binding/carrier roles,
  enforces public state/value invariants,
  requires the complete successor bundle
```

The binding input performs the raw packet/state comparisons because the state covenant cannot rely on reading another input's unlocking program.

Every verifier carrier also requires the real state category at the fixed state-input role. This prevents anyone from spending and burning a carrier independently.

### Rolling bundle

Current foundation status (2026-07-28): **local hard-limit candidate found;
release qualification open**. The bounded-retry PF7 ECIP candidate is
non-total and rejected. PF11 remains only a semantic correctness oracle:
five executor carriers, four exact-MSM carriers, a separate identity-aware
Miller-genesis carrier, and a terminal carrier. Its totalized five-executor
implementation exceeds the BCH-2026 operation ceiling and is not deployable.
The V2 CLI operational boundary accepts only the exact PF10-FusedQGenesis
topology and ordered roles; a PF11 descriptor fails with
`PF11_SEMANTIC_ORACLE_ONLY` before settlement pins, runtime material, or an
action context can be constructed. This does not remove PF11 from generic
descriptor or oracle tooling.

The separately identified `PF10-FusedQGenesis` topology is the provisional
local candidate. It fuses the final MSM window and identity-aware Miller
genesis at role 8, places the terminal at role 9, binding at role 10, state at
role 11, and funding at role 12. The current local Libauth evidence is
development-only: `.codex-build/v2-pf10-libauth-qualification/libauth.json`
(`sha256:83588c201252930a2f6d403ed11662175d381177c5bc70909b2224f813106478`)
records all thirteen inputs accepted for deterministic deposit, transfer, and
withdrawal fixtures, serialized sizes 97,852/97,852/97,886 bytes, a 10,000-byte
maximum unlock, and 96.76% peak operation use. Its own claims exclude a final
key, BCHN, LeanBCH, maintainer benchmark, live-chain provenance, production,
and release qualification. These facts are development telemetry, not BCHN,
LeanBCH, ceremony, audit, clean-host, or release qualification. A circuit
redesign requires a new VK and a fresh candidate search. See
[`VERIFIER_FOUNDATION_DECISION.md`](./VERIFIER_FOUNDATION_DECISION.md).

Candidate selection:

1. Reject proof-dependent retry behavior or variable-length unlocks.
2. Reject transaction size above the full 100,000-byte standard-policy limit.
3. Reject any unlock above the full 10,000-byte standard-policy limit.
4. Reject any VM resource above its full standard limit.
5. Treat 90,000-byte transaction and 9,500-byte unlock margins as telemetry
   only; they must never reject an otherwise standard candidate.
6. Among passing candidates choose the smallest complete transaction; break
   ties by smallest maximum unlock, then lowest VM cost.

Provisional PF10 genesis outputs (thirteen outputs):

```text
0        state NFT with initial 128-byte state
1..10    verifier carriers for roles 0..9
11       binding carrier
12       wallet change
```

Genesis must create exactly one mutable NFT of category `instanceId`, create no fungible tokens of that category, and leave no minting authority.

Every provisional PF10 action consumes exactly thirteen inputs:

```text
0..4     PairFold exec0..exec4 from prior outputs 1..5
5..7     three exact-MSM carriers from prior outputs 6..8
8        fused final-MSM/identity-aware Miller-genesis from prior output 9
9        PairFold terminal carrier from prior output 10
10       binding carrier from prior output 11
11       state NFT from prior output 0
12       one wallet-owned tokenless P2PKH funding input
```

All rolling inputs share the immediately preceding bundle transaction ID and exact source indices.

Deposit and transfer outputs (thirteen outputs):

```text
0        successor state NFT
1..10    exact successor verifier carriers for roles 0..9
11       exact successor binding carrier
12       fresh wallet P2PKH change
```

Withdrawal has fourteen outputs: `0` successor state, `1..10` successor
verifier carriers, `11` successor binding, exact-`D` P2PKH payout at `12`, and
fresh wallet P2PKH change at `13`.

All non-state inputs and outputs are tokenless. Carrier, binding, and state base values remain exact across transitions. State output value is:

```text
stateBaseSats + postState.reserveSats
```

Do not reuse the old 1,080-sat state base. At instance construction:

```text
baseValue =
  roundUpTo100(
    max(1000, 2 × pinnedBchnDustThreshold(finalOutput))
  )
```

Compute and pin separate values for state, verifier-carrier, and binding outputs using the final locks and 128-byte token prefix.

### Exact-MSM frame and public-input ingress

Each exact-MSM stage uses one exact 128-byte state frame. Its
fixed big-endian layout is `rX[32] || rY[32] || rZ[32] || in0[16] || in1[16]`,
where `rX`, `rY`, and `rZ` are canonical BN254 base-field elements and `in0`
and `in1` are the two unsigned 128-bit big-endian halves of the packet
SHA-256. Frame decoding rejects any other length, a coordinate outside the
canonical field range, or a noncanonical encoding. The u128 limbs have no sign
byte or alternate byte order; they are never decoded through BCH's signed VM
number format. A VM-only conversion adds a zero sign byte after canonical
decoding when required by a numeric opcode. Every frame binds the same
`in0`/`in1`; PF10's fused role consumes the final frame and applies the
identity-aware Miller genesis without changing the transcript.

### Exact non-circular transaction binding

`transactionContextHash` commits to:

- Domain and context version.
- Network, profile, instance, and action kind.
- Transaction version and locktime.
- Ordered input/output roles and counts.
- Every sequence and source outpoint.
- Every source value, locking-bytecode hash, and canonical token-prefix hash.
- Every output value, locking-bytecode hash, and canonical token-prefix hash.

It excludes:

- All unlocking bytecode.
- The proof and packet.
- The wallet signature.
- The current transaction ID.

The packet commits to the context hash; the Groth16 proof commits to the packet; the binding covenant recomputes both packet digest and transaction context from the actual transaction.

All verifier proof/hint encodings must be deterministic and fixed-width. Padding is profile-pinned. No valid proof may require changing randomness, fee, packet, public input, or witness and proving again merely to obtain an encodable verifier unlock.

### Self-funded fees only

- No sponsor service, sponsor API, sponsor input, fee ticket, faucet service, faucet client, or automatic funding.
- Deposit input funds `D + fee + change`.
- Transfer and withdrawal inputs fund `fee + change`.
- Withdrawal releases exactly `D` from the pool.
- Pool reserve and carrier values never fund miner fees.
- The wallet selects exactly one owned tokenless P2PKH UTXO.
- If none is sufficient, fail before proving with `FUNDING_UTXO_REQUIRED`.
- Consolidation and wallet funding are explicit out-of-band transactions.
- Change is sent to a fresh wallet P2PKH address and must exceed the pinned dust threshold.
- Default fee rate is 1 sat/B.
- The client requires explicit confirmation above 10 sat/B.
- Changing fee or change after proving requires a new proof because transaction context changes.
- Sign the funding input using Schnorr `SIGHASH_ALL|UTXOS|FORKID` only after the proof and exact transaction are fixed.

### Durable lifecycle

Public interfaces:

```text
encodePoolStateV2 / decodePoolStateV2
encodeActionPacketV2 / decodeActionPacketV2
prepareAction
proveAction
signAction
broadcastAction
resumeOperation
abandonOperation
recoverPool
```

Journal states:

```text
draft
funding_selected
tip_synced
proving
proved
needs_reproof
signed
broadcast
mempool
confirmed
settled
conflicted
reorged
abandoned
```

Action flow:

1. Follow the unique state lineage from the instance's genesis outpoint.
2. Validate confirmed state plus a reversible mempool overlay.
3. Reserve the private note and funding UTXO atomically.
4. Construct the exact transaction skeleton and packet.
5. Prove and locally verify.
6. Re-sync immediately before signing.
7. If the state outpoint changed, mark `needs_reproof`; never sign the stale transaction.
8. Regenerate paths, output randomness, record, packet, context, and proof.
9. Execute every input locally in the pinned VM.
10. Broadcast through the single mandatory network gate.
11. Commit canonical state only after confirmation.
12. Roll back on conflict, dropped mempool parent, or reorg.
13. Stop after three automatic conflicts; unlimited retry requires explicit user selection.

SQLite uses WAL, `synchronous=FULL`, atomic state/tree/note/journal writes, and a 100-block undo journal.

Recovery rules:

- Never select an unrelated candidate merely because it has the highest sequence.
- Anchor at descriptor genesis and follow the unique spent-state lineage on the active best chain.
- Treat mempool descendants as reversible state.
- Full recovery requires historical action packets because roots do not contain membership data.
- Action packets remain available in the binding inputs on chain.
- Snapshots are accepted only after height, block hash, state outpoint, raw 128-byte state, and reconstructed roots match locally validated chain data.
- Raw-genesis fallback parses and applies each historical action exactly once.
  It must not authenticate its output by replaying the same history again.
- Normal snapshot import reconstructs terminal roots bottom-up exactly once,
  materializes authenticated internal nodes, the note frontier, successor
  leaves, and the big-endian predecessor index during that pass, then commits
  the complete checkpoint atomically. It never replays pre-checkpoint Merkle
  updates.
- Only post-checkpoint suffix actions use fixed-depth incremental updates.
- Historical packet discovery is streamed from the canonical lineage for note
  recovery without rebuilding historical tree paths. Missing or corrupt packet
  data yields incomplete recovery or explicit raw fallback, never an
  authoritative zero balance.
- Snapshot signatures establish distribution provenance, not consensus validity.
- Deeper-than-100-block reorgs trigger wipe and replay.

### CLI

```text
shieldkit wallet create
shieldkit wallet receive
shieldkit pool add <descriptor>
shieldkit sync
shieldkit deposit --to <shield-address> --broadcast
shieldkit transfer --note <id> --to <shield-address> --broadcast
shieldkit withdraw --note <id> --to <cashaddr> --broadcast
shieldkit recover
shieldkit status
shieldkit doctor
```

`wallet receive` only shows the address, required UTXO size, and observed balance. It contains no faucet integration or recommendation.

After qualification, V2 Direct becomes the default. V1 mutations require `--protocol v1-legacy` plus an explicit linkability warning.

## 4. Implementation sequence

### Phase A — Replace and freeze the specification

- Replace the active V2 plan with this plan and preserve the superseded batching
  design under `docs/archive/v2-batching/`.
- Freeze the relation, state, packet, address, profile, and domain identifiers in
  `IDS_AND_DOMAINS.md`, against the values enforced by the V2 codecs and profile
  validators.
- Rename the current misleading `shielded-action-v2` implementation as legacy.
- Build strict TypeScript and Rust codecs for the 128-byte state and 552-byte packet.
- Reject unknown keys, wrong lengths, noncanonical fields, wrong endianness, wrong token category order, and nonzero flags.
- Publish byte-offset diagrams and cross-language known-answer vectors.
- Implement independent state-transition and indexed-tree reference models.
- Prove or model state arithmetic, tree insertion, value conservation, and counter bounds before circuit work.

### Phase B — Circuit and verifier foundation gate

Current circuit sources are development-only and not qualification. Current
development-key PF10 proof evidence proves witness validity and local Groth16
verification for deterministic deposit, transfer, and withdrawal fixtures, but
its claims expressly exclude a final key, BCH VM, and production. No present
local artifact proves a final relation, final key, p95 performance result, or
release candidate; BCHN, LeanBCH, the unmodified maintainer benchmark,
ceremony, and independent audits remain missing.

- Implement the complete final `PoolActionV2Direct` relation under an explicitly development-only setup.
- Compile and record constraints, R1CS hash, WASM/native prover artifacts, and public-input ABI.
- Generate real proofs for the actual circuit and VK.
- Replace bounded-retry ECIP `vk_x` with exact fixed-round MSM using the
  canonical 128-byte BE frame.
- Complete PF11 as the semantic oracle with four MSM carriers, a separate
  identity-aware input-9 Miller genesis, and input-10 terminal transcript.
- Without waiting for PF11 production qualification, build
  `PF10-FusedQGenesis`, fusing only the final MSM window and identity-aware
  Miller genesis. Use a complete withdrawal as its first size/resource kill
  test, then require all action kinds and the full adversarial matrix.
- Search hard-limit-safe MSM window boundaries and other transcript-preserving
  repartitions. Generate deterministic verifier candidates and apply the
  carrier selection rule to complete transactions, not component lower bounds.
- Add instance/category guards and the rolling successor outputs.
- Execute real deposit, transfer, and withdrawal settlements using:
  - latest unmodified verifier benchmark;
  - Libauth;
  - BCHN `testmempoolaccept`;
  - mined BCHN execution;
  - LeanBCH.
- Measure every source output, output, lock, unlock, transaction, VM cost, and hash iteration.
- If no rolling verifier candidate passes, mark V2 Direct blocked. Do not restore preparation transactions or weaken packet binding.

### Phase C — Persistent trees, wallet, and recovery

Current local persistence/proving boundary (not qualification): schema v12
persists each owned note's note index and nullifier. `deriveProvingTransition`
returns the versioned compact proving object from one read-only SQLite
transaction, including fixed 32-level note membership/append and indexed
nullifier paths; it does not hand the prover an in-memory history tree.
`buildDirectV2CircuitInput` accepts that versioned compact object. The current
store suite is 42/42 and CLI suite is 28/28 when run with `TMPDIR=/dev/shm`;
both are local-only test evidence.

- Implement persistent note frontier and internal nodes.
- Implement indexed-nullifier nodes, successor leaves, and ordered predecessor index.
- Add wallet note records, transparent UTXO reservations, pending operations, undo data, and mempool overlays.
- Build a native Rust recovery scanner exposed to Node.
- Support one-pass raw-genesis replay and independently anchored authenticated
  snapshots. Build a bounded streaming format; do not require a monolithic
  hex-encoded JSON history.
- Materialize and atomically install persistent nodes/frontier/successor/index
  during the same bottom-up snapshot pass. Never follow snapshot
  authentication with full historical path replay.
- Add crash-safe separation of prepare, prove, sign, broadcast, and confirmed-state commit.
- Centralize every send behind the mandatory network gate.
- Create secrets atomically with mode `0600`.
- Verify signed/hash-pinned artifacts before use.
- Use tracked workspace lockfiles and immutable `npm ci`.

### Phase D — Final setup and audits

After the circuit and packet are frozen:

- Conduct one Groth16 phase-2 ceremony with at least five independent contributors.
- Apply a final public beacon.
- Independently verify the transcript on two clean machines.
- Reproduce final artifacts on two independent clean hosts.
- Obtain independent audits for:
  - protocol and privacy;
  - circuit, note encryption, and ceremony;
  - verifier carriers, binding, state covenant, and transaction topology;
  - wallet, persistence, recovery, and network gate.
- Any critical/high, applicable unresolved medium, skipped mandatory test, synthetic proof, unavailable VM, or non-reproducible artifact blocks qualification.

## 5. Qualification and rollout

Required test evidence:

Current Q04 result: the bounded tree/nullifier gate is verified at source commit
`b60e91a2914e959d456e31a3ec0f6d3288d3a194`. Four independent 25,000-entry
histories (100,000 aggregate) performed 100 close/reopen checkpoints and 500
duplicate, ordering, successor-pointer, alias, and noncanonical-field probes,
including scheduled `Fr=0` and `Fr-1` keys, with zero discrepancies and zero
unexpected accepts. The independent evidence-verification result is
`.codex-build/qualification-b60e91a/q04/q04-SuXwEl/verification.json`
(`sha256:daa795ef146c1e0bb06045ab2c2b92797db6d1201209edc912e6dd69f89de41b`),
which binds `evidence.json`
(`sha256:b48541fd0971af508f23e14f0c172a1b4c88440b6b8782e7e58381775488de01`).
This is a bounded aggregate-four-history result, not one 100,000-entry history
or any claim beyond 100,000 historical nullifiers; Q07 lifecycle/performance
qualification remains separate and open.

- State codec vectors for every boundary and every one-byte mutation across all 128 bytes.
- Rejection of 127- and 129-byte state commitments.
- Token-category byte-order and explorer-display conversion tests.
- Packet codec vectors and every one-byte mutation across all 552 bytes.
- Full SHA-256/two-limb public-input vectors across TypeScript, Rust, circuit, and covenant.
- 256 final-key proofs and exact real transactions per action kind: 768 total.
- Proof, packet, state, profile, category, carrier, token, value, role, outpoint, fee, change, and payout mutation matrices.
- Standalone carrier burn, partial bundle, mixed parent, fake category, duplicate state NFT, minting authority, and omitted successor attacks.
- Exhaustive depth-4 indexed-tree state-space tests.
- A bounded, reproducible 100,000-entry indexed-nullifier scaling campaign:
  four fixed-seed, 25,000-entry valid histories; durable checkpoint/reopen at
  every 1,000 entries; and deterministic duplicate, ordering, successor-pointer,
  alias, and noncanonical-field rejection probes at every checkpoint. Every
  accepted transition, membership path, and non-membership witness must agree
  with an independently implemented production-Poseidon oracle.
- The bounded campaign establishes correctness and measured performance only
  through 100,000 historical nullifiers. No result may be extrapolated into a
  claim about larger histories; the fixed-depth operation-count bound and
  separately reported storage/I/O measurements remain required evidence.
- Separately measure one-time bottom-up snapshot authentication, raw fallback,
  suffix replay, warm fixed-depth updates, and cold database I/O. None of these
  measurements may be mislabeled as another.
- Freeze the 100,000-action recovery/performance history to one deposit,
  99,998 transfers that repeatedly replace the one live note, and one final
  withdrawal. This ends with 99,999 note leaves, 99,999 nullifiers, zero live
  notes, and zero reserve; it exercises both append-only trees near the full
  bounded-history size and prevents an easier action mix from being selected
  after measurements are known.
- Normal nullifiers at field zero and `Fr−1`.
- Duplicate keys, bad ordering, corrupt successor pointers, aliases, and noncanonical field encodings.
- Invalid/subgroup points, malformed records, reused randomness, non-decryptable outputs, Faerie-style outputs, and secret-canary scans.
- Ten thousand crash injections across journal states.
- Reorg depths 1, 2, 10, and 100 plus deeper wipe-and-replay.
- Competing-wallet campaigns with 2, 4, 8, and 16 users.
- Mempool-parent loss, conflicting siblings, and malicious self-transfer contention.
- No lost notes, double commitments, incorrect reservations, or premature state commits.

Hard policy limits and published-machine performance targets are distinct:

```text
final transaction                 ≤ 100,000 bytes
every unlocking bytecode          ≤ 10,000 bytes
every standard VM resource        ≤ 100%
```

The preceding three limits are the only byte/VM pass-fail ceilings. Any
smaller byte or resource margin is non-blocking risk telemetry. Performance
targets on the published reference machine are:

```text
proof generation p95              ≤ 60 seconds
prover peak RSS                    ≤ 4 GiB
incremental state application      ≤ 250 ms
100k-action full recovery          ≤ 15 minutes
recovery peak RSS                  ≤ 2 GiB
authenticated local store          ≤ 2.5 GiB
```

At 100,000 historical actions, warm per-action tree work must remain within
10% of its 1,000-action measurement; cold database I/O is reported separately.
The benchmark must also record the fixed-depth tree operation counts, so that
the bounded timing result is not presented as an unmeasured larger-history
claim.

Clean-machine qualification:

1. Verify signed manifests and pinned artifacts.
2. Install using `npm ci`.
3. Create or import a wallet.
4. Display a funding address and wait for out-of-band funding.
5. Sync from pool genesis.
6. Deposit in one pool transaction.
7. Transfer in one pool transaction.
8. Withdraw in one pool transaction.
9. Delete local pool state.
10. Recover from chain history.
11. Spend the recovered note successfully.

Each real host runs `scripts/v2-clean-machine-qualification.mjs` once against
an approved compiled release root and emits its own Ed25519-signed host
envelope. The envelope binds the host role, release-root authorization, final
profile/descriptor/runtime pins, clean source commit/tree, command plan,
out-of-band funding checkpoint, raw actions, and relative SHA-256 references to
the exact lane artifacts. For every action, the host replays a canonical local
Libauth all-input result plus manifest-authorized Ed25519 envelopes for the
maintainer verifier, BCHN mempool policy, mined BCHN inclusion, and LeanBCH.
The signed envelopes bind the final descriptor, pinned tools and commands,
machine manifests, raw transaction, and action subject. The independent
`scripts/v2-q08-pair-qualification.mjs` verifier must re-read and replay every
referenced artifact from both host bundles before validating them as one
matching clean-host pair. A boolean lane claim is never evidence. This
architecture is implementation support, not Q-08 evidence: Q-08 remains
missing until two real clean hosts run it.

Chipnet rollout:

1. Deploy a high-capacity qualification instance.
2. Complete a 30-day soak with at least 1,000 direct settlements.
3. Deploy the disposable 32-live-note playground without sponsor or faucet support.
4. Fill 32 notes, reject deposit 33 before proving, withdraw, refill, recover, and repeat under contention.
5. Switch the public playground only after final-key and clean-machine gates pass.

`scripts/v2-chipnet-soak.mjs` independently re-verifies the root-bound Q-02
corpus and the Q-08 host-pair artifact before considering Chipnet evidence; its
presence does not satisfy either external gate.

Permitted privacy claim:

> A passive BCH observer cannot cryptographically determine which qualifying historical note produced a later nullifier from public chain data alone.

Required nonclaims:

- Deposit funding is visible.
- Every action's transparent fee input and change are visible.
- Transfer publicly pairs one nullifier with one new output.
- Withdrawal publicly pairs one nullifier with one transparent payout.
- Timing, amount, action shape, RPC traffic, IP metadata, sender knowledge, recipient knowledge, and low pool activity can reduce practical privacy.
- Live-note count is not a guaranteed anonymity set.
- Disk use grows linearly with history.
- A single pool is not concurrent-write scalable.

V1 state and artifacts do not migrate into V2. Mainnet deployment remains outside this plan and requires a separate reviewed decision.
