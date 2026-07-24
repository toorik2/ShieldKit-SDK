# G1 shielded-action relation candidate

Status: G1 feasibility candidate; not a profile and not deployment material

Version: 0.2.0

## 1. Purpose and falsification boundary

This document defines the minimum real relation that the first proof-system
candidate must implement. It is exact enough to compile, generate arbitrary
valid witnesses, produce invalid witnesses, and measure prover and BCH
verification cost. G1 must reject this candidate if the real artifacts cannot
fit the frozen client and transaction budgets.

G2, not this document, freezes the final field layout, cardinality, tree depths,
hash instantiation, encryption construction, and BCH transaction topology.
Changing any of those after G2 creates a new candidate and invalidates dependent
evidence.

This is `shielded-action-v2`, not the archived `PoolActionV1` relation. In
particular, the denomination is the frozen **10,000,000 satoshis**, and no
digest-only circuit or synthetic verifier can satisfy this document. Its
public-input ABI remains `shielded-action-public-input-v1`; the fixed 752-byte
`SCAR` packet retains packet version byte `1` because V2 does not change its
wire layout.

## 2. Candidate primitives

The G1 candidate evaluates these concrete choices:

- proof system: Groth16 over BN254;
- in-circuit hash: one pinned, vector-tested BN254 Poseidon instantiation;
- transaction/action digest: SHA-256 split into two unsigned big-endian
  128-bit public inputs;
- note tree: append-only binary Merkle tree, candidate depth 32;
- nullifier set: collision-fail-closed sparse binary Merkle tree, candidate
  depth 128;
- recipient recovery: native-field BabyJubJub ECDH, Poseidon masks, and a
  Poseidon authenticator constrained in the relation; and
- note value: exactly `D = 10,000,000` satoshis.

The final profile must pin source closure, versions, parameters, domain tags,
byte encodings, generated vectors, and artifact hashes. A library name alone is
not a primitive specification.

The 128-level nullifier tree indexes `BE_u128(canonicalFr(nf)[16..32])`, the
least-significant 128 bits of the canonical nullifier field encoding, traversed
least-significant bit first. This avoids the two structurally zero high bits of
BN254 field encodings, but remains a feasibility candidate rather than a claim
of 128-bit collision resistance for an unbounded population. A truncated-key
collision must reject without value creation. G1/G2 must publish its lifetime
liveness bound or select a deeper tree.

## 3. Identifiers

All textual literals below are ASCII without a terminator. `u8`, `u32`, and
`u64` encodings are fixed-width little-endian. SHA-256 results are opaque
32-byte strings unless explicitly converted to field limbs.

`profileId` and `instanceId` are derived exactly as specified by
[`manifest-v1.md`](../verifier-profile/manifest-v1.md). In particular, the
instance preimage binds network, profile, immutable reserve cap, the
category-creating output-0 input, and the derived state NFT category. That
category is known before genesis construction, so neither identifier depends on
the transaction identifier of the genesis transaction itself.

The verifier bundle, profile manifest, every circuit domain, every note, every
state, and every action bind both `profileId` and `instanceId` where applicable.
No registry or maintainer key can change either identifier.

## 4. Field and byte rules

Let `Fr` be the BN254 scalar field. A field element has one canonical 32-byte
big-endian encoding representing an integer strictly below the field modulus.
Reduction of non-canonical bytes is forbidden.

For any opaque 32-byte digest `x`:

```
xHi = BE_u128(x[0..16])
xLo = BE_u128(x[16..32])
```

Both limbs are canonical `Fr` elements. Byte order changes occur only at the
named codec boundary. Reserved bytes and inactive fields are zero.

`H(tag, values...)` denotes the exact profile-selected Poseidon invocation.
Domain tags are profile constants and are included in the verifier-bundle
identity. At minimum, distinct tags exist for:

- spend authority;
- note commitment;
- nullifier;
- note-tree leaf, node, and empty value;
- nullifier-tree leaf, node, and empty value;
- pool state; and
- dummy or inactive slots if G2 selects a padded cardinality.

## 5. Notes and spend authority

A real note has private fields and two independently derived, per-profile and
per-instance wallet keys:

```
sk      canonical nonzero scalar in [1, BabyJubJub subgroup order)
rk      canonical nonzero scalar in [1, BabyJubJub subgroup order)
SP      [sk]Base8
RP      [rk]Base8
rho     canonical nonzero Fr unique note nonce
r       canonical nonzero Fr commitment randomness
ak      H(SPEND_AUTHORITY, profileHi, profileLo, instanceHi, instanceLo,
          SP.x, SP.y, RP.x, RP.y)
cm      H(NOTE, profileHi, profileLo, instanceHi, instanceLo, D, ak, rho, r)
nf      H(NULLIFIER, profileHi, profileLo, instanceHi, instanceLo, sk, rho)
```

`SP` and `RP` must be non-identity prime-subgroup points. `cm` and `nf` must be
nonzero canonical fields. The relation proves that `sk` derives `SP`, that the
same `SP` and recovery point `RP` derive the note's `ak`, and that the same
`sk` derives its nullifier. Knowledge of a caller-supplied point, nullifier, or
public tag is not spend authorization. The precise encrypted-record binding is
defined by `spec/recovery-record-v2.md`.

The wallet derives `sk`, `rk`, `rho`, and `r` under separately
domain-separated seed paths. Concurrent operations must never reuse `rho`, `r`,
encryption nonces, or proving randomness.

## 6. Authenticated state

The private state preimage is:

```
profileId        bytes32
instanceId       bytes32
noteRoot         Fr
nullifierRoot    Fr
nextLeafIndex    u32
actionSequence   u64
liveNoteCount    u32
reserveSats      u64
maximumReserve   u64
```

It satisfies:

```
reserveSats = liveNoteCount * D
reserveSats <= maximumReserve
nextLeafIndex < 2^noteTreeDepth
```

With the candidate `u32` counter and depth-32 tree, an output action additionally
requires `pre.nextLeafIndex <= 2^32 - 2`, so its successor remains representable.
This leaves the last depth-32 leaf unused. G2 may widen the counter instead, but
must regenerate and remeasure every dependent artifact if it does.

The state commitment is the profile-pinned `H(POOL_STATE, ...)` over every
field above, including the two-limb encodings of the identifiers. No circuit,
verification-key, profile, instance, reserve-cap, or counter field may be
omitted.

The state NFT commitment candidate is an 80-byte canonical encoding:

| Offset | Bytes | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `SHST` |
| 4 | 1 | format version `1` |
| 5 | 1 | network identifier |
| 6 | 2 | zero |
| 8 | 32 | `profileId` |
| 40 | 32 | canonical state commitment |
| 72 | 8 | `actionSequence`, little-endian |

This remains below the frozen 120-byte budget. G2 must prove that the covenant
binds all encoded fields to the proof packet and successor output.

## 7. Public action statement

The Groth16 verifier exposes exactly two ordered field inputs:

```
public[0] = BE_u128(SHA256(actionPacket)[0..16])
public[1] = BE_u128(SHA256(actionPacket)[16..32])
```

The circuit receives every action-packet bit privately, recomputes SHA-256 in
the relation, and constrains the decoded semantic fields below. Merely proving a
digest preimage is non-conforming.

The fixed-layout G2 packet must contain at least:

- format version, network, action kind, `profileId`, and `instanceId`;
- complete pre-state and post-state preimages and commitments;
- active input note commitment and nullifier, or canonical inactive values;
- active output note commitment and fixed-size encrypted record, or canonical
  inactive values;
- public deposit or withdrawal descriptor;
- `transactionContextDigest`; and
- no unparsed extension, vendor tag, or unconstrained byte.

`transactionContextDigest` commits to the transaction's semantic preimage while
excluding unlocking bytecode, signatures, and the proof itself to avoid a
circular transaction identifier. Its G2 canonical encoding must cover:

- transaction version and locktime;
- every ordered input's outpoint, sequence, source value, source locking
  bytecode hash, and token data hash;
- every ordered output's value, locking bytecode hash, and token data hash; and
- the exact input/output role counts.

The BCH covenants must independently derive or validate the same context from
introspection. This creates the required chain:

```
Groth16 proof -> exact action packet -> transaction context -> actual BCH roles
```

If current BCH introspection cannot implement this chain within the standard
envelope, G1/G2 must record the falsifier and replace the topology rather than
silently weakening transaction binding.

## 8. Transition relation

The common constraints:

1. authenticate the verifier profile and instance identifiers;
2. parse every packet byte canonically and reject nonzero reserved/inactive
   fields;
3. recompute both state commitments and require
   `post.actionSequence = pre.actionSequence + 1`;
4. recompute the active input's `ak`, `cm`, and `nf`, prove membership of `cm`
   in `pre.noteRoot`, and prove the nullifier-key leaf is empty;
5. insert the active nullifier for spend actions;
6. recompute and append the active output commitment for output actions;
7. leave a tree root unchanged when its action has no operation on that tree;
8. enforce the action-specific count and reserve equations below;
9. bind the exact fixed-size encrypted output record for output actions and
   require the inactive record to be all zero;
10. bind the public boundary descriptor and `transactionContextDigest`; and
11. recompute the action digest and its two public limbs.

The initial cardinality candidate is exactly one note:

| Action | Real inputs | Real outputs | Note tree | Nullifier tree | Live/reserve delta |
| --- | ---: | ---: | --- | --- | --- |
| deposit | 0 | 1 | append `cmOut` | unchanged | `+1`, `+D` |
| transfer | 1 | 1 | append `cmOut` | insert `nfIn` | unchanged |
| withdrawal | 1 | 0 | unchanged | insert `nfIn` | `-1`, `-D` |

Additional action constraints:

- deposit requires a public contribution of exactly `D`;
- transfer has no public reserve boundary;
- withdrawal requires exactly one public output of `D` to the packet-bound
  script;
- no action creates variable-value, zero-value, or same-action-spendable notes;
- the pool reserve never pays the miner fee;
- one transparent fee input and one canonical change output are present in the
  transaction context, even when change is zero; and
- verifier-carrier source values may contribute to the miner fee only as
  explicitly accounted by the complete transaction.

The circuit proves the reserve transition. Covenants prove that the actual state
input value, successor value, deposit contribution, withdrawal output, fee
input, carrier values, change, and miner fee match the packet.

## 9. Recovery record v2

An output action carries the fixed 192-byte V2 record defined in
[`recovery-record-v2.md`](../recovery-record-v2.md): `version=2`, `slot=0`, one
canonical compressed BabyJubJub ephemeral point, canonical `c_rho`, `c_r`, and
Poseidon authenticator fields, then 62 zero bytes. A withdrawal carries the
all-zero inactive record.

The proof binds every record byte and constrains the active record's point
canonicality, nonidentity and subgroup membership; the unique ephemeral scalar
and its point; ECDH with a private recovery point; both Poseidon masks; the
authenticator; and the exact output `rho`, `r`, `cm`, and `ak`. The private
spend and recovery points are both bound into `ak`, so substituting either key
cannot create a valid note. Neither stable public point is serialized into the
record, avoiding public receipt linkage. The exact derivation and recovery
procedure is normative in `recovery-record-v2.md`.

## 10. Required G1 artifacts and tests

This candidate advances only with:

1. source, R1CS, witness-generator, proving-key, verification-key, and BCH
   verifier-script artifacts generated from pinned tools;
2. a fresh local setup in a verifier bundle permanently marked
   `development-only`;
3. at least two independently initialized development bundles demonstrating
   different profile identifiers and genesis data through the same loader;
4. arbitrary valid witnesses for all three actions at boundary state values;
5. negative witnesses for every equation, field encoding, tree path, action
   branch, state term, and public digest limb;
6. native, browser, and Android-class proving measurements against the frozen
   budgets;
7. complete standard BCH transactions using the actual verifier artifacts;
8. all-byte, per-input, VM-cost, relay-fee, and headroom measurements; and
9. independent VM/formal agreement on accepting and rejecting transactions.

Until those exist, this document is a falsifiable relation target only.
