# ShieldKit Protocol V2 Direct — Identifiers and Poseidon Domains

Status: development identifier freeze for the current Phase-A sources. This
registry records the values the current V2 sources validate or emit; A-01 remains
open until a reviewed immutable specification tag exists, and this file is not
final-artifact, covenant, or qualification evidence. Changing a value pinned in
`profileCore` creates a new profile. Changing another protocol identifier requires
the corresponding circuit, setup, verifier, covenant, manifest, instance, vector,
and qualification review.

## Protocol identifiers

| Purpose | Exact identifier |
|---|---|
| Groth16 relation (`profileCore.proof.relationId`) | `shieldkit-pool-action-v2-direct` |
| Profile-core schema (`profileCore.schema`) | `shieldkit-profile-core-v2-direct` |
| Profile-ID hash prefix | ASCII `SKP2` |
| Instance-descriptor schema | `shieldkit-instance-descriptor-v2-direct` |
| Artifact-manifest schema | `shieldkit-artifact-manifest-v2-direct` |
| Native state encoding | `shieldkit-pool-state-sks2-native128` |
| Action packet encoding | `shieldkit-direct-action-sda2-552` |
| Address encoding | `shieldkit-address-v2-direct` |
| Encrypted record encoding | `shieldkit-note-record-v2-direct-128` |
| Public-input ABI | `shieldkit-sda2-sha256-be-u128x2` |
| Note tree | `shieldkit-note-tree-v2-depth32` |
| Nullifier tree | `shieldkit-indexed-nullifier-tree-v2-depth32` |
| Development-profile note leaf schema | `shieldkit-note-leaf-v2` |
| Development-profile nullifier leaf schema | `shieldkit-indexed-nullifier-leaf-v2` |
| `profileCore.crypto.poseidonId` | `circomlib-poseidon-bn254` |
| Recovery snapshot Poseidon profile | `shieldkit-pool-action-v2-direct-poseidon-v1` |
| Rolling bundle unlock ABI | `shieldkit-rolling-bundle-unlock-v2-direct` |

The existing identifier `shielded-action-v2` is V1 legacy research. It is not an
alias for the relation above, and its artifacts, state, packets, profiles, setup,
or instances cannot be relabeled or migrated into V2 Direct.

`shieldkit-profile-v2-direct` is not a V2 Direct profile-core schema: the current
profile-core validator rejects it. It appears only as a negative test mutation and
must not be emitted by a V2 Direct profile builder.

The canonical binary address encoding is exactly 168 bytes:

```text
0..3      ASCII "SKA2"
4         networkId
5..7      zero flags
8..39     profileId
40..71    instanceId
72..103   compressed spend point S
104..135  compressed incoming-view point V
136..167  authority
```

The point encodings are the same canonical BabyJub encodings used by the encrypted
record. A user-facing checksummed text representation may wrap these exact bytes;
it must not define a second binary meaning.

## Domain derivation

Poseidon domain separators are obtained by rejection sampling SHA-256 digests:

```text
prefix = ASCII("ShieldKit/PoolActionV2Direct/domain/v1/")

for counter from 0 through 0xffffffff:
  candidate = SHA256(prefix || ASCII(label) || U32BE(counter))
  value = OS2IP_BE(candidate)
  accept the first value satisfying 0 < value < BN254_Fr_MODULUS
```

Labels use the grammar `[A-Z][A-Z0-9_]*`. No modular reduction is used. The
accepted 32-byte digest is both the canonical big-endian field encoding and the
published identifier. `packages/action/v2/domains.mjs` independently re-derives
and checks every pinned value.

## Pinned separators

| Label | Counter | Canonical 32-byte big-endian value |
|---|---:|---|
| `ADDRESS` | 3 | `174c18c76e6b8e7e9035476f0419293d25aabb87220e613924e58345d11914df` |
| `RHO` | 0 | `0d166c9d3f0e891e85bb4a502a6ec7303938d7bfc56f1b6e6e443fa8793f8a82` |
| `NOTE` | 1 | `194fd66837e146a0a8dddfcc309eb8bc1a51deb31924e089b8960ae102c7c349` |
| `NULLIFIER` | 1 | `23358847ffca5391ad471ef321c12099073bff6145a867d14700e8e976377460` |
| `RECORD_MASK_RHO` | 1 | `0ddef22b3c03788145c0aed1bfba5a211f13466c813c0a5d9ed2e92ab173f966` |
| `RECORD_MASK_R` | 3 | `1af24bc8a85aa4b05369756d4f60843ff6dc26f886999d215ed61e38a4ae2db0` |
| `RECORD_TAG` | 2 | `03db9f4bbae24de0b96466001641dc5753651feaa55a8541ededbcaf2bb2da7e` |
| `NOTE_LEAF` | 1 | `0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a` |
| `NOTE_TREE_EMPTY` | 9 | `28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad` |
| `NOTE_TREE_NODE` | 9 | `06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153` |
| `NULLIFIER_TREE_LEAF` | 5 | `21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2` |
| `NULLIFIER_TREE_EMPTY` | 3 | `2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb` |
| `NULLIFIER_TREE_NODE` | 0 | `241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4` |

## Indexed-nullifier leaf tags

Leaf type values are exact field integers:

| Type | Value | Meaning |
|---|---:|---|
| Empty | 0 | Unoccupied physical position |
| Minimum sentinel | 1 | Physical position 0; less than every normal key |
| Normal | 2 | A full canonical BN254 field nullifier |
| Maximum sentinel | 3 | Physical position 1; greater than every normal key |

Each indexed-nullifier leaf hash receives, in order:

```text
NULLIFIER_TREE_LEAF,
leafType,
physicalIndex,
key,
successorPhysicalIndex,
successorKey
```

Sentinel keys are encoded as zero but interpreted only with their distinct type and
fixed physical position. A normal zero key and a normal `Fr−1` key are therefore
unambiguous and legal. A pointer to physical position 1 denotes the maximum
sentinel; its serialized successor key is zero.

An empty leaf is exactly:

```text
Poseidon(NULLIFIER_TREE_EMPTY, 0)
```

Internal nodes are exactly:

```text
Poseidon(NULLIFIER_TREE_NODE, left, right)
```

The note-tree empty leaf and internal nodes use the corresponding `NOTE_TREE_*`
domains. The final circuit and all language implementations must consume these
exact constants and argument orders.

## Note and encrypted-record argument order

Every 32-byte profile/instance identifier is split into its first and second
16-byte chunks, each interpreted as an unsigned big-endian integer. The exact
Poseidon calls are:

```text
authority =
  Poseidon(ADDRESS, profile[0], profile[1], instance[0], instance[1],
           S.x, S.y, V.x, V.y)

rho =
  Poseidon(RHO, profile[0], profile[1], instance[0], instance[1],
           postActionSequence, rhoBlind)

cm =
  Poseidon(NOTE, profile[0], profile[1], instance[0], instance[1],
           denominationSats, authority, rho, r)

nf =
  Poseidon(NULLIFIER, profile[0], profile[1], instance[0], instance[1],
           sk, rho, cm)
```

For encryption, `E = [esk]B8` and `shared = [esk]V`. The two masks deliberately
exclude `cm`, avoiding a decryption circularity:

```text
rhoMask =
  Poseidon(RECORD_MASK_RHO,
           profile[0], profile[1], instance[0], instance[1],
           shared.x, shared.y, E.x, E.y)

rMask =
  Poseidon(RECORD_MASK_R,
           profile[0], profile[1], instance[0], instance[1],
           shared.x, shared.y, E.x, E.y)

encryptedRho = (rho + rhoMask) mod Fr
encryptedR   = (r + rMask) mod Fr

tag =
  Poseidon(RECORD_TAG,
           profile[0], profile[1], instance[0], instance[1],
           shared.x, shared.y, E.x, E.y,
           cm, encryptedRho, encryptedR)
```

The record is `compressed-E[32] || encryptedRho-BE[32] ||
encryptedR-BE[32] || tag-BE[32]`. BabyJub compression is the circomlib
little-endian-y encoding with the x-sign bit in the most significant bit of the
last byte. Every point is canonical, nonidentity, and in the prime subgroup.

```text
outputNoteLeaf =
  Poseidon(NOTE_LEAF, cm, tag)
```

The tag is not a free commitment supplied by the prover. For every accepted
output, the circuit derives it from the domain, profile, instance, ECDH shared
point, canonical ephemeral point, `cm`, `encryptedRho`, and `encryptedR`;
requires the exact record tag bytes to equal that value; and requires the exact
packed ephemeral-point bytes to equal the derived point. The leaf therefore
binds the note commitment and the authenticated record semantics without a
second Poseidon hash over the same record. A spend recomputes `cm`, supplies the
leaf-bound tag, and proves membership. It does not redundantly decrypt or hash
the historical ciphertext.

`rhoBlind`, `r`, `sk`, `ivk`, and `esk` are nonzero canonical values in their
respective fields; `sk`, `ivk`, and `esk` must also be below the BabyJub prime
subgroup order. Derived Poseidon values and active packet fields may legally be
zero. Record opening decrypts `rho` and `r`, recomputes `cm`, authenticates the
tag, recomputes the output leaf from `cm` and the authenticated tag, and only
then derives the nullifier.

## Transaction-context encoding

The transaction-context preimage starts with this exact 100-byte header:

```text
0..3    ASCII "SDC2"
4       networkId
5       action kind
6..7    zero flags
8..39   profileId
40..71  instanceId
72..75  transaction version u32le
76..79  locktime u32le
80..81  input count u16le
82..83  output count u16le
84..91  pre-action sequence u64le
92..99  post-action sequence u64le
```

Each ordered input contributes 116 bytes:

```text
role code u8 || verifier ordinal u8 || zero flags u16le ||
outpoint transaction hash in BCH wire byte order[32] ||
outpoint index u32le || input sequence u32le || source value u64le ||
SHA256(source locking bytecode)[32] ||
SHA256(exact source token prefix, or empty bytes)[32]
```

Each ordered output contributes 76 bytes:

```text
role code u8 || verifier ordinal u8 || zero flags u16le ||
value u64le || SHA256(locking bytecode)[32] ||
SHA256(exact token prefix, or empty bytes)[32]
```

Role codes are verifier=1, binding=2, state=3, funding=4, withdrawal=5,
change=6. The context hash is SHA-256 over the header followed by all input
records and then all output records. It excludes every unlocking bytecode,
proof, packet, signature, and the current transaction ID.
