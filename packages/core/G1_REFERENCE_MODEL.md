# G1 deterministic transition reference

Status: feasibility reference only. It does not compile a circuit, generate or
verify a proof, execute BCH VM bytecode, or establish any G1/G2/release claim.

`shielded-transition.mjs` uses the pinned `circomlibjs@0.1.7` BN254 Poseidon
implementation. No SHA-derived substitute or injectable hash callback exists.

## Bound identities and codecs

`profileId` and `instanceId` are required canonical lowercase 32-byte inputs.
This reference **does not derive either identifier**. The only authority for
`instanceId` is verifier-profile manifest v1: its canonical derivation binds
the selected profile, network, immutable reserve cap, category-input outpoint,
and state-NFT category. The reference separately binds the same immutable
`maximumReserve` in every state commitment and rejects any state exceeding it.

Fr uses strict 32-byte big-endian encoding below the BN254 scalar modulus.
SHA-256 public inputs are its two unsigned big-endian 128-bit halves, each
encoded as canonical Fr. All uint state fields are canonical decimal strings
and serialize little-endian in action packets.

## Candidate Poseidon domain tags

| Name | Fr literal |
| --- | ---: |
| `SPEND_AUTHORITY` | 1004 |
| `NOTE` | 1002 |
| `NULLIFIER` | 1003 |
| `NOTE_TREE_LEAF` | 1010 |
| `NOTE_TREE_NODE` | 1011 |
| `NOTE_TREE_EMPTY` | 1012 |
| `NULLIFIER_TREE_LEAF` | 1020 |
| `NULLIFIER_TREE_NODE` | 1021 |
| `NULLIFIER_TREE_EMPTY` | 1022 |
| `POOL_STATE` | 1030 |

The note tree is append-only at depth 32 and consumes append-index bits from
least significant to most significant. The sparse nullifier tree is depth 128,
indexes the least-significant 128 bits of the canonical nullifier Fr encoding,
and likewise consumes that unsigned integer's bits least-significant first. A
spend proves the selected sparse leaf is the canonical empty leaf; an occupied
leaf therefore rejects both a duplicate and a truncated-key collision without
value creation.

Because the candidate encodes `nextLeafIndex` as `u32`, an output action
requires the pre-state index to be at most `2^32 - 2`; the successor may be
`2^32 - 1`, after which no further output action is representable. Thus this
candidate uses at most `2^32 - 1` leaves and deliberately leaves the final
depth-32 leaf unused. G2 must either retain this explicit terminal rule or widen
the counter and regenerate the relation, vectors, and profile.

The action packet has a fixed v1 reference encoding and binds complete pre/post
states, note/nullifier material, fixed 192-byte active V2 output record or zero
inactive record, boundary descriptor, and transaction-context digest. The V2
relation constrains its native-field BabyJubJub ECDH, masks, and Poseidon
authenticator; it is not the obsolete X25519/AEAD draft.

The numeric Chipnet discriminator `2` and 192-byte record length are
profile-candidate constants, not claims about a BCH consensus network enum or a
frozen G2 wire format. They must be replaced only by changing the candidate
profile material and regenerating every dependent vector and artifact.

`maximumReserve` follows the verifier-bundle genesis rule: it is a nonzero
multiple of 10,000,000 satoshis and is no greater than
2,100,000,000,000,000 satoshis. This prevents the reference model from
constructing a state that the profile loader could never admit.
