# G1 Circom relation scope

Status: relation compilation and core-vector witness evidence only. This is not
a complete G1 verdict, setup/proof evidence, BCH/Chipnet evidence, or a
deployment claim.

## Pinned implementation

- Circom compiler: `circom2` package `0.2.23` (compiler `2.2.3` at build)
- Poseidon and SHA-256 templates: `circomlib` `2.0.5`
- witness/R1CS tooling: `snarkjs` `0.7.6`

The circuit directly instantiates `Poseidon(...)` and `Sha256(6016)`. It has no
injectable hash, digest-only hash input, mock verifier, or `OP_TRUE` path.

## Packet and relation constrained now

`G1Relation` computes `Sha256(6016)` over the exact 752-byte
`packages/core/shielded-transition.mjs:serializeActionPacket` layout:

- `SCAR`, version, network, action code, and zero reserved byte;
- complete serialized pre- and post-state: duplicated profile/instance IDs,
  note/nullifier roots, LE `u32`/`u64` counters, reserve/cap, and state
  commitments;
- input commitment, nullifier, output commitment, all 192 record bytes, LE
  `u64` boundary amount, withdrawal script hash, and transaction-context
  digest.

Each packet bit is driven from a typed relation signal; no caller-controlled
packet-bit vector or zero-fill remainder exists. The public inputs are exactly
the two big-endian 128-bit SHA-256 limbs from the core vectors.

The relation also enforces:

- one-hot deposit/transfer/withdrawal selection and state deltas;
- 128-bit profile/instance digest limbs in both state commitments;
- canonical `u32`/`u64` ranges, state commitments, sequence increment,
  reserve/live-note equations, reserve cap, and `cap = D * maximumLiveNotes`;
- a nonzero denomination, a nonzero maximum-live-note count, and
  `maximumReserve <= 2,100,000,000,000,000` satoshis;
- real spend `ak`, input `cm`, and `nf` Poseidon equations plus nonzero guards;
  `ak` is `Poseidon(1004, profile, instance, BabyPbk(sk))`, binding spend
  authority to the same BabyJubJub recipient key used for output recovery;
- real output `cm` Poseidon equation plus active nonzero and withdrawal-zero
  inactive constraints;
- depth-32 append-empty and membership paths;
- depth-128 nullifier empty-leaf and insertion paths. The key is exactly
  `BE_u128(canonicalFr(nf)[0..16])`: `Num2Bits(254)[128..253]`, followed by
  two canonical zero most-significant bits, traversed least-significant first;
- zero deposit inactive spend/path slots and zero withdrawal inactive
  append/output slots; and
- boolean record bits, zero for withdrawal, SHA-bound for every action; and
- recovery record v2 semantic binding: fixed `version=2, slot=0`, canonical
  compressed nonidentity prime-subgroup BabyJubJub recipient/ephemeral points,
  ephemeral scalar-to-point relation, ECDH, field masks for the exact output
  `rho` and `r`, a Poseidon authenticator, and thirty zero pad bytes. The
  recipient point is re-hashed to the exact output `ak`.

`u32` note-index capacity is handled conservatively: output actions require
`preNextLeafIndex <= 2^32 - 2`, so the post-state index remains representable
(`<= 2^32 - 1`). An attempted append from the terminal representable value is
rejected rather than wrapping or serializing an unencodable `2^32` state. This
is a deliberately narrower terminal behavior than an unbounded abstract tree.

## Intentionally absent and unclaimed

The profile/instance identifiers are externally authenticated relation inputs;
the circuit does not derive them from a raw manifest-v1 preimage. Also absent:
reconstruction of the BCH transaction-context preimage behind its SHA-256
digest, covenant/transaction binding, a ceremony or development setup,
zkey/proof artifacts, BCH VM execution, and independent formal cross-checking.
The V2 construction makes no X25519, HKDF, ChaCha20-Poly1305,
indistinguishability, constant-time, setup, proving, verification, or G1
readiness claim.
