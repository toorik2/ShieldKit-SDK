# G1 Circom relation scope

Status: compiling feasibility subset; not a complete G1 relation, not proof
evidence, and not a BCH/Chipnet/deployment claim.

## Pinned implementation

- Circom compiler: `circom2` package `0.2.23` (compiler `2.2.3` at build)
- Poseidon and SHA-256 templates: `circomlib` `2.0.5`
- witness/R1CS tooling: `snarkjs` `0.7.6`

The circuit directly instantiates `Poseidon(...)` and `Sha256(5472)`. It has no
injectable hash, digest-only hash input, mock verifier, or `OP_TRUE` path.

## Constrained now

- one-hot deposit/transfer/withdrawal selector and action deltas;
- 128-bit profile/instance digest limbs in both state commitments;
- canonical `u32`/`u64` state ranges, state commitments, sequence increment,
  reserve/live-note equations, reserve cap, and cap as `D * maximumLiveNotes`;
- real spend `ak`, input `cm`, and `nf` Poseidon equations plus nonzero guards;
- real output `cm` Poseidon equation plus active nonzero and withdrawal-zero
  inactive constraints;
- depth-32 append-empty and membership paths;
- depth-128 nullifier empty-leaf and insertion paths. The key is exactly
  `BE_u128(canonicalFr(nf)[0..16])`: `Num2Bits(254)[128..253]`, followed by
  the two canonical zero most-significant bits, traversed least-significant
  first;
- all deposit inactive spend/path slots and withdrawal inactive append/output
  slots are constrained to zero;
- 192-byte record bits are boolean and zero for withdrawal; and
- actual SHA-256 over a fixed 684-byte typed prefix, constrained to exactly two
  public big-endian 128-bit limbs.

## Intentionally incomplete and unclaimed

The reference packet in `packages/core/shielded-transition.mjs` is 752 bytes.
This circuit currently hashes a distinct 684-byte **typed prefix** containing
only header, identifiers, and selected pre-state fields, then zero pads it.
It does **not** claim byte-for-byte packet compatibility. The following fields
are constrained elsewhere in the circuit but are not yet SHA-packet-bound:

- post-state preimage and both state commitments;
- active input/output commitments and nullifier;
- record bits for deposit/transfer;
- boundary amount and withdrawal script digest;
- transaction-context digest; and
- the remaining canonical packet serialization/reserved-byte layout.

Also absent: raw manifest-v1 preimage derivation of profile/instance IDs,
X25519/HKDF/ChaCha20-Poly1305 validity, full raw-byte Fr codec checks for every
packet field, BCH transaction-context preimage constraints, covenant binding,
real proving/setup artifacts, and cross-implementation packet vectors. These
gaps mean the current circuit cannot satisfy the complete G1 relation target.
