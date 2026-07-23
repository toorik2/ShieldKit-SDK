# PF7 signal-seam probe

Status: failed bounded experiment; not G2 evidence  
Date: 2026-07-23  
Candidate: `bn254-onetx-pf7-sub62-r1`

## Question

Can the existing composed PF7 verifier authenticate the canonical 752-byte
shield.cash action packet by adding a public-signal carrier only to the genesis
and terminal roles?

## Probe

- Packet: genuine development-v0 deposit packet, 752 bytes.
- Packet SHA-256:
  `3b3f83ecabc740a380a2a2b7ca6ee6cd08b01ccea4dd983e069ec37006fdafda`.
- Trial carrier: 64 bytes, `BE32(in0) || BE32(in1)`, appended as the final
  genesis witness argument.
- Genesis trial guard: require the carrier halves to equal the two Groth16
  public inputs.
- Terminal trial guard: parse the canonical input-7 `PUSHDATA2(752)` packet,
  hash it at runtime, split the digest into two big-endian 128-bit halves, and
  compare those halves with the carrier.

## Result

The terminal packet guard authenticated the intended packet in isolation, and
the genesis role accepted its carrier check. The composed transaction did not
verify:

- `exec0` through `exec4`: reject
- `genesis`: accept
- `terminal`: reject
- complete verifier gate: reject

Failed-candidate measurements, reported only to bound the experiment:

- serialized wire bytes: 55,339
- delta to the 59,000-byte project ceiling: 3,661
- maximum verifier unlocking bytecode: 9,287
- delta to the 10,000-byte per-input ceiling: 713

These measurements are not a fit or headroom claim because the verifier gate
failed.

## Cause and boundary

The rejection was traced to a specific positional error rather than an
inherent 64-byte-carrier limit. The selected composed PF7 plan requires the
genesis unlocking bytecode to begin with:

```
PUSHDATA2(448) || projectionContext
```

All five executors and the terminal read that projection at raw offset 3. The
failed experiment instead emitted:

```
PUSHDATA(64) || carrier || PUSHDATA2(448) || projectionContext
```

They therefore parsed carrier bytes as the projection. Genesis accepted
because its newly generated parameter declaration matched that altered stack
layout; the other roles retained the fixed projection offset.

The current PF7 still has no valid authenticated public-signal carrier. The
existing public-input pushes are unsuitable as terminal fixed-offset carriers:
in this deposit fixture their observed genesis-unlock positions were 2,876 and
2,859, and their positions vary with action witness shape. Baking those offsets
into the terminal would break the required action-invariant source locking
bytecodes.

## Required next step

Add a first-class, fixed-layout public-signal seam to the composed PF7
generator while preserving the existing projection window. The selected ABI
extends the first push from 448 to 480 bytes:

```
PUSHDATA2(480) || projectionContext[448] ||
SHA256(actionPacket)[32] || existing arguments
```

The projection remains at raw bytes `[3,451)`, so the executor reads do not
move. The raw action digest is at `[451,483)`. Genesis must split its two
16-byte big-endian halves and compare them bijectively with the Groth16 public
inputs; it must not reduce, truncate, or interpret a high-bit limb as negative.
The terminal can read that fixed digest and authenticate an exact
`PUSHDATA2(752) || actionPacket` at input 7.

The existing action-specific packet equality guard must be replaced: retaining
it would bake one action packet into the terminal source lock and violate
action invariance. Generate the verifier source locks only after the static
carrier grammar is fixed, then qualify the complete
deposit/transfer/withdrawal corpus. No G2 integration or size claim is
permitted before all seven verifier roles pass the normal and standard
BCH-2026 VMs and the new seam survives substitution, truncation, non-minimal
encoding, carrier, limb, packet, high-bit-limb, and cross-action attacks.

A separate `PUSHDATA2(448) || projection || PUSH64 || padded limbs` layout is
also structurally possible, but it is not selected: it adds 33 wire bytes and
duplicates 32 zero-padding bytes without adding a security property.

The experimental worktree was restored to its pre-probe clean state. No failed
candidate patch was retained as verifier authority.
