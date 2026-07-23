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

The current PF7 composed grammar has no fixed authenticated public-signal
carrier. Adding a final genesis argument changes the witness grammar committed
by the composed executor plan, so a terminal/genesis-only patch is not a valid
extension.

The existing public-input pushes are also unsuitable as terminal fixed-offset
carriers. In this deposit fixture their observed genesis-unlock positions were
2,876 and 2,859, and their positions vary with action witness shape. Baking
those offsets into the terminal would break the required action-invariant
source locking bytecodes.

## Required next step

Add a first-class, fixed-layout public-signal seam to the composed PF7
generator, rebuild every affected executor/genesis/terminal commitment, and
qualify the full deposit/transfer/withdrawal action corpus. No G2 integration
or size claim is permitted before all seven verifier roles pass the normal and
standard BCH-2026 VMs and the new seam survives substitution, truncation,
non-minimal encoding, carrier, limb, packet, and cross-action attacks.

The experimental worktree was restored to its pre-probe clean state. No failed
candidate patch was retained as verifier authority.
