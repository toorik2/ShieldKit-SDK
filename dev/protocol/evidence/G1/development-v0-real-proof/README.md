# Development-v0 real proof and verifier record

Observed 2026-07-23. This is a bounded, hash-pinned record of real local
development artifacts. It does not import the large witness, proving-key,
transaction, or unlocking-bytecode files; their absolute source paths, byte
counts, and SHA-256 values are recorded in `artifact-hashes.json`.

## Result

**G1 verdict: FAIL (open).** The local, `development-only` Groth16 setup
produced and independently verified deposit, transfer, and withdrawal proofs.
The exact deposit proof was converted through the pinned PF7 adapter and used
in a ten-input all-real BCH-2026/libauth VM transaction: **10/10 inputs
accepted**, all unlocks executed, with **81,563 wire bytes** and **82,739
score bytes**. The raw adversarial run reports **18/18 rejected, 0 false
accepts, 0 setup errors**.

This is not a qualification result. `exec0` is 9,596 B, above the 9,500-B G1
component target, and direct `snarkjs` proving peaked at 6.83--7.09 GiB RSS,
above the frozen 4-GiB desktop proving budget (a G1/G4 feasibility constraint).
The setup is local `development-only`; it is not a
ceremony or production setup. No BCHN standardness, Chipnet, full settlement,
LeanBCH, funding, broadcast, or mainnet claim is made.

`deposit-pf7-adapter.json` is copied byte-for-byte from the measured source.
Its historical `qualification` sentence says the then-current PF7 builder
rejected adapter input. That sentence is source metadata, not this record's
result: `pf7-result.json`, produced by verifier.cash commit
`c9a0c1653709ae360d69611a997ac114bf9a4c8f`, is the later actual result and
shows the converted deposit proof accepted in all ten VM inputs.

## Contents

- `observation.json` is the schema-valid G1 evidence record.
- `proof-corpus-result-summary.json` is a bounded transcription of the real
  corpus outcome, including timings, peak RSS, and external artifact hashes.
- `deposit-pf7-adapter.json` is a byte-for-byte source copy; `pf7-result.json`
  is a bounded semantic transcription whose external byte-exact source is
  pinned in `artifact-hashes.json`.
- `raw-attacks-summary.json` enumerates all attack names and outcomes; the
  25,990-B raw runner output remains external and is hash-pinned.
- `commands.md` gives the exact recorded production, verification, and hash
  commands plus the observation environment.
