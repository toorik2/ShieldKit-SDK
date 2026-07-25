# Two real development-only Groth16 setups

Observed: 2026-07-23

Candidate relation: `g1-bn254-groth16-single-note-v0`

Status: setup replacement prerequisite passed; profile/genesis replacement and
G1 remain open.

## Fixed common inputs

- R1CS: 608,499 constraints, exactly two public inputs, SHA-256
  `46e109afbd2e1b129bcd9a5661b4a98e268cf6753144349686829f139c4f5d3a`
- Witness-generator WASM SHA-256:
  `1332f89bf4287fc51d7a6f4fd86acb45511a3aaf4ccd4859c6aecda4dd4b3b57`
- Phase-1 power-20 artifact SHA-256:
  `159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd`
- Pinned `snarkjs@0.7.6` CLI SHA-256:
  `6d787e37a4d1a2c6dd6032dadca09c0b3b007d4d4578bb6232a98136555d051a`

Each run performed a fresh Groth16 initialization plus one private local
Phase-2 contribution. Both are permanently `development-only`; neither is a
multi-party ceremony or production setup.

## Distinct outputs

| Field | Development v0 | Development v1 |
| --- | --- | --- |
| randomness commitment | `c13f7d258f20507733166aa73c4ed0b1489c058cd17fcd5405854cf3ca71dc6b` | `66b7b0c14d241548c21e71e8e122264a22d28f6be657b2f766c52b767f97ff36` |
| initializer commitment | `904286963a0fe146fbbc8623964ecbf67d8c8d05ffee692413dfc342fcfc76f8` | `ee998d41ee7e3bd350c610d579284697961ba8b00e0721a4b8ca9b49c70d81f1` |
| final zkey SHA-256 | `37a7ee2fe9e7ee1e2583d60e0e52d86360d7c7a7be5b23dbb0cc166bb5905453` | `d69d2ccc38964ec4e50b12e73bc31a562bb18871e5ddef8693de6cc92f18bb24` |
| verification key SHA-256 | `d4b6b4e0a6c371a019ffa7457a7c2a265b7e3a90ae2a12619424a249903c9a59` | `da160f126c13550ecd302547caaf1308434574c50e76268b3b310c64203d2358` |
| setup metadata SHA-256 | `43475c7c38e336c68cdedb21a4f9f5e87c806234e26ecb0e31c492463decf887` | `d092b52767e184d9fea08b9ff51e3824074d1c363e1ef2299b31ec4160555b60` |

Pinned `snarkjs zkey verify` accepted both final zkeys against the exact R1CS
and Phase-1 artifact. Independently re-exporting each verification key produced
the exact published VK hash.

Each setup then proved the same deposit, transfer, and withdrawal witnesses.
All six setup/action pairs passed independent pinned Groth16 verification. The
public-signal files are identical between setups, while every proof and the
verification key differ as expected. Result records:

- v0: `02a121f8a3d22bbd2afec20b8443256d7bda8b7dc5a0f4b607b1a823ffde9bfa`
- v1: `63b874000f03edaced8fb4f32d1684c134a864e96ed98de7d41fab3d0bc04486`

Both private entropy files were overwritten and unlinked only after zkey
verification and VK re-export. The entropy was never placed in argv,
environment metadata, Git, or output logs. Secure deletion is best effort on
SSD, copy-on-write, journaled, or snapshotted storage.

## Remaining boundary

This proves two independent local setup outputs and unchanged relation/wallet
semantics. It does not yet satisfy the complete replacement requirement:
setup-specific BCH verifier scripts must be generated for v1, both complete
typed bundles must derive distinct profile identifiers and distinct genesis
data, and both must pass the same transaction/conformance gates. A future
multi-party ceremony must use this interface but create another new profile,
genesis, instance, artifact set, and evidence package; it may not replace
either live instance.
