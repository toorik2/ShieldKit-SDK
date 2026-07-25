# Real second-profile replacement replay

Status: **PASS for the development-only profile-replacement mechanism; not a
ceremony, deployment, Chipnet, recovery-soundness, or release result.**

This run replaces every setup- and verifier-dependent artifact, opens the new
bundle through the unchanged typed SDK, generates fresh context-bound proofs,
closes exact serialized-fee fixed points, executes complete ten-input
BCH-2026 transactions, and performs a caller-pinned PF7 final replay.

The replacement profile is intentionally local development material:

- profile:
  `sha256:b5ca7199c1f0aeb643ebb19fe7a1efbea0c9be28c07418c7b884f67621701a30`
- instance:
  `sha256:1e6800a24dc49e8b45bde274434ed01255ed0b8fd452fcd78b4e5a78f10242b0`
- verification key:
  `da160f126c13550ecd302547caaf1308434574c50e76268b3b310c64203d2358`
- proving key:
  `d69d2ccc38964ec4e50b12e73bc31a562bb18871e5ddef8693de6cc92f18bb24`
- PF7 verifier set:
  `7ce32c08ea21c555e3ff10ad536a301c3242f6f99fab77b4d1f1f3eb8164e94c`
- PF7 carrier source set:
  `ad0e4ba2332ada17a761b766564137b1f1bd2de2f21c2915fccf187797d0c789`

Its category input is the synthetic, unfunded pre-genesis outpoint
`22…22:0`. None of the transactions below were funded, relayed, broadcast, or
confirmed.

## Exact complete transactions

| Action | Transaction ID | Wire bytes | Fee | Maximum unlock | PF7 unlock bytes |
|---|---|---:|---:|---:|---|
| deposit | `b933ec8020496fdadf7d6096f851a295c62f8c0f48b369e0b545c061ac1be0a3` | 56,767 | 56,767 sat | 9,275 | 8,177 / 6,654 / 7,066 / 7,066 / 8,393 / 7,478 / 9,275 |
| transfer | `5d24b6b152feb7c267b872615a1489076a1c1998cefe0db3d1ebba3c27f701f8` | 56,704 | 56,704 sat | 9,213 | 8,177 / 6,654 / 7,066 / 7,066 / 8,393 / 7,477 / 9,213 |
| withdrawal | `5a21285d24a5318eea6ecb3b49ff5a73fd8cfb39c47040bb54d971dfb09fd9a9` | 56,778 | 56,778 sat | 9,277 | 8,177 / 6,654 / 7,066 / 7,066 / 8,393 / 7,477 / 9,277 |

Every transaction:

- uses the frozen seven-PF7-plus-three-structural-input topology;
- charges exactly one satoshi per serialized byte;
- remains below the 59,000-byte target and 10,000-byte per-unlock limit;
- has a 20-byte binding lock and 88-byte state lock; and
- is accepted at all ten inputs by both the standard and consensus Libauth
  BCH-2026 VMs.

The canonical complete-action evidence hashes are:

- deposit:
  `deba5455ec7aa20a724bd1a8ec5d1396a9c928c47d4c08a8ffd8c5c1700d51b3`
- transfer:
  `274303b8e39c7633bc28571db9dfa07eeaeb2417cb68a67acc674307e63892c0`
- withdrawal:
  `97feeb7fe2e017a2c17543dd7be725feaa8de2c6ef809579deafaf6debd2a4b8`

## Fresh proofs and final replay

The selected snarkjs-normalized Groth16 proofs and public signals are:

| Action | Proof SHA-256 | Public signals SHA-256 | Packet SHA-256 |
|---|---|---|---|
| deposit | `e875e542419831e2169f6119536d81305d0b274908f71852901c8a9474609b3e` | `25c99f861bf84044be8d0a0c507adc91dabcf5f48b8bfc68ae86c9027a9442b2` | `841df0997be9a2605c0147a9ad3978e0f7c5924216522e289b307704df62f383` |
| transfer | `0585f1be888991e4da3ec206276b0d0dbef432d56d11221e15152c77f49988ab` | `7872751eb5632c7a5aea9bcd9308c335ecd4c5f33be74e535f08c3a588272c82` | `24d59143f5c8a9e63a06320d0b0b4f59be9ac6311c079b7b405bd18522ccd9ae` |
| withdrawal | `7d48f895e5fbc005098cfece9fd270e3c127759ec8dc3c96692dbef12103bf21` | `dcd3f944aa274db16addee7330672bee68035ebf9b9d6c9c70bfcbdb846c515c` | `4795ef25cff4cce2e462b3cdceaae74a9e288d28c9746fa629a93fa520ddc9cf` |

All three proofs pass pinned snarkjs verification. The final-replay command
rebuilt every action twice, required identity-stable build artifacts, reran
raw-terminal attacks and cross-action seam substitutions, and matched the
caller-pinned verifier/source sets. Its corpus is
`84a4d13d19c0d45666d73ea7d810c16a6733fca8eb86811df4cf9c696b0cff2c`;
the final-replay manifest is
`92ebe439d7672005c212f3a04298d549b5d1045fef39c9018404f1bc14ac0519`.

## SDK replacement boundary

The unchanged desktop SDK exposes the same 11 typed methods for both the live
v0 development bundle and this v1 development bundle. Cross-profile loading is
rejected. The canonical replacement-drill result is
`af1ba6818e708888e242a10d7a454cf303093dac889ca3ad1fefeb612dc82709`.

## Evidence location and current invalidation boundary

Public evidence is rooted at:

`/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-live-flow-019f8ed4/profile-replacement-v1-current`

The run proves that setup/VK/PF7/profile replacement does not require an SDK
surface or settlement-topology redesign. It does **not** qualify this relation
for release. The current relation permits recovery-record poisoning because it
hash-binds, but does not cryptographically validate, the active encrypted
record. A corrected recovery-bound relation must receive a new setup, profile,
PF7 qualification, and complete replay before any production claim.
