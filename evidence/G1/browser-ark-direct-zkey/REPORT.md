# Direct-ZKey Ark/Circom browser spike

Status: **FAIL** — no browser proof was produced; this does not qualify G4 or
authorize a prover, artifact, relation, or budget change.

## Scope

This narrowly tests whether an independently source-pinned Rust/WASM path can
consume the current SnarkJS ZKey directly, run the matching Circom witness WASM
in Chromium, and produce a Groth16 proof. It uses the historical, invalidated
V1 development profile only as backend-compatibility telemetry. It has no
network, wallet, node, broadcast, relayer, or hosted-prover dependency.

The profile artifacts were read directly from the local development evidence:

- `final.zkey`, 321,581,772 bytes, SHA-256
  `d69d2ccc38964ec4e50b12e73bc31a562bb18871e5ddef8693de6cc92f18bb24`;
- `g1_relation.wasm`, 9,977,099 bytes, SHA-256
  `1332f89bf4287fc51d7a6f4fd86acb45511a3aaf4ccd4859c6aecda4dd4b3b57`.

This profile must not be reused: it is development-only and was superseded
after the V1 recovery-record soundness finding. No claim here applies to the
current relation or any future profile.

## Upstream and build audit

The audited upstream is `gakonst/ark-circom`, commit
`09e92d4c5887cec9ea558dc7e775a8ab3b02aafc` (2025-08-26), source
`Cargo.toml` SHA-256
`5596a385ec5426e8f559e238b227ac3bff51820bccf0e5a32057c77230b93ca8`.

It contains `read_zkey`, which parses SnarkJS ZKey sections into an Arkworks
BN254 proving key and matrices, and it uses `CircomReduction` for Circom setup
semantics. Its published manifest is not a usable pinned browser build:

- five Arkworks dependencies point at moving Git branches;
- crate constraints mix Arkworks 0.5 with current Git dependencies that resolve
  to 0.6; and
- `wasmer = "6.1.0-rc.3"` permits 6.1.0 and a newer incompatible wasm-bindgen
  ABI.

An isolated scratch fork pinned Arkworks 0.6 release commits (algebra
`a5460be2d98e709133f3947eae535d3d67ca3355`, groth16
`0bb3e604c534bd118ed477eaf1231f591d6fc40f`, snark
`d027f19d699d3af459ae4924366d71159231bc82`, crypto-primitives
`ba00127bf673d93d73a3e8bf969cb9eeced20d12`, r1cs-std
`70a8298c82ef22b6ab81ee3a6cbf5138a3691aeb`), Wasmer exactly
6.1.0-rc.3, wasm-bindgen exactly 0.2.100, and js-sys exactly 0.3.77. Its
lockfile SHA-256 was
`1c21a905dc888086f186799bad03c423df598b9cc26410b1bf59f5228ade5f8e`.

The smallest wrapper takes byte arrays for the direct ZKey and Circom WASM,
JSON input, and a caller-provided 32-byte CSPRNG seed. It calls `read_zkey`,
then `WitnessCalculator::from_module`, then the existing Arkworks
`create_proof_with_reduction_and_matrices`; it does not convert the ZKey or
substitute a relation. Wrapper source SHA-256:
`8cb3179f44bdd58e8ccb3d539229e18d39b7fd540a45c808f0dea094cc98b9f7`.

With Rust 1.97.1, `wasm32-unknown-unknown`, and wasm-bindgen-cli 0.2.100, the
source-pinned fork compiled. The emitted browser module was 3,227,133 bytes,
SHA-256 `48aeb8529f43997bb3ebd1658e48246c29e5875911190fc85bc96bace29160f1`.

## Chromium measurement

Chromium executed the direct module in a user-systemd cgroup with
`MemoryMax=2,147,483,648` and `MemorySwapMax=0`. The runner served only its
loopback assets, disabled Chromium background networking, and supplied the
real deposit input.

Observed result:

- wall time: 90,213.448 ms;
- CPU: 95.514297 s;
- cgroup `memory.peak`: 1,499,402,240 bytes;
- result: `relation wasm compile: Validation error: Unknown validation error`;
- proof/public signals: absent; pinned SnarkJS verification: not runnable.

The error occurs after `read_zkey` returns and when Wasmer-JS validates the
real Circom witness module. Therefore the direct ZKey path was reached, but
this backend cannot execute the matching witness format and cannot prove.
Independently, its 90.2-second failure already exceeds the frozen 60-second
browser p95 limit, even though it remained below the 2 GiB cap.

Raw result SHA-256: `85ca431b49aa56881fd56d62f8860d02fa5b2a01cf7f1b9a14093d9b16f9b580`.
Runner SHA-256: `2b468d2c1f774d0efc82f8075abca8ceb4b684ef9c6eab12e4d3dd50c70f35db`.

## Verdict

The proposed Ark/Circom path is not a browser-prover fallback for shield.cash.
The direct ZKey parser is real, but the source needs a maintained pinned fork,
and the only tested Wasmer-JS runtime rejects the exact witness module before
proof creation. The required compatible proof and pinned-SnarkJS verification
do not exist. The browser G4 gate remains open/failed for the exact current
profile and requires a distinct, profile-bound browser prover with a fresh
full proof and <=2 GiB / <=60-second measurement.
