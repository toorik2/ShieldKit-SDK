# G1 package-registry toolchain observation

Observed: 2026-07-23T13:19:23Z

Verdict for the narrow claim: **PASS** — the listed package metadata was
retrieved directly from the npm registry on the recorded host.

This record establishes available package coordinates; it does not select,
install, reproduce, or qualify a protocol toolchain.

| Component | Registry version |
| --- | --- |
| `circom2` | 0.2.23 |
| `snarkjs` | 0.7.6 |
| `circomlib` | 2.0.5 |
| `circomlibjs` | 0.1.7 |
| `cashscript` | 0.13.2 |
| `cashc` | 0.13.2 |
| `@bitauth/libauth` | 3.0.0 |

The installed local runtime is Node.js 25.9.0 and npm 11.12.1 on x86-64 Arch
Linux. It is an observation host, not yet the pinned reproducible build
environment.

## Limitations

- Registry metadata can change and does not prove tarball integrity.
- No dependency was installed by this observation.
- No circuit, verifier, covenant, or transaction was built.
- No browser or Android runtime was measured.
- The current registry release is not automatically compatible with the BCH
  activation rules required by the protocol.
- G1 requires a separately pinned source closure, lockfile, tarball hashes,
  build container, and reproduction from at least one independent environment.

