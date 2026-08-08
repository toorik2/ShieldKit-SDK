# Native recovery scanner

`shieldkit-v2-recovery` deterministically reconstructs PF10 state from
caller-authenticated raw BCH transactions. It does not query a node, prove
block inclusion, choose the active chain, execute the BCH VM, or turn a content
hash into a signature.

Build with the repository toolchain:

```bash
cargo +1.97.1 build --locked
cargo +1.97.1 test --locked
cargo +1.97.1 clippy --all-targets --all-features --locked -- -D warnings
```

The binary accepts one command and reads from standard input:

```bash
shieldkit-v2-recovery scan < request.json
shieldkit-v2-recovery scan-stream < request.frames > material.frames
shieldkit-v2-recovery authenticate-snapshot < request.json
shieldkit-v2-recovery authenticate-snapshot-stream < request.frames > material.frames
shieldkit-v2-recovery verify-snapshot < request.json
```

| Command | Purpose |
| --- | --- |
| `scan` | Replay anchored genesis and action transactions and return authenticated material |
| `scan-stream` | Perform the same raw replay using bounded, counted, transcript-bound frames |
| `authenticate-snapshot` | Validate a compact snapshot against independently supplied profile, genesis, and tip anchors |
| `authenticate-snapshot-stream` | Authenticate a snapshot with bounded action frames |
| `verify-snapshot` | Authenticate a snapshot, repeat full raw replay, and require equality |

JSON requests are capped at 256 MiB. Stream frames use the `SKR2F001` magic,
32-bit big-endian lengths, a 524,288-byte payload cap, contiguous counts, a
SHA-256 transcript, and immediate EOF after the terminal frame. The raw-scan
and snapshot stream schemas are distinct and never interchangeable.

Streamed output is provisional until a valid terminal frame and clean process
exit. Consumers must stage rows and roll back on truncation, reordering,
duplicate indexes, digest failure, trailing bytes, or scanner failure.

The caller remains responsible for authenticating the profile and active-chain
anchors at the required confirmation depth. The Node integration is
[`recovery-native.mjs`](../../packages/pool/v2/recovery-native.mjs); it pins the
opened binary and validates the framed output before committing material.
