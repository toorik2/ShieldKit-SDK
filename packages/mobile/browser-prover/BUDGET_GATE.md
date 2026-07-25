# Browser prover budget gate

This is an evidence note for the current `development-only` G1 profile, not a
claim that the desktop-browser G4 requirement has passed. The browser adapter
only permits the profile-bound relation, proving key, witness generator, and
verification key; it does not use a hosted prover or a substituted relation.

## Frozen measurement

Profile binding: Chipnet,
`sha256:fd0090245d7ce7306dfd29b9f69f0c14c2b1e47fc76b441e8164d8609e3e545a`,
instance
`sha256:dc75731f22a82baca91893b073e2870a08e939baf80a539dd4f5424d76e4a63d`.
The selected real action is deposit. Chromium is started with networking
disabled except the adapter-owned loopback server; its pinned snarkjs bundle
does local `groth16.fullProve`, and its output must pass pinned local snarkjs
verification before publication.

The adapter uses the smallest valid initial witness allocation (one 64 KiB WASM
page) and snarkjs `singleThread: true`. This removes the package's 32,767-page
witness default and worker replication as explanations for the observed peak.

The authoritative frozen-budget run used a user-systemd cgroup-v2 unit with
`MemoryMax=2,147,483,648` and `MemorySwapMax=0`. It was kernel OOM-killed before
a proof was emitted: 2 GiB peak, 22.941 s wall time, 32.941833 s CPU time. The
raw structured record is
`/home/toorik/Projects/ZK-Proofs/.codex-artifacts/g2-dev-profile-build/g4-browser-prover/authoritative-cgroup-result.json`
(SHA-256 `8c65c635869c96c6507ffb6d2bd6801662f35f011d23fe93efd1d3df5afe3761`).

An explicitly non-qualifying 4 GiB/no-swap diagnostic was also OOM-killed before
a proof at its 4 GiB ceiling (45.564 s wall time). Its purpose was to distinguish
the snarkjs witness-allocation default from the actual Groth16 phase; it showed
the latter remains materially above the frozen browser budget. Record:
`/home/toorik/Projects/ZK-Proofs/.codex-artifacts/g2-dev-profile-build/g4-browser-prover/singlethread-4g-diagnostic.json`
(SHA-256 `d8361ae0ca7727e2d86b990d0d00a3fbd10a5e1ffd7a1e32ecd93e95ced06c8a`).

## Candidate boundary

No other locally installed browser-compatible Groth16 prover accepts this
profile's current snarkjs `final.zkey` plus real witness format. The native
rapidsnark binary is intentionally a desktop-only adapter. The older
wasmsnark/websnark packages require a separate legacy `proving_key.bin` format;
they do not directly authenticate the current typed proving-key artifact, and
their runtime creates a 5,000-page WASM memory for the main instance and every
worker. No unproven conversion or arbitrary browser artifact is admitted as a
fallback.

Verdict: the current profile/browser combination fails the frozen <=2 GiB gate.
Do not call browser proving supported, change the budget, or alter the
relation/verifier to conceal this result. A future candidate needs a
profile-bound, independently verified browser-WASM prover implementation and a
fresh 2 GiB/no-swap empirical pass.
