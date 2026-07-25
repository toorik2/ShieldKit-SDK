# G1/G4 desktop-browser local prover: low128 v0

Status: **FAIL** for the frozen 2 GiB desktop-browser process-memory budget.

Chromium 150 executed browser-native `snarkjs.min.js` Groth16 proving against
the exact development-only low128-v0 WASM and 321,581,772-byte zkey. This was
a local static UMD browser package served only from an allowlisted loopback
server; it used no Node proving, remote prover, hosted service, BCH activity,
or network artifact retrieval. The resulting proofs were verified by the
pinned local `snarkjs@0.7.6` CLI and the exact verification key.

One initial sample per action completed in 11.398–12.089 seconds, below the
60-second time gate. The direct Chromium process tree (browser plus
descendants; Node harness and loopback server excluded) peaked at
9,429,252–10,567,700 KiB RSS. This is far above the 2 GiB frozen budget.
The RSS sum is conservative because Chromium processes can share pages, but it
is still an explicit fail against the configured process-tree measurement; no
desktop-browser readiness or p95 qualification is claimed.

All artifact, runtime, proof, and public-signal identities are in
`raw/result-summary.json`, which hash-binds the full external browser result.
The setup remains permanently `development-only`; this evidence neither selects
a production backend nor establishes G1/G4 PASS.
