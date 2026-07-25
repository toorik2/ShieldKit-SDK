# Complete real-action LeanBCH cross-check

`real-actions-full10-leanbch-crosscheck.mjs` is the fixture-bound independent
VM differential for all ten settlement inputs of the public real deposit,
transfer, and withdrawal transactions. The fixture contains the exact raw
transaction and all ten source outputs; the runner records SHA-256 values for
both before execution.

Run it only against a clean LeanBCH checkout with a compiled `xcheck_idxN`
runner and its explicitly pinned native secp256k1 FFI archive:

```sh
node bch/g2-compressed-covenants/real-actions-full10-leanbch-crosscheck.mjs \
  --lean-root /absolute/clean/LeanBCH \
  --lake /absolute/path/to/lake \
  --output /absolute/new/full10-crosscheck.json
```

`--oracle native` is the default and is required for a full comparison: input
9 carries a real P2PKH signature. `--oracle reject` is diagnostic only. It
must agree on inputs 0 through 8 and must disagree at input 9; it is never
full ten-input evidence.

This runner intentionally does not claim BCHN relay, peer acceptance, mining,
Chipnet inclusion, standardness, a 256-proof corpus, or production readiness.
LeanBCH's native secp256k1 oracle also has the strict-DER/low-S encoding
limitations documented in its own source, so its result is independent
conformance evidence rather than a BCHN replacement.
