# Native prover adapter

Local-only, fail-closed execution of a caller-hash-pinned native Groth16 prover
against caller-hash-pinned zkey, verification key, and witnesses. It measures
the direct prover process from Linux `/proc`, verifies every output with pinned
`snarkjs`, and requires exact public-signal equality. It never generates setup
or witnesses and performs no BCH or network operation.

The caller supplies absolute artifact paths in a strict manifest. Generated
proofs and results are intentionally written outside Git; the corresponding G1
evidence records their hashes and measurements only. A passing run is initial
feasibility evidence, not a p95 hardware qualification or a G1 PASS.
