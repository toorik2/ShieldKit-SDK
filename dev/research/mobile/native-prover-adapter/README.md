# Native prover adapter

Local-only, fail-closed execution of the typed `rapidsnark` backend against an
authenticated verifier profile bundle. The caller must pin `chipnet`,
`profileId`, and `instanceId` together; the adapter then derives the zkey and
verification key only from that immutable bundle, refusing mixed-profile
artifacts or hot swaps. It measures the complete local prover process tree
from Linux `/proc`, verifies every output with pinned `snarkjs`, and requires
exact public-signal equality. It never generates setup or witnesses and
performs no BCH or network operation.

The caller supplies absolute pinned executable, `snarkjs`, witness, bundle, and
output paths in a strict manifest. Generated proofs and results are
intentionally written outside Git; the corresponding evidence records their
hashes and measurements only. A passing run is initial feasibility evidence,
not p95 hardware qualification or a gate pass by itself.
