# BN254 one-transaction lane

Scope: `lanes/bn254-onetx/**` plus the assigned `.vc/runs/<run-id>/` directory.

- Preserve the frontier candidate's fixed-VK, fixed-deployment, runtime-proof, ten-input capability unless the task explicitly defines a different track.
- The public score is locking bytes + unlocking bytes + serialized one-transaction overhead. Wire-only or pre-hardening numbers do not win this lane.
- Every input must execute in the real BCH-2026 VM against its actual sibling inputs and remain standard. State, source roles, carrier lengths, coordinates, transaction context, and deployment bindings are load-bearing.
- Qualification requires a real bundle and independent judge result. Promotion additionally requires full corpus, A1, role, deployment, UTXO-envelope, public-bench, provenance, and LeanBCH evidence.
- The candidate orchestration source under `src/c7/` is lane-owned. Arithmetic generators under `build/chunked/pairing/` remain shared read-only unless a task explicitly expands the worker's write scope.
- Write generated CashScript, vectors, logs, transactions, and evidence only below `.vc/`.
