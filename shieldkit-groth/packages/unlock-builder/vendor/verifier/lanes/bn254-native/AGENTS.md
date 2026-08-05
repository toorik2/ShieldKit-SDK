# BN254 native covenant lane

Scope: `lanes/bn254-native/**` plus the assigned `.vc/runs/<run-id>/` directory.

- This lane is the multi-transaction, CashToken-threaded BN254 Groth16 verifier family.
- Preserve runtime proof binding, fixed verification key, P2SH32 deployment, token-state continuity, and terminal token consumption.
- The frozen 170,366-byte crown is a historical script-byte measurement. New evidence must report transaction overhead separately and score their sum.
- Arithmetic generators under `build/chunked/pairing/`, the harness, judge, artifacts, and shared packages are read-only unless explicitly assigned.
- Promotion requires fresh independent invalid-run, token-safety, full provenance, standard transaction, and LeanBCH evidence; historical transcripts alone do not reopen that gate.
