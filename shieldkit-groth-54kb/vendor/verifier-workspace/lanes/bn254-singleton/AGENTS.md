# BN254 singleton size lane

Scope: `lanes/bn254-singleton/**` plus the assigned `.vc/runs/<run-id>/` directory.

- This lane owns the non-runnable BN254 Groth16 singleton byte-size track.
- Preserve runtime proof binding, fixed VK, full EIP-197 checks, exact public-bench scoring, and the explicit `non-deployable-size-only` classification.
- The held public crown is 4,651 score: 4,292 locking + 272 unlocking + 87 transaction envelope.
- Fast checks may hash and score the recovered artifacts. Do not claim a local VM replay or deterministic rebuild unless those expensive gates actually ran.
- Shared judge, harness, historical optimizer tools, catalogue, and root artifacts are read-only unless explicitly assigned.
