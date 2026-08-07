# BLS12-381 singleton size lane

Scope: `lanes/bls12-381-singleton/**` plus the assigned `.vc/runs/<run-id>/` directory.

- This lane owns the non-runnable BLS12-381 Groth16 singleton byte-size track.
- Preserve runtime proof binding, fixed VK, exact public-bench scoring, and the explicit `non-deployable-size-only` classification.
- The held public crown is 3,715 score: 3,425 locking + 205 unlocking + 85 transaction envelope.
- The recovered submission has no BLS G1/G2 subgroup check. Preserve that limitation explicitly; do not present this artifact as a production verifier.
- Fast checks may hash and score the recovered artifacts. Do not claim a local VM replay or deterministic rebuild unless those expensive gates actually ran.
- Shared judge, harness, historical optimizer tools, catalogue, and root artifacts are read-only unless explicitly assigned.
