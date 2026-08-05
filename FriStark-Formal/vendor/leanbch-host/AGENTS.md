# LeanBCH agent contract

LeanBCH is the canonical BCH-2026 execution, consensus, standardness, operation-cost, optimizer-proof, conformance, and trust toolkit used by verifier.cash. Read `TOOLS.md` and `tooling/manifest.json` before creating measurement, VM, transaction, optimizer, cross-check, conformance, or proof infrastructure.

- Reuse a manifest capability when one exists. Extend the toolkit only when the manifest and `TOOLS.md` show a genuine gap.
- Use `optimizer/cost.mjs` for large-script libauth measurement; use the Lean meter and verifier for independent small-operation checks and proofs.
- Treat optimizer emission, covenant analysis, standardness, and consensus verification as distinct capabilities with distinct trust boundaries.
- Run `tools/opt-ci/verify.sh` only in an owned clean worktree because it regenerates tracked trust artifacts.
- Never present a dirty working tree as a pinned toolchain. Record the commit, HEAD tree, manifest hash, dirty paths, and working-tree fingerprint.
- Do not weaken or bypass the secp256k1 oracle boundary, operation-cost gates, transaction context, or adversarial checks to improve a size result.
