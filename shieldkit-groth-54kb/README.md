# ShieldKit-Groth-54KB

Contained workspace for swapping the ShieldKit-Groth verifier to the
**bn254-onetx-pf6-a3-r1** ("54KB") Groth16 verifier and carrying the result to
production readiness.

## The swap in one sentence

Current product verifier = PF10-FusedQGenesis (10 verifier roles, 13-input
actions, ~91 KB verifier bytecode). Target = PairFold-6 dens-rich a3
(6 roles, 9-input actions, **54,671 script bytes** / score 54,949).

## Isolation rules (hard)

- **All work and all writes happen under this folder.** No writes to
  `../shieldkit-groth-94kb/`, `../verifier.cash/`, `../Groth16-Formal/`, or
  `../../ZK-Proofs` siblings, except read-only reference.
- Vendored/pinned inputs are copied in with SHA-256 recorded under `vendor/`
  (the pf6 lane is already vendored inside shieldkit-groth at
  `packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/`; copy from there,
  never edit in place).
- Every claim in `docs/` is backed by a machine-produced record under
  `evidence/` (schema + sha256 + command + date).
- Toolchain pins: cashc `1c707c1dbf87396b30ba5e0704b1db44475ce893`,
  libauth `3.1.0-next.8`, leanbch `51201015fdaef4562debf2a2b1cab4013a45e8b4`,
  BCH-2026, Node v22.23.1. No unpinned toolchain runs.
- Chipnet-only. No mainnet claim, no production-qualified claim until the
  release gates in PLAN.md are independently closed.

## Layout

| Path | Purpose |
|------|---------|
| `PLAN.md` | Master plan: work packages to production readiness (START HERE) |
| `design/` | Protocol/architecture design docs (topology, layouts, binding) |
| `docs/` | Working notes, decisions, requirement matrix deltas |
| `src/` | New first-party code (topology, witnesses, adapter, profile) |
| `vendor/` | Hash-pinned copies of upstream material (lane, fixtures, TCB) |
| `evidence/` | Qualification evidence mirroring `external-release-gate.mjs` paths |

## Status

**PLANNING** — see PLAN.md. No implementation started.
