# Verified deterministic optimizer — pass ↔ proof manifest

The recompiler's byte reductions historically came from a **stochastic search** (annealing +
topo-search). This suite reduces bytes **deterministically** instead: it applies transforms that
are each **machine-checked sound in Lean** (the `stackcert` repo), iterated to a **fixpoint**. No
search; every byte removed carries a soundness proof for free. The *search* found the crown; the
*proofs* keep shrinking it — reproducibly, and portably across targets.

This is the answer to "reduce without search": treat the stackcert theorems as a **rewrite
library** and run it as an optimizer.

## The passes and their soundness theorems

| pass | tool | soundness theorem (`stackcert`) | shape |
|---|---|---|---|
| **fold-application** | `fold-pass/fold_pass.mjs` | `FoldTable` (2,114 folds, window-complete L≤4) + `Peephole` (L=5 curated) | per-fold rfl-theorems |
| **CSE** (subroutine factoring) | `cse-pass/cse_pass.mjs` | `InvokeCSE.invoke_cse` | **one** general theorem — covers every factoring |
| **const-derivation** | pipeline splices (`ederive-deriv.mjs`, …) | `Ederive.ederive_pushes_E`, `tail_pushes_inv2`, `twist_pushes_b2`, `Providers.invoke_const_provider` | per-constant |
| **reschedule / move-arrange** | `pipeline-sub6k` scheduler | `schedule_refines` ∪ `schedule_refines_move_cond` | the recompiler core |

All are 0-sorry, axiom-clean (`propext` / `Quot.sound` / core `Classical.choice`), and enforced by
`stackcert/scripts/verify.sh` (6 gates).

## The principle

- Each pass is a **deterministic** rewrite: `recompiler-output → smaller recompiler-output`.
- Each rewrite is **sound by a stackcert theorem** — so soundness needs *no* per-result
  differential test. (CSE is the cleanest: one theorem covers *all* factorings, no per-instance
  proof. Folds are per-fold theorems, but window-complete for L≤4.)
- Passes run **to fixpoint** (they are deterministic but not always idempotent — e.g. CSE exposes
  nested repeats on a 2nd pass), and the suite **alternates** passes until none reduces.
- The tools' `--gate` (round-trip byte-exact + per-subroutine + whole-main differential) verifies
  the **implementation** (splice / id-allocation / encoding), *not* the soundness — that's the theorem.

## Empirical record (BN254 singleton)

| step | pass | Δ | locking |
|---|---|---|---|
| search crown | anneal/topo | — | 5,628 |
| fold-completeness | fold-pass | −152 | 5,476 |
| … (E-derivation, p-pool, L5 folds, marshalling-CSE) | mixed | … | 4,818 |
| complete CSE | cse-pass | −459 | 4,359 |
| CSE fixpoint | cse-pass (2nd pass) | −13 | **4,346** |

**fold ⊥ CSE on the 4,346 crown:** the CSE bodies are ascending-index ROLL/PICK *rotations*, and
the only foldable ROLL adjacencies are `<3>ROLL²→2SWAP` / `<5>ROLL²→2ROT`, never present — so the
fold pass finds 0 here. They are orthogonal on this artifact; the whole post-marshalling gain is CSE.

## Usage

```sh
node optimize.mjs            <in.hex> <out.hex>            # BOTH passes, combined fixpoint (one command)
node cse-pass/cse_pass.mjs   <in.hex> <out.hex> [--gate]   # CSE alone, to fixpoint
node fold-pass/fold_pass.mjs <in.hex> <out.hex> [--gate]   # folds alone, to fixpoint
# each pass's --selfcheck reproduces a bundled known reduction as a regression guard
```

`optimize.mjs` alternates CSE↔fold until a full round removes nothing (each sub-pass already runs
to its own fixpoint; alternation catches CSE-exposed folds and vice-versa). Verified: `optimize.mjs
singleton-5177-locking4818-marshcse.hex out` reaches the **4,346** crown (−472 B) — CSE-fixpoint
then fold-0, byte-identical to `singleton-4705-locking4346-foldcse.hex`.

## Target-agnostic

None of the passes inspect field arithmetic; they need only a `dissect` / `runSubroutine` /
decompile round-trip for the target VM (here `pipeline-sub6k`, BCH-2026 loosened). Point them at a
**BLS12-381** singleton and they factor/fold it too — the −459 B CSE move should transfer for free.

## Doctrine

Built under `prove → productize → apply`: once a transform is proven and applied once, its applier
becomes a first-class tested tool *before* the next use — so no capability is re-derived, and every
census/scan is complete-by-construction (no false "exhausted"). See the `prove-then-productize`
memory; the CSE tool caught its own single-pass incompleteness (−13 B) this way.
