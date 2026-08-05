# foldgen — complete fold-table generator (decidable stack-effect, no SMT)

`foldgen.py` enumerates the **window-complete** set of sound peephole folds over the
BCH2026 stack-shuffle op alphabet and emits them as a machine-checkable Lean module
(`LeanBCH/Opt/FoldTable.lean`). One deterministic tool, no SMT, no trusted external solver.

```
python3 tools/foldgen/foldgen.py > LeanBCH/Opt/FoldTable.lean   # regenerate (L=4,D=12,MAXIDX=6)
python3 tools/foldgen/foldgen.py --report                     # human-readable fold report
python3 tools/foldgen/foldgen.py --check LeanBCH/Opt/FoldTable.lean   # determinism gate (diff)
```

## Method — decidable stack effect (the differentiator)

Every op is modelled as a total function on a symbolic stack `[0,1,…,d-1]` (index 0 = TOP,
matching the Lean `x :: y :: s` convention), returning `None` on underflow. For a sequence
`seq`, its **effect** is the tuple, over all initial depths `d ∈ 0..D`, of either the frozen
output stack (a permutation/selection of the input symbols) or `U` (underflow). Two sequences
are semantically equal on the shuffle algebra **iff their effects are equal** — a *decidable*
finite check, no SMT/`native_decide`. This is the key departure from Alive / souper / FORVES,
which discharge equivalence with an SMT backend in the trusted base.

Pipeline (all in `foldgen.py`):

1. **Enumerate** every sequence of length `0..L` over the alphabet
   (`DUP DROP OVER SWAP ROT NIP TUCK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP`, plus
   `PICK n` / `ROLL n` for `n ∈ 0..MAXIDX`).
2. **Canonicalize** by effect: bucket sequences into effect-classes; the min-byte member
   (tie-break: byte cost, then length, then op-name order) is the class **representative**.
3. **Derive folds**:
   - *Unconditional* `Correct src dst`: any strictly-costlier member of an effect-class folds
     to its representative (equal on *all* depths, including identical underflow).
   - *Conditional* (depth-guarded): grouping by the effect at depth `D`, the global min-byte
     rep agrees with `src` for every depth `≥ k` (but differs below `k`, e.g. deleting an op
     drops its underflow re-check); emitted as `∀ st, k ≤ st.1.length → run src st = run dst st`.
4. **Validate**: assert the enumeration reproduces every curated `Peephole.lean` fold
   (`OVER OVER→2DUP`, `SWAP SWAP→∅ [k2]`, …) — fails loudly otherwise.
5. **Filter + soundness re-check**: keep primitive sources of length `≤ 3` that are not already
   in the curated set; drop `ROLL 0` noise (a conditional no-op already covered by curated
   `roll0_nop`); independently re-verify every emitted fold's effect equality before emit.
6. **Emit Lean**: each fold becomes a theorem whose proof destructures the main stack to the
   depth the rule touches, then closes every case by `rfl` (uncond) or
   `first | rfl | simp_all [run, step] | omega` (conditional).

## Parameters

| flag        | default | meaning                                             |
|-------------|---------|-----------------------------------------------------|
| `--len -L`  | 4       | max source sequence length (the "window")           |
| `--depth -D`| 12      | max symbolic stack depth probed for the effect      |
| `--maxidx -M`| 6      | max `PICK`/`ROLL` index enumerated                  |

`D` must exceed the deepest reach of any length-`L` sequence for the effect check to be exact;
`D=12` comfortably covers `L=4` with `MAXIDX=6`. At the defaults the tool emits **2114**
theorems (1700 unconditional + 414 depth-guarded).

## Determinism

Output is **byte-identical across runs**: enumeration order is a fixed `itertools.product`,
all buckets are insertion-ordered `dict`s, all orderings are stable sorts, and `set`s are used
only for membership tests (never iterated for output). `tools/opt-ci/verify.sh` re-runs the tool and
diffs against the checked-in `LeanBCH/Opt/FoldTable.lean` (`--check`), so the committed table is
provably exactly the generator output — no hand-edits.

## Retargeting to another op-set

The op semantics live in one place — the `ap(op, s)` transition table and the `ONEBYTE`
alphabet / `cost_op` byte model at the top of `foldgen.py`. To target a different stack VM:
edit `ap` (add/replace op cases), `ONEBYTE`/`ALPHA` (the enumerated alphabet), and `cost_op`
(the byte-cost model), then update the `LEAN`/`lean_op` renderers so the emitted constructors
match your Lean `Op` inductive. The enumerate → canonicalize → derive → emit pipeline and the
determinism guarantees are op-set-agnostic. Update `KNOWN_UNCOND`/`KNOWN_COND` to whatever
curated set you want validated-reproduced.
