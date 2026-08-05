# Lean verified byte-recompiler harness (`lean-recompiler-spike`)

Durable, machine-checked proof artifact for the **verifier.cash** singleton byte-recompiler
(`tools/singleton-recompiler`). Proves — in **Lean 4.31 core, NO mathlib** — that the recompiler's
transformations are pure stack-function equivalences: correct for **all** inputs over an **abstract
value type `α`** (not just the 8-random-Fp differential test that gates the hot loop). Value meaning
is irrelevant to these rewrites (they preserve stack *shape*/*wiring*, not crypto semantics), so `α`
is left opaque and node operators are uninterpreted (`NodeOp.sem`): only the WIRING is verified.

Toolchain pinned in `lean-toolchain`: `leanprover/lean4:v4.31.0`. Pure `lake`, no dependencies
(`lake-manifest.json` is empty).

---

## What it proves (module map)

| Module | Content | Status |
|---|---|---|
| `Recompiler/Basic.lean` | Stack sub-VM: `Op` (DUP/DROP/OVER/SWAP/ROT/NIP/TUCK/PICK/ROLL/…/2-ops/PUSH/`CALL nin sem`), `step` (underflow ⇒ `none`, faithful abort), `run`, `Correct src dst := ∀ st, run src st = run dst st`, `run_append`, `Correct.congr` (splice a proven rewrite into any `pre ++ · ++ post`). | ✅ |
| `Recompiler/Peephole.lean` | Peephole rewrite equivalences, each a `Correct` over all inputs/`α`: `over_over ⇒ 2DUP`, `swap_over ⇒ TUCK`, `swap_drop ⇒ NIP`, `pick0_dup`, `pick1_over`, `roll1_swap`, `roll2_rot`, `roll0_nop`, `pick2_thrice`, `pick3_twice`, `roll3/5_twice`, `swap_swap`/`dup_drop`/`over_drop`. | ✅ |
| `Recompiler/Passthrough.lean` | Altstack passthrough: `fromAltN_spec`, `toAltN_spec`, `drain_repark_id`, `passthrough_correct`, `park_restore_id` (drain-N-then-repark is identity on the alt stack). | ✅ |
| `Recompiler/Dag.lean` | Value-DAG IR: `NodeOp`/`Ref`/`Node`/`Block`, the denotation `denote` (entry stacks ↦ exit `State`), and `WellFormed` (topo-order + arity + semArity + Nodup ids + out-index bounds) — the decompile invariant surfaced as a Lean predicate. | — (defs) |
| `Recompiler/Scheduler.lean` | Faithful **emitter model** of `scheduler.mjs` (`scheduleBlock`/`emit`): CSE-const homes, per-node operand materialize (MOVE `moveOps` on last use / COPY `copyOps` on reuse), `CALL`, eager-drop, incremental exit arrange. **Opaque-operator abstraction** is the enabling move. | — (emitter) |
| `Recompiler/StepLemmas.lean`, `Simulation.lean`, `Compose.lean` | **`schedule_refines`**: `run (emit b) (entryState M A) = some (denote b M A)` for every `WellFormed b`, all `M A`, all `α`. The emitter provably refines the DAG denotation. | ✅ |
| `Recompiler/Decompile.lean` | **`bridge_block`**: `run rawOps (entryState M A) = some (denote (decompileBlock rawOps …) M A)` — the decompiler is faithful (the inverse of the scheduler). Then **`end_to_end`** (per block): `run (emit (decompileBlock rawOps)) = run rawOps`. **Non-vacuous**: a concrete `Nat` block with a real binary `CALL` computing `3 + 4 = 7` is decompiled, shown `WellFormed`, and both capstones (`bridge_block`, `end_to_end`) are shown to FIRE on it. | ✅ |
| `Recompiler/Control.lean` | **`whole_program_end_to_end`**: `runProg isT fuel (optProg prog) st = runProg isT fuel prog st` for every decompile-accepted (`Shaped`) program, ALL inputs, ALL fuel, abstract `α` and abstract branch predicate `isT`. Composes the per-block bridge over the full IF/ELSE/ENDIF + BEGIN/UNTIL + VERIFY control tree. **Non-vacuous**: a concrete program (real `CALL` block THEN an IF/ELSE) is `Shaped` and fires the theorem; a separate witness shows the semantics genuinely BRANCHES (same program, different results under true vs false cond). | ✅ |
| `Recompiler/Floor.lean` | **`copy_floor`** (+ `conserve`, `dups_ge`): the combinatorial COPY lower bound. See below. **NOTE:** charges `D = Σ(fanout−1)` bytes assuming one single `DUP` per copy — valid over the 1-copy machine, but UNSOUND as a *packed* byte floor (see `PackedFloor`). | ✅ |
| `Recompiler/PackedFloor.lean` | **`packed_copy_floor` / `packed_copy_floor_ceil`** (+ `conserveP`): the SOUND packed COPY floor once the copy set includes `2DUP`/`2OVER` (+2) and `3DUP` (+3): `#copy-bytes ≥ ⌈D/3⌉`, since no VM op creates >3 occurrences. TIGHT — the `3DUP` witness meets `⌈D/3⌉` with EQUALITY and BEATS the old `D`-byte charge (1 < 3). Adjacency-tight floor `∈ [⌈D/3⌉, D]` (NP-hard) documented. | ✅ |

Chaining `schedule_refines` (verified emitter) with `bridge_block` (verified decompiler) closes the
recompiler correctness chain `run(recompiled) = run(original)` per block; `Control.lean` lifts that
over the whole-program control structure.

---

## The ONE disclosed boundary — structured `Prog` control vs flat bytecode control

`Basic.run` is a straight-line fold with **no** control flow. The real bytecode's control opcodes
(`OP_IF`/`NOTIF`/`ELSE`/`ENDIF`, `OP_BEGIN`/`UNTIL`, `OP_VERIFY`) are re-emitted **verbatim** between
blocks by the recompiler, and the real VM **branches** on them. `Control.lean` therefore models a
program as a **structured** `Prog = List (Item α)` (`block`/`ifte`/`loop`/`verify`) with a big-step
semantics `runProg` that actually branches (fuel-bounded loop iteration; the theorem holds for ALL
fuel, so all terminating runs are covered and non-terminating runs give `none = none`).

**Why this is faithful, not a cheat:**
- The alternative — modelling control ops as opaque no-ops in the flat fold — would be **unfaithful**
  (it would not branch); the structured model captures exactly what the VM does.
- **No frame/passthrough gap:** `decompile.mjs`'s `beginBlock()` relabels the FULL current stack as
  fresh entry slots (`entryDepth = main.length`), so every block consumes and produces the entire
  stack. Hence at each block leaf the runtime state is exactly `entryState M A` with
  `|M| = entryDepth`, `|A| = entryAlt`, and `end_to_end` applies with no passthrough side-condition.
- The `Shaped` judgment is the Lean surfacing of `decompile.mjs`'s depth tracking plus its fail-loud
  reconciliation checks (branch-shape consistency, loop-invariance), which guarantee the flat control
  flow matches this tree.

**Scoped out (syntactic layer, not correctness-relevant):** byte-level `parse` (`asm.mjs`) and
`<n> OP_PICK → PICK n` folding — the `Op`-list is the shared semantic interface both the scheduler and
decompiler commit to. The scheduler's greedy ready-list node ordering and shallow-operand heuristics
are **byte-only** optimizations, deliberately decoupled from correctness: `denote` is node-order
invariant, so any valid topological emission order is equally covered by `schedule_refines` (this model
emits in `b.nodes` order).

---

## The floor lemma (`Recompiler/Floor.lean`)

`copy_floor` (proved over a minimal `push`/`dup`/`pop` counting machine via the `conserve` conservation
law): **a value produced once but consumed `k` times forces ≥ `k − 1` explicit COPY (dup) ops.** The
witness `[push 7, dup, dup, pop, pop, pop]` shows event counts `(#push,#dup,#pop) = (1,2,3)` — fan-out
3 costs exactly 2 dups, so the floor is **tight** (met with equality) and the model is non-degenerate.

- **Bounds the COPY floor: YES.** A genuine, mechanically-proven, non-vacuous lower bound on the number
  of duplications a fan-out forces.
- **Bounds the MOVEMENT floor: NO.** Choosing a stack layout that minimises total reordering cost
  (ROLL/PICK depth, stale-tail deletion) is a bounded-register stack-sequencing problem with no clean
  closed form (NP-hard); deliberately **out of scope**.
- **Bridge to the value-DAG (`Recompiler.fanout`):** `fanout b r` counts a ref's demand across
  `nodes.flatMap Node.ins ++ exit ++ exitAlt`. A node output is produced once (`CALL`) and each
  consuming edge is served by one primitive — a MOVE on the last use, a COPY on earlier uses — so a
  value's emitter sub-trace is a `Floor` program with `#push = 1`, `#pop = fanout`, giving
  `#copies ≥ fanout − 1`. **Honest scope:** `copy_floor` is fully mechanised over the `Floor` model;
  the correspondence to `Scheduler.emit` (that it realises exactly this per-value sub-trace) is
  DOCUMENTED, not yet mechanised (it needs a per-value projection of the emitter trace). A concrete
  block with a fan-out-3 output is checked (`fanout … = 3` by `decide`).

---

## Reproduce

```bash
export PATH="$HOME/.elan/bin:$PATH"
cd tools/lean-recompiler-spike

# 1) Whole-project build — expect "Build completed successfully"; ZERO "declaration uses sorry".
lake build
lake build 2>&1 | grep -c "declaration uses sorry"        # ⇒ 0

# 2) Independent axiom audit (no sorryAx anywhere).
cat > /tmp/AxAudit.lean <<'EOF'
import Recompiler
open Recompiler
#print axioms schedule_refines
#print axioms bridge_block
#print axioms end_to_end
#print axioms whole_program_end_to_end
#print axioms Recompiler.Floor.conserve
#print axioms Recompiler.Floor.copy_floor
#print axioms Recompiler.Floor.dups_ge
EOF
lake env lean /tmp/AxAudit.lean

# 3) Grep-confirm no unsound escape hatches. Every hit below is inside a comment/docstring,
#    NOT a declaration: the `sorry`/`admit` hits are historical narration; the sole `opaque`
#    hit is the WORD "opaque no-ops" in Control.lean's header prose, not the `opaque` keyword.
grep -rnwE "sorry|admit" Recompiler/ Main.lean            # only docstring narration
grep -rnE "native_decide|@\[extern|@\[implemented_by" Recompiler/ Main.lean   # ⇒ (none)
grep -rnE "^\s*axiom\b|^\s*opaque\b" Recompiler/ Main.lean # ⇒ 1 comment-line false positive
```

The only build warnings are two `unusedVariables` linter notes in `Compose.lean` (`hLS`, `hLe`) — no
`sorry`, no errors.

---

## Axiom profile

`#print axioms` on every top theorem yields only Lean's standard classical trust base — **no `sorryAx`,
no custom `axiom`, no `native_decide`, no `@[extern]`/`@[implemented_by]`:**

| Theorem | Axioms |
|---|---|
| `schedule_refines` | `[propext, Classical.choice, Quot.sound]` |
| `bridge_block` | `[propext, Classical.choice, Quot.sound]` |
| `end_to_end` | `[propext, Classical.choice, Quot.sound]` |
| `whole_program_end_to_end` | `[propext, Classical.choice, Quot.sound]` |
| `Floor.conserve` | `[propext, Quot.sound]` |
| `Floor.copy_floor` | `[propext, Quot.sound]` |
| `Floor.dups_ge` | `[propext, Quot.sound]` |
| `PackedFloor.conserveP` | `[propext, Quot.sound]` |
| `PackedFloor.packed_copy_floor` | `[propext, Quot.sound]` |
| `PackedFloor.packed_copy_floor_ceil` | `[propext, Quot.sound]` |
| `Recompiler.fanout` (def) | none |

`{propext, Classical.choice, Quot.sound}` is the standard sound axiom set of Lean's classical logic;
the `Floor` lemmas do not even use `Classical.choice`.

**Note (stale narration):** some docstrings in `Simulation.lean` / `Compose.lean` retain historical
"sorry-frontier" wording from development. That frontier is **closed** — `lake build` reports 0
`declaration uses sorry` and the axiom audit above shows no `sorryAx`. Trust the build + `#print
axioms`, not the prose.
