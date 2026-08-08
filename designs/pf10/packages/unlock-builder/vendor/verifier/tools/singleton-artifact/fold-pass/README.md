# fold-pass — the FoldTable(L≤4) + Peephole(L=5) deterministic fold optimizer

A permanent, reusable, self-verifying tool that folds **every** maximal run of pure
stack ops in a recompiler-output singleton down to its shortest equivalent form, using
only the machine-checked stackcert stack identities. Bytecode-level stack-op
superoptimization — deterministic, no search.

On the BN254 search crown it shaves **−152 B** (5,628 → 5,476 locking), reproducing the
committed `singleton-5835-locking5476-foldcomplete.hex` **byte-for-byte**
(sha256 `63601c1e6ce1dca0c7d90f4773669b5798ead38d559baf372aa01c09d8226687`). One command,
reproducible.

## What it does

Input: a singleton as locking-bytecode **hex** — an `OP_DEFINE` subroutine table
(`bodyPush; idPush; OP_DEFINE` records) followed by the main routine.

For each code region (main + every body), the pass:

1. **Tokenizes** the op list into maximal runs of **pure** stack ops (`DUP DROP OVER
   SWAP ROT NIP TUCK 2DUP 2DROP 2OVER 2ROT 2SWAP`, plus `<k>PICK`/`<k>ROLL` merged into
   one token). Every pure token carries its **exact source bytes**, so anything the fold
   does not touch re-emits byte-for-byte. Impure ops (arithmetic, control, INVOKE, big
   pushes) split the runs and are never crossed.
2. **Greedy longest-window fold to fixpoint.** Within each run, at position *i* it tries
   window sizes 5..2 (longest first); for the first window that has a **strictly shorter
   equivalent** replacement (drawn from the decompiler-safe alphabet + deletion + pairs of
   single-byte ops, in fixed order), it splices the replacement in and restarts. Iterated
   until a full sweep changes nothing.
3. **Rebuilds** the program (`rebuild`) with the folded bodies + main, then repeats the
   whole pass until a pass folds nothing (**program-level fixpoint**).

It is **deterministic**: a fixed replacement alphabet, fixed window order (5→2), and
first-shorter-equivalent-wins. Same input → same bytes, every run.

## Why it is SOUND — one machine-checked theorem *per fold*

Every replacement the pass applies is a bytecode-level **stack IDENTITY** — it leaves the
stack in exactly the same state on every input, at every depth. Each such identity is a
rewrite in the stackcert rewrite library:

- **`FoldTable`** — **window-complete for L ≤ 4**: every net-negative identity over the
  decompiler-safe alphabet on windows of ≤ 4 pure ops has a proven `rfl`-theorem
  (2,114 folds). Window-completeness is the key claim: no L ≤ 4 fold is missed, and none
  is unproven.
- **`Peephole`** — a curated **L = 5** extension: identity-cycles (`ROT^3 → ∅`,
  `2ROT^3 → ∅`) and staircase collapses (`ROT ROT ROT <n>ROLL → <n>ROLL`, etc.).

This is the **opposite shape** to `cse-pass`, whose *entire* soundness is the single
general theorem `InvokeCSE.invoke_cse` (one theorem covers every factoring, no per-instance
proof). The fold pass instead carries a **per-fold proof obligation** — acceptable only
because the table is window-complete for L ≤ 4, so completeness is guaranteed rather than
hoped for.

The headline identities, each independently proven (and cross-checked by a pure-JS stack
model in `foldcomplete-src/proofcheck.mjs`):

| fold | identity | needs depth |
|---|---|---|
| `DROP DROP` → `2DROP` | `(a,b) → ()` | 2 |
| `OVER OVER` → `2DUP` | `(a,b) → (a,b,a,b)` | 2 |
| `SWAP OVER` → `TUCK` | `(a,b) → (b,a,b)` | 2 |
| `<3>ROLL <3>ROLL` → `2SWAP` | swap top pairs | 4 |
| `<5>ROLL <5>ROLL` → `2ROT` | rotate top 6 by 2 | 6 |
| `<3>PICK <3>PICK` → `2OVER` | copy pair 2-deep | 4 |
| `ROT ROT ROT` → `∅` | `ROT³ = id` | 3 |
| `2ROT 2ROT 2ROT` → `∅` | `2ROT³ = id` | 6 |
| `<4>ROLL <5>ROLL` → `2ROT SWAP`, `ROT <3>ROLL` → `2SWAP SWAP`, `DUP <2>PICK` → `2DUP SWAP`, … | L≤4 composites | ≤6 |

As a redundant, target-VM belt-and-braces check, the pass **also** confirms each window
replacement live on the loosened VM across a run of **deep sentinel depths** before
applying it — the `equiv` oracle. It requires identical stacks at *every* depth in the
test set (base = `max(11, maxK+4)`, five consecutive depths), so an "identity" that only
coincides at one depth is rejected. This is why `DUP DUP` is **not** folded to `2DUP`
(`(a)→(a,a,a)` ≠ `(a,b)→(a,b,a,b)`) and `<1>PICK <1>PICK` is **not** `2OVER`.

## The `idxPush` correctness note (a bug this tool fixes)

A `<k>PICK`/`<k>ROLL` token is a depth-operand push followed by the PICK/ROLL opcode. The
naive encoding `idxPush(k) = 0x50 + k` is **only valid for 1 ≤ k ≤ 16**, where
`0x51..0x60` are the single-byte opcodes `OP_1..OP_16`. At **k = 17** it produces `0x61`
— which is `OP_NOP2` (`CHECKSEQUENCEVERIFY`), **not a push** — and every larger k emits an
unrelated *opcode* in place of a numeric operand. The deep ROLL/PICK staircase bodies in
these singletons reach index ~38, so a naive re-encode **silently corrupts** them. Correct
encoding (`fold_pass.mjs :: idxPush`):

```
k == 0        -> OP_0         (0x00)
1 <= k <= 16  -> OP_1..OP_16  (0x51..0x60), one byte
k >= 17       -> direct push of the minimal signed little-endian VM number
                 (via bigIntToVmNumber — so 128 -> [0x80,0x00], never reads as negative)
```

Belt-and-braces: the pass **preserves the exact source bytes** of every op it does not
fold, so anything untouched round-trips byte-for-byte regardless of original encoding;
`idxPush` is used only to emit fold *replacements*. The `--gate` round-trip byte-exact
check would fail loudly if either were wrong.

## Usage

```sh
# run the pass, write the reduced hex, print folds applied + byte delta
node fold_pass.mjs <in.hex> <out.hex>

# ... and additionally run all 3 gates; exit 0 iff every gate passes
node fold_pass.mjs <in.hex> <out.hex> --gate

# determinism/regression self-check (see below); exit 0 iff reproduced
node fold_pass.mjs --selfcheck
```

Portable: the pipeline is a **relative** import (`../pipeline-sub6k`) and the self-check
crowns are resolved relative to the tool file — no absolute/scratch paths.
`@bitauth/libauth` resolves via normal node module lookup (the repo's `node_modules`).

## Gate discipline (3 gates)

`--gate` runs all three; the pass is only accepted if **all** pass. The gates verify the
**implementation** (tokenize/splice/`idxPush`/rebuild), not the soundness — that's the
per-fold theorem.

1. **Round-trip byte-exact** — the folded program decompiles and recompiles to itself,
   byte-for-byte (main + every body).
2. **Per-subroutine differential** — every *changed* body is semantically identical
   before/after over random field inputs; every *unchanged* body is byte-identical (and
   skipped from execution — trivially equal).
3. **Whole-main differential** — the whole program (defs + random deep stack + main)
   produces identical results, or identical benign errors, over many random deep stacks.

## Self-check — what it asserts

`--selfcheck` is a three-part regression guard:

1. **Oracle unit tests** — the `equiv` oracle **FIRES** on `DROP DROP → 2DROP`,
   `<3>ROLL <3>ROLL → 2SWAP`, `<5>ROLL <5>ROLL → 2ROT`, and **REJECTS** the non-identities
   `DUP DUP ≠ 2DUP`, `<1>PICK <1>PICK ≠ 2OVER`.
2. **Crown reproduction** — `../singleton-5987-locking5628-search.hex` (5,628 B) folds to
   **exactly 5,476 B** with sha `63601c1e…226687` (byte-identical to the committed
   `singleton-5835-locking5476-foldcomplete.hex`), and all 3 gates pass on the result.
3. **`fold ⊥ CSE` true-negative** — `../singleton-4705-locking4346-foldcse.hex` (the CSE
   crown) folds to **0 folds** (its bodies are ascending-index ROLL/PICK rotations with no
   foldable ROLL adjacency), confirming the pass finds nothing where there is nothing.

## Gate performance & intensity knobs

Some recompiler bodies are *intrinsically* expensive on the loosened VM (this crown's
body#33 — a final-exponentiation-like routine — costs ~22 s per eval, independent of input
magnitude). The fold decision itself is cheap and memoized (the pass over 5,628 B runs in
~2 s), but the **executing** gates (arity probe + per-subroutine differential) hit those
bodies. Two mechanisms keep the tool usable without weakening the shipped defaults:

- **Self-validating early-stop in the wide-arity probe.** A body's arity is monotone, so
  once `FOLD_ARITY_STABLE` (default 6) consecutive successes are seen past the last error,
  `in`/`out` are known and further probing stops (still capped at `FOLD_ARITY_MAXK`,
  default 45). Self-validating: an under-probed arity makes GATE1's byte-exact round-trip
  underflow → `rt-exact` goes FALSE, so a bad arity can never pass silently. Set
  `FOLD_ARITY_STABLE=1` for the fastest self-validated probe.
- **Env-configurable trial counts** (defaults = thorough): `FOLD_SUB_TRIALS` (GATE2, 8),
  `FOLD_MAIN_TRIALS` (GATE3, 200). Fold equivalence is value-independent (each fold is a
  context-free stack identity), so any nonzero count that passes corroborates the rest.
  Fast self-check on this crown:

  ```sh
  FOLD_ARITY_STABLE=1 FOLD_SUB_TRIALS=2 FOLD_MAIN_TRIALS=50 \
    node fold_pass.mjs --selfcheck    # reproduces 5476, gates green, in a few minutes
  ```

## Target-agnostic — reusable for BLS / any singleton

The pass never inspects field arithmetic; it needs only, for the target VM, a `dissect` /
`rebuild` / `runSubroutine` / decompile round-trip (here from `../pipeline-sub6k`, the
BCH-2026 loosened VM) plus the VM itself for the equivalence oracle. Point it at a
BLS12-381 singleton — or any future recompiler output — and it folds that too. The fold
identities are universal stack facts; nothing is BN254-specific (the field modulus is used
only as the PRNG modulus for gate inputs).

## Files

- `fold_pass.mjs` — the whole pass + gates + self-check (single self-contained file).
- `README.md` — this file.

Depends on `../pipeline-sub6k/{asm,program,decompile}.mjs` and `@bitauth/libauth`. The
underlying grammar/proof scaffolding lives in `../foldcomplete-src/` (`peephole.mjs`
grammar, `proofcheck.mjs` pure-JS identity proofs, `enumerate.mjs` census); this tool
productizes it into one reproducible command.
