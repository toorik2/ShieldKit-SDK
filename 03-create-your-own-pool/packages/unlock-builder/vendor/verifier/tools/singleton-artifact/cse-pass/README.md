# cse-pass — the complete `invoke_cse` deterministic optimizer pass

A permanent, reusable, self-verifying tool that factors **every** net-positive
repeated contiguous op-subsequence in a recompiler-output singleton into a shared
`OP_INVOKE` body. Bytecode-level common-subexpression elimination.

On the BN254 crown it shaves **−472 B** (4,818 → 4,346 locking), iterating to a
FIXPOINT — `invoke_cse` is deterministic but NOT idempotent: a 2nd pass exposes a
nested sub-staircase (shared once the 1st pass splits the marshalling streams), so the
pass repeats until nothing more factors. One command, no search, reproducible.

## What it does

Input: a singleton as locking-bytecode **hex** — an `OP_DEFINE` subroutine table
(`bodyPush; idPush; OP_DEFINE` records) followed by the main routine.

The pass is three deterministic stages plus a splice:

1. **Census** — build one op-stream per code region (main + every body), intern
   each op to an integer token, concatenate into one global array with a **unique
   negative barrier between regions** (so no "repeat" is ever detected across a
   region boundary). Then for each length `L ∈ [2, 130]`, hash every window of `L`
   ops and group by content; any content occurring ≥ 2× is a candidate.
2. **Greedy disjoint set-pack** — repeatedly take the single most byte-negative
   factoring whose occurrences are still non-overlapping and lie in unconsumed
   positions, mark those positions consumed, allocate the next free id (40+).
   Net model: `net(B,K) = B·(1−K) + 3K + pushHeader(B) + 3`; threshold `net ≤ −10`.
3. **Apply** — replace each chosen occurrence with `[push id; OP_INVOKE]` (3 bytes)
   and append one new `OP_DEFINE` per new id. Re-serialize with minimal push headers.

It is **deterministic**: `Map` iteration is insertion order (by length, then first
occurrence), ties broken by first-seen. Same input → same bytes, every run.

## Why it is SOUND — one general theorem, no per-factoring proof

Every factoring is justified by a **single** machine-checked theorem:

> **`Stackcert.InvokeCSE.invoke_cse`** — OP_INVOKE stack-transparency: replacing any
> contiguous op-subsequence by `[push id; OP_INVOKE]`, where a new `OP_DEFINE` binds
> `id` to exactly that subsequence, preserves execution on every input stack.

This is the whole soundness argument. There is **no per-factoring proof obligation**
— contrast the fold-table, which needs a separate theorem per rewrite. Any factoring
the census can emit is, by construction, an instance of this one theorem. That makes
the pass "sound by construction": correctness scales to arbitrarily many factorings
for free.

The gates below are **not** the soundness argument — they are a belt-and-braces
empirical check that the *implementation* (splice, id allocation, header choice)
faithfully realizes the theorem.

## Two correctness constraints (essential — do not remove)

The pass is sound regardless, but the **byte-exact round-trip gate** imposes two
implementation constraints, both documented in the source:

- **Dangling-const-push filter.** The round-trip decompiler models an `OP_INVOKE`'s
  outputs as *opaque*. If a factored subsequence *ends* with a constant push whose
  value is consumed as the depth operand of an **external** `OP_PICK`/`OP_ROLL` (the
  op right after the factored region), that depth stops being statically known after
  factoring and the decompiler cannot resolve it. Such contents are rejected from
  candidacy. (Soundness is unaffected — `invoke_cse` still holds — but the byte-exact
  gate needs depth operands to stay statically resolvable.) Sub-patterns ending in the
  PICK/ROLL itself, or in a DROP / arithmetic op, remain factorable.
- **Wide-arity probe.** The shared `probeArity` caps input probing at 30, but the
  deepest ROLL/PICK staircase bodies consume ~35 inputs; capped, their arity is
  under-estimated and the round-trip decompiler underflows. The pass probes wider
  (default 45). Runtime semantics are unchanged — this only feeds the gate's input
  counts.

## Usage

```sh
# run the pass, write the reduced hex, print the byte delta + factorings applied
node cse_pass.mjs <in.hex> <out.hex>

# ... and additionally run all 4 gates; exit 0 iff every gate passes
node cse_pass.mjs <in.hex> <out.hex> --gate

# determinism/regression self-check: reproduce the bundled 4818 -> 4346 fixpoint crown,
# assert byte count AND gates; exit 0 iff reproduced
node cse_pass.mjs --selfcheck
```

Portable: the pipeline is a **relative** import (`../pipeline-sub6k`) and the
self-check crown is resolved relative to the tool file — no absolute/scratch paths.
`@bitauth/libauth` resolves via normal node module lookup (the repo's `node_modules`).

## Gate discipline (the DW's 4 gates)

`--gate` / `--selfcheck` run all four; the pass is only accepted if **all** pass:

1. **Round-trip byte-exact** — the factored program decompiles and recompiles to
   itself, byte-for-byte (main + every body).
2. **Per-subroutine differential** — every original body is semantically identical
   before/after over random field inputs; unchanged bodies are byte-identical.
3. **`invoke_cse` local differential** — inline content vs `[push id; OP_INVOKE]`
   on the shared def table produce identical stacks over 120 random deep stacks per
   factoring.
4. **Whole-main differential** — the whole program (defs + random stack + main)
   produces identical results (or identical benign errors) over 200 random deep
   stacks.

## Gate performance & intensity knobs

The gate suite runs the target program hundreds of times on the loosened VM. Some
recompiler bodies are *intrinsically* expensive (e.g. this crown's body#33 — a
final-exponentiation-like routine — costs ~29 s per VM eval, independent of input
magnitude), so the full-strength gates can take many minutes on such a program.

Two mechanisms keep the tool usable without weakening the shipped defaults:

- **Self-validating early-stop in the wide-arity probe.** A body's arity is monotone
  (errors below `in`, succeeds at/above), so once `CSE_ARITY_STABLE` (default 6)
  consecutive successful probes are seen past the last error, `in`/`out` are known and
  further probing is redundant — we stop (still capped at `CSE_ARITY_MAXK`, default 45).
  This is **self-validating**: an under-probed (wrong) arity makes GATE1's byte-exact
  round-trip decompile underflow → `rt-exact` goes FALSE, so a bad arity can never pass
  silently. Set `CSE_ARITY_STABLE=1` for the fastest self-validated probe.
- **Env-configurable trial counts** (defaults = the DW's thorough values):
  `CSE_SUB_TRIALS` (GATE2, 10), `CSE_CSE_TRIALS` (GATE3, 120), `CSE_MAIN_TRIALS`
  (GATE4, 200). `invoke_cse` equivalence is value-independent, so any nonzero count that
  passes corroborates the rest — reduce them for a fast smoke-test, keep the defaults for
  a full audit. Example fast self-check on this crown:

  ```sh
  CSE_ARITY_STABLE=1 CSE_SUB_TRIALS=1 CSE_CSE_TRIALS=1 CSE_MAIN_TRIALS=1 \
    node cse_pass.mjs --selfcheck    # reproduces 4346, every pass gated, in seconds
  ```

## Target-agnostic — reusable for BLS / any singleton

The pass never inspects field arithmetic; it only needs, for the target VM, a
`dissect` / `runSubroutine` / decompile round-trip. Here those come from
`../pipeline-sub6k` (the BCH-2026 loosened VM). Point the tool at a BLS12-381
singleton — or any future recompiler output — and it factors that too, provided the
pipeline can dissect/run that program. Nothing in the census, greedy pack, or splice
is BN254-specific (the field modulus is used only as the PRNG modulus for gate inputs).

## Files

- `cse_pass.mjs` — the whole pass + gates + self-check (single self-contained file).
- `README.md` — this file.

Depends on `../pipeline-sub6k/{asm,program,decompile}.mjs` and `@bitauth/libauth`.
