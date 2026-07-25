# Op-cost floor-prover — scope

**The problem this exists to solve.** "This op is optimal / this is the op-cost floor" is a *non-existence*
claim (∀ implementations, none is cheaper). Non-existence claims are near-unauditable — across the crown
work, ~20 such claims ("floor is defended", "chunking optimal", …) turned out false, because the evidence
behind them was "an agent tried N things and stopped", not a proof. The only thing that turns a floor claim
from a *hypothesis* into a *fact the kernel audits* is a machine-checked **lower bound**. Today `Opt/NlcsFloor.lean`
is the only floor-prover, and it is provably too weak for the case that matters: it bounds *permutation*
transport (`#move ≥ n − LCS`), which is vacuous for a body that *computes* (outputs are fresh values, so
LCS(entry,exit)=0). This scope is the extension that makes "the Fp12 arithmetic core is optimal" a theorem.

See the `feedback-nonexistence-claim-trust` memory for the epistemics; this is the "buildable fix" it names.

## What a floor-prover can and cannot prove (read this first — it bounds the ambition honestly)

- ✅ **CAN:** a machine-checked LOWER BOUND on the op-cost of computing a **fixed** function (e.g. `fp12Mul`
  as specified by the 2-3-2 tower) on the BCH-2026 VM: *any* straight-line program computing this bilinear
  map costs ≥ L op.
- ❌ **CANNOT:** rule out a *different algorithm/representation* (a different tower, direct extension, a
  cleverer schedule) — that is a *different* map with its own rank. Nor a *different scheme/curve* (the only
  route to sub-100k). Nor does the arithmetic bound touch the **shuffle/movement** floor (the larger ~55k
  half of the core — Phase 3, research-grade) or the covenant/chunking floor. **A tight floor here audits
  "this op is optimal," not "no cheaper verifier exists."** State that boundary whenever the tool is cited.

## The bound, in three composable pieces

BCH-2026 straight-line op-cost = `100·(#ops) + arithmeticCost + stackPushedBytes` (already in `Cost/Metrics`).
The arithmetic floor is built from:

**Piece A — per-multiplication op-cost lower bound (nearly free; the cost model already exists).**
`Cost/Arith.arithCost` bills OP_MUL `arith = intByteLen(a)·intByteLen(b) + intByteLen(result)`. Prove: an
essential field multiply of two operands each with `intByteLen ≥ k` costs ≥ `k²` arith. For reduced BN254
field elements the generic operand width is 32 B, so each essential Fp-mult ≥ ~1024 arith + 100 base.
(Subtlety to handle honestly: the bound needs the operands to be *full-width*; a rigorous proof argues the
essential multiplications in the bilinear map act on non-degenerate, full-width inputs — else a prover could
"cheat" with small operands. This is the one real modelling care-point.)

**Piece B — essential-multiplication (bilinear rank) lower bound (the algebraic-complexity core).**
The count of essential Fp-multiplications to compute a bilinear map = its tensor rank. Small, *proven*,
*elementarily-formalizable* cases:
- `Fp2` mul = rank **3** (Karatsuba; Winograd's "complex mult needs 3 real mults" — substitution-method proof).
- `Fp6 = Fp2[v]/(v³−ξ)` mul = rank **6** over Fp2 (degree-2 poly mult mod a cubic).
- `Fp12 = Fp6[w]/(w²−v)` mul = rank **3** over Fp6 (Karatsuba).
- Compose over Fp via rank (sub/super-)multiplicativity → a lower bound on total Fp-mults for `fp12Mul`,
  `fp12Sqr`, `mul034` (sparse). These are the numbers to beat: shipped uses 74 / 52 / 49 mulFp.

**Piece C — compose (A × B).** `op-cost(fp12Mul) ≥ rank(fp12Mul) · min-per-mult-cost`. Machine-check the
composition in Lean (both inputs are Lean objects: the rank theorem and the `Cost/Arith` per-mul bound).
Then compare to the *shipped* op-cost: either **prove it sits at the floor** (turns "optimal" into a theorem)
or **reveal headroom** (a lever we missed — which would be a win, not a loss).

## Phases (each shippable; risk ascends)

- **P0 (low risk, days):** formalize Piece A — the per-OP_MUL op-cost lower bound from the existing
  `Cost/Arith` model, incl. the full-width-operand care-point. Deliverable: `Opt/OpMulFloor.lean`,
  0-sorry, axiom-clean.
- **P1 (medium, the real work):** formalize Piece B for `Fp2` (rank 3) via the substitution method in
  Lean-core (no mathlib), then `Fp6`/`Fp12` by composition. Deliverable: `Opt/BilinearRankFloor.lean`.
  This is bounded algebra-complexity formalization — the small ranks have elementary proofs.
- **P2 (low, given P0+P1):** compose into `Opt/Fp12OpCostFloor.lean` — a kernel-checked op-cost lower bound
  for `fp12Mul`/`fp12Sqr`/`mul034`; run it against the shipped counts. Register the headline theorems in
  `Meta/Headlines.lean` so the necessity/axiom gates cover them.
- **P3 (RESEARCH, may not land):** extend `NlcsFloor` from permutation-only to *value-producing* DAGs for a
  movement lower bound on the ~55k shuffle — pebbling / fan-in / operand-fetch-count argument. Honest status:
  this is the hard half and may stay a structural hypothesis rather than a theorem. Do not promise it.

## Trust property delivered

After P0–P2, "the Fp12 arithmetic core (~33k of the ~88k body) is at its op-cost floor" becomes a claim the
Lean kernel audits — not "an agent couldn't find a cheaper schedule." That closes the epistemics gap for the
arithmetic half of the core. The shuffle half (~55k) stays a *strong structural hypothesis* (measured
net-negativity of every representation lever) until P3 lands — and the tool must SAY so, never launder the
un-proven half into the proven one. Everything above bounds the *fixed tower on this VM*; cross-scheme
optimality remains open research, by design.
