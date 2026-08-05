/-
  Pure DEEP quotient q(x) — Lean field ops only.

  Matches native_ct_air_stark._deep_replay.q_at term order:
    cols: α·(ck-Pcz)/(x-z), α·(ck-Pczg)/(x-zg)
    selectors: α·(sel_k - mask_z)/(x-z)
    range_weight: α·(rw_k - rw_zg)/(x-zg)
    composition: α·(cc - comp_z)/(x-z)

  Accept kernel uses this formula on proof openings + public samples.
  Does NOT use pre-multiplied deep_q_terms exports.
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks

namespace FriStark.Deep.QAt

open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)

/-- Public selector samples at query index k (base field). -/
structure SelAtK where
  is_full : F
  is_partial : F
  is_block_start : F
  is_reabsorb : F
  is_range : F
  is_range_first : F
  is_range_step : F
  is_range_last : F
  rc : List F
  chain_minv : List F
  range_weight : F

/-- Public selector masks at DEEP point z (extension), parallel to SelAtK base keys + rc + chain. -/
structure SelMaskZ where
  is_full : E
  is_partial : E
  is_block_start : E
  is_reabsorb : E
  is_range : E
  is_range_first : E
  is_range_step : E
  is_range_last : E
  rc : List E
  chain_minv : List E

/-- Full inputs for pure q_at (proof openings + public samples; no pre-mul terms). -/
structure QAtInput where
  x : F
  z : E
  zg : E
  comp_z : E
  rw_zg : E
  cc : E
  /-- Trace column values at k, FLAT_COLS order. -/
  ck : List F
  Pcz : List E
  Pczg : List E
  deep_alphas : List E
  sel : SelAtK
  selMask : SelMaskZ

/-- Pure DEEP quotient evaluation. -/
def eval (inp : QAtInput) : Option E := Id.run do
  let xz := sub (fromBase inp.x) inp.z
  let xzg := sub (fromBase inp.x) inp.zg
  match inv xz, inv xzg with
  | none, _ => none
  | _, none => none
  | some invz, some invzg =>
    let mut acc := zero
    let mut ai := 0
    let n := min inp.ck.length (min inp.Pcz.length inp.Pczg.length)
    -- columns: dual DEEP at z and zg
    for i in [0:n] do
      if ai ≥ inp.deep_alphas.length then return none
      let cke := fromBase inp.ck[i]!
      acc := add acc (mul inp.deep_alphas[ai]! (mul (sub cke inp.Pcz[i]!) invz))
      ai := ai + 1
      if ai ≥ inp.deep_alphas.length then return none
      acc := add acc (mul inp.deep_alphas[ai]! (mul (sub cke inp.Pczg[i]!) invzg))
      ai := ai + 1
    -- 8 selector keys with masks at z
    let sels : List (F × E) := [
      (inp.sel.is_full, inp.selMask.is_full),
      (inp.sel.is_partial, inp.selMask.is_partial),
      (inp.sel.is_block_start, inp.selMask.is_block_start),
      (inp.sel.is_reabsorb, inp.selMask.is_reabsorb),
      (inp.sel.is_range, inp.selMask.is_range),
      (inp.sel.is_range_first, inp.selMask.is_range_first),
      (inp.sel.is_range_step, inp.selMask.is_range_step),
      (inp.sel.is_range_last, inp.selMask.is_range_last)]
    for (s, m) in sels do
      if ai ≥ inp.deep_alphas.length then return none
      acc := add acc (mul inp.deep_alphas[ai]! (mul (sub (fromBase s) m) invz))
      ai := ai + 1
    let nrc := min inp.sel.rc.length inp.selMask.rc.length
    for i in [0:nrc] do
      if ai ≥ inp.deep_alphas.length then return none
      acc := add acc (mul inp.deep_alphas[ai]!
        (mul (sub (fromBase inp.sel.rc[i]!) inp.selMask.rc[i]!) invz))
      ai := ai + 1
    let nch := min inp.sel.chain_minv.length inp.selMask.chain_minv.length
    for i in [0:nch] do
      if ai ≥ inp.deep_alphas.length then return none
      acc := add acc (mul inp.deep_alphas[ai]!
        (mul (sub (fromBase inp.sel.chain_minv[i]!) inp.selMask.chain_minv[i]!) invz))
      ai := ai + 1
    -- range_weight at zg
    if ai ≥ inp.deep_alphas.length then return none
    acc := add acc (mul inp.deep_alphas[ai]!
      (mul (sub (fromBase inp.sel.range_weight) inp.rw_zg) invzg))
    ai := ai + 1
    -- composition
    if ai ≥ inp.deep_alphas.length then return none
    acc := add acc (mul inp.deep_alphas[ai]! (mul (sub inp.cc inp.comp_z) invz))
    some acc

/--
  Lean recomputes q and checks equality to expected (e.g. FRI layer-0 / cc binding).
  Defined via `Option.any` so semantic theorems can use ∃-eval form without
  kernel-deep-unfolding the heavy `Id.run` body of `eval`.
-/
def matchesExpect (inp : QAtInput) (expect : E) : Bool :=
  (eval inp).any (fun q => eq q expect)

/-- Semantic: DEEP quotient evaluates to a field element equal to `expect`. -/
def DeepEvalEquals (inp : QAtInput) (expect : E) : Prop :=
  ∃ q, eval inp = some q ∧ eq q expect = true

theorem matchesExpect_iff_deepEval (inp : QAtInput) (expect : E) :
    matchesExpect inp expect = true ↔ DeepEvalEquals inp expect := by
  simp only [matchesExpect, DeepEvalEquals, Option.any_eq_true]

theorem matchesExpect_implies_deepEval (inp : QAtInput) (expect : E)
    (h : matchesExpect inp expect = true) : DeepEvalEquals inp expect :=
  (matchesExpect_iff_deepEval inp expect).mp h

theorem deepEval_implies_matchesExpect (inp : QAtInput) (expect : E)
    (h : DeepEvalEquals inp expect) : matchesExpect inp expect = true :=
  (matchesExpect_iff_deepEval inp expect).mpr h

end FriStark.Deep.QAt
