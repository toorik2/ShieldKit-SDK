/-
  Production coset multi-fold matching native_ct_air_stark._coset_fold
  (fold-8 path: pairs cur[m] with cur[m+h], xpos = (off·oN^(base+m·stride))^(2^(li0+f))).
-/
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.FRI.Coset

open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)

/-- Recompute domain point x = (off * oN^gidx)^(2^(li0+f)) mod P. -/
def domainX (off oN gidx li0 f : Nat) : F :=
  let basePt := mul (off % P) (pow (oN % P) gidx)
  pow basePt (1 <<< (li0 + f))

/--
  Fold a 2^s-coset at layer li0 down to one extension element.
  `betas` must have length ≥ s (betas[li0 : li0+s] from the FRI transcript).
  Returns none on length/beta/domain failure.
-/
def cosetFold (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) : Option E := Id.run do
  if s == 0 then
    return coset[0]?
  -- expect |coset| = 2^s
  if coset.length != (1 <<< s) then return none
  if betas.length < s then return none
  if N == 0 then return none
  let n := N >>> li0
  let stride := n >>> s
  let mut cur := coset
  for f in [0:s] do
    let h := cur.length / 2
    if cur.length != h * 2 then return none
    if f ≥ betas.length then return none
    let beta := betas[f]!
    let mut nxt : List E := []
    for m in [0:h] do
      let gidx := base + m * stride
      let xpos := domainX off oN gidx li0 f
      match friFold cur[m]! cur[m + h]! beta xpos with
      | none => return none
      | some folded => nxt := nxt ++ [folded]
    cur := nxt
  return cur[0]?

/-- Coset fold binds `expect` — `Option.any` form for ∃-eval semantic theorems. -/
def verifyCosetFold (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) : Bool :=
  (cosetFold coset betas base li0 s off oN N).any (fun got => eq got expect)

/-- Semantic: multi-fold yields a value equal to `expect`. -/
def CosetEvalEquals (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) : Prop :=
  ∃ got, cosetFold coset betas base li0 s off oN N = some got ∧ eq got expect = true

theorem verifyCosetFold_iff_cosetEval
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E) :
    verifyCosetFold coset betas base li0 s off oN N expect = true ↔
      CosetEvalEquals coset betas base li0 s off oN N expect := by
  simp only [verifyCosetFold, CosetEvalEquals, Option.any_eq_true]

theorem verifyCosetFold_implies_cosetEval
    (coset : List E) (betas : List E)
    (base li0 s off oN N : Nat) (expect : E)
    (h : verifyCosetFold coset betas base li0 s off oN N expect = true) :
    CosetEvalEquals coset betas base li0 s off oN N expect :=
  (verifyCosetFold_iff_cosetEval coset betas base li0 s off oN N expect).mp h

end FriStark.FRI.Coset
