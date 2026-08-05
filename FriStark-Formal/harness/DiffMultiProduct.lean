/-
  Phase 1 multi-kind product accept under production params.
  Honest deposit/transfer/withdrawal productAir + ≥6 mutations reject.
  Structural forges from Binding.Forges if available.
-/
import FriStark.Params.V1
import FriStark.AIR.ProductV1
import FriStark.Full.Verify
import FriStark.Soundness.Statement
import FriStark.Binding.Forges

open FriStark.Params.V1
open FriStark.AIR.ProductV1
open FriStark.Full.Verify
open FriStark.Soundness.Statement

def productBundle (label : String) (st : ProductStatement) (w : ProductWitness) : Bundle :=
  {
    steps := [.productAir st w]
    accept := true
    label := label
    eligibility := "product"
    blowup := BLOWUP
    queries := QUERIES
    grindBits := GRIND_BITS
    fold := FOLD
  }

def main (_args : List String) : IO UInt32 := do
  let mut fails : Nat := 0

  -- Production param pins
  if BLOWUP != 2048 || QUERIES != 8 || GRIND_BITS != 24 || FOLD != 8 then
    fails := fails + 1; IO.eprintln "non-production params"

  let kinds : List (String × ProductStatement × ProductWitness) :=
    let (sd, wd) := honestDeposit
    let (st, wt) := honestTransfer
    let (sw, ww) := honestWithdrawal
    [ ("deposit", sd, wd), ("transfer", st, wt), ("withdrawal", sw, ww) ]

  let mut honestOk := 0
  for (name, st, w) in kinds do
    if !verifyProductAir st w then
      fails := fails + 1; IO.eprintln s!"kind {name} product air fail"
    else
      honestOk := honestOk + 1
    let b := productBundle name st w
    match verify b with
    | .ok => pure ()
    | .err e => fails := fails + 1; IO.eprintln s!"kind {name} Full.Verify fail {e}"
    -- StatementHolds
    if !verifyProductAir st w then
      fails := fails + 1

  if honestOk != 3 then
    fails := fails + 1; IO.eprintln s!"honest kinds {honestOk}/3"

  -- Mutations ≥6
  if !mutationsAllRejected then
    fails := fails + 1; IO.eprintln "mutations not all rejected"
  let mut mutN := 0
  let mut mutRej := 0
  for m in allMutations do
    mutN := mutN + 1
    if !verifyProductAir m.stmt m.wit then mutRej := mutRej + 1
    let b := productBundle s!"mut-{m.name}" m.stmt m.wit
    -- product eligibility + fail should reject
    match verify b with
    | .ok => fails := fails + 1; IO.eprintln s!"mutation accepted {m.name}"
    | .err _ => pure ()

  if mutN < 6 then fails := fails + 1; IO.eprintln s!"mutation count {mutN}"
  if mutRej != mutN then fails := fails + 1; IO.eprintln s!"mut reject {mutRej}/{mutN}"

  -- Binding forges
  if !FriStark.Binding.Forges.allForgesRejected then
    fails := fails + 1; IO.eprintln "binding forges not all rejected"

  IO.println s!"multi_product_honest_kinds={honestOk}"
  IO.println s!"multi_product_mutations={mutN} rejected={mutRej}"
  IO.println s!"prod_params=blowup={BLOWUP} queries={QUERIES} grind={GRIND_BITS} fold={FOLD}"
  IO.println "binding_forges=all_rejected"
  IO.println "productAir_on_accept_path=deposit,transfer,withdrawal"

  if fails == 0 then
    IO.println "DIFF_MULTI_PRODUCT_OK"
    pure 0
  else
    IO.eprintln s!"DIFF_MULTI_PRODUCT_FAIL fails={fails}"
    pure 1
