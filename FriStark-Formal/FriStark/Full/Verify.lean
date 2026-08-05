/-
  Pure Lean STARK verify accept kernel.

  DEEP public samples rebuilt via Domain.SelRebuild (INTT+Horner on H-layout).
  Composition via AIR.ComposeExt.matchesCompZ.
  Export samples are not the sole accept-path public inputs.
-/
import FriStark.Verify.Types
import FriStark.Transcript.FiatShamir
import FriStark.Hash.Merkle
import FriStark.Hash.Sha256
import FriStark.FRI.Verify
import FriStark.FRI.Coset
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Deep.Replay
import FriStark.Deep.QAt
import FriStark.Domain.PublicEval
import FriStark.Domain.SelRebuild
import FriStark.AIR.ComposeExt
import FriStark.AIR.ProductV1
import FriStark.Params.V1

namespace FriStark.Full.Verify

open FriStark.Verify.Types
open FriStark.Hash.Sha256 (Bytes)
open FriStark.Hash.Merkle
open FriStark.FRI.Verify
open FriStark.FRI.Coset
open FriStark.Field.Ext
open FriStark.Field.Goldilocks (F)
open FriStark.Deep.Replay
open FriStark.Deep.QAt
open FriStark.Domain.SelRebuild
open FriStark.AIR.ComposeExt
open FriStark.AIR.ProductV1
open FriStark.Params.V1
open FriStark.Transcript.FiatShamir

/-- DEEP q_at core openings; selectors rebuilt from H-layout in Lean. -/
structure DeepQAtCore where
  x : F
  z : E
  zg : E
  proofCompZ : E
  cc : E
  ck : List F
  Pcz : List E
  Pczg : List E
  deep_alphas : List E
  expectFri0 : E

structure ComposePack where
  cur : List (String × E)
  nxt : List (String × E)
  z : E
  wNext : E
  lastF : F
  zhInv : E
  Hd : List F
  pub : List (String × E)
  rc : List E
  chainMinv : List E
  alphasT : List E
  alphasB : List E
  bounds : List Boundary
  Mext : List (List F)
  Minv : List (List F)
  diag : List F
  Minv0 : List F
  held : List String
  expectCompZ : E

inductive Step where
  | params (blowup queries grind fold : Nat)
  | fsAbsorb (pre data post : Bytes)
  | fsAbsorbInt (pre : Bytes) (v : Nat) (post : Bytes)
  | fsChallenge (pre : Bytes) (expect : F) (post : Bytes)
  | fsExtChallenge (pre : Bytes) (a0 a1 : F) (post : Bytes)
  | fsChallengeIdx (pre : Bytes) (domain expectIdx : Nat) (post : Bytes)
  | grindCheck (state nonce : Bytes) (bits : Nat)
  | natListEq (a b : List Nat)
  | natEq (a b : Nat)
  | bytesEq (a b : Bytes)
  | merkleDigest (root leaf : Bytes) (path : List (Bytes × Nat))
  | friFold (v w beta folded : E) (xpos : Nat)
  | cosetFold (coset : List E) (betas : List E)
      (base li0 s off oN N : Nat) (expect : E)
  | extEq (a b : E)
  | deepZ (zProof zgProof zGot : E) (oT : F)
  | deepAlphas (got expect : List E)
  | deepQAt (inp : QAtInput) (expect : E)
  | deepQAtLayout (layout : HLayout) (core : DeepQAtCore)
  | composeCheck (pack : ComposePack)
  | productAir (st : ProductStatement) (w : ProductWitness)

structure Bundle where
  steps : List Step
  accept : Bool
  label : String
  eligibility : String
  blowup : Nat
  queries : Nat
  grindBits : Nat
  fold : Nat

def qatFromLayout (layout : HLayout) (core : DeepQAtCore) : QAtInput :=
  {
    x := core.x
    z := core.z
    zg := core.zg
    comp_z := core.proofCompZ
    rw_zg := rwAtZg layout core.zg
    cc := core.cc
    ck := core.ck
    Pcz := core.Pcz
    Pczg := core.Pczg
    deep_alphas := core.deep_alphas
    sel := selAtBase layout core.x
    selMask := selMaskAtZ layout core.z
  }

def runStep (s : Step) : VerifyResult :=
  match s with
  | .params b q g f =>
      if b == BLOWUP && q == QUERIES && g == GRIND_BITS && f == FOLD then .ok else .err "params"
  | .fsAbsorb pre data post =>
      if (absorb ⟨pre⟩ data).bytes == post then .ok else .err "fsAbsorb"
  | .fsAbsorbInt pre v post =>
      if (absorbInt ⟨pre⟩ v).bytes == post then .ok else .err "fsAbsorbInt"
  | .fsChallenge pre expect post =>
      let (c, s') := challenge ⟨pre⟩
      if c == expect && s'.bytes == post then .ok else .err "fsChallenge"
  | .fsExtChallenge pre a0 a1 post =>
      let (c0, s1) := challenge ⟨pre⟩
      let (c1, s2) := challenge s1
      if c0 == a0 && c1 == a1 && s2.bytes == post then .ok else .err "fsExtChallenge"
  | .fsChallengeIdx pre domain expectIdx post =>
      let (i, s') := challengeIdx ⟨pre⟩ domain
      if i == expectIdx && s'.bytes == post then .ok else .err "fsChallengeIdx"
  | .grindCheck st n bits =>
      if grindOk st n bits then .ok else .err "grind"
  | .natListEq a b => if a == b then .ok else .err "natListEq"
  | .natEq a b => if a == b then .ok else .err "natEq"
  | .bytesEq a b => if a == b then .ok else .err "bytesEq"
  | .merkleDigest r l p => if verifyDigest r l p then .ok else .err "merkle"
  | .friFold v w beta folded xpos =>
      if verifyFoldStep v w folded beta xpos then .ok else .err "friFold"
  | .cosetFold coset betas base li0 s off oN N expect =>
      if verifyCosetFold coset betas base li0 s off oN N expect then .ok else .err "cosetFold"
  | .extEq a b => if eq a b then .ok else .err "extEq"
  | .deepZ zp zgp zg oT => if checkZ zp zgp zg oT then .ok else .err "deepZ"
  | .deepAlphas got exp => if got == exp then .ok else .err "deepAlphas"
  | .deepQAt inp expect =>
      if matchesExpect inp expect then .ok else .err "deepQAt"
  | .deepQAtLayout layout core =>
      if matchesExpect (qatFromLayout layout core) core.expectFri0 then .ok
      else .err "deepQAtLayout"
  | .composeCheck pack =>
      if matchesCompZ pack.cur pack.nxt pack.z pack.wNext pack.lastF pack.zhInv pack.Hd
          pack.pub pack.rc pack.chainMinv pack.alphasT pack.alphasB pack.bounds
          pack.Mext pack.Minv pack.diag pack.Minv0 pack.held pack.expectCompZ
      then .ok else .err "composeCheck"
  | .productAir st w =>
      if verifyProductAir st w then .ok else .err "productAir"

/-- Recursive step runner — pure, no `Id.run` (Warrant Wave B). -/
def verifySteps : List Step → VerifyResult
  | [] => .ok
  | s :: rest =>
    match runStep s with
    | .ok => verifySteps rest
    | e => e

/-- Prop: every step returns `.ok`. -/
def stepsAllRunOk : List Step → Prop
  | [] => True
  | s :: rest => runStep s = .ok ∧ stepsAllRunOk rest

theorem verifySteps_ok_iff (steps : List Step) :
    verifySteps steps = .ok ↔ stepsAllRunOk steps := by
  induction steps with
  | nil =>
    simp [verifySteps, stepsAllRunOk]
  | cons s rest ih =>
    cases h : runStep s with
    | ok =>
      simp [verifySteps, stepsAllRunOk, h, ih]
    | err w =>
      simp [verifySteps, stepsAllRunOk, h]

theorem stepsAllRunOk_of_mem (steps : List Step) (s : Step)
    (hAll : stepsAllRunOk steps) (hMem : s ∈ steps) : runStep s = .ok := by
  induction steps with
  | nil => cases hMem
  | cons t rest ih =>
    cases hMem with
    | head => exact hAll.1
    | tail _ hRest => exact ih hAll.2 hRest

/-- Bool form of the product-params fail branch (matches historical Id.run verify). -/
def paramsFail (b : Bundle) : Bool :=
  (b.eligibility == "product") &&
    ((b.blowup != BLOWUP) || (b.queries != QUERIES) ||
     (b.grindBits != GRIND_BITS) || (b.fold != FOLD))

/-- Production param gate as Prop (EndToEnd / Warrant). -/
def paramsGate (b : Bundle) : Prop :=
  b.eligibility ≠ "product" ∨
    (b.blowup = BLOWUP ∧ b.queries = QUERIES ∧
     b.grindBits = GRIND_BITS ∧ b.fold = FOLD)

/-- Pure accept kernel (behavior-preserving vs former Id.run loop). -/
def verify (b : Bundle) : VerifyResult :=
  if paramsFail b then .err "non-production params"
  else if b.steps.isEmpty then .err "empty"
  else verifySteps b.steps

/-- Executable characterization of accept (no Id.run). -/
theorem verify_eq_ok_iff (b : Bundle) :
    verify b = .ok ↔
      paramsFail b = false ∧ b.steps.isEmpty = false ∧ verifySteps b.steps = .ok := by
  unfold verify
  cases paramsFail b with
  | true => simp
  | false =>
    cases b.steps.isEmpty with
    | true => simp
    | false => simp

theorem steps_ne_nil_of_not_isEmpty {α : Type _} (xs : List α)
    (h : xs.isEmpty = false) : xs ≠ [] := by
  cases xs with
  | nil => simp at h
  | cons _ _ => exact List.cons_ne_nil _ _

theorem not_isEmpty_of_steps_ne_nil {α : Type _} (xs : List α)
    (h : xs ≠ []) : xs.isEmpty = false := by
  cases xs with
  | nil => exact absurd rfl h
  | cons _ _ => rfl

theorem verify_ok_iff (b : Bundle) :
    verify b = .ok ↔
      paramsFail b = false ∧ b.steps ≠ [] ∧ stepsAllRunOk b.steps := by
  constructor
  · intro h
    have hE := (verify_eq_ok_iff b).mp h
    exact ⟨hE.1, steps_ne_nil_of_not_isEmpty _ hE.2.1,
      (verifySteps_ok_iff b.steps).mp hE.2.2⟩
  · intro ⟨hPF, hNe, hSteps⟩
    exact (verify_eq_ok_iff b).mpr
      ⟨hPF, not_isEmpty_of_steps_ne_nil _ hNe, (verifySteps_ok_iff b.steps).mpr hSteps⟩

theorem verify_ok_implies_stepsAllRunOk (b : Bundle) (h : verify b = .ok) :
    stepsAllRunOk b.steps :=
  ((verify_ok_iff b).mp h).2.2

theorem verify_ok_implies_step (b : Bundle) (s : Step)
    (h : verify b = .ok) (hMem : s ∈ b.steps) : runStep s = .ok :=
  stepsAllRunOk_of_mem b.steps s (verify_ok_implies_stepsAllRunOk b h) hMem

def agrees (b : Bundle) : Bool := (verify b).isOk == b.accept

def hasLayoutDeep (b : Bundle) : Bool :=
  b.steps.any fun s => match s with | .deepQAtLayout .. => true | _ => false

def hasComposeCheck (b : Bundle) : Bool :=
  b.steps.any fun s => match s with | .composeCheck .. => true | _ => false

def hasCosetFold (b : Bundle) : Bool :=
  b.steps.any fun s => match s with | .cosetFold .. => true | _ => false

end FriStark.Full.Verify
