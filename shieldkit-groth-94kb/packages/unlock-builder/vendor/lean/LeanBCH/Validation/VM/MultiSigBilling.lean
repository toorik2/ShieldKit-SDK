/-
  KATs for the CHECKMULTISIG arm of `LeanBCH.VM.kappa` (VM/Meter.lean).

  These drive the LIVE billing fold over hand-built pre-states, so they pin what the pure
  `Cost.multiSigSchnorrCost` witnesses in `Cost/Sig.lean` cannot: the DUMMY-element dispatch
  (Schnorr vs legacy/ECDSA) and, critically, the SIGNATURE ORDER.

  ORDERING — why `.reverse` is load-bearing in `Meter.lean`'s Schnorr arm. `kappa` slices the
  signatures off the stack TOP-first, but BCHN's loop index `iSig = 0` is the DEEPEST (first-pushed)
  signature: `idxBottomSig = idxTopSig + nSigsCount - 1` (`interpreter.cpp:1571`) read at `:1593`.
  `VM/Extended.lean:225` reverses for exactly this reason. The two asymmetric cases below
  (`deepest_null` / `deepest_sig`) are the discriminator: without the `.reverse` they bill 1 and 0,
  and the second is an UNDER-bill against consensus, which bills 1.
-/
import LeanBCH.VM.Meter

namespace LeanBCH.Validation
open LeanBCH LeanBCH.VM

/-- A CHECKMULTISIG (0xae) pre-state. Stack layout top→bottom, per `VM/Extended.lean:197`:
    `N, pk_N..pk_1, M, sig_M..sig_1, dummy`. `sigsDeepFirst` is given in BCHN `iSig` order
    (deepest / first-pushed first), so the stack itself needs them reversed. -/
private def cmsState (n : Nat) (sigsDeepFirst : List Bytes) (dummy : Bytes) : State :=
  { stack := [UInt8.ofNat n] :: (List.replicate n [(0x02 : UInt8)])
               ++ [[UInt8.ofNat sigsDeepFirst.length]]
               ++ sigsDeepFirst.reverse ++ [dummy]
    instrs := #[⟨0xae, []⟩] }

/-- A non-null signature body (any non-empty item; `kappa` only tests emptiness). -/
private def sigNonNull : Bytes := List.replicate 65 (0x11 : UInt8)

/-- The sig-check count `kappa` bills from a CHECKMULTISIG pre-state. -/
private def billed (n : Nat) (sigsDeepFirst : List Bytes) (dummy : Bytes) : Nat :=
  (kappa (cmsState n sigsDeepFirst dummy)).signatureCheckCount

-- ── SCHNORR path (dummy NON-empty): one sig-check per signature reached ────────────────
-- BCHN `interpreter.cpp:1616` bills TallySigChecks(1) per loop iteration, after CheckSig.

-- 1-of-3 Schnorr, the signature present ⇒ 1 (consensus: EXACT). Pre-fix `kappa` billed 3.
example : billed 3 [sigNonNull] [0x01] = 1 := rfl
-- 2-of-3 Schnorr, both present ⇒ 2 (consensus: EXACT). Pre-fix `kappa` billed 3.
example : billed 3 [sigNonNull, sigNonNull] [0x03] = 2 := rfl
-- 2-of-3 Schnorr, BOTH NULL — the `0u4tu8` witness shape
-- (`conformance/evidence/LBCH-2026-001-rootcause.tsv`) ⇒ 0, matching BCHN. Unchanged by the fix.
example : billed 3 [[], []] [0x03] = 0 := rfl
-- nSigsCount = 0 with a non-empty dummy ⇒ 0: BCHN's loop body never runs (`:1574`).
example : billed 3 [] [0x00] = 0 := rfl

-- ── THE ORDERING DISCRIMINATOR ─────────────────────────────────────────────────────────
-- DEEPEST signature null ⇒ BCHN's iSig=0 fails CheckSig (`:2562`) ⇒ SIG_NULLFAIL (`:1611`)
-- before any tally ⇒ 0. Scanning top-first instead would bill 1 here.
example : billed 3 [[], sigNonNull] [0x03] = 0 := rfl
-- DEEPEST signature present, the SHALLOWER one null ⇒ BCHN tallies iSig=0 (1), then iSig=1
-- fails ⇒ 1. Scanning top-first would bill 0 here — an UNDER-bill. This is the case that
-- makes `.reverse` mandatory.
example : billed 3 [sigNonNull, []] [0x03] = 1 := rfl

-- ── LEGACY / ECDSA path (dummy EMPTY): BIT-IDENTICAL to pre-fix behaviour ──────────────
-- BCHN `interpreter.cpp:1689-1692` bills nKeysCount in one shot when not all sigs are null.

-- 2-of-3 ECDSA, signatures present ⇒ nKeys = 3 (the deliberate consensus upper bound).
example : billed 3 [sigNonNull, sigNonNull] [] = 3 := rfl
-- ECDSA all-null ⇒ 0 (the `areAllSignaturesNull` gate).
example : billed 3 [[], []] [] = 0 := rfl
-- The ordering asymmetry must NOT leak into the ECDSA path: both mixed orders still bill nKeys.
example : billed 3 [[], sigNonNull] [] = 3 := rfl
example : billed 3 [sigNonNull, []] [] = 3 := rfl

/-! ### ECDSA-path invariance, proved rather than sampled

The fix must leave the legacy/ECDSA path BIT-IDENTICAL. `legacyArmPreFix` below is the multisig
arm exactly as it stood before the fix (`VM/Meter.lean:143-150` at commit `a8b7682`), transcribed
verbatim — note it computes the signature slice in ONE expression, where the fixed code hoists
`nSigs` into a `let`. The theorem then says: on every state whose DUMMY element is empty, the
fixed billing agrees with the pre-fix billing, for ALL stacks — so no empty-dummy vector can move.
This is a universally-quantified statement, not a corpus sample. -/
private def legacyArmPreFix (stack : Stack) : Cost.Metrics :=
  match stack[0]? with
  | some nTop =>
      let nKeys := (vmNumberToBigInt nTop).toNat
      let sigs  := (stack.drop (nKeys + 2)).take
                     ((stack[nKeys + 1]?.map (fun m => (vmNumberToBigInt m).toNat)).getD 0)
      if sigs.all (·.isEmpty) then Cost.sigCost .checkMultiSig 0 0 0
      else Cost.multiSigCost nKeys
  | none => Cost.sigCost .checkMultiSig 0 0 0

/-- The multisig arm as it now stands (the `kappa` body, isolated). -/
private def multiSigArm (stack : Stack) : Cost.Metrics :=
  match stack[0]? with
  | some nTop =>
      let nKeys := (vmNumberToBigInt nTop).toNat
      let nSigs := (stack[nKeys + 1]?.map (fun m => (vmNumberToBigInt m).toNat)).getD 0
      let sigs  := (stack.drop (nKeys + 2)).take nSigs
      let dummy := (stack[nKeys + 2 + nSigs]?).getD []
      if !dummy.isEmpty then
        Cost.multiSigSchnorrCost (sigs.reverse.takeWhile (fun sg => !sg.isEmpty)).length
      else if sigs.all (·.isEmpty) then Cost.sigCost .checkMultiSig 0 0 0
      else Cost.multiSigCost nKeys
  | none => Cost.sigCost .checkMultiSig 0 0 0

/-- **ECDSA-path invariance.** Whenever the dummy element is EMPTY (the legacy/ECDSA selector,
    BCHN `interpreter.cpp:1543-1544`), the fixed arm bills exactly what the pre-fix arm billed —
    for every stack. The Schnorr change therefore cannot perturb any ECDSA vector. -/
theorem multiSigArm_ecdsa_unchanged (stack : Stack) (nTop : Bytes) (h0 : stack[0]? = some nTop)
    (hd : ((stack[(vmNumberToBigInt nTop).toNat + 2
              + (((stack[(vmNumberToBigInt nTop).toNat + 1]?).map
                    (fun m => (vmNumberToBigInt m).toNat)).getD 0)]?).getD []).isEmpty = true) :
    multiSigArm stack = legacyArmPreFix stack := by
  unfold multiSigArm legacyArmPreFix
  rw [h0]
  simp only [hd, Bool.not_true, Bool.false_eq_true, if_false]

/-- The empty-stack case is unchanged too (both arms take the `none` branch). -/
theorem multiSigArm_none_unchanged (stack : Stack) (h0 : stack[0]? = none) :
    multiSigArm stack = legacyArmPreFix stack := by
  unfold multiSigArm legacyArmPreFix; rw [h0]

/-- Sanity: the two arms genuinely DIFFER on the Schnorr path, so the theorem above is not
    vacuous — a 1-of-3 Schnorr vector bills 1 now and billed 3 before. -/
example : (multiSigArm (cmsState 3 [sigNonNull] [0x01]).stack).signatureCheckCount = 1 := rfl
example : (legacyArmPreFix (cmsState 3 [sigNonNull] [0x01]).stack).signatureCheckCount = 3 := rfl

/-- And the isolated arm agrees with the LIVE `kappa` fold, so the invariance theorem is about
    the code that actually runs. -/
example : multiSigArm (cmsState 3 [sigNonNull] [0x01]).stack
            = kappa (cmsState 3 [sigNonNull] [0x01]) := rfl
example : multiSigArm (cmsState 3 [sigNonNull, sigNonNull] []).stack
            = kappa (cmsState 3 [sigNonNull, sigNonNull] []) := rfl

end LeanBCH.Validation
