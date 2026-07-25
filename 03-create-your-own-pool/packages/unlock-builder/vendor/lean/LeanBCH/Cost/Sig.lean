/-
  LeanBCH.Cost.Sig — the signatureCheckCount + signing-serialization hash tier.

  libauth bills a signature op `signatureCheckCount += 1` and hashes a message:
   • CHECKDATASIG hashes the ON-STACK message (length recoverable from state) →
     hashDigestIterations = hashIterations(msgLen).
   • CHECKSIG hashes the TX SIGNING SERIALIZATION, whose length is EXTERNAL to the stack
     VM (generateSigningSerializationBch) → hashDigestIterations = 1 + hashIterations(serLen),
     with `serLen` supplied by the emitter (out-of-model input; the cost stays a pure
     function of op + state + serLen). +1 for the double-SHA256 sighash.
   • CHECKMULTISIG's `sigCost` arm bills 1 tick only; the sig-check COUNT is stack-derived at
     billing time by `kappa` (VM/Meter.lean), which dispatches on the DUMMY element because
     BCH-2026 bills the two multisig paths differently — `multiSigCost` (legacy/ECDSA, nKeys in
     one shot, interpreter.cpp:1689-1692) vs `multiSigSchnorrCost` (Schnorr checkbits, one per
     signature reached, interpreter.cpp:1616). The per-verify signing-serialization hash term is
     a SEPARATE correction (`multiSigHashExtra`, VM/Extended.lean) and is still un-modeled here.
     The differential targets CHECKDATASIG (fully internal).

  Formula pinned STRUCTURALLY (`rfl` laws + `decide` boundary witnesses below). NOTE — the
  sigcheck-COUNT tier (`signatureCheckCount`, ⇒ 26000·n) is NOT in the build-time cost differential
  (`conformance/cost/`, `LeanBCH.VM.CostDifferential`): a real CHECKSIG differential needs live
  secp256k1 signatures, outside this mathlib-free core (see Extended.lean's mock-oracle sig KATs for
  the counting, and the vmb_2026 corpus boundary families for the 26000 rate end-to-end). The
  message-hash iterations reuse the hash tier (`Cost.Hash`), which IS covered by that differential.

  HONESTY: `serLen` is currently an EXTERNAL parameter. Once `LeanBCH.Tx.Sighash` lands
  (this same wave) the VM will compute the signing-serialization length internally from the
  14-field sighash layout, closing this gap; `serLen` here is a placeholder for that value.

  Transcribed from `stackcert/Stackcert/Cost/Sig.lean` (SigKind/Metrics now `LeanBCH.*`).
-/
import LeanBCH.Kinds
import LeanBCH.Cost.Hash

namespace LeanBCH.Cost
open LeanBCH

/-- Per-op `Metrics` delta of a signature opcode. `serLen` = tx signing-serialization length
    (emitter-supplied, CHECKSIG only; internalized once `LeanBCH.Tx.Sighash` lands),
    `msgLen` = on-stack message length (CHECKDATASIG),
    `resultBytes` = intByteLen of the pushed boolean (1 for true, 0 for false). -/
def sigCost (k : SigKind) (serLen msgLen resultBytes : Nat) : Metrics :=
  match k with
  | .checkDataSig =>
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := hashIterations msgLen, stackPushedBytes := resultBytes }
  | .checkSig =>
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1 + hashIterations serLen, stackPushedBytes := resultBytes }
  | .checkMultiSig =>
      -- Bills the instruction tick only; the sigcheck count is nKeys-dependent and read from the
      -- stack at billing time via `multiSigCost` (kappa passes it). This arm is the `serLen=0` shape.
      { evaluatedInstructionCount := 1 }

/-- CHECKMULTISIG cost: libauth bills `signatureCheckCount += publicKeys.length` (⇒ 26000·nPubKeys)
    whenever the signatures are non-null — the single largest sig-op op-cost term. The per-verify
    signing-serialization hash iterations are the same serLen-external term deferred in `checkSig`
    (documented under-bill: serLen threading pending the sighash-length internalization). -/
def multiSigCost (nPubKeys : Nat) : Metrics :=
  { evaluatedInstructionCount := 1, signatureCheckCount := nPubKeys }

/-- CHECKMULTISIG cost on the **SCHNORR** path (non-empty dummy = checkbits bitfield). BCH-2026
    consensus bills the two multisig paths DIFFERENTLY, and this is the one `multiSigCost` above is
    NOT: BCHN `src/script/interpreter.cpp:1616` bills `metrics.TallySigChecks(1)` **once per
    signature**, inside the `for (iSig = 0; iSig < nSigsCount; iSig++)` loop at `:1574` — and only
    AFTER that signature passes its encoding checks (`:1598`) and `checker.CheckSig` (`:1606`), which
    `return`s `SIG_NULLFAIL` (`:1611`) on the first failure. The legacy/ECDSA path instead bills
    `TallySigChecks(nKeysCount)` in one shot (`:1689-1692`).

    `nSigChecks` is supplied by `kappa` as the number of LEADING NON-EMPTY signatures in `iSig`
    order. That is oracle-free (an empty signature always fails `CheckSig` — `interpreter.cpp:2562`)
    but it cannot know whether a *non-empty* signature verifies, so its relationship to consensus is:

    | case | this cost vs BCHN |
    |---|---|
    | every declared signature non-empty AND verifying (the only accept path) | **EXACT** (`= nSigsCount`) |
    | `nSigsCount = 0` | **EXACT** (both 0) |
    | first EMPTY signature at `iSig = j` | **EXACT** (`= j`) |
    | a non-empty signature fails encoding/verification at `iSig = j` | **UPPER BOUND** (`≥ j`) |
    | malformed bitfield / stack underflow | **UPPER BOUND** (BCHN bills 0) |

    So: **an UPPER BOUND in general, exact on the accept path and on the null-signature path.** It is
    never below BCHN's tally, so the soundness direction is preserved (over-reject possible,
    over-accept not). It is never described as exact. -/
def multiSigSchnorrCost (nSigChecks : Nat) : Metrics :=
  { evaluatedInstructionCount := 1, signatureCheckCount := nSigChecks }

/-!
### The signatureCheckCount + signing-serialization tier, PINNED

Structural laws (`rfl`, quantified over ALL inputs) + `by decide` boundary witnesses at the
SHA-256 block edges (`hashIterations` steps 1→2 at 55B→56B). These PIN the hash-iteration formula
that the message-hash tier shares with `Cost.Hash` (covered by the build-time differential,
`conformance/cost/`); the sigcheck COUNT term is corpus-exercised (vmb_2026), not in that
differential — libauth is the spec of record for the NUMBERS. `decide` reduces the fuel-free
`hashIterations` Nat-floor-div, so no `native_decide` — axioms stay `[propext]`.
-/

-- ── Structural laws (quantified, definitional) ─────────────────────────────────

/-- CHECKDATASIG bills exactly ONE signature check, for every state. -/
theorem sigCost_checkDataSig_sigcount (s m r : Nat) :
    (sigCost .checkDataSig s m r).signatureCheckCount = 1 := rfl

/-- CHECKDATASIG hashes the ON-STACK message: `hashDigestIterations = hashIterations msgLen`
    (independent of the CHECKSIG-only `serLen`). This is THE formula the differential pins. -/
theorem sigCost_checkDataSig_hash (s m r : Nat) :
    (sigCost .checkDataSig s m r).hashDigestIterations = hashIterations m := rfl

/-- CHECKDATASIG pushes the boolean verdict: `stackPushedBytes = resultBytes` (1 true / 0 false). -/
theorem sigCost_checkDataSig_push (s m r : Nat) :
    (sigCost .checkDataSig s m r).stackPushedBytes = r := rfl

/-- CHECKSIG bills ONE signature check. -/
theorem sigCost_checkSig_sigcount (s m r : Nat) :
    (sigCost .checkSig s m r).signatureCheckCount = 1 := rfl

/-- CHECKSIG hashes the tx SIGNING SERIALIZATION with the double-SHA256 `+1`:
    `hashDigestIterations = 1 + hashIterations serLen` (the on-stack `msgLen` is irrelevant). -/
theorem sigCost_checkSig_hash (s m r : Nat) :
    (sigCost .checkSig s m r).hashDigestIterations = 1 + hashIterations s := rfl

/-- CHECKMULTISIG is honestly UNDER-MODELED: exactly one instruction tick, nothing else —
    no signatureCheckCount, no hashDigestIterations (a documented under-bill for the variable
    nKeys/nSigs structure the differential does NOT target). -/
theorem sigCost_checkMultiSig_undermodel (s m r : Nat) :
    sigCost .checkMultiSig s m r = { evaluatedInstructionCount := 1 } := rfl

-- ── Boundary witnesses: CHECKDATASIG msgLen 0/31/32/55/56, true & false verdict ───────
-- serLen is a don't-care for CHECKDATASIG (fixed at 0 below); the point is hashIterations
-- msgLen = 1 up to 55B, stepping to 2 at 56B (the 64-byte SHA-256 compression-block edge).

/-- msgLen 0 (empty message), TRUE verdict ⇒ 1 sig-check, 1 hash-iter, 1 pushed byte. -/
theorem sigCost_cds_msg0_true :
    sigCost .checkDataSig 0 0 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1, stackPushedBytes := 1 } := by decide

/-- msgLen 0, FALSE verdict ⇒ same metrics but 0 pushed bytes (empty item). -/
theorem sigCost_cds_msg0_false :
    sigCost .checkDataSig 0 0 0 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1, stackPushedBytes := 0 } := by decide

/-- msgLen 31 ⇒ still ONE compression block. -/
theorem sigCost_cds_msg31_true :
    sigCost .checkDataSig 0 31 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1, stackPushedBytes := 1 } := by decide

/-- msgLen 32 ⇒ still ONE compression block. -/
theorem sigCost_cds_msg32_true :
    sigCost .checkDataSig 0 32 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1, stackPushedBytes := 1 } := by decide

/-- msgLen 55 ⇒ the LAST length that fits ONE block (55 + 8-byte length pad = 63 < 64). -/
theorem sigCost_cds_msg55_true :
    sigCost .checkDataSig 0 55 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 1, stackPushedBytes := 1 } := by decide

/-- msgLen 56 ⇒ the length pad spills into a SECOND block ⇒ hashIterations steps to 2. -/
theorem sigCost_cds_msg56_true :
    sigCost .checkDataSig 0 56 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 2, stackPushedBytes := 1 } := by decide

/-- The 55→56 boundary, stated as the hash-iteration STEP the differential must reproduce. -/
theorem sigCost_cds_block_boundary :
    (sigCost .checkDataSig 0 55 1).hashDigestIterations + 1
      = (sigCost .checkDataSig 0 56 1).hashDigestIterations := by decide

-- ── CHECKSIG witnesses: the `+1` double-SHA256 sighash over the serialization ─────────

/-- serLen 0 ⇒ hashDigestIterations = 1 + hashIterations 0 = 1 + 1 = 2 (the base `+1`). -/
theorem sigCost_cs_ser0 :
    sigCost .checkSig 0 0 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 2, stackPushedBytes := 1 } := by decide

/-- serLen 55 ⇒ 1 + 1 = 2 (serialization still one block). -/
theorem sigCost_cs_ser55 :
    sigCost .checkSig 55 0 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 2, stackPushedBytes := 1 } := by decide

/-- serLen 56 ⇒ 1 + 2 = 3 (serialization crosses the block edge; the `+1` rides on top). -/
theorem sigCost_cs_ser56 :
    sigCost .checkSig 56 0 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 3, stackPushedBytes := 1 } := by decide

/-- A realistic ~194-byte P2PKH signing serialization ⇒ hashIterations 194 = 4, +1 = 5. -/
theorem sigCost_cs_ser194 :
    sigCost .checkSig 194 0 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 5, stackPushedBytes := 1 } := by decide

-- ── CHECKMULTISIG witness: the documented 1-tick under-model ───────────────────────────

/-- CHECKMULTISIG: one tick, no sig-check / hash billing (under-modeled, flagged). -/
theorem sigCost_cms_one_tick :
    sigCost .checkMultiSig 0 0 0 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 0,
        hashDigestIterations := 0, stackPushedBytes := 0 } := by decide

-- ── Schnorr-multisig witnesses: one sig-check per signature reached ────────────────────

/-- The Schnorr path bills exactly the count it is handed, for every input (structural). -/
theorem multiSigSchnorrCost_sigcount (n : Nat) :
    (multiSigSchnorrCost n).signatureCheckCount = n := rfl

/-- It bills ONE instruction tick, like every other `kappa` leaf — the property
    `LeanBCH.VM.kappa_evalCount` needs from this arm. -/
theorem multiSigSchnorrCost_tick (n : Nat) :
    (multiSigSchnorrCost n).evaluatedInstructionCount = 1 := rfl

/-- It bills NO hash iterations and NO pushed bytes: the multisig sighash term is the separate
    `multiSigHashExtra` correction in `VM/Extended.lean`, not this one. -/
theorem multiSigSchnorrCost_no_hash (n : Nat) :
    (multiSigSchnorrCost n).hashDigestIterations = 0 ∧
      (multiSigSchnorrCost n).stackPushedBytes = 0 := ⟨rfl, rfl⟩

/-- `nSigsCount = 0` ⇒ zero sig-checks: BCHN's loop body (`interpreter.cpp:1574`) never runs. -/
theorem multiSigSchnorrCost_zero :
    multiSigSchnorrCost 0 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 0,
        hashDigestIterations := 0, stackPushedBytes := 0 } := by decide

/-- A 1-of-N Schnorr multisig bills ONE sig-check, whatever N is — the case that made the
    pre-fix `kappa` over-bill by `N` (it billed `nKeys`). -/
theorem multiSigSchnorrCost_one :
    multiSigSchnorrCost 1 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 1,
        hashDigestIterations := 0, stackPushedBytes := 0 } := by decide

/-- A 2-of-N Schnorr multisig bills TWO. -/
theorem multiSigSchnorrCost_two :
    multiSigSchnorrCost 2 =
      { evaluatedInstructionCount := 1, signatureCheckCount := 2,
        hashDigestIterations := 0, stackPushedBytes := 0 } := by decide

/-- **The Schnorr bill never exceeds the number of signatures declared.** The leading-non-empty-run
    count `kappa` passes to `multiSigSchnorrCost` is bounded by the signature-slice length, so the
    Schnorr path can never bill more than `nSigsCount` sig-checks. (The stronger `≤ nKeys` is NOT
    provable here: `kappa` does not enforce `M ≤ N` — that bound is `Extended.lean:220`'s job.) -/
theorem schnorr_bill_le_sigs (sigs : List (List UInt8)) :
    (multiSigSchnorrCost (sigs.reverse.takeWhile (fun sg => !sg.isEmpty)).length).signatureCheckCount
      ≤ sigs.length := by
  have h := (List.takeWhile_sublist (l := sigs.reverse) (fun sg => !sg.isEmpty)).length_le
  simpa [multiSigSchnorrCost] using h

end LeanBCH.Cost
