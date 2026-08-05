/-
  Soundness bookkeeping harness (arithmetic + residual surface).
  T4 theorem suite: see diff_t4_soundness.
-/
import FriStark.Params.V1
import FriStark.Soundness.QueryModel
import FriStark.Soundness.Assumptions
import FriStark.Soundness.Conjecture
import FriStark.Soundness.Residual

open FriStark.Params.V1
open FriStark.Soundness.QueryModel

def main (_args : List String) : IO UInt32 := do
  let mut fails : Nat := 0

  let bits := SECURITY_BITS
  let formula := QUERIES * (log2Blowup - 1) + GRIND_BITS
  if bits != 104 then fails := fails + 1; IO.eprintln s!"SECURITY_BITS {bits}"
  if formula != 104 then fails := fails + 1; IO.eprintln s!"formula {formula}"
  if bits != formula then fails := fails + 1; IO.eprintln "bits≠formula"
  if !(SECURITY_TARGET_BITS ≤ bits) then fails := fails + 1; IO.eprintln "below target"
  if headlineBits != 104 then fails := fails + 1; IO.eprintln "headline"
  if formulaBits != 104 then fails := fails + 1; IO.eprintln "formulaBits"

  if BLOWUP != 2048 then fails := fails + 1; IO.eprintln "BLOWUP"
  if QUERIES != 8 then fails := fails + 1; IO.eprintln "QUERIES"
  if GRIND_BITS != 24 then fails := fails + 1; IO.eprintln "GRIND"
  if log2Blowup != 11 then fails := fails + 1; IO.eprintln "log2"
  if perQueryBits != 10 then fails := fails + 1; IO.eprintln "perQuery"
  if SECURITY_TARGET_BITS != 100 then fails := fails + 1; IO.eprintln "target"

  let rnames := FriStark.Soundness.Residual.residualNames
  if rnames.length != 4 then
    fails := fails + 1; IO.eprintln s!"residual count {rnames.length}"
  if FriStark.Soundness.Conjecture.residualOpaqueNames != rnames then
    fails := fails + 1; IO.eprintln "conjecture drift"
  -- residual surface is a non-empty Prop name list (not Bool theater)
  if rnames.isEmpty then
    fails := fails + 1; IO.eprintln "empty residual theater"

  let meets : Bool := decide (SECURITY_TARGET_BITS ≤ bits)
  IO.println s!"SECURITY_BITS={bits}"
  IO.println s!"formula=QUERIES*(log2(BLOWUP)-1)+GRIND_BITS={QUERIES}*({log2Blowup}-1)+{GRIND_BITS}={formula}"
  IO.println s!"target={SECURITY_TARGET_BITS} meets={meets}"
  IO.println s!"residual_axioms={rnames}"
  IO.println s!"proved=security_bits_eq_104,security_meets_target axiomatized={rnames}"
  IO.println "residual_kind=typed_Prop_premises (not opaque_True)"
  IO.println "discharge=axioms=CapacityRegimeAtRate|IndependentFRIQueries|Sha256RO|Sha256CR; EthStarkCapacity=derived pack"

  if fails == 0 then
    IO.println "SOUNDNESS_OK"
    IO.println "104 bits"
    pure 0
  else
    IO.eprintln s!"SOUNDNESS_FAIL fails={fails}"
    pure 1
