namespace FriStark.Host.Redeem
/-- Per-role differential certificate (abstract Lean + dual-vm host accept). -/
structure RoleDiffCert where
  role : String
  corpusSize : Nat
  mismatches : Nat
  dualVmN : Nat
  abstractMismatch : Nat
  dualVmDisagree : Nat
  deriving Repr

/-- Measured gate: dual-vm n≥1, abstract mismatches=0, dual-vm all agreeAccept. -/
def RoleDiffCert.ok (c : RoleDiffCert) : Bool :=
  c.dualVmN ≥ 1 && c.abstractMismatch == 0 && c.dualVmDisagree == 0 &&
  c.mismatches == 0 && c.corpusSize ≥ c.dualVmN

end FriStark.Host.Redeem
