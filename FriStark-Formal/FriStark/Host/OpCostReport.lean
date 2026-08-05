namespace FriStark.Host.OpCostReport
structure Delta where
  maxAbsDelta : Nat
  deriving Repr
/-- Op-cost micro-deltas are reported, not fail-gated (accept parity is the gate). -/
def reportOnly (_d : Delta) : Bool := true
end FriStark.Host.OpCostReport
