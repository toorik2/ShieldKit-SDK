/-
  Independent product/AIR proposition `StatementHolds`.

  Defined from ProductV1 checklist only — **not** `Full.Verify.verify = .ok`.
-/
import FriStark.AIR.ProductV1

namespace FriStark.Soundness.Statement

open FriStark.AIR.ProductV1

structure ProductClaim where
  st : ProductStatement
  w : ProductWitness
  deriving DecidableEq, Repr

/-- Independent product/AIR proposition (ProductV1 checklist as Prop). -/
def StatementHolds (c : ProductClaim) : Prop :=
  verifyProductAir c.st c.w = true

theorem statement_holds_iff_verifyProductAir (c : ProductClaim) :
    StatementHolds c ↔ verifyProductAir c.st c.w = true := Iff.rfl

theorem statement_holds_of_bool (st : ProductStatement) (w : ProductWitness)
    (h : verifyProductAir st w = true) : StatementHolds ⟨st, w⟩ := h

def KindActiveHolds (st : ProductStatement) : Prop := kindActiveOk st = true
def TransitionHolds (st : ProductStatement) : Prop :=
  stateTransitionOk st.kind st.preState st.postState = true
def PacketBindHolds (st : ProductStatement) (w : ProductWitness) : Prop :=
  packetBindsStatement st w.packetBytes = true
def PacketCommitHolds (st : ProductStatement) (w : ProductWitness) : Prop :=
  packetCommitOk st.packetCommit w.packetBytes = true

theorem honest_deposit_holds :
    StatementHolds ⟨honestDeposit.1, honestDeposit.2⟩ :=
  statement_holds_of_bool _ _ (by native_decide)

theorem honest_transfer_holds :
    StatementHolds ⟨honestTransfer.1, honestTransfer.2⟩ :=
  statement_holds_of_bool _ _ (by native_decide)

theorem honest_withdrawal_holds :
    StatementHolds ⟨honestWithdrawal.1, honestWithdrawal.2⟩ :=
  statement_holds_of_bool _ _ (by native_decide)

theorem mutations_all_rejected : mutationsAllRejected = true := by native_decide

theorem mut_packet_commit_not_holds :
    verifyProductAir mutPacketCommitMismatch.stmt mutPacketCommitMismatch.wit = false := by
  native_decide

theorem mut_wrong_kind_not_holds :
    verifyProductAir mutWrongKind.stmt mutWrongKind.wit = false := by
  native_decide

theorem honest_deposit_kindActive :
    KindActiveHolds honestDeposit.1 :=
  show kindActiveOk honestDeposit.1 = true by native_decide

theorem honest_deposit_transition :
    TransitionHolds honestDeposit.1 :=
  show stateTransitionOk honestDeposit.1.kind honestDeposit.1.preState honestDeposit.1.postState = true by
    native_decide

end FriStark.Soundness.Statement
