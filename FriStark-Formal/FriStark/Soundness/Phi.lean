/-
  Wave C (100%) — PublicStatementΦ = every named PHI_SPEC clause.
  Not `abbrev PublicStatementΦ := StatementHolds`.
-/
import FriStark.AIR.ProductV1
import FriStark.Soundness.Statement
import FriStark.Binding.Presence
import FriStark.Packing.Topology

namespace FriStark.Soundness.Phi

open FriStark.AIR.ProductV1
open FriStark.Soundness.Statement
open FriStark.Binding.Presence
open FriStark.Packing.Topology

private theorem band_left {a b : Bool} (h : (a && b) = true) : a = true := by
  cases a <;> cases b <;> simp_all
private theorem band_right {a b : Bool} (h : (a && b) = true) : b = true := by
  cases a <;> cases b <;> simp_all

inductive PhiClause where
  | S3_kind
  | network
  | profileLen
  | instanceLen
  | S5_packetCommitLen
  | S7_nullifierLen
  | S8_leafLen
  | S9_withdrawalLen
  | txContextLen
  | S6_preProfile
  | S6_postProfile
  | A4_kindActive
  | A5_transition
  | packetLen
  | A2_packetBind
  | A1_packetCommit
  | recordRegion
  deriving DecidableEq, Repr

/--
  S3: raw packet kind byte decodes as a Kind and matches statement kind.
  Not constant `true` — fails on illegal kind codes (ofU8? none) and mismatches.
-/
def kindCodeOk (st : ProductStatement) (w : ProductWitness) : Bool :=
  match Kind.ofU8? (w.packetBytes.getD 5 0) with
  | some k => k == st.kind
  | none => false

/-- packetBindsStatement conjunct #4 is the kind byte at offset 5 (left-assoc &&). -/
private theorem packet_bind_kind_byte (st : ProductStatement) (p : List UInt8)
    (h : packetBindsStatement st p = true) :
    (p.getD 5 0 == st.kind.toU8) = true := by
  simp only [packetBindsStatement] at h
  -- 13 left-assoc conjuncts; peel rightmost 9 via band_left, then band_right → kind
  have r12 := band_left h
  have r11 := band_left r12
  have r10 := band_left r11
  have r9 := band_left r10
  have r8 := band_left r9
  have r7 := band_left r8
  have r6 := band_left r7
  have r5 := band_left r6
  have r4 := band_left r5
  exact band_right r4

private theorem kind_ofU8_toU8 (k : Kind) : Kind.ofU8? k.toU8 = some k := by
  cases k <;> native_decide

private theorem kindCodeOk_of_packet_bind (st : ProductStatement) (w : ProductWitness)
    (h : packetBindsStatement st w.packetBytes = true) :
    kindCodeOk st w = true := by
  have hK := packet_bind_kind_byte st w.packetBytes h
  have hu : w.packetBytes.getD 5 0 = st.kind.toU8 := LawfulBEq.eq_of_beq hK
  unfold kindCodeOk
  rw [hu, kind_ofU8_toU8]
  simp [BEq.rfl]

def clauseBool : PhiClause → ProductClaim → Bool
  | .S3_kind, c => kindCodeOk c.st c.w
  | .network, c => networkOk c.st.networkId
  | .profileLen, c => c.st.profileId.length == 32
  | .instanceLen, c => c.st.instanceId.length == 32
  | .S5_packetCommitLen, c => c.st.packetCommit.length == 4
  | .S7_nullifierLen, c => c.st.publicNullifier.length == 4
  | .S8_leafLen, c => c.st.outputNoteLeaf.length == 4
  | .S9_withdrawalLen, c => c.st.withdrawalHash.length == 32
  | .txContextLen, c => c.st.transactionContextHash.length == 32
  | .S6_preProfile, c => c.st.preState.profileId == c.st.profileId
  | .S6_postProfile, c => c.st.postState.profileId == c.st.profileId
  | .A4_kindActive, c => kindActiveOk c.st
  | .A5_transition, c => stateTransitionOk c.st.kind c.st.preState c.st.postState
  | .packetLen, c => c.w.packetBytes.length == 552
  | .A2_packetBind, c => packetBindsStatement c.st c.w.packetBytes
  | .A1_packetCommit, c => packetCommitOk c.st.packetCommit c.w.packetBytes
  | .recordRegion, c =>
      match c.st.kind with
      | .withdrawal => isZeroBytes128 (c.w.packetBytes.drop 360 |>.take 128)
      | _ => (c.w.packetBytes.drop 360 |>.take 128).length == 128

def clauseHolds (cl : PhiClause) (c : ProductClaim) : Prop := clauseBool cl c = true

abbrev Phi_S3_kind (c : ProductClaim) : Prop := clauseHolds .S3_kind c
abbrev Phi_network (c : ProductClaim) : Prop := clauseHolds .network c
abbrev Phi_A4_kindActive (c : ProductClaim) : Prop := clauseHolds .A4_kindActive c
abbrev Phi_A5_transition (c : ProductClaim) : Prop := clauseHolds .A5_transition c
abbrev Phi_A1_packetCommit (c : ProductClaim) : Prop := clauseHolds .A1_packetCommit c
abbrev Phi_A2_packetBind (c : ProductClaim) : Prop := clauseHolds .A2_packetBind c

/-! ### Product-claim meaning (S2) — independent Props; checklist is executable lemma -/

/-- Kind-active authorization (inactive field zeros by kind). -/
def AuthorizationHolds (c : ProductClaim) : Prop := kindActiveOk c.st = true
/-- Pre→post SKS3 transition by kind (counts, roots, reserve, sequence). -/
def TransitionClaimHolds (c : ProductClaim) : Prop :=
  stateTransitionOk c.st.kind c.st.preState c.st.postState = true
/-- Packet binds statement fields (SDA3 layout). -/
def PacketBindClaimHolds (c : ProductClaim) : Prop :=
  packetBindsStatement c.st c.w.packetBytes = true
/-- Poseidon packet commitment matches witness. -/
def PacketCommitClaimHolds (c : ProductClaim) : Prop :=
  packetCommitOk c.st.packetCommit c.w.packetBytes = true
/-- Network is mainnet/chipnet. -/
def NetworkClaimHolds (c : ProductClaim) : Prop := networkOk c.st.networkId = true

/-- Core product meaning as conjunction of independent Props. -/
def ProductMeaningHolds (c : ProductClaim) : Prop :=
  AuthorizationHolds c ∧ TransitionClaimHolds c ∧ PacketBindClaimHolds c ∧
  PacketCommitClaimHolds c ∧ NetworkClaimHolds c

/--
  Human-facing product statement: every PHI **in** clause (product-AIR statement).
  Executable form: verifyProductAir. Core meaning is ProductMeaningHolds.
-/
def PublicStatementΦ (c : ProductClaim) : Prop := ∀ cl : PhiClause, clauseHolds cl c

theorem publicStatementΦ_means (c : ProductClaim) (h : PublicStatementΦ c) :
    ProductMeaningHolds c := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simpa [AuthorizationHolds, clauseHolds, clauseBool] using h .A4_kindActive
  · simpa [TransitionClaimHolds, clauseHolds, clauseBool] using h .A5_transition
  · simpa [PacketBindClaimHolds, clauseHolds, clauseBool] using h .A2_packetBind
  · simpa [PacketCommitClaimHolds, clauseHolds, clauseBool] using h .A1_packetCommit
  · simpa [NetworkClaimHolds, clauseHolds, clauseBool] using h .network

/-- Checklist Bool is executable form under Φ (not the definition of meaning Props). -/
theorem clause_A4_eq_authorization (c : ProductClaim) :
    clauseHolds .A4_kindActive c ↔ AuthorizationHolds c := by
  simp [clauseHolds, clauseBool, AuthorizationHolds]

theorem clause_A5_eq_transition (c : ProductClaim) :
    clauseHolds .A5_transition c ↔ TransitionClaimHolds c := by
  simp [clauseHolds, clauseBool, TransitionClaimHolds]

theorem clause_A2_eq_bind (c : ProductClaim) :
    clauseHolds .A2_packetBind c ↔ PacketBindClaimHolds c := by
  simp [clauseHolds, clauseBool, PacketBindClaimHolds]

theorem clause_A1_eq_commit (c : ProductClaim) :
    clauseHolds .A1_packetCommit c ↔ PacketCommitClaimHolds c := by
  simp [clauseHolds, clauseBool, PacketCommitClaimHolds]

def Phi2Binding (m : BindingModel) : Prop := wellFormed m = true
def Phi2Topology (t : TopologyV1) : Prop := wellFormedTopology t = true
abbrev Phi0 (c : ProductClaim) : Prop := StatementHolds c
abbrev Phi1 (c : ProductClaim) : Prop := PublicStatementΦ c

/-- Production crown packing: product Φ + topology + **required** binding (no none⇒True). -/
def CrownPhi (c : ProductClaim) (t : TopologyV1) (m : BindingModel) : Prop :=
  PublicStatementΦ c ∧ Phi2Topology t ∧ Phi2Binding m

/-- Peel verifyProductAir's && chain into 16 booleans (clause order). -/
theorem verifyProductAir_conjuncts (c : ProductClaim)
    (h0 : verifyProductAir c.st c.w = true) :
    networkOk c.st.networkId = true ∧
    (c.st.profileId.length == 32) = true ∧
    (c.st.instanceId.length == 32) = true ∧
    (c.st.packetCommit.length == 4) = true ∧
    (c.st.publicNullifier.length == 4) = true ∧
    (c.st.outputNoteLeaf.length == 4) = true ∧
    (c.st.withdrawalHash.length == 32) = true ∧
    (c.st.transactionContextHash.length == 32) = true ∧
    (c.st.preState.profileId == c.st.profileId) = true ∧
    (c.st.postState.profileId == c.st.profileId) = true ∧
    kindActiveOk c.st = true ∧
    stateTransitionOk c.st.kind c.st.preState c.st.postState = true ∧
    (c.w.packetBytes.length == 552) = true ∧
    packetBindsStatement c.st c.w.packetBytes = true ∧
    packetCommitOk c.st.packetCommit c.w.packetBytes = true ∧
    clauseBool .recordRegion c = true := by
  simp only [verifyProductAir, clauseBool] at h0
  -- associate left: (((((a1&&a2)&&a3)...)&&a15)&&rec)
  have h := h0
  let a1 := networkOk c.st.networkId
  let a2 := decide (c.st.profileId.length = 32)
  -- use == form
  clear a1 a2
  -- sequential:
  have r16 := band_right h
  have t15 := band_left h
  have r15 := band_right t15
  have t14 := band_left t15
  have r14 := band_right t14
  have t13 := band_left t14
  have r13 := band_right t13
  have t12 := band_left t13
  have r12 := band_right t12
  have t11 := band_left t12
  have r11 := band_right t11
  have t10 := band_left t11
  have r10 := band_right t10
  have t9 := band_left t10
  have r9 := band_right t9
  have t8 := band_left t9
  have r8 := band_right t8
  have t7 := band_left t8
  have r7 := band_right t7
  have t6 := band_left t7
  have r6 := band_right t6
  have t5 := band_left t6
  have r5 := band_right t5
  have t4 := band_left t5
  have r4 := band_right t4
  have t3 := band_left t4
  have r3 := band_right t3
  have t2 := band_left t3
  have r2 := band_right t2
  have r1 := band_left t2
  exact ⟨r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16⟩

theorem publicStatementΦ_of_verifyProductAir (c : ProductClaim)
    (h : verifyProductAir c.st c.w = true) : PublicStatementΦ c := by
  intro cl
  have hc := verifyProductAir_conjuncts c h
  cases cl with
  | S3_kind =>
      have hBind : packetBindsStatement c.st c.w.packetBytes = true :=
        hc.2.2.2.2.2.2.2.2.2.2.2.2.2.1
      exact kindCodeOk_of_packet_bind c.st c.w hBind
  | network => exact hc.1
  | profileLen => exact hc.2.1
  | instanceLen => exact hc.2.2.1
  | S5_packetCommitLen => exact hc.2.2.2.1
  | S7_nullifierLen => exact hc.2.2.2.2.1
  | S8_leafLen => exact hc.2.2.2.2.2.1
  | S9_withdrawalLen => exact hc.2.2.2.2.2.2.1
  | txContextLen => exact hc.2.2.2.2.2.2.2.1
  | S6_preProfile => exact hc.2.2.2.2.2.2.2.2.1
  | S6_postProfile => exact hc.2.2.2.2.2.2.2.2.2.1
  | A4_kindActive => exact hc.2.2.2.2.2.2.2.2.2.2.1
  | A5_transition => exact hc.2.2.2.2.2.2.2.2.2.2.2.1
  | packetLen => exact hc.2.2.2.2.2.2.2.2.2.2.2.2.1
  | A2_packetBind => exact hc.2.2.2.2.2.2.2.2.2.2.2.2.2.1
  | A1_packetCommit => exact hc.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1
  | recordRegion => exact hc.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

theorem publicStatementΦ_of_statementHolds (c : ProductClaim)
    (h : StatementHolds c) : PublicStatementΦ c :=
  publicStatementΦ_of_verifyProductAir c h

/-- verifyProductAir is the && of clauseBool for the 15 non-S3 clauses. -/
theorem verifyProductAir_eq_clause_chain (c : ProductClaim) :
    verifyProductAir c.st c.w =
      (clauseBool .network c &&
        clauseBool .profileLen c &&
        clauseBool .instanceLen c &&
        clauseBool .S5_packetCommitLen c &&
        clauseBool .S7_nullifierLen c &&
        clauseBool .S8_leafLen c &&
        clauseBool .S9_withdrawalLen c &&
        clauseBool .txContextLen c &&
        clauseBool .S6_preProfile c &&
        clauseBool .S6_postProfile c &&
        clauseBool .A4_kindActive c &&
        clauseBool .A5_transition c &&
        clauseBool .packetLen c &&
        clauseBool .A2_packetBind c &&
        clauseBool .A1_packetCommit c &&
        clauseBool .recordRegion c) := by
  cases c.st.kind <;> rfl

theorem verifyProductAir_of_publicStatementΦ (c : ProductClaim)
    (h : PublicStatementΦ c) : verifyProductAir c.st c.w = true := by
  rw [verifyProductAir_eq_clause_chain]
  have b (cl : PhiClause) : clauseBool cl c = true := h cl
  simp [b .network, b .profileLen, b .instanceLen, b .S5_packetCommitLen,
    b .S7_nullifierLen, b .S8_leafLen, b .S9_withdrawalLen, b .txContextLen,
    b .S6_preProfile, b .S6_postProfile, b .A4_kindActive, b .A5_transition,
    b .packetLen, b .A2_packetBind, b .A1_packetCommit, b .recordRegion]

theorem publicStatementΦ_iff_verifyProductAir (c : ProductClaim) :
    PublicStatementΦ c ↔ verifyProductAir c.st c.w = true :=
  ⟨verifyProductAir_of_publicStatementΦ c, publicStatementΦ_of_verifyProductAir c⟩

theorem publicStatementΦ_iff_statementHolds (c : ProductClaim) :
    PublicStatementΦ c ↔ StatementHolds c := by
  simpa [StatementHolds] using publicStatementΦ_iff_verifyProductAir c

/-- Checklist Bool is a lemma under Φ, not the definition of Φ. -/
theorem checklist_lemma_of_phi (c : ProductClaim) (h : PublicStatementΦ c) :
    StatementHolds c :=
  (publicStatementΦ_iff_statementHolds c).mp h

theorem product_meaning_of_verifyProductAir (c : ProductClaim)
    (h : verifyProductAir c.st c.w = true) : ProductMeaningHolds c :=
  publicStatementΦ_means c (publicStatementΦ_of_verifyProductAir c h)

theorem product_meaning_of_phi (c : ProductClaim) (h : PublicStatementΦ c) :
    ProductMeaningHolds c :=
  publicStatementΦ_means c h

theorem crownPhi_of_parts (c : ProductClaim) (t : TopologyV1) (m : BindingModel)
    (hΦ : PublicStatementΦ c) (hT : Phi2Topology t) (hB : Phi2Binding m) :
    CrownPhi c t m := ⟨hΦ, hT, hB⟩

theorem honest_deposit_phi :
    PublicStatementΦ ⟨honestDeposit.1, honestDeposit.2⟩ :=
  publicStatementΦ_of_statementHolds _ honest_deposit_holds

theorem honest_transfer_phi :
    PublicStatementΦ ⟨honestTransfer.1, honestTransfer.2⟩ :=
  publicStatementΦ_of_statementHolds _ honest_transfer_holds

theorem honest_withdrawal_phi :
    PublicStatementΦ ⟨honestWithdrawal.1, honestWithdrawal.2⟩ :=
  publicStatementΦ_of_statementHolds _ honest_withdrawal_holds

theorem mut_wrong_kind_not_phi :
    verifyProductAir mutWrongKind.stmt mutWrongKind.wit = false := by native_decide
theorem mut_wrong_roots_not_phi :
    verifyProductAir mutWrongRoots.stmt mutWrongRoots.wit = false := by native_decide
theorem mut_nonzero_inactive_not_phi :
    verifyProductAir mutNonzeroInactive.stmt mutNonzeroInactive.wit = false := by native_decide
theorem mut_packet_commit_not_phi :
    verifyProductAir mutPacketCommitMismatch.stmt mutPacketCommitMismatch.wit = false := by
  native_decide
theorem mut_wrong_sequence_not_phi :
    verifyProductAir mutWrongSequence.stmt mutWrongSequence.wit = false := by native_decide
theorem mut_capacity_not_phi :
    verifyProductAir mutCapacityOverflow.stmt mutCapacityOverflow.wit = false := by native_decide
theorem mutations_all_rejected_phi : mutationsAllRejected = true := by native_decide

def phiInScopeClauseIds : List String :=
  [ "S3_kind", "network", "profileLen", "instanceLen", "S5_packetCommitLen"
  , "S7_nullifierLen", "S8_leafLen", "S9_withdrawalLen", "txContextLen"
  , "S6_preProfile", "S6_postProfile", "A4_kindActive", "A5_transition"
  , "packetLen", "A2_packetBind", "A1_packetCommit", "recordRegion"
  ]

theorem phi_in_scope_count : phiInScopeClauseIds.length = 17 := by native_decide

def phiOutOfScopeClauseIds : List String :=
  [ "A6_note_tree", "A7_nullifier_tree", "A8_ec_free_full", "S12_statementId", "T4_funding"
  , "full_BCH_script_VM"
  ]

theorem phi_out_of_scope_count : phiOutOfScopeClauseIds.length = 6 := by native_decide

theorem publicStatementΦ_projects (c : ProductClaim) (h : PublicStatementΦ c) :
    Phi_A4_kindActive c ∧ Phi_A5_transition c ∧ Phi_A1_packetCommit c ∧ Phi_A2_packetBind c :=
  ⟨h .A4_kindActive, h .A5_transition, h .A1_packetCommit, h .A2_packetBind⟩

end FriStark.Soundness.Phi
