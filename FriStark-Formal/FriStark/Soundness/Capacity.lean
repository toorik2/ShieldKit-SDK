/-
  ethSTARK / BCIKS capacity-regime FRI — full formal accounting.

  **Proved (this module):**
  - Rate ρ = rateNum/rateDen pins for composition deg ~2T (ρ = 2/BLOWUP)
  - Capacity bit formula at power-of-two inverse rates: bits = log2(rateDen/rateNum)
  - V1: bits/query = 10, multi-query FRI = 80, + grind = 104
  - Config well-formedness for Params.V1

  **Residual (literature crypto — not proved from ℤ):**
  - `CapacityRegimeAtRate rateNum rateDen bits`:
      one FRI query at rate ρ has capacity-regime soundness ≈ 2^{-bits}
  - `IndependentFRIQueries n`:
      n queries add security bits (independent challenges; no adaptive free lunch)

  `EthStarkCapacity` is a **derived package** of (config match ∧ single-query residual
  ∧ independence residual ∧ proved bit formula), not a bare monoline axiom.
-/
import FriStark.Params.V1

namespace FriStark.Soundness.Capacity

open FriStark.Params.V1

/-! ### Pure rate / log2 accounting (proved) -/

/--
  floor(log2 n) for n ≥ 1 via repeated halving.
  For n = 2^k returns k; for n = 0 returns 0.
-/
def natLog2 : Nat → Nat
  | 0 => 0
  | 1 => 0
  | n + 2 =>
    let m := n + 2
    1 + natLog2 (m / 2)

theorem natLog2_1 : natLog2 1 = 0 := by native_decide
theorem natLog2_2 : natLog2 2 = 1 := by native_decide
theorem natLog2_4 : natLog2 4 = 2 := by native_decide
theorem natLog2_1024 : natLog2 1024 = 10 := by native_decide
theorem natLog2_2048 : natLog2 2048 = 11 := by native_decide

/-- True when n is a power of two (n = 2^k for some k ≥ 0; 1 = 2^0). -/
def isPow2 : Nat → Bool
  | 0 => false
  | 1 => true
  | n + 2 =>
    let m := n + 2
    m % 2 == 0 && isPow2 (m / 2)

theorem isPow2_1 : isPow2 1 = true := by native_decide
theorem isPow2_1024 : isPow2 1024 = true := by native_decide
theorem isPow2_2048 : isPow2 2048 = true := by native_decide
theorem isPow2_3 : isPow2 3 = false := by native_decide

/--
  Capacity-regime bits per query at rate ρ = rateNum/rateDen
  when rateDen = rateNum * 2^k (exact):
    bits = log2(rateDen/rateNum) = k
  (= -log2(ρ) for dyadic rates).

  Matches product pin: rate 2/2048 → inv 1024 → 10 bits
  (= log2(BLOWUP) - 1 when rateNum = 2 and blowup = rateDen).
-/
def capacityBitsAtRate (rateNum rateDen : Nat) : Option Nat :=
  if rateNum == 0 then none
  else if rateDen % rateNum != 0 then none
  else
    let inv := rateDen / rateNum
    if isPow2 inv then some (natLog2 inv) else none

theorem capacityBits_v1_rate :
    capacityBitsAtRate 2 2048 = some 10 := by native_decide

theorem capacityBits_rate_one_blowup :
    capacityBitsAtRate 1 2048 = some 11 := by native_decide

/-- Multi-query FRI bit product (additive security under independence). -/
def multiQueryFriBits (queries bitsPerQuery : Nat) : Nat :=
  queries * bitsPerQuery

theorem multiQuery_v1 : multiQueryFriBits 8 10 = 80 := by native_decide

/-- Full headline under capacity + grind. -/
def securityBitsCapacity (queries bitsPerQuery grindBits : Nat) : Nat :=
  multiQueryFriBits queries bitsPerQuery + grindBits

theorem securityBits_v1_formula : securityBitsCapacity 8 10 24 = 104 := by native_decide

/-! ### V1 config as a structured capacity instance -/

/-- FRI capacity configuration (ethSTARK-style parameters). -/
structure CapacityConfig where
  blowup : Nat
  queries : Nat
  rateNum : Nat
  rateDen : Nat
  grindBits : Nat
  deriving Repr, DecidableEq

/-- Production V1 capacity config (composition deg ~2T ⇒ ρ = 2/BLOWUP). -/
def configV1 : CapacityConfig where
  blowup := BLOWUP
  queries := QUERIES
  rateNum := 2
  rateDen := BLOWUP
  grindBits := GRIND_BITS

/--
  Config is algebraically well-formed for capacity accounting:
  - rateDen = blowup (LDE domain vs trace)
  - rateNum | rateDen and inv is power of two
  - bits formula matches capacityBitsAtRate
  - queries, grind positive pins
-/
def CapacityConfig.wellFormed (c : CapacityConfig) : Prop :=
  c.rateNum ≥ 1 ∧
  c.rateDen = c.blowup ∧
  c.queries ≥ 1 ∧
  (∃ bits,
    capacityBitsAtRate c.rateNum c.rateDen = some bits ∧
    securityBitsCapacity c.queries bits c.grindBits =
      c.queries * bits + c.grindBits)

theorem configV1_wellFormed : configV1.wellFormed := by
  refine ⟨by native_decide, rfl, by native_decide, ?_⟩
  refine ⟨10, ?_, ?_⟩
  · native_decide  -- capacityBitsAtRate 2 2048 = some 10
  · native_decide  -- 8*10+24 arithmetic

/-- V1 bits/query from rate formula (= Params.V1.perQueryBits). -/
def bitsPerQueryV1 : Nat := 10

theorem bitsPerQueryV1_eq_capacity :
    capacityBitsAtRate configV1.rateNum configV1.rateDen = some bitsPerQueryV1 := by
  native_decide

theorem bitsPerQueryV1_eq_params : bitsPerQueryV1 = perQueryBits := by native_decide

theorem bitsPerQueryV1_eq_log2Blowup_minus_1 :
    bitsPerQueryV1 = log2Blowup - 1 := by native_decide

/-- V1: rate inverse is 1024 = 2^10. -/
theorem v1_rate_inv : configV1.rateDen / configV1.rateNum = 1024 := by native_decide

theorem v1_rho_num_den : configV1.rateNum = 2 ∧ configV1.rateDen = 2048 := by
  native_decide

theorem v1_fri_bits : multiQueryFriBits configV1.queries bitsPerQueryV1 = 80 := by
  native_decide

theorem v1_security_bits :
    securityBitsCapacity configV1.queries bitsPerQueryV1 configV1.grindBits = 104 := by
  native_decide

theorem v1_security_eq_params : SECURITY_BITS = 104 := security_bits_eq_104

/-- log2(BLOWUP) pin matches natLog2. -/
theorem log2Blowup_eq_natLog2 : log2Blowup = natLog2 BLOWUP := by native_decide

/--
  Identity: for rateNum=2 and rateDen=blowup=2^L,
  capacity bits = L - 1 = log2(blowup) - 1.
-/
theorem capacity_bits_eq_log2Blowup_minus_1
    (L : Nat) (hBlow : BLOWUP = 2 ^ L) (hL : L = log2Blowup) :
    capacityBitsAtRate 2 BLOWUP = some (L - 1) := by
  -- concrete V1 discharge
  subst hL
  have : BLOWUP = 2048 := blowup_pin
  simp [this]
  native_decide

theorem capacity_bits_v1_log_form :
    capacityBitsAtRate 2 BLOWUP = some (log2Blowup - 1) := by
  native_decide

/-! ### Literature residuals (minimal crypto surface) -/

/-!
  **R-cap-1 — Single-query capacity regime**

  At Reed-Solomon / FRI rate ρ = rateNum/rateDen, under the ethSTARK/BCIKS
  *capacity regime* (not unique decoding), one random FRI query contributes
  `bits` bits of soundness, where `bits` is the capacity formula
  `log2(rateDen/rateNum)` for dyadic rates.

  This is the research residual — not proved from field axioms in this sandbox.
-/
axiom CapacityRegimeAtRate (rateNum rateDen bits : Nat) : Prop

/-!
  **R-cap-2 — Independent multi-query composition**

  `n` FRI queries with independent challenges yield additive security:
  total FRI bits = n * bitsPerQuery (errors multiply in the usual model).

  Also literature/model residual (adaptive query / correlated challenge gaps
  are out of scope here).
-/
axiom IndependentFRIQueries (n bitsPerQuery : Nat) : Prop

/--
  ethSTARK capacity package for concrete parameters:
  well-formed rate + proved bit formula + both capacity residuals.
-/
def EthStarkCapacityPack (blowup queries rateNum rateDen : Nat) : Prop :=
  rateDen = blowup ∧
  rateNum ≥ 1 ∧
  (∃ bits,
    capacityBitsAtRate rateNum rateDen = some bits ∧
    CapacityRegimeAtRate rateNum rateDen bits ∧
    IndependentFRIQueries queries bits)

/-- V1 pack: production pin. -/
def EthStarkCapacityV1 : Prop :=
  EthStarkCapacityPack BLOWUP QUERIES 2 BLOWUP

/--
  Under V1 pack residuals, FRI query contribution is the proved multi-query count.
-/
def friBitsUnderPack (_h : EthStarkCapacityV1) : Nat :=
  multiQueryFriBits QUERIES bitsPerQueryV1

theorem friBitsUnderPack_eq_80 (_h : EthStarkCapacityV1) :
    friBitsUnderPack _h = 80 := by
  simp only [friBitsUnderPack]
  native_decide

def securityBitsUnderPack (_h : EthStarkCapacityV1) : Nat :=
  securityBitsCapacity QUERIES bitsPerQueryV1 GRIND_BITS

theorem securityBitsUnderPack_eq_104 (_h : EthStarkCapacityV1) :
    securityBitsUnderPack _h = 104 := by
  simp only [securityBitsUnderPack]
  native_decide

/-- Build V1 pack from the two literature residuals (config arithmetic proved). -/
theorem ethStarkV1_of_residuals
    (hCap : CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1)
    (hInd : IndependentFRIQueries QUERIES bitsPerQueryV1) :
    EthStarkCapacityV1 := by
  refine ⟨rfl, by native_decide, ?_⟩
  refine ⟨bitsPerQueryV1, ?_, hCap, hInd⟩
  exact bitsPerQueryV1_eq_capacity

/-- Extract single-query residual from pack. -/
theorem pack_implies_single (h : EthStarkCapacityV1) :
    CapacityRegimeAtRate 2 BLOWUP bitsPerQueryV1 := by
  obtain ⟨_, _, bits, hBits, hCap, _⟩ := h
  have : bits = bitsPerQueryV1 := by
    have h10 : capacityBitsAtRate 2 BLOWUP = some 10 := capacityBits_v1_rate
    simp only [bitsPerQueryV1] at *
    -- hBits : capacityBitsAtRate 2 BLOWUP = some bits
    -- h10 : ... = some 10
    have : some bits = some 10 := by
      rw [← hBits, h10]
    exact Option.some.inj this
  simpa [this] using hCap

theorem pack_implies_indep (h : EthStarkCapacityV1) :
    IndependentFRIQueries QUERIES bitsPerQueryV1 := by
  obtain ⟨_, _, bits, hBits, _, hInd⟩ := h
  have : bits = bitsPerQueryV1 := by
    have h10 : capacityBitsAtRate 2 BLOWUP = some 10 := capacityBits_v1_rate
    simp only [bitsPerQueryV1] at *
    have : some bits = some 10 := by rw [← hBits, h10]
    exact Option.some.inj this
  simpa [this] using hInd

/-- Residual names for the capacity *literature* surface (two axioms). -/
def capacityResidualNames : List String :=
  [ "CapacityRegimeAtRate"
  , "IndependentFRIQueries"
  ]

theorem capacity_residual_count : capacityResidualNames.length = 2 := by native_decide

/-- EthStarkCapacity is a pack (exists bits + residuals), not a monoline axiom. -/
theorem ethStark_pack_shape
    (h : EthStarkCapacityV1) :
    ∃ bits,
      capacityBitsAtRate 2 BLOWUP = some bits ∧
      CapacityRegimeAtRate 2 BLOWUP bits ∧
      IndependentFRIQueries QUERIES bits := by
  obtain ⟨_, _, bits, hBits, hCap, hInd⟩ := h
  exact ⟨bits, hBits, hCap, hInd⟩

end FriStark.Soundness.Capacity
