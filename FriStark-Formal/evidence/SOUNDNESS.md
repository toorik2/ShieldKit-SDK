# Soundness bookkeeping — ethSTARK capacity fully built out

**Sandbox:** `/home/toorik/Projects/ZK-Proofs/FriStark-Formal`  
**Module:** `FriStark/Soundness/Capacity.lean` + `Residual.lean`  
**Harness:** `diff_t4_soundness` → `capacity_fully_structured=true`, `ethstark_capacity_fully_built=true`

---

## What “capacity fully built” means

### Proved in Lean (no crypto)

| Claim | Result |
|-------|--------|
| `capacityBitsAtRate 2 2048` | `some 10` |
| `natLog2 1024` / `2048` | 10 / 11 |
| Multi-query FRI bits `8 * 10` | 80 |
| `+ GRIND_BITS 24` | **104** |
| `configV1.wellFormed` | true |
| `bitsPerQueryV1 = perQueryBits = log2Blowup - 1` | true |
| Rate ρ = 2/BLOWUP (composition deg ~2T) | pinned |

Formula identity:

```text
bits/query = log2(rateDen/rateNum)     for dyadic rates
           = log2(2048/2) = log2(1024) = 10
FRI bits   = QUERIES * 10 = 80
Headline   = 80 + 24 = 104
```

### Derived packages (not axioms)

| Name | Definition |
|------|------------|
| `EthStarkCapacityPack` | rateDen=blowup ∧ ∃bits, formula ∧ CapacityRegimeAtRate ∧ IndependentFRIQueries |
| `EthStarkCapacityV1` | pack at BLOWUP/QUERIES/2/BLOWUP |
| `FriCapacityRegime` | `:= EthStarkCapacityV1` |
| `EthStarkCapacity …` | `:= EthStarkCapacityPack …` (no longer a bare axiom) |

### Literature residuals only (capacity)

| Axiom | Meaning |
|-------|---------|
| **`CapacityRegimeAtRate rateNum rateDen bits`** | One FRI query at rate ρ has ~`bits` capacity-regime security (ethSTARK/BCIKS model; **not** unique decoding; **not** proved from ℤ) |
| **`IndependentFRIQueries n bits`** | `n` independent queries add bits (`n * bits`) |

Construction:

```text
CapacityRegimeAtRate(2,2048,10) ∧ IndependentFRIQueries(8,10)
    ⇒  EthStarkCapacityV1   (proved theorem ethStarkV1_of_residuals)
    ⇒  fri bits = 80, security with grind = 104 (proved arithmetic)
```

### Full residual axiom list (4)

1. `CapacityRegimeAtRate`
2. `IndependentFRIQueries`
3. `Sha256RandomOracle`
4. `Sha256CollisionResistance`

### Wave D — residual **games** packaging (3 games)

| Game | Definition |
|------|------------|
| `FriSecurityGame` | `CapacityRegimeAtRate(2,BLOWUP,10) ∧ IndependentFRIQueries(QUERIES,10)` |
| `FiatShamirROGame` | `FiatShamirRandomOracle` (= Sha256 RO) |
| `CollisionResistanceGame` | `Sha256CollisionResistance` (+ `BreaksCollisionResistance` adv shape) |

Module: `FriStark/Soundness/Games.lean`. Underlying axioms remain 4; empty residual not claimed.
`ResidualGames.cryptoBits_eq_104` under `toPremises`.
`ResidualBroken R` typed break surface. `fri_bits_of_security_game` uses games in FRIReduction.

---

## StatementHolds + E2E + Warrant (full track)

**Φ:** `PublicStatementΦ` = production product-AIR statement.  
Core meaning Props: `AuthorizationHolds`, `TransitionClaimHolds`, `PacketBindClaimHolds`,
`PacketCommitClaimHolds`, `NetworkClaimHolds` (= `ProductMeaningHolds`) defined from
AIR checkers; clause checklist is executable lemma under Φ.

**Kernel + packing spine:**

```text
acceptKernel = unpack blob | lean
CovenantAccept := topo ∧ bindingOk(required) ∧ productOk(required) ∧
                  productAirOnKernel ∧ verify(acceptKernel).isOk
mkFullIRProductBundle := params + productAir + friFold + deepQAt + prodIRBridgeSteps
  -- multi-query (Merkle×8 + coset s=1×8) + production-layer coset s=FOLD×2
utxo_stark_warrant: Accept → ∃c product ∧ Φ c   -- NO residual 104 packaging
utxo_stark_warrant_scoreboard_accounting: formulaBits = 104  -- accounting only
scriptFragmentAccept ⇔ CovenantAccept  (Host.CovenantScript fragment)
```

**Residuals:** see RESIDUAL_KILL_TABLE.md / ResidualKill.lean.  
SHA-256 CR/RO eternal crypto; capacity/FRI multi-query eternal literature; scoreboard ≠ security theorem.

**SemanticAccept** remains a lemma surface, not the sole apex.

DiffWarrant: `WARRANT_OK` + spine + `WARRANT_FULL_IR_OK` + `WARRANT_SCRIPT_FRAGMENT_OK` +
`WARRANT_RESIDUAL_KILL_OK`.

## ∃-eval + poly depth (Phase 3)

- DEEP/FRI: `DeepEvalEquals` / `CosetEvalEquals` / `FriFoldEvalEquals`
- PolyLemmas: composeAtExt equality, foldOnce=friFold, Horner≡INTT public samples, coset length gates

---

## Claim discipline

- ✅ Capacity **accounting** fully formalized and machine-checked for V1
- ✅ ethSTARK monoline **unpacked** into rate formula (proved) + two literature hyps
- ✅ 104 crypto under pack + hash residuals
- ❌ “Capacity regime is a theorem of arithmetic” — still literature residual
- ❌ Empty residual / unconditional STARK soundness

---

## Harness

```bash
.lake/build/bin/diff_t4_soundness
.lake/build/bin/diff_soundness
.lake/build/bin/diff_warrant
bash tools/ci/verify.sh
```

**Residuals frozen:** R1/R2 eternal literature (capacity/independence); R3/R4 eternal crypto; scoreboard ≠ security theorem.
