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

## StatementHolds + E2E + Warrant (name-on-the-line)

**Φ honesty:** `PublicStatementΦ` **is** the production product-AIR statement  
(`∀ PhiClause, clauseHolds` / Auth·Transition·Bind·Commit structure).  
Executable form: `verifyProductAir`. `StatementHolds` ↔ that executable form.  
Docs do **not** claim “not checklist” while denying this relationship.

**Kernel + packing spine (mandatory product + binding + productAir mem):**

```text
acceptKernel = unpack blob | lean
CovenantAccept := topo ∧ bindingOk(required) ∧ productOk(required) ∧
                  productAirOnKernel ∧ verify(acceptKernel).isOk
PublicStatementΦ_of := topo ∧ ∃ binding ∧ ∃ product Φ   -- no none => True
utxo_stark_warrant: Accept → (∃c product ∧ Φ c) ∧ bits(R)=104
utxo_stark_warrant_product_on_kernel: Accept → productAir ∈ kernel.steps
utxo_stark_rejects_no_product / _no_binding
utxo_stark_warrant_core: Accept → kernelVerify = .ok
```

Scoreboard under R is **accounting**, not a STARK soundness theorem.  
ResidualBroken / ResidualBreakEvidence non-vacuous (fri|fs|collision).

**SemanticAccept** remains a lemma surface, not the sole apex.

Mutations: ≥6 fail `verifyProductAir`. DiffWarrant: `WARRANT_OK` + spine tags  
`product_present`, `productAir_mem`, `unpack_kernel`, `phi_forced`.

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
