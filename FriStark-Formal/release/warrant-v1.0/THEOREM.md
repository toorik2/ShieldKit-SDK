# Warrant crown — name-on-the-line (honest Φ)

## Signed sentence (THEOREM = Lean)

> **Under residual games R** (≤3: FRI / Fiat–Shamir RO / CollisionResistance — literature/hash **assumptions**, not proved from ℤ):  
> production **CovenantAccept** (topology ∧ **required binding** ∧ **mandatory product** ∧ `productAir` ∈ kernel steps ∧ `verify(acceptKernel)`)  
> implies **PublicStatementΦ** of that product claim, and the V1 scoreboard under R is the pinned accounting (**104**).

**We do not claim:** empty residual; STARK soundness from field arithmetic; full BCH script ≡ Accept; prover correctness.

## Crown (Lean)

| Name | Kind | Statement |
|------|------|-----------|
| **`utxo_stark_warrant`** | thm | Accept → `(∃ c, product? = some c ∧ PublicStatementΦ c) ∧ bits(R)=104` |
| **`utxo_stark_warrant_phi_and_bits`** | thm | Accept → `PublicStatementΦ_of ∧ bits(R)=104` |
| **`utxo_stark_warrant_product_on_kernel`** | thm | Accept → ∃ c b, product + `productAir ∈ b.steps` + Φ |
| **`utxo_stark_rejects_no_product`** | thm | `product? = none` → Accept = false |
| **`utxo_stark_rejects_no_binding`** | thm | `binding? = none` → Accept = false |
| **`utxo_stark_warrant_core`** | thm | Accept → `kernelVerify = .ok` |

## Accept spine

```text
CovenantAccept a :=
  wellFormedTopology ∧ bindingOk (required) ∧ productOk (required) ∧
  productAirOnKernel ∧ verify(acceptKernel).isOk

acceptKernel = unpack π | lean
PublicStatementΦ_of := topo ∧ ∃ binding ∧ ∃ product Φ
  -- no | none => True
```

## Φ honesty

**PublicStatementΦ** is the production **product-AIR statement** (Auth / Transition / Bind / Commit structure of that predicate).  
Executable form: `verifyProductAir`. Prop and Bool are intentionally related (`↔`); docs do **not** market “not checklist” while denying that.

S3: `Kind.ofU8?` on packet kind byte matches `st.kind`.

## Residual

R packages residual premises; scoreboard is **accounting under R**, not a game-soundness theorem.  
`ResidualBreakEvidence` is non-vacuous (fri ¬Game | fs ¬Game | collision adv).
