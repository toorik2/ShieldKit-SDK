# Read the core (name-on-the-line — one Accept)

```text
Params/V1
  → Field → Hash → Transcript → FRI → Deep → Domain → AIR/ProductV1
  → Full/Verify                 sole kernel apex (pure verify / verifySteps)
  → Packing/Unpack              acceptKernel = unpack|lean
                                CovenantAccept = topo ∧ binding ∧ product ∧
                                  productAir∈kernel ∧ verify(kernel)
  → Soundness/Phi               PublicStatementΦ = product-AIR statement
  → Soundness/Games             ResidualGames + non-vacuous break evidence
  → Soundness/StepAlgebra       all production Step ctors: runStep=.ok ⇒ NamedP
  → Soundness/Warrant           utxo_stark_warrant crown
```

**Not apex:** SemanticAccept (lemma), Abstract.Verify (Agree only), dual-VM, Python STK.

**Spine:** mandatory product + binding; no optional `True` on crown.
**Φ:** product-AIR statement (honest); checklist Bool is the executable form.
