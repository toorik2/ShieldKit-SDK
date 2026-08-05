# Read the core (full STARK + UTXO fragment track)

```text
Params/V1
  → Full/Verify                 pure kernel (full IR)
  → Packing/Unpack              CovenantAccept + mkFullIRProductBundle
  → Host/CovenantScript         scriptFragmentAccept ⇔ CovenantAccept
  → Soundness/Phi               ProductMeaningHolds + PublicStatementΦ
  → Soundness/ResidualKill      kill vs eternal residual table
  → Soundness/StepAlgebra       Step ⇒ NamedP bridges
  → Soundness/Warrant           utxo_stark_warrant (Φ; scoreboard separate accounting)
```

**Not apex:** SemanticAccept, Abstract.Verify, dual-VM (corollary only).
**Not security theorem:** formulaBits / 104 scoreboard under unused residual premises.
