# Warrant crown — full STARK + UTXO track

## Signed sentence (THEOREM = Lean)

> **Production `CovenantAccept`** (topology ∧ required binding ∧ mandatory product ∧
> `productAir` ∈ kernel steps ∧ `verify(acceptKernel)`, on a **full-IR** production bundle)
> implies the **human product statement `PublicStatementΦ`** (product-AIR meaning:
> Auth ∧ Transition ∧ Bind ∧ Commit ∧ network + remaining PHI **in** clauses).
>
> The FRI/DEEP/FS/Merkle accept path is justified by **NamedP bridges** from pure IR:
> `verify = .ok` on the full production IR bundle implies product `StatementHolds` and
> `FriFoldBind` / `DeepFri0Bind` (and FS/Merkle/coset/layer steps run `.ok` on path) —
> Lean `FullIREndToEnd.full_ir_verify_implies_product_and_bridges`. Full pure honest-prod
> is also gated. **V1 scoreboard 104 is formula accounting only** (capacity bits formula
> proved; R1/R2 proximity literature eternal with necessity) — not residual-premise security.
>
> **UTXO fragment (M4 freeze):** `scriptFragmentAccept` ⇔ `CovenantAccept` on the production
> redeem fixture class (`FriStark.Host.CovenantScript`). Modeled claims bound = 6.
> Eternal remainder bound = 4 (full opcode VM, sighash, fee paths, CashToken beyond
> category length) each with a one-sentence non-dischargeability reason in Lean —
> not silent “script not modeled” done-theater.

**We do not claim:** empty residual for SHA-256 CR/RO; STARK proximity discharged from ℤ;
full BCH script interpreter; prover correctness.

## Crown (Lean)

| Name | Statement |
|------|-----------|
| `utxo_stark_warrant` | Accept → ∃ product ∧ Φ (no residual 104 packaging) |
| `utxo_stark_warrant_phi` | Accept → PublicStatementΦ_of |
| `utxo_stark_warrant_product_on_kernel` | Accept → productAir ∈ kernel ∧ Φ |
| `utxo_stark_warrant_scoreboard_accounting` | `formulaBits = 104` (accounting) |
| `script_fragment_iff_covenant` | scriptFragmentAccept = CovenantAccept |
| `full_ir_verify_implies_product_and_bridges` | verify full-IR bundle ⇒ StatementHolds ∧ FriFoldBind ∧ DeepFri0Bind |
| `full_ir_verify_of_productAir` | productAir ok ⇒ verify full-IR = .ok |
| `verify_ok_mem_*_implies_*` | verify + step ∈ steps ⇒ NamedP (FRI/coset/merkle/deep/FS) |

## Residual (S0 kill-list complete)

See `evidence/RESIDUAL_KILL_TABLE.md` and `FriStark.Soundness.ResidualKill`.

| Class | Items |
|-------|--------|
| Eternal literature | CapacityRegimeAtRate, IndependentFRIQueries (proximity hyps) |
| Eternal crypto | Sha256 RO, Sha256 CR |
| Package-only | FriSecurityGame, FiatShamirROGame, CollisionResistanceGame |
| Eternal ops | Prover, private-trace, network/wallet |

**No active-build residual fog.** Scoreboard 104 = formulaBits accounting only.

## Accept spine (floor + full IR)

```text
CovenantAccept := topo ∧ binding ∧ product ∧ productAirOnKernel ∧ verify(acceptKernel)
mkFullIRProductBundle := params :: productAir :: friFold :: deepQAt
                         ++ prodIRBridgeSteps
  -- prodIRBridgeSteps from C-pure-verify.simple honest-prod:
  --   FS×4 + Merkle×8 + coset s=1×8 + coset s=FOLD×8 (layer) + DEEP z
isFullIRBundle requires multi-query (merkle≥QUERIES ∧ coset≥QUERIES)
  ∧ production-layer coset (s=FOLD, |coset|=2^s)
  ∧ friFold ∧ deepQAt ∧ deepZ ∧ fsAbsorb (+params+productAir)
verify full-IR = .ok ⇒ StatementHolds ∧ FriFoldBind ∧ DeepFri0Bind
  (FullIREndToEnd; FS/Merkle/coset/layer steps also .ok on path)
Accept track = Lean multi-query full-IR sample ∧ full pure multi-query FRI gate
  (diff_pure_verify on C-pure-verify.simple honest-prod: 889 lines, 16 layer cosets)
pure-path Lean-inline remainder: bound 4 with necessity (PureIRFragment freeze)
scriptFragmentAccept r := CovenantAccept r.toAccept
eternal remainder: bound 4 names with necessity reasons (M4 freeze)
```
