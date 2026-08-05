# Non-claims — kill-list complete (full formalization track)

## Eternal literature (proximity STARK — frozen R1/R2 with necessity)

**Proved (no hyp):** capacity **accounting** — `capacityBitsAtRate 2/2048 = 10`,
multi-query product 80, +grind 104, `configV1.wellFormed`, `formulaBits = 104`
(`capacity_accounting_discharged` / `capacityAccountingOk` in ResidualKill).

**Eternal (necessity 1:1 in `residualLiteratureNecessity`):**

- **`CapacityRegimeAtRate`** — ethSTARK/BCIKS capacity-regime proximity; not ℤ/field arithmetic  
- **`IndependentFRIQueries`** — multi-query additive security under independent challenges  

Scoreboard 104 is **formulaBits accounting only** — not residual-premise security.

## Eternal crypto (standard external modeling — R3/R4 with necessity)

- **SHA-256 collision resistance** proved from ℤ alone — eternal; necessity in `residualCryptoNecessity`  
- **SHA-256 / Fiat–Shamir as random oracle** proved from ℤ — eternal; necessity in `residualCryptoNecessity`  

## Eternal ops / process

- Prover correctness  
- Private-trace re-derive  
- Network / wallet / key management  
- Full fee / P2PKH funding economics (T4)

## UTXO / script — fragment vs remainder

### Modeled fragment (proved)

- Topology wf + binding locking presence  
- Product-AIR statement Φ  
- productAir on kernel + verify(acceptKernel)  
- `scriptFragmentAccept ⇔ CovenantAccept` (definitional)  
- Optional CashToken category length checks  

### Eternal remainder (size-bounded, M4 freeze)

Bound = **4** (`scriptFragmentEternalBound`). Every name has a necessity reason
(`scriptFragmentEternalNecessity`, 1:1 with `scriptFragmentEternalRemainder`):

| Remainder | Why eternal (non-dischargeable in this TCB) |
|-----------|-----------------------------------------------|
| full_BCH_opcode_interpreter | Accept is CovenantAccept spine, not OP_* semantics |
| sighash_preimage | Consensus serialization outside STARK kernel TCB |
| fee_paths_P2PKH | Wallet/consensus policy, not product-AIR soundness |
| cashtoken_consensus_beyond_category_len | Only length-32 category/commitment modeled |

Modeled fragment bound = **6** (`scriptFragmentModeledBound`).
See `FriStark.Host.CovenantScript` (`m4ScriptFreezeStatus`).

## Pure production IR — Lean Accept fragment vs full path (S4 freeze)

**Modeled (Lean Accept constant):** multi-query Merkle×8, coset s=1×8, layer s=FOLD×8,
FS sample, DEEP z, NamedP e2e (`full_ir_verify_implies_product_and_bridges`). Bound **7**
claims (`pureIRModeledBound`).

**Full multi-query FRI path (required gate):** `diff_pure_verify` on
`vectors/verify/C-pure-verify.simple` honest-prod — 889 step lines, Merkle 40, coset 24,
layer s=8 ×16, DEEP 8, FS 8. DiffWarrant **fails** without this path
(`pureIRAcceptTrackComplete`).

**Eternal Lean-inline remainder (bound 4, necessity 1:1 in `pureIREternalNecessity`):**

| Remainder | Why eternal (not fog) |
|-----------|------------------------|
| full_pure_889_step_lean_inline | Compile/size: full path is pure gate, not 889-step Lean constant |
| full_pure_layer_coset_remainder_8_of_16 | Accept samples 8/16; rest same form on pure gate |
| full_pure_deepQAtLayout_H_rebuild | Layout DEEP on pure gate; Lean e2e uses deepQAt fixture |
| full_pure_fs_absorb_int_challenge_stream | Full FS stream on pure gate; Accept models sample + opens |

See `FriStark.Packing.PureIRFragment` (`pureIRFragmentFreezeStatus`).

## PHI **out** (statement)

- A6 note tree membership/append  
- A7 nullifier tree inserts  
- A8 full EC-free note crypto beyond Poseidon packet commit  
- S12 statementId SHA256 encoding  
- T4 funding P2PKH economics  

## Forbidden claims

- Empty residual / unconditional STARK soundness from field arithmetic  
- Scoreboard 104 as “security theorem of residual premises”  
- Dual-VM host agreement as the definition of Accept  
- “Script not modeled” as DONE without fragment classification above  
