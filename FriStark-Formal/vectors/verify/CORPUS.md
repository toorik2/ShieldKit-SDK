# Multi-proof corpus (Phase 1) — production pin only

**Params:** blowup=2048, nq=8, grind_b=24, **fold_step=8**, deep=True.

## STARK CT-AIR proofs (Python STK.verify ok)

| ID | Path | Depth | fold_step |
|----|------|-------|-----------|
| prod_d1 | `prod_proof_d1.json` | 1 | 8 |
| prod_d2 | `prod_proof_d2.json` | 2 | 8 |
| prod_d3 | `prod_proof_d3.json` | 3 | 8 |

Gate: `python3 harness/check_multi_proof_prod.py` → **DIFF_MULTI_STARK_OK**  
(also asserts MANIFEST `multi_proof.stark_ct` basenames match exactly these three files).

Pure/full Lean IR exporters still use **d2** as primary STARK accept corpus (`DIFF_PURE_VERIFY_OK` / `DIFF_FULL_MATH_OK`).

## Product AIR kinds (production-param Lean accept)

| Kind | Gate |
|------|------|
| deposit / transfer / withdrawal | `diff_multi_product` → **DIFF_MULTI_PRODUCT_OK** |

Mutations: 6/6 reject. Binding forges: all rejected.
