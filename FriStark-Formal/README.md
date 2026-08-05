# FriStark-Formal

Isolated Lean formalization of the BCH Goldilocks DEEP-ALI FRI-STARK verifier path
(production params only). Roadmap: **Warrant** (machine-checked accept ⇒ public statement under residual games).

**Do not edit** LeanBCH / verifier.cash / shieldkit product trees from this sandbox.

## Claims language (honest)

| Claim class | Meaning |
|-------------|---------|
| **Parity** | Lean accept ⇔ reference oracle accept on production-param corpora |
| **Property** | Named forge classes / mutations reject under Lean models |
| **Refinement** | Role differential certs (or dual-VM) without acceptance divergence |
| **Soundness-under-residuals** | 104-bit **arithmetic** proved; crypto level conditional on residual axioms (CapacityRegimeAtRate, IndependentFRIQueries, Sha256RandomOracle, Sha256CollisionResistance) — **not** empty residual / not “proved STARK soundness from ℤ” |
| **Warrant (v1.0 surface)** | `verify` / `CovenantAccept` ⇒ `PublicStatementΦ` under residual **games**s — `evidence/THEOREM.md`, `release/warrant-v1.0/` |

**Anti-hype:** `evidence/NONCLAIMS.md` · **TCB:** `evidence/TCB.md` · **Roadmap:** `evidence/WARRANT_ROADMAP.md`

## Params (Params.V1, fail-closed)

`BLOWUP=2048` `QUERIES=8` `GRIND_BITS=24` `FOLD=8` → `SECURITY_BITS=104` (target ≥100).

## Quick start

```bash
lake build
bash tools/ci/verify.sh
python3 harness/check_params_drift.py
```

See `evidence/STATUS.md`, `evidence/SOUNDNESS.md`, and Warrant docs under `evidence/`.
