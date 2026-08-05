# Warrant roadmap (condensed)

Full plan: session plan.md (FriStark-Formal → Warrant).  
Floor: Phases 0–3 package content pin `f867782381e609a60288682718cce8534a3142ba`.

---

## Waves

| Wave | Name | Exit |
|------|------|------|
| **A** | Constitution | THEOREM/TCB/NONCLAIMS/PHI_SPEC + Warrant scaffold; pin hygiene |
| **B** | One Accept | `verify_ok_iff_stepsAllOk`; `verify=.ok → Φ0`; SemanticAccept demoted |
| **C** | Real Φ | PublicStatementΦ = Φ1+Φ2 map; PHI_SPEC in-scope formal |
| **D** | FRI/DEEP + games | poly textbook; residual games (≤3 target); no empty residual |
| **E** | UTXO refine | unpack + CovenantAccept → verify; dual-VM corollary |
| **F** | Forge ontology | FORGE_ONTOLOGY + vectors + gates |
| **G** | Inner beauty | kill dual Accept stories; READ_CORE |
| **H** | Release | `release/warrant-v1.0` + tag + REPRODUCE.sh |

## Tags

`warrant-v0.3` … `warrant-v1.0` as in THEOREM.md.

## Regression floor (every wave)

```bash
bash tools/ci/verify.sh
python3 harness/check_multi_proof_prod.py   # fold_step=8 d1/d2/d3
```

Isolation: formalization only under FriStark-Formal.

## Pin hygiene

| Field | Meaning |
|-------|---------|
| **package_pin** | Last commit changing Lean / vectors / harness / CI content |
| **git_HEAD** | Tip including STATUS bookkeeping; may differ from package_pin |
| Never | package_pin := hash of STATUS-only commit as “content done” |

## Current milestone

- **Floor:** Phases 0–3 green under residuals  
- **Done:** Waves A–H (constitution → release/warrant-v1.0)  
- **Gate:** `diff_warrant` → `WARRANT_OK` · `bash tools/ci/verify.sh`  

## North star

See THEOREM.md. Empty residual is **not** the north star; the crown sentence under game-form R is.
