# LeanBCH integration for Goldilocks FRI

## P0 — Dual-VM xcheck (wired)

**Tools**

| Script | Role |
|--------|------|
| `measure/export-xcheck-fixtures.mjs` | Write `{prefix}_tx.hex` + `{prefix}_srcouts.hex` + meta |
| `measure/leanbch-xcheck.mjs` | libauth vs LeanBCH `xcheck_idxN` for **every** input |
| `measure/measure.sh` (sound-secure) | Runs both after harness bench |

**Fixture format** (matches LeanBCH / vmb style)

- `*_tx.hex` — full wire `encodeTransaction`
- `*_srcouts.hex` — `encodeTransactionOutputs(sourceOutputs)` (count-prefixed)
- Lean: `$LEANBCH_ROOT/.lake/build/bin/xcheck_idxN <prefix> <idx>`

**Gates**

| Gate | Meaning |
|------|---------|
| `libauthAllAccept` | Real BCH-2026 VM accepts all inputs |
| `densityAllOk` | op-cost ≤ (41+unlock)×800 each input |
| `leanbchAllAgreeAccept` | Lean `leanVerifyInput` matches libauth accept |
| `dualVmAcceptGreen` | **Hard dual-VM ship signal** (accept parity) |
| `leanbchAllAgreeOpCost` / `dualVmGreen` | Exact op-cost match (currently **false**: small systematic deltas ≤ ~1.2k observed) |

Op-cost micro-deltas are **reported** (`opCost.maxAbsDelta`) but do **not** fail measure when accepts agree. Investigate later (P2SH full-path billing).

**Env**

```bash
export LEANBCH_ROOT=/path/to/LeanBCH   # default: <repo>/../LeanBCH
# ensure: (cd $LEANBCH_ROOT && lake build xcheck_idxN)
./lanes/goldilocks-98k/measure/measure.sh sound-secure --nq 7 --grind-b 30 --depth 4
# or standalone:
node measure/export-xcheck-fixtures.mjs --vectors vectors/sound-secure-vectors.json --out-dir vectors/xcheck --prefix sound-secure
node measure/leanbch-xcheck.mjs --vectors vectors/sound-secure-vectors.json --out-dir vectors/xcheck --prefix sound-secure
```

Same scripts live under `lanes/goldilocks-target-80k/measure/`.

## P1 — Density report (wired)

`measure/density-report.mjs` classifies each role (blob / deepquery / aggFRI / comp_trans / comp_final):

- Prefer harness bench `operationCost` when `--bench` given (authoritative scored path)
- Else LeanBCH `optimizer/cost.mjs` `measureRun` if importable
- Else libauth metrics

Outputs `vectors/sound-secure-density-report.json` with `byRole` totals and `kind`:
`over-density` | `op-pad-tight` | `near-op-pad-bound` | `code-or-witness-bound`.

Use during **&lt;80k** golf: cut code/witness only when not `op-pad-tight`; never drop FRI security knobs.

## P2 — Dialect experiment (scaffold)

**Goal:** feed hand-emitted FRI redeem bytecode into LeanBCH `optimizer/` IR so proven fold/CSE can run.

**Barriers**

- Goldilocks redeems are **Python → CashAssembly**, not cashc `[body][id] DEFINE` framing.
- Covenant dialect refuses in-place edit of hash-committed bodies (correct for P2SH32).

**Experiment path (not done)**

1. Parse redeem hex → flat op list (libauth / cashAssembly).
2. New dialect `dialect/cash-assembly-redeem.mjs`: parse DEFINE table + main, emit same shape.
3. Run `optimize.mjs --gate` on **offline** redeem only; re-package P2SH32; re-xcheck.
4. Success criterion: dualVmAcceptGreen + score strictly decreases + forges still reject.

Track work under `target-80k` only; do not claim ship wins without re-measure.

## P3 — Merkle / SHA256 KAT (scaffold)

**Goal:** Lean-side KAT that `sha256` / trunc-25 path opens match Python/stark prover for a fixed vector.

**Not implemented in LeanBCH core** (no Goldilocks module). Proposed:

1. Export one secure-tip merkle open: leaf preimage, sibling list (25 B), root (25 B).
2. Lean `#eval` using `LeanBCH.Crypto.sha256` + truncate; guard equality.
3. Lives in verifier.cash `lanes/goldilocks-98k/lean/` or a thin LeanBCH overlay — optional.

## Skip

Fp12 floors, `bn254_adapter`, miller `chunkplan` — wrong algebra/packaging for FRI.
