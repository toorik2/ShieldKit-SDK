# ShieldKit action benchmark

Primary end-to-end benchmark defined by repo-root **`BENCHMARK_PLAN.md`**.

Schema: **`shieldkit-action-benchmark-run/v2`**

## What this is

Measures how long a complete semantic pool action (deposit / transfer / withdrawal)
takes until the **exact** transaction is observed in the **BCHN mempool** after
`sendrawtransaction`.

- Acceptance = mempool membership (not `testmempoolaccept`)
- First try only
- Full 64-char txids
- Span DAG with critical path (parallel branches not summed)
- Failures retained as plan outcome classes

## What this is not

| Surface | Schema | Role |
| --- | --- | --- |
| **This package** | `shieldkit-action-benchmark-run/v2` | Primary e2e action benchmark |
| `shieldkit-groth-94kb/bench` S0/S1/S2 | `shieldkit-component-bench-scorecard-v1` | Component prove/scaling microbenchmarks |
| `cli/bench.mjs` | `shieldkit-isolated-proof-bench-v1` | Experimental isolated proof / axis compare |
| Pipeline timings helper | `shieldkit-bench-pipeline-v1` | Operator table for PF10 product timings |

Do not present component or isolated-proof scorecards as end-to-end performance.

## Commands

```bash
# Help
npm run bench:action -- --help

# One action (PF10 needs a funded product data-home)
npm run bench:action -- --design pf10 --action deposit --data-home /abs/path

# Phase 5 smoke — nine design×action cells (live or honest fail-closed)
npm run bench:action:smoke -- --out-dir /tmp/smoke-out

# Campaign report (no global winner)
npm run bench:action:report -- --runs-dir bench/results/smoke --out-dir bench/results/report

# Promote selected immutable records into evidence/
node bench/action/promote.mjs bench/results/smoke/pf10-deposit.json
```

FRI multi-GB proves require `SHIELDKIT_FRI_BENCH_LIVE=1` (or `--live`).

## Cache modes

Only claim these when mechanically established:

- `warm-resident` — process/session + immutable artifacts loaded; no action-dependent cache
- `cold-installed` — verifiably cache-cold host/image with artifacts installed
- `readiness` — clean install → first accepted action (separate journey)

A fresh subprocess alone is not cold-installed.

## Results

Raw outputs under `bench/results/` are **gitignored**. Promote deliberately with
`promote.mjs` into `evidence/action-benchmark/`.

## Tests

```bash
node --test bench/action/*.test.mjs
```
