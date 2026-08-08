# PF10 component & pipeline helpers

**Not the primary end-to-end action benchmark.**

Primary action traces (deposit/transfer/withdrawal → exact BCHN mempool) live in:

- Plan: repo-root `BENCHMARK_PLAN.md`
- Implementation: `bench/pipeline/` (`shieldkit-action-benchmark-run/v2`)
- Entry: `npm run bench:action` / `npm run bench:action:smoke`

## Surfaces in this directory

| Mode | Schema | Measures |
| --- | --- | --- |
| Component S0/S1/S2 scorecard | `shieldkit-component-bench-scorecard-v1` | Isolated prove / scaling microbenchmarks |
| Pipeline helper | `shieldkit-bench-pipeline-v1` | PF10 product timing table (tip → mempool → commit) |
| Cold start | (pipeline/coldstart report) | Machine cold-start journey (not warm action primary) |

Pipeline mode still broadcasts a real Chipnet action when used live; treat it as an
operator helper. Prefer `bench/pipeline/` for plan-normative campaigns and reports.

## Pipeline / cold-start (legacy public entry)

```bash
npm run bench -- --data-home /absolute/path/to/install-or-v2-beta-product
npm run bench:cold-start -- --data-home /absolute/path/to/install-or-v2-beta-product
```

Requires `session.json`. Result files under `bench/results/` are gitignored.

```bash
node --test designs/pf10/bench/*.test.mjs \
  designs/pf10/bench/pf10-baseline/run-bench.test.mjs
```
