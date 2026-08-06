# ShieldKit scalability bench (simple)

Three stories. One JSON scorecard. Thin adapters. Compare deltas.

This is a **measurement** tool. It does **not** claim that pool capacity equals an anonymity set, and it does not rank multi-writer tip designs in v1.

## Stories

| ID | Name | What it measures | Network |
|----|------|------------------|---------|
| **S0** | Micro | One deposit-shaped **native prove** on the shipped PF10 path + designed max unlock | No |
| **S1** | Ladder | `N` sequential deposit-shaped proves (local load) | No |
| **S2** | Smoke | Optional Chipnet 5 deposit + 1 transfer + 5 withdraw via product CLI | Yes |

## Scorecard fields (`shieldkit-bench-scorecard-v1`)

`design`, `commit` (full 40-char sha), `story`, `N`, `ok`, `first_try`, `prove_ms_p50`, `prove_ms_p95`, `total_ms_p95`, `tx_bytes`, `max_unlock_bytes`, `unlock_margin` (= `10000 - max_unlock_bytes` when known), `notes`.

Success requires `ok: true` and `first_try: true` (no multi-retry).

## Prerequisites (S0 / S1)

A product **data-home** with:

- offline pin / product artifact install (`v2-beta-product-artifacts`)
- linked runtime cache for an instance
- native prover under `…/native`
- deposit qualification `input.json` / `public.json`

Default discovery paths are tried automatically. Override:

```bash
export SHIELDKIT_BENCH_DATA_HOME=/absolute/path/to/.../v2-beta-product
# only if instance cannot be read from wallet.sqlite:
export SHIELDKIT_BENCH_INSTANCE_ID=<64-hex>
```

Refuse ambient `NODE_OPTIONS` / `NODE_PATH` (native prover policy).

## Run baseline (pf10)

From monorepo root (`shieldkit-sdk/`):

```bash
# S0
node shieldkit-groth/bench/pf10-baseline/run-s0.mjs \
  --out shieldkit-groth/bench/results/s0.json

# S1 (N=10)
node shieldkit-groth/bench/pf10-baseline/run-s1.mjs --N 10 \
  --out shieldkit-groth/bench/results/s1-n10.json

# Compare two scorecards
node shieldkit-groth/bench/compare.mjs \
  shieldkit-groth/bench/results/s0.json \
  shieldkit-groth/bench/results/s0.json
```

## S2 (optional Chipnet)

```bash
export SHIELDKIT_BENCH_DATA_HOME=...
export SHIELDKIT_BENCH_PAYOUT=bchtest:q...   # external, not fee wallet
export SHIELDKIT_BENCH_NOTE_ID=<64-hex>     # owned note for transfer
node shieldkit-groth/bench/pf10-baseline/run-s2.mjs \
  --out shieldkit-groth/bench/results/s2.json
```

If env/funds/RPC are missing, S2 emits **one** `ok: false` scorecard with a single blocker in `notes` (no retry loop). S0/S1 stay the daily tools.

## Adding another design

Copy `pf10-baseline/`, change `design` id in the runners, point prove/assemble at that design’s shipped path. Keep the same scorecard fields so `compare.mjs` works.

## Unit tests

```bash
node --test shieldkit-groth/bench/scorecard.test.mjs
```

## Layout

```text
bench/
  README.md
  scorecard.mjs / scorecard.schema.json / scorecard.test.mjs
  compare.mjs
  pf10-baseline/run-s0.mjs run-s1.mjs run-s2.mjs product-prove.mjs
  results/          # gitignored
```
