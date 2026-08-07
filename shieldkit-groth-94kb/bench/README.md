# PF10 benchmark

This benchmark measures the PF10 beta. It does not measure anonymity and it
does not establish mainnet, production, or audit readiness.

| Mode | Measures | Side effect |
| --- | --- | --- |
| Pipeline | tip lookup through proof, mempool admission, and local commit | broadcasts one real Chipnet action |
| Cold start | clone, install, pin fetch, native setup, and one cold proof | uses an existing session; does not create a pool |

Both modes require an existing funded PF10 data home with `session.json`:

```bash
npm run bench -- --data-home /absolute/path/to/install-or-v2-beta-product
npm run bench:cold-start -- --data-home /absolute/path/to/install-or-v2-beta-product
```

Use `--json-out FILE` to choose the report path. Pipeline also accepts
`--kind deposit|transfer|withdraw`, `--to ADDRESS`, and `--note 64hex`.
Cold start accepts `--sandbox DIR` and `--keep`. The command rejects ambient
`NODE_OPTIONS` and `NODE_PATH`.

Every report identifies the product version, PF10 design, network, and commit.
Compare reports only when the mode, profile, host, artifacts, and measurement
method match. Result files under `bench/results/` are intentionally ignored.

See the root [Start guide](../../docs/product/start.md) for PF10 setup. Run the
focused tests with:

```bash
node --test shieldkit-groth-94kb/bench/*.test.mjs \
  shieldkit-groth-94kb/bench/pf10-baseline/run-bench.test.mjs
```
