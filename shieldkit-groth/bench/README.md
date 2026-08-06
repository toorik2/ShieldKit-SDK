# ShieldKit bench

Two modes. One command.

This is a **measurement** tool. It does **not** claim that pool capacity equals an anonymity set.

Every report includes a **subject** block (table header + JSON `subject`) so results are self-describing:

```text
ShieldKit-Groth 0.3.0-beta.1  (shieldkit-v2-beta-chipnet)
design=pf10-baseline  verifier=DIRECT_V2_PF10  (PF10 Groth16 (BN254) on-chain unlock)  network=chipnet
commit=<40-char-sha>
```

## Modes

| Flag | What it measures | Network |
|------|------------------|---------|
| *(default)* | **Pipeline** — one live act tip → prove → **mempool admit** → commit | Yes (live) |
| `--cold-start` | **Machine cold-start** — clone, npm ci, CDN pin, native, empty install, **one cold prove** | CDN + live pool for prove |

## Run

From monorepo root (`shieldkit-sdk/`):

```bash
# Default: full pipeline (live deposit → mempool)
node shieldkit-groth/bench/pf10-baseline/run-bench.mjs \
  --data-home /absolute/path/to/.../v2-beta-product

# Cold-start: machine blank install + cold prove (no pool create)
node shieldkit-groth/bench/pf10-baseline/run-bench.mjs --cold-start \
  --data-home /absolute/path/to/.../v2-beta-product
```

Shared:

| Flag | Meaning |
|------|---------|
| `--data-home ABS` | Product data-home (`…/v2-beta-product`). Or `SHIELDKIT_BENCH_DATA_HOME`. |
| `--json-out FILE` | Write report JSON (defaults under `bench/results/`). |

Pipeline only:

| Flag | Meaning |
|------|---------|
| `--kind deposit\|transfer\|withdraw` | Default `deposit` |
| `--to` / `--note` | Withdraw payout / transfer note |

Cold-start only:

| Flag | Meaning |
|------|---------|
| `--sandbox DIR` | Default `~/.cache/shieldkit-bench` |
| `--keep` | Keep sandbox after run (default: delete) |

### Defaults

- **Pipeline** writes `bench/results/pipeline.json`
- **Cold-start** writes `bench/results/coldstart.json` and uses **machine** path (CDN download + native pin-verify + empty data-home install + one cold prove)
- Cold-start proves against the **live** pool session; it never creates a pool
- Warm/steady prove is not a separate bench mode — pipeline’s prove step is the warm path in context of a full act

### Fairness (cold-start)

Machine cold-start always prints a **Fairness note** in the table and JSON (`fairness[]`): CDN pin is timed; native is timed separately; product install into empty data-home is timed; full product ceremony has no public CDN yet.

## Prerequisites

A product **data-home** with session, artifacts, linked runtime, native prover, and (for pipeline live) funds + RPC path.

Refuse ambient `NODE_OPTIONS` / `NODE_PATH` when the native prover loads.

## Internal runners

`run-pipeline.mjs` and `run-coldstart.mjs` implement the two modes. Prefer `run-bench.mjs`. Older S0/S1/S2 scripts are not part of the public two-mode surface.
