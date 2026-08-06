# ShieldKit bench

Public, portable measurements for **ShieldKit-Groth** on **Chipnet**.

Two modes. One command. Every report names what it measured.

```text
ShieldKit-Groth 0.3.0-beta.1  (shieldkit-v2-beta-chipnet)
design=pf10-baseline  verifier=DIRECT_V2_PF10  (PF10 Groth16 (BN254) on-chain unlock)  network=chipnet
commit=<40-char-sha>
```

This is a **measurement** tool. It does **not** claim that pool capacity equals an anonymity set, and it makes **no mainnet / production / audit** claim.

---

## Modes

| Flag | Measures | Needs |
|------|----------|--------|
| *(default)* | **Pipeline** — live act tip → prove → **mempool admit** → commit | Funded Chipnet product data-home (real spend) |
| `--cold-start` | **Machine cold-start** — clone, `npm ci`, CDN pin download, native pin-verify, empty install, **one cold prove** | Same data-home for cold prove; sandbox under `~/.cache` |

Warm prove in isolation is not a third mode: pipeline’s `proofGen` step is the warm prove in a full act.

---

## Quick start

Prerequisites:

- Node.js **≥ 22.5**
- Chipnet product **data-home** with `session.json` (see [USER_GUIDE](../docs/USER_GUIDE.md))
- No ambient `NODE_OPTIONS` / `NODE_PATH` (native prover policy)

```bash
git clone https://github.com/toorik2/ShieldKit-SDK.git
cd ShieldKit-SDK
npm ci

# Required: absolute path to outer install root OR …/v2-beta-product
export SHIELDKIT_BENCH_DATA_HOME=/absolute/path/to/your/install-or-v2-beta-product

# Full act → mempool (spends Chipnet funds)
npm run bench -- --data-home "$SHIELDKIT_BENCH_DATA_HOME"

# First-machine install cost + one cold prove (does not create a pool)
npm run bench:cold-start -- --data-home "$SHIELDKIT_BENCH_DATA_HOME"
```

Equivalent:

```bash
node shieldkit-groth/bench/pf10-baseline/run-bench.mjs --data-home /abs/...
node shieldkit-groth/bench/pf10-baseline/run-bench.mjs --cold-start --data-home /abs/...
```

### Flags

| Flag | Meaning |
|------|---------|
| `--data-home ABS` | **Required** (or `SHIELDKIT_BENCH_DATA_HOME`). Outer install root or `…/v2-beta-product`. |
| `--json-out FILE` | Report JSON (default under `bench/results/`, gitignored). |
| `--kind deposit\|transfer\|withdraw` | Pipeline only (default `deposit`). |
| `--to` / `--note` | Withdraw / transfer. |
| `--sandbox DIR` | Cold-start only (default `~/.cache/shieldkit-bench`). |
| `--keep` | Cold-start: keep sandbox after run. |
| `--help` | Subject + usage. |

There are **no author-machine default data-homes**. If you omit `--data-home` and env, the bench fails closed with `BENCH_DATA_HOME_REQUIRED`.

---

## What each mode does

### Pipeline (default)

Runs one **live** product CLI act and prints tip → mempool timings:

```text
 1. Look up tip on network
 …
 5. Make ZK proof              ← native prove
 …
 9. Broadcast + mempool/readback
10. Save local state
```

JSON: `subject`, per-step `ms`, `txid`, sums.

### Cold-start (`--cold-start`)

Times a **machine** first install into a temporary sandbox, then **one cold prove** against the **existing** live pool session (never creates a pool):

1. Clone repo  
2. `npm ci`  
3. CDN pin download (trust-manifest URL + sha256)  
4. Native prover copy + pin-verify  
5. Product artifact install into empty data-home  
6. Cold prove only (warm prove is pipeline, not this story)  
7. Disk footprint  

Always prints a **Fairness note** (CDN pin timed; full product ceremony has no public CDN yet; empty install timed; live pool for prove).

Sandbox is **deleted** unless `--keep`.

---

## Reading results

Every JSON report includes:

```json
"subject": {
  "product": "ShieldKit-Groth",
  "productId": "shieldkit-v2-beta-chipnet",
  "version": "0.3.0-beta.1",
  "design": "pf10-baseline",
  "verifier": "DIRECT_V2_PF10",
  "verifierLabel": "PF10 Groth16 (BN254) on-chain unlock",
  "network": "chipnet",
  "commit": "<full-40-char-sha>"
}
```

Use `subject` + git tag when comparing numbers across machines.

---

## Robustness notes

- Data-home resolution accepts **outer install root** or **nested `v2-beta-product`**.
- Pipeline CLI gets the **outer** root when the session lives under `shieldkit/v2-beta-product`.
- Unknown flags are rejected (public surface is only the two modes).
- `results/` is gitignored — keep machine noise out of PRs.
- Internal runners (`run-pipeline.mjs`, `run-coldstart.mjs`) implement the modes; prefer `run-bench.mjs`.

---

## Tests

```bash
node --test shieldkit-groth/bench/*.test.mjs shieldkit-groth/bench/pf10-baseline/run-bench.test.mjs
```
