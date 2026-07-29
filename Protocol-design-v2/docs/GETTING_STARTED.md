# Getting started — Protocol-design-v2

## Prerequisites

- Node.js ≥ 20  
- Repo install (`npm ci` / workspace)  
- Circuit artifacts at `.cache/v2-direct-circuit/` (`circuit_final.zkey`, `circuit.wasm`, `verification_key.json`) — **development keys only**  
- Chipnet access for live broadcast: `V2_CHIPNET_LIVE=1` and working RPC (default: SSH `layer1-node` bitcoin-cli)  
- Short densFuel temp dir: `V2_DENSFUEL_TMPDIR` under ~80 chars (e.g. `~/.cache/skd`)

## 1. Create home

```bash
export SK_HOME="$PWD/.shieldkit-v2-lab"
mkdir -p "$SK_HOME"
```

## 2. Wallets

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet create
```

Prepare `funding-wallet.json` (mode **0600**) with your transparent P2PKH keys and UTXOs.  
**Never** commit this file. There is **no** built-in agent/codex wallet path.

```bash
chmod 600 ./funding-wallet.json
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet set-funding ./funding-wallet.json
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet receive
```

## 3. Create a pool (Chipnet)

Category parent: pure P2PKH outpoint used as CashToken mint parent. Must be **vout 0** (CLI splits if needed).

```bash
export V2_CHIPNET_LIVE=1
export V2_DENSFUEL_TMPDIR="$HOME/.cache/skd"
mkdir -p "$V2_DENSFUEL_TMPDIR"

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool create \
  --broadcast \
  --category-utxo <64hex_txid>:<vout>
```

Writes `pool.json` + `live-tip.json` under `$SK_HOME`.

## 4. Deposit / withdraw

Ensure funding UTXOs cover **denomination + fees** (~10.2M+ sats for deposit).

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" deposit --broadcast
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" status
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" withdraw \
  --note note-1 --to bchtest:q… --broadcast
```

## 5. Doctor

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" doctor
```

## Honest limits

- **Dev keys only** — not real-money privacy (banner every run).  
- **Mainnet gated** until Phase D.  
- Privacy is **unlinkability in a set**, not invisibility — see [PRIVACY.md](../PRIVACY.md).  
- Offline prove without `--broadcast` does not invent txids.
