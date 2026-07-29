# Getting started — Protocol-design-v2

Full narrative: **[GOLDEN_PATH.md](../GOLDEN_PATH.md)**.

## Prerequisites

- Node.js ≥ 20  
- `npm ci` from monorepo root  
- Circuit artifacts: `.cache/v2-direct-circuit/` (**dev keys only**)  
- `npm run unlock-builder:setup` once  
- Chipnet coins for the funding address  
- Network: **public Fulcrum by default** (no bitcoind)

```bash
export V2_DENSFUEL_TMPDIR="$HOME/.cache/skd"
mkdir -p "$V2_DENSFUEL_TMPDIR"
export V2_CHIPNET_LIVE=1
export SK_HOME="$PWD/Protocol-design-v2/.home-lab"
```

## Create + use a pool

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" init
# fund fundingAddress on Chipnet faucet, then:

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool create \
  --broadcast --category-utxo <txid:vout>

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" deposit --broadcast
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" withdraw \
  --note note-1 --to bchtest:q… --broadcast
```

## Join an existing pool

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool join ./descriptor.json
# same deposit / withdraw commands
```

## Doctor

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" doctor
```

## Honest limits

- **Dev keys only** — not real-money privacy.  
- **Mainnet gated** until Phase D.  
- Privacy = unlinkability in a set — [PRIVACY.md](../PRIVACY.md).  
