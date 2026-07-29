# Protocol-design-v2

**ShieldKit Protocol V2 Direct** — publishable **lab** surface for the fully functioning V2 design.

```
DEV KEYS ONLY — not for real-money privacy
Unaudited WIP · Chipnet-first · Mainnet gated until Phase D
```

| | |
|--|--|
| **Implementation** | `03-create-your-own-pool/packages/v2-direct/` |
| **CLI** | `Protocol-design-v2/bin/shieldkit-v2.mjs` → same implementation |
| **Authority** | `03-create-your-own-pool/docs/protocol/v2-direct/IMPLEMENTATION_PLAN.md` |
| **Maturity** | [MATURITY.md](./MATURITY.md) |
| **Privacy** | [PRIVACY.md](./PRIVACY.md) |
| **Getting started** | [docs/GETTING_STARTED.md](./docs/GETTING_STARTED.md) |

## Product path (sole)

One private witness → one local Groth16 proof → one wallet-owned funding input → one BCH settlement (densFuel carriers + binding + CashScript SKS2 state).

No faucet. No sponsor. No prep-tx theater.

## Quick CLI

From repo root (Node ≥ 20, workspace installed):

```bash
# Help + maturity banner
node Protocol-design-v2/bin/shieldkit-v2.mjs --help

# Or via package script
npm run v2-direct -- --help
```

### Blank-machine flow (Chipnet)

```bash
HOME=./.my-v2-home
mkdir -p "$HOME"

# 1) Shielded note wallet (secrets mode 0600)
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$HOME" wallet create

# 2) Transparent funding wallet (you generate keys; chmod 600)
# funding-wallet.json:
# {
#   "privateKeyHex": "...",
#   "publicKeyHex": "...",
#   "lockingBytecodeHex": "...",
#   "address": "bchtest:...",
#   "utxos": [{ "txid": "...", "vout": 0, "valueSats": "20000000" }]
# }
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$HOME" wallet set-funding ./funding-wallet.json

# 3) Create pool on Chipnet (category parent must be mintable; non-0 vout is auto-split)
export V2_CHIPNET_LIVE=1
export V2_DENSFUEL_TMPDIR="${HOME}/.cache/skd"   # short path for tsx IPC
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$HOME" pool create \
  --broadcast --category-utxo <txid:vout>

# 4) Deposit / withdraw (funding UTXOs in funding-wallet.json or note-wallet utxos)
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$HOME" deposit --broadcast
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$HOME" withdraw --note <id> --to <cashaddr> --broadcast
```

Join an existing pool: `pool add descriptor.json` (include `liveTip` for live settle).

## Publish gates implemented

1. **`pool create`** — vout0 category, densFuel carriers, SKS2 genesis, writes `liveTip`  
2. **Pin-bind settle** — `dens.packetBytes` always used after pin-compatible `transactionContextHash` bind  
3. **Blank-machine funding** — `--funding-wallet` / `V2_FUNDING_WALLET_JSON` / `<home>/funding-wallet.json` only (no hard-coded agent paths)  
4. **Docs** — this README + PRIVACY + MATURITY + GETTING_STARTED  
5. **Dev-keys banner** — every CLI invocation  
6. **Mainnet gated** — until audits + Phase D (`V2_ALLOW_MAINNET=1` + `--i-understand-mainnet` escape hatch is not a qualification)

## Evidence (lab)

- Chipnet product D/T/W, capacity, contention, recover-respend: `docs/protocol/v2-direct/{STATUS,EVIDENCE,QUALIFICATION}.md`
- Single-pool 5-in/5-out + forensics: `.cache/v2-direct-forensics-1pool-5x5/` (gitignored)

## What remains for “production privacy product”

See MATURITY.md Phase D. Do not remove the banner or mainnet gate until those items are closed and reviewed.
