# Protocol-design-v2

**One CLI** for ShieldKit Protocol V2 Direct:

- **Create your own pool** on Chipnet  
- **Interact** (deposit / transfer / withdraw)  
- **Join** an existing live pool via descriptor  

```
DEV KEYS ONLY — not for real-money privacy
Unaudited WIP · Chipnet-first · Mainnet gated until Phase D
```

| | |
|--|--|
| **CLI** | [`bin/shieldkit-v2.mjs`](./bin/shieldkit-v2.mjs) |
| **Golden path** | [GOLDEN_PATH.md](./GOLDEN_PATH.md) |
| **Privacy** | [PRIVACY.md](./PRIVACY.md) |
| **Maturity** | [MATURITY.md](./MATURITY.md) |
| **Getting started** | [docs/GETTING_STARTED.md](./docs/GETTING_STARTED.md) |
| **Code** | `../03-create-your-own-pool/packages/v2-direct/` |

## Blank machine (shortest)

```bash
# from monorepo root after npm ci + unlock-builder:setup + circuit artifacts
export SK_HOME="$PWD/Protocol-design-v2/.home-lab"
export V2_CHIPNET_LIVE=1
export V2_DENSFUEL_TMPDIR="$HOME/.cache/skd"
mkdir -p "$V2_DENSFUEL_TMPDIR"

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" init
# fund the printed fundingAddress on Chipnet, then:

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool create \
  --broadcast --category-utxo <txid:vout>
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" deposit --broadcast
```

**No bitcoind required** by default — public Chipnet Fulcrum TLS.  
**No hard-coded agent wallets** — keys live under `--home` (mode 0600).

Join someone else’s pool:

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool join ./descriptor.json
```

## npm scripts (repo root)

```bash
npm run protocol-v2 -- --help
npm run protocol-v2 -- --home ./my-home init
```

## Publish gates

1. `pool create` (vout0 category, densFuel carriers, liveTip)  
2. Pin-bind settle (`dens.packetBytes`)  
3. Blank-machine funding + **scan** via public Fulcrum  
4. Docs + honest privacy/non-claims  
5. Dev-keys banner every run  
6. Mainnet gated until Phase D  

## Not this folder

| Legacy (V1) | Path |
|-------------|------|
| Create pool | `03-create-your-own-pool/` + `npm run create-pool` |
| Demo playground | `02-use-chipnet-demo-pool/` + `shieldkit playground` |

V2 story is **only** this CLI under `Protocol-design-v2/`.
