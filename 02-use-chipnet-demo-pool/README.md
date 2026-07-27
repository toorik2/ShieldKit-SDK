# Chipnet playground (CLI)

Shared **development-only** Chipnet instance — not a browser app, not hosted SaaS.  
Your pool: [`../03-create-your-own-pool/`](../03-create-your-own-pool/).

| | |
|--|--|
| Capacity | 16 live × 0.1 BCH (`reserveCap` = 1.6 BCH) |
| CLI | `npm run shieldkit -- playground …` |
| Aliases | `playground`, `chipnet-playground` |
| Pins | [`instance.json`](./instance.json) · [`docs/PROFILES.md`](../03-create-your-own-pool/docs/PROFILES.md) |

You only spend notes you create. Other notes in the tip are not yours without their seeds.

**Blank machine join:** the playground tip is usually multi-history (not empty).  
`playground tip` and `deposit`/`withdraw` automatically:

1. discover the live State NFT tip  
2. walk settle parents tip → genesis on Electrum  
3. fill `state.json` `settlementLog`  
4. rebuild the **public** tip forest (no foreign note secrets)

Your `openNotes` stay empty until *you* deposit. You never need strangers’ seeds.

## Setup

```bash
npm install                         # deps + unlock toolchain (postinstall)
npm run fetch-playground-bundle     # ~455MB profile arts (sha256 in instance.json)
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip   # tip + settlementLog + public tipForest
```

## Act

Needs: funded Chipnet hot wallet in `wallets.json` (never commit; gitignored).

```bash
# wallets.json: hot.{address,publicKeyHex,privateKeyHex,lockingBytecodeHex}
npm run shieldkit -- playground deposit  --wallets ./wallets.json --scan-fees --broadcast
npm run shieldkit -- playground withdraw --wallets ./wallets.json --scan-fees --broadcast
# force tip rescan: --refresh-tip
# skip chain walk (debug only): --no-fetch-settlement-log
```

| | Fee UTXO value floor (fee **rate** always **1 sat/B**) |
|--|--|
| deposit | ≥ ~10.11M = 0.1 BCH note + PF7 7k + binding 1k + settle funding 59.5k + pads |
| transfer / withdraw | ≥ ~71k = PF7 + binding + settle funding + prep pad + dust |

Prep only: `playground request-template --kind deposit` then `playground deposit --request prep.json`.

## RPC

Default: public Chipnet Fulcrum (`chipnet.bch.ninja:50002`, `chipnet.imaginary.cash:50002`).  
Override: `SHIELDKIT_ELECTRUM=host:50002` or `SHIELDKIT_RPC_URL=…`. No bitcoind required.
