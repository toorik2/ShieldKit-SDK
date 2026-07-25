# Use Chipnet demo pool

> **CLI demo only — not a browser app, not a hosted service.**  
> Product (your own genesis): [`../create-your-own-pool/`](../create-your-own-pool/).  
> Learn (static site): [`../local-explainer-webpage/`](../local-explainer-webpage/).

| | |
|--|--|
| **Role** | Shared **Chipnet playground** instance |
| **Network** | Chipnet · `development-only` · Unaudited WIP |
| **Capacity** | **1 live note** (`reserveCap` = 0.1 BCH) — thin demo, not privacy |
| **API** | `npm run shieldkit -- playground …` → same kit as your pool |
| **Aliases** | `chipnet-playground`, `playground` |

---

## Cold start (blank machine)

```bash
# from monorepo root after git clone
npm install                    # installs package deps (postinstall)
npm run fetch-playground-bundle   # ~455MB profile arts (sha256-pinned)

npm run rpc:probe              # public Chipnet Fulcrum by default
npm run shieldkit -- playground doctor
```

### Full act (deposit / transfer / withdraw)

This is **CLI**, not the explainer webpage. You need:

1. **Fee wallet JSON** with a funded Chipnet P2PKH hot key  
2. **Current State NFT tip** (`--state-txid` or `use-chipnet-demo-pool/state.json`)  
3. Network (public Fulcrum by default)

```bash
# wallets.json shape (keep secrets local — never commit)
# {
#   "hot": {
#     "address": "bchtest:…",
#     "publicKeyHex": "02…",
#     "privateKeyHex": "…",
#     "lockingBytecodeHex": "76a914…88ac"
#   }
# }

# Write tip once (genesis or last settle txid), then acts update state.json
echo '{"stateTxid":"<TIP_TXID>","feeUtxos":[],"history":[],"openNotes":[]}' \
  > use-chipnet-demo-pool/state.json

npm run shieldkit -- playground deposit \
  --wallets ./wallets.json --scan-fees --broadcast

npm run shieldkit -- playground withdraw \
  --wallets ./wallets.json --scan-fees --broadcast
```

Deposit fee UTXO must be **≳ 11.5M sats** (0.1 BCH note + binding/carriers + miner fee).  
Transfer/withdraw need **≳ 1.5M sats**.

Chipnet faucet options change over time — search “BCH chipnet faucet” or fund from your own Chipnet node.

### Prep-only (no broadcast)

```bash
npm run shieldkit -- playground request-template --kind deposit
# fill funding fields → playground deposit --request prep.json
```

---

## RPC / chain access

Ordered fallbacks (first that works wins):

| Priority | Source | Env |
|----------|--------|-----|
| 1 | Your Bitcoin JSON-RPC | `SHIELDKIT_RPC_URL=http://user:pass@host:48332` |
| 2 | Your Electrum/Fulcrum | `SHIELDKIT_ELECTRUM=host:50002` |
| 3 | **Public Chipnet Fulcrum** | `chipnet.bch.ninja:50002`, `chipnet.imaginary.cash:50002` |
| 4 | Lab SSH `layer1-node` | operator kit only |

```bash
npm run rpc:probe
# or
SHIELDKIT_RPC_URL=http://127.0.0.1:48332 npm run rpc:probe
```

Public endpoints are **untrusted** and rate-limited. Query privacy is out of scope.

---

## Instance identity

See [`instance.json`](./instance.json):

- `instanceId` · `profileId` · `stateNftCategory`  
- Explorer: `https://chipnet.chaingraph.cash/tx/{txid}`

**This is not your pool.** Create-own-pool ⇒ new profile + genesis + new `instanceId`.
