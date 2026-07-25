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
2. Network (public Fulcrum by default)  
3. **Tip** — *not* a fixed kit constant. It **moves every settle**.

**Tip handling (automatic):**

```bash
# Discover live tip from chain → writes use-chipnet-demo-pool/state.json
npm run shieldkit -- playground tip

# Or let deposit discover tip when state.json has no stateTxid
npm run shieldkit -- playground deposit --wallets ./wallets.json --scan-fees --broadcast

# Force re-scan before an act (if someone else settled)
npm run shieldkit -- playground deposit --wallets ./wallets.json --refresh-tip --scan-fees --broadcast
```

`state.json` is a **local cache** of the last tip + your openNotes/fees.  
Truth is always: *unspent State NFT for this instance’s category on Chipnet*.

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

## Chain access — average user needs **no node**

ShieldKit talks to Chipnet through an **abstract RPC layer**. Average users do **not** run `bitcoind` and do **not** need free public JSON-RPC (there isn’t a reliable one for Chipnet).

| Who | What you use | Config |
|-----|----------------|--------|
| **Average demo user** | **Public Fulcrum (Electrum TLS)** — built in | nothing — just `npm run rpc:probe` |
| Optional preference | Your own Fulcrum/Electrum | `SHIELDKIT_ELECTRUM=host:50002` |
| Power user / operator | Your own BCHN JSON-RPC | `SHIELDKIT_RPC_URL=http://user:pass@host:48332` |
| Lab only | SSH `layer1-node` | auto if host works |

**Public defaults (tested):**

- `chipnet.bch.ninja:50002` (TLS)  
- `chipnet.imaginary.cash:50002` (TLS)

These cover tip discovery, fee UTXO scan, broadcast, and doctor. They are **untrusted / rate-limited**; query privacy is out of claim.

```bash
npm run rpc:probe
# → backend: electrum · label: chipnet.bch.ninja:50002 · height: …
```

What still needs *you* (not RPC): a **funded Chipnet wallet** (≳ 11.5M sats for deposit) and local secrets in `wallets.json`.

---

## Instance identity

See [`instance.json`](./instance.json):

- `instanceId` · `profileId` · `stateNftCategory`  
- Explorer: `https://chipnet.chaingraph.cash/tx/{txid}`

**This is not your pool.** Create-own-pool ⇒ new profile + genesis + new `instanceId`.
