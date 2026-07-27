# Golden path — Chipnet deposit & withdraw

Unaudited WIP. **Chipnet only** for this path. Mainnet is not a product claim.

Goal: blank machine → install → pins → fund → **deposit** → **withdraw**.

Two tracks:

| Track | When to use |
|-------|-------------|
| **A · Your pool** | Birth a new instance, then act |
| **B · Playground** | Shared demo pool (cap 16 live notes) |

---

## Prerequisites

- Node.js **20+**
- ~**500 MB** free (circuit pin artifacts)
- Chipnet coins on a hot wallet (see below)
- Network access to public Chipnet Electrum / Fulcrum (default) or your own RPC

**Wallet file** (`wallets.json`):

```json
{
  "hot": {
    "address": "bchtest:…",
    "privateKeyHex": "…",
    "publicKeyHex": "…",
    "lockingBytecodeHex": "76a914…88ac"
  }
}
```

Fund `hot.address` on Chipnet faucet / peer:

| Action | Rough need (one coin ≥ this) |
|--------|------------------------------|
| Deposit | **~0.11 BCH** (0.1 note + fees/carriers) |
| Withdraw | **~0.01 BCH** |

Fees are **automatic** (1 sat/B). The client scans and may merge small UTXOs for you.

---

## Track A — Your own pool

```bash
git clone <this-repo> && cd shieldkit-sdk   # or your remote
npm install
npm run fetch-pin-artifacts               # ~450MB; once per machine

# Birth pool + genesis on Chipnet (uses wallets + scan-fund)
npm run create-pool -- \
  --out ./my-pool \
  --with-genesis \
  --network chipnet \
  --wallets ./wallets.json \
  --scan-fund \
  --max-notes 16 \
  --broadcast

# Deposit 0.1 BCH into the pool
npm run shieldkit -- deposit --pool ./my-pool --wallets ./wallets.json --broadcast

# Withdraw one of your notes
npm run shieldkit -- withdraw --pool ./my-pool --wallets ./wallets.json --broadcast
```

What happens under the hood (you should not need these):

- Tip discovery from chain  
- Fee UTXO scan (+ auto-consolidate if coins are fragmented)  
- Prove + densFuel unlock (often **30–90s**)  
- Exact 1 sat/B fee; change returns to hot wallet  
- Note secrets saved in `state.json` openNotes (backup that file / use encrypted wallet APIs)

---

## Track B — Playground (shared demo)

```bash
npm install
npm run fetch-playground-bundle
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip

npm run shieldkit -- playground deposit --wallets ./wallets.json --broadcast
npm run shieldkit -- playground withdraw --wallets ./wallets.json --broadcast
```

See also [`PLAYGROUND.md`](./PLAYGROUND.md) and `02-use-chipnet-demo-pool/`.

---

## Operator checks

```bash
npm run rpc:probe
npm run shieldkit -- doctor --pool ./my-pool
```

Verbose internals (ECIP / fee inventory JSON):

```bash
SHIELDKIT_VERBOSE=1 npm run shieldkit -- deposit --pool ./my-pool --wallets ./wallets.json --broadcast
# or:  --verbose
```

---

## Multi-user blank e2e (lab)

Proves shared tip + chain-as-log rebuild (needs funded wallets + pin artifacts):

```bash
npm run e2e:multiuser-blank
```

Report: full 64-char settle txids under `.cache/e2e-multiuser-blank-*/report.json`.

---

## What this path is / is not

| Claim | Status |
|-------|--------|
| Chipnet deposit/withdraw for a **technical operator** | Supported |
| Auto tip, fees, coin merge | Supported (defaults on) |
| End-user mobile wallet UX | **Not** this release |
| Mainnet | **Not** claimed — unaudited; refuse without explicit gates |

Privacy / risk docs: [`PRIVACY.md`](./PRIVACY.md), [`SMART_CONTRACT_REDTEAM.md`](./SMART_CONTRACT_REDTEAM.md).
