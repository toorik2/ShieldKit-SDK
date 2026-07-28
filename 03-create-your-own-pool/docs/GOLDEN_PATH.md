# Golden path — Chipnet deposit & withdraw

Unaudited WIP. **Chipnet only** for this path. Mainnet is not a product claim.

Goal: blank machine → install → pins → fund → **deposit** → **withdraw**.

Two tracks:

| Track | When to use |
|-------|-------------|
| **A · Your pool** | Birth a new instance, then act |
| **B · Playground** | Shared demo pool (cap 32 live notes) |

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
npm ci
npm run fetch-pin-artifacts               # ~450MB proving pin; once per machine
npm run unlock-builder:setup              # immutable vendored toolchain

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

Pin artifacts are development-only (Chipnet research), not a multi-party production
ceremony. A new setup/VK implies a new profile and genesis.

What happens under the hood (you should not need these):

- Tip discovery from chain  
- Fee UTXO scan. If coins are fragmented, the top-level command stages,
  gates, and broadcasts one consolidation, then exits; re-run the requested
  action after that UTXO becomes visible.
- Prove + densFuel unlock (often **30–90s**)  
- Exact 1 sat/B fee; change returns to hot wallet  
- Note secrets saved in `state.json` openNotes (backup that file / use encrypted wallet APIs)
- Every operation is prepared into `.shieldkit/operations/pending.json` before
  any network send. State changes only after all journaled transactions
  broadcast; retry an interrupted operation with `--resume-pending --broadcast`.

---

## Track B — Playground (shared demo)

The moving demo tip may be **multi-history** (other operators may have acted).
Blank machines do **not** need a residual journal: `tip` / first act walk chain history
(tip → genesis), fill `settlementLog`, and rebuild the public tip forest automatically.

```bash
npm ci
npm run fetch-playground-bundle
npm run unlock-builder:setup
npm run rpc:probe
npm run shieldkit -- playground doctor
npm run shieldkit -- playground tip   # discovers tip + rebuilds public forest from chain

npm run shieldkit -- playground deposit --wallets ./wallets.json --broadcast
npm run shieldkit -- playground withdraw --wallets ./wallets.json --broadcast
```

`wallets.json` is gitignored — never commit keys. Prefer `.local/wallets.json` if you like.

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
