# Golden path — blank machine → create & use a V2 pool

**Unaudited WIP · DEV KEYS ONLY · Chipnet only · not real-money privacy**

One CLI under this folder does **both**:

1. **Create your own pool**  
2. **Interact** (deposit / transfer / withdraw / join existing)

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs   # or: npm run protocol-v2
```

---

## Prerequisites

| Need | Notes |
|------|--------|
| Node **20+** | |
| Repo install | `npm ci` from monorepo root |
| Circuit artifacts | `.cache/v2-direct-circuit/` (dev zkey/wasm/vkey) — **dev keys only** |
| densFuel toolchain | `npm run unlock-builder:setup` once |
| Chipnet coins | Fund the address printed by `init` (faucet/peer) |
| Network | Default: **public Chipnet Fulcrum TLS** (no bitcoind) |

Short densFuel temp dir (tsx IPC path limit):

```bash
export V2_DENSFUEL_TMPDIR="$HOME/.cache/skd"
mkdir -p "$V2_DENSFUEL_TMPDIR"
```

---

## Track A — Create your own pool

```bash
export SK_HOME="$PWD/Protocol-design-v2/.home-lab"   # any private dir
export V2_CHIPNET_LIVE=1
export V2_DENSFUEL_TMPDIR="$HOME/.cache/skd"

# 1) Bootstrap shielded + transparent funding wallets
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" init
# → prints fundingAddress — fund it on Chipnet (≥ ~0.2 BCH for genesis + first deposit)

# 2) Scan UTXOs (public Fulcrum; no local node)
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan

# 3) Birth pool on chain (category parent = pure P2PKH outpoint; auto-splits to vout0)
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool create \
  --broadcast \
  --category-utxo <txid:vout>

# 4) Deposit 0.1 BCH
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" wallet funding-scan   # refresh after genesis change
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" deposit --broadcast

# 5) Withdraw to a transparent cashaddr
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" status
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" withdraw \
  --note note-1 --to bchtest:q… --broadcast
```

Rough funding (one coin ≥):

| Step | Need |
|------|------|
| Pool create (carriers + state) | ~0.08–0.12 BCH category parent |
| Deposit | **~0.102 BCH** (0.1 note + fees) |
| Withdraw | **~0.002 BCH** fee coin |

---

## Track B — Join / interact with an existing live pool

Someone (or a demo host) gives you a **descriptor** with `profileId`, `instanceId`, `genesisTxid`, and **`liveTip`** (7 carriers + binding + state).

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" init   # if new machine
# fund + funding-scan as above

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" pool join ./descriptor.json
# alias: pool add

node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" deposit --broadcast
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" withdraw --note note-1 --to bchtest:q… --broadcast
```

There is **no separate demo CLI** — same binary; join = interact with a shared instance when you have a descriptor + tip.

---

## Doctor

```bash
node Protocol-design-v2/bin/shieldkit-v2.mjs --home "$SK_HOME" doctor
```

Checks wallet secrets mode, funding wallet, liveTip presence, reserve invariants. Always reminds: **dev keys only**.

---

## Privacy (honest)

- **Core:** chain observer should not map which deposit note funded which withdraw inside a real multi-note set.  
- **Not claimed:** network privacy, small-set safety, timing/fee-graph resistance, mainnet product readiness.  
- See [PRIVACY.md](./PRIVACY.md) and [MATURITY.md](./MATURITY.md).

---

## Layout (contained under v2)

| Path | Role |
|------|------|
| `Protocol-design-v2/bin/shieldkit-v2.mjs` | **The** user CLI |
| `Protocol-design-v2/*.md` | Story, privacy, maturity |
| `03-create-your-own-pool/packages/v2-direct/` | Implementation package |

Legacy V1 `create-pool` / `playground` CLIs remain under `03-create-your-own-pool/` and `02-use-chipnet-demo-pool/` — **not** this V2 product path.
