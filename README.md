# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

> **Primary:** create your own pool — `packages/kit` + `packages/profile`.  
> **Optional:** try the Chipnet live demo — `chipnet-playground-live-pool/`.

| | |
|--|--|
| **Status** | Unaudited — Work In Progress |
| **Default network** | Chipnet |
| **Mainnet** | One config change + WIP warnings — not a release claim |
| **Production privacy** | `ceremony-production` + **new genesis** (no hot-swap) |

We do **not** offer a hosted pool for third-party apps. The playground is only so you can **try the kit** before standing up **yours**.

---

## Path

| Step | What | Where |
|------|------|--------|
| **1. Create your pool** | Init + genesis + operate | **`packages/profile`** + **`packages/kit`** |
| **2. (Optional) Try live demo** | Fixed Chipnet example instance | [`chipnet-playground-live-pool/`](chipnet-playground-live-pool/) |
| **3. Operate** | deposit · transfer · withdraw · recover | `createKit` / CLI |

Config sketch: [`templates/init.development.json`](templates/init.development.json).

---

## Quick start

```bash
npm test
node scripts/shieldkit.mjs --help

# Product — create and run your own
node scripts/shieldkit.mjs init --config templates/init.development.json
# → package profile bundle, write instance.json, genesis, then:

# Optional — try the Chipnet live pool first
node scripts/fetch-playground-bundle.mjs
node scripts/shieldkit.mjs playground doctor
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';

// Your pool (after init + genesis) — primary
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));

// Optional live demo
// const example = await loadInstance('chipnet-playground');
// const kit = await createKit(instanceToKitConfig(example));
```

You own: **keys · frontend · RPC · broadcast**.  
ShieldKit does not store secrets, host a pool service, or open sockets.

---

## Four verbs

| Verb | Your pool | Live demo |
|------|-----------|-----------|
| **init** | `init --config templates/init.development.json` | — |
| **act** | `deposit --bundle ./my-pool --request …` | `playground deposit --request …` |
| **recover** | `recover --bundle ./my-pool …` | `playground recover …` |
| **doctor** | load your instance | `playground doctor` |

Missing inputs → **`ok: false`** (fail-closed).

---

## Repository map

```text
packages/
  kit/        app entry: createKit
  profile/    init · genesis · loadInstance   ← create-your-pool lives here
  action/ · prove/ · recover/
templates/    init.development.json
chipnet-playground-live-pool/   optional Chipnet demo instance (not product)
scripts/      shieldkit CLI · fetch-playground-bundle · domain tests
docs/         CHARTER · PRIVACY · PLAYGROUND · ARCHITECTURE
```

---

## Mainnet

```js
network: 'mainnet'
```

Always: **Unaudited — Work In Progress**.  
Broadcast: `--i-understand-mainnet`.

---

## Invariants

- **1 sat/B** · unlock ≤ **10 000** B · settlement ≤ **59 000** B  
- Verifier: `bn254-onetx-pf7-sub62-r1` (7 PF7)  
- New setup ⇒ new profile + new genesis  

---

## Safety & docs

[SECURITY.md](SECURITY.md) · [docs/CHARTER.md](docs/CHARTER.md) · [docs/PRIVACY.md](docs/PRIVACY.md) · [docs/PLAYGROUND.md](docs/PLAYGROUND.md) · [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [LICENSE](LICENSE)
