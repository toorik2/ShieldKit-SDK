# ShieldKit

**Private BCH transfers. Your pool. Your keys. Your app.**

> **ShieldKit creates shielded pools.  
> The Chipnet playground is our pool.  
> Your pool is the same thing with your genesis.**

| | |
|--|--|
| **Status** | Unaudited — Work In Progress |
| **Default network** | Chipnet |
| **Mainnet** | One config change + WIP warnings — not a release claim |
| **Production privacy** | `ceremony-production` + **new genesis** (no hot-swap) |

---

## Two doors, one SDK

| You are… | You want… | Start here |
|----------|-----------|------------|
| **App builder** | Use a live pool in an app or CLI | [**Chipnet playground**](examples/chipnet-playground/) — *our* pool |
| **Pool creator** | Birth a new pool | [**Create your own pool**](examples/create-your-pool/) — *your* genesis |

Same APIs (`loadInstance` → `createKit`). Only the **instance binding** changes.

---

## Quick start

```bash
npm test
node scripts/shieldkit.mjs --help

# App builders — official Chipnet playground
export SHIELDKIT_PLAYGROUND_BUNDLE=/path/to/profile-bundle   # see playground README
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs playground profile-info

# Pool creators
node scripts/shieldkit.mjs init --config examples/create-your-pool/init.example.json
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';

// Our pool
const playground = await loadInstance('chipnet-playground');
const kit = await createKit(instanceToKitConfig(playground));

// Your pool (after init + genesis)
// const mine = await loadInstance('./my-pool');
// const kit = await createKit(instanceToKitConfig(mine));

// kit.planAction(request) · kit.recoverAuthenticatedHistory(...)
// kit.warnings includes product status
```

You own: **keys · frontend · RPC · broadcast**.  
ShieldKit does not store secrets or open sockets.

---

## Four verbs

| Verb | App builder (playground) | Pool creator / any instance |
|------|--------------------------|-----------------------------|
| **init** | — | `init --config …` |
| **act** | `playground deposit\|transfer\|withdraw --request …` | `deposit … --bundle … --request …` |
| **recover** | `playground recover --history … --seed-hex …` | `recover --bundle …` |
| **doctor** | `playground doctor` | `doctor` |

Missing inputs → **`ok: false`** (fail-closed).

---

## Repository map

```text
packages/     kit · profile · action · prove · recover
scripts/      shieldkit CLI · domain tests
examples/
  chipnet-playground/   our Chipnet pool (instance.json)
  create-your-pool/     birth your own
docs/         charter · privacy · architecture · playground model
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

[SECURITY.md](SECURITY.md) · [docs/PRIVACY.md](docs/PRIVACY.md) · [docs/PLAYGROUND.md](docs/PLAYGROUND.md) · [LICENSE](LICENSE)
