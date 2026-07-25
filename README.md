# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

> **ShieldKit creates shielded pools.  
> The Chipnet playground is a live example of a pool built with this kit.  
> Your product is your own pool — same toolkit, your genesis.**

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
| **1. Try the example** | Play against our Chipnet demo instance (optional) | [`examples/chipnet-playground`](examples/chipnet-playground/) |
| **2. Create your pool** | Init + genesis — the actual product job | [`examples/create-your-pool`](examples/create-your-pool/) |
| **3. Operate** | deposit · transfer · withdraw · recover on **your** instance | `createKit` / CLI |

Same APIs either way. Playground and “your pool” differ only by **instance binding**.

---

## Quick start

```bash
npm test
node scripts/shieldkit.mjs --help

# Optional — try the Chipnet example pool first
export SHIELDKIT_PLAYGROUND_BUNDLE=/path/to/profile-bundle
node scripts/shieldkit.mjs playground doctor

# Product path — create and run your own
node scripts/shieldkit.mjs init --config examples/create-your-pool/init.example.json
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';

// Optional example instance (our Chipnet playground)
// const example = await loadInstance('chipnet-playground');
// const kit = await createKit(instanceToKitConfig(example));

// Your pool (after init + genesis)
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));

// kit.planAction(request) · kit.recoverAuthenticatedHistory(...)
```

You own: **keys · frontend · RPC · broadcast**.  
ShieldKit does not store secrets, host a pool service, or open sockets.

---

## Four verbs

| Verb | Example playground | Your pool |
|------|--------------------|-----------|
| **init** | — | `init --config …` |
| **act** | `playground deposit --request …` | `deposit --bundle ./my-pool --request …` |
| **recover** | `playground recover …` | `recover --bundle ./my-pool …` |
| **doctor** | `playground doctor` | `doctor` / load your instance |

Missing inputs → **`ok: false`** (fail-closed).

---

## Repository map

```text
packages/     kit · profile · action · prove · recover
scripts/      shieldkit CLI · domain tests
examples/
  chipnet-playground/   live Chipnet *example* (not a hosted product)
  create-your-pool/     create your own instance
docs/
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
