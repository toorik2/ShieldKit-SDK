# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

> **Primary:** create your own pool.  
> **Optional:** try the Chipnet example first.  
> **Start:** `packages/kit` (+ `profile` for init/instance).

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
| **1. Create your pool** | Init + genesis — the product job | [`examples/create-your-pool`](examples/create-your-pool/) |
| **2. (Optional) Try the example** | Play against our Chipnet demo instance | [`examples/chipnet-playground`](examples/chipnet-playground/) |
| **3. Operate** | deposit · transfer · withdraw · recover on **your** instance | `createKit` / CLI |

Same APIs either way. Playground and “your pool” differ only by **instance binding**.

---

## Quick start

```bash
npm test
node scripts/shieldkit.mjs --help

# Product path — create and run your own
node scripts/shieldkit.mjs init --config examples/create-your-pool/init.example.json

# Optional — try the Chipnet example pool first
node scripts/fetch-playground-bundle.mjs   # pin + sha256 in instance.json
node scripts/shieldkit.mjs playground doctor
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';

// Your pool (after init + genesis) — primary
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));

// Optional example instance (our Chipnet playground)
// const example = await loadInstance('chipnet-playground');
// const kit = await createKit(instanceToKitConfig(example));

// kit.planAction(request) · kit.recoverAuthenticatedHistory(...)
```

You own: **keys · frontend · RPC · broadcast**.  
ShieldKit does not store secrets, host a pool service, or open sockets.

---

## Four verbs

| Verb | Your pool | Example playground |
|------|-----------|--------------------|
| **init** | `init --config …` | — |
| **act** | `deposit --bundle ./my-pool --request …` | `playground deposit --request …` |
| **recover** | `recover --bundle ./my-pool …` | `playground recover …` |
| **doctor** | `doctor` / load your instance | `playground doctor` |

Missing inputs → **`ok: false`** (fail-closed).

---

## Repository map

```text
packages/     kit · profile · action · prove · recover
scripts/      shieldkit CLI · domain tests · fetch-playground-bundle
examples/
  create-your-pool/     create your own instance  ← primary
  chipnet-playground/   live Chipnet *example* (optional)
docs/         CHARTER · PRIVACY · PLAYGROUND · ARCHITECTURE
```

**Start coding:** `packages/kit` · instance/init: `packages/profile`.

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
