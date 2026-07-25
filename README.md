# ShieldKit

**Private BCH transfers. Your pool. Your keys. Your app.**

Offline toolkit for Bitcoin Cash: deposit → privately transfer → withdraw, with local proving.

| | |
|--|--|
| **Status** | Unaudited — Work In Progress |
| **Default network** | Chipnet |
| **Mainnet** | One config change (`network: 'mainnet'`) + WIP warnings; not a release claim |
| **Production privacy** | Requires `ceremony-production` profile + **new genesis** |

---

## Install & CLI

```bash
npm test                          # protocol freeze check (local; no CI)
node scripts/run-domain-tests.mjs # unit suite
node scripts/shieldkit.mjs --help
node scripts/shieldkit.mjs doctor
```

```js
import { createKit } from './packages/kit/index.mjs';

const kit = await createKit({
  network: 'chipnet', // or 'mainnet'
  bundleDirectory: './profile-bundle',
  expectedProfile: { network: 'chipnet', profileId, instanceId },
});
// kit.warnings includes product status
// kit.planAction(request) · kit.recoverAuthenticatedHistory(...)
```

You own: keys · frontend · RPC · broadcast.  
ShieldKit does not store secrets or open network connections.

---

## Four verbs

| Verb | Command | Library |
|------|---------|---------|
| **init** | `shieldkit init --config …` | `packages/profile` — setup → profile → load |
| **act** | `shieldkit deposit\|transfer\|withdraw --bundle … --request …` | `createKit` → plan → sign → prove → settle |
| **recover** | `shieldkit recover --bundle … --history … --seed-hex …` | `recoverAuthenticatedHistory` |
| **doctor** | `shieldkit doctor` | honesty + mainnet gates |

Missing inputs → **`ok: false`** (fail-closed).

---

## Repository map (this page is the product)

```text
packages/     kit · profile · action · prove · recover
scripts/      shieldkit CLI · domain tests · freeze check
examples/     demo-profile (Chipnet lab)
docs/         charter · privacy · architecture
```

| Open | Purpose |
|------|---------|
| [`packages/kit`](packages/kit) | App integration (`createKit`) |
| [`packages/profile`](packages/profile) | Birth a pool (dev or ceremony) |
| [`examples/demo-profile`](examples/demo-profile) | Lab profile pointer |
| [`docs/`](docs) | Product docs |
| [`scripts/freeze/`](scripts/freeze) | Protocol freeze only (not app API) |

---

## Mainnet

```js
network: 'mainnet'   // only required config change
```

Always shown: **Unaudited — Work In Progress**.  
Broadcast: `--i-understand-mainnet`.  
Real production claims: ceremony profile + new genesis (no hot-swap).

---

## Invariants

- **1 sat/B** fees · unlock ≤ **10 000** B · settlement ≤ **59 000** B  
- Verifier: `bn254-onetx-pf7-sub62-r1` (7 PF7)  
- New setup ⇒ new profile + new genesis  

---

## Safety & license

[SECURITY.md](SECURITY.md) · [docs/PRIVACY.md](docs/PRIVACY.md) · [LICENSE](LICENSE)
