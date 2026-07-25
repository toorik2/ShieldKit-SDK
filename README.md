# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

## Two folders

| Folder | Role |
|--------|------|
| **[`create-your-own-pool/`](create-your-own-pool/)** | **Product** — kit, profile, CLI, templates, docs |
| **[`chipnet-playground/`](chipnet-playground/)** | **Optional demo** — fixed Chipnet live instance |

```text
ShieldKit-SDK/
  create-your-own-pool/   ← start here for real work
  chipnet-playground/     ← optional try-first
  README.md · package.json · SECURITY.md · LICENSE
```

| | |
|--|--|
| **Status** | Unaudited — Work In Progress |
| **Default network** | Chipnet |
| **Mainnet** | One config change + WIP warnings — not a release claim |
| **Production privacy** | `ceremony-production` + **new genesis** (no hot-swap) |

We do **not** offer a hosted pool for third-party apps.

---

## Quick start

```bash
npm test
npm run shieldkit -- --help

# Product
npm run shieldkit -- init --config create-your-own-pool/templates/init.development.json

# Optional demo
npm run fetch-playground-bundle
npm run shieldkit -- playground doctor
```

```js
import {
  createKit,
  loadInstance,
  instanceToKitConfig,
} from './create-your-own-pool/packages/kit/index.mjs';

// Your pool (after init + genesis)
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));

// Optional demo
// const demo = await loadInstance('chipnet-playground');
```

You own: **keys · frontend · RPC · broadcast**.

---

## Safety & docs

[SECURITY.md](SECURITY.md) · [create-your-own-pool/docs/](create-your-own-pool/docs/) · [LICENSE](LICENSE)
