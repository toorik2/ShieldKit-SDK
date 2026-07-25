# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

We do **not** offer a hosted pool for third-party apps. The Chipnet playground is an optional live demo only.

---

## Quick start

```bash
npm test
npm run shieldkit -- --version
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
// const demo = await loadInstance('use-chipnet-demo-pool');
```

You own: **keys · frontend · RPC · broadcast**.

---

## Two folders

| Folder | Role |
|--------|------|
| **[`create-your-own-pool/`](create-your-own-pool/)** | **Product** — kit, profile, CLI, templates, docs |
| **[`use-chipnet-demo-pool/`](use-chipnet-demo-pool/)** | **Optional demo** — fixed Chipnet live instance |

```text
ShieldKit-SDK/
  create-your-own-pool/   ← start here for real work
  use-chipnet-demo-pool/  ← optional try-first
  README.md · package.json · SECURITY.md · LICENSE · CHANGELOG.md
```

---

## Safety & docs

[SECURITY.md](SECURITY.md) · [create-your-own-pool/docs/](create-your-own-pool/docs/) · [CHANGELOG.md](CHANGELOG.md) · [LICENSE](LICENSE)
