# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

| | |
|--|--|
| **Toolkit version** | **0.1.0** (semver · pre-1.0 · source of truth: root `package.json`) |
| **Status** | Unaudited — Work In Progress |
| **Maturity label** | `evidence experiment` (charter — **not** derived from semver) |
| **Profile / instance** | Content IDs only (`sha256:…`) — **not** toolkit versions |
| **Default network** | Chipnet |
| **Mainnet** | One config change + WIP warnings — not a release claim |
| **Production privacy** | `ceremony-production` + **new genesis** (no hot-swap) |

> Toolkit version **X.Y.Z** · Profile/instance = **content IDs** · Maturity = **charter labels**.  
> Do not treat `0.1.0` as Chipnet/mainnet qualification or production privacy.

Versioning: [CHANGELOG.md](CHANGELOG.md) · [create-your-own-pool/docs/VERSIONING.md](create-your-own-pool/docs/VERSIONING.md) · [PROFILES.md](create-your-own-pool/docs/PROFILES.md)

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

We do **not** offer a hosted pool for third-party apps.

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

## Release tags (split)

| Tag | Means |
|-----|--------|
| `v0.y.z` | Toolkit **code** |
| `playground-bundle-vN` / `demo-bundle-vN` | Large **profile blobs** only (sha256-pinned) |

---

## Safety & docs

[SECURITY.md](SECURITY.md) · [create-your-own-pool/docs/](create-your-own-pool/docs/) · [LICENSE](LICENSE)
