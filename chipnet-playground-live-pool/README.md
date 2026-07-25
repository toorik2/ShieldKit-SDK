# Chipnet playground — live example pool

> **Optional demo only.**  
> Product path: `packages/kit` + `packages/profile` (create and run **your** pool).  
> This directory is a fixed Chipnet **instance** you can try first.

| | |
|--|--|
| **Role** | Optional live example — not a hosted service |
| **Network** | Chipnet · `development-only` · Unaudited WIP |
| **API** | Same as any pool: `loadInstance('chipnet-playground')` → `createKit` |
| **Instance id** | `chipnet-playground` (stable; path is just the monorepo home) |

---

## Setup (one-time)

Profile bundle (~455 MB proving key) is **not in git**. Pin + sha256 in [`instance.json`](./instance.json).

```bash
node scripts/fetch-playground-bundle.mjs
# → chipnet-playground-live-pool/bundle/ + export line

# or
export SHIELDKIT_PLAYGROUND_BUNDLE=/path/to/profile-bundle
```

```bash
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs playground profile-info
```

---

## Play (then create yours)

```js
import { loadInstance, instanceToKitConfig } from '../packages/profile/instance.mjs';
import { createKit } from '../packages/kit/index.mjs';

const example = await loadInstance('chipnet-playground');
const kit = await createKit(instanceToKitConfig(example));
```

```bash
node scripts/shieldkit.mjs playground deposit --request ./prep.json
```

You supply Chipnet RPC, fee keys, proofs, broadcast.

**Your pool:** `packages/profile` init (+ [`templates/init.development.json`](../templates/init.development.json)) → genesis → `loadInstance('./my-pool')`.

---

## Coordinates

Pinned in [`instance.json`](./instance.json). Immutable for this example. New pool = new genesis.
