# Chipnet playground — live example pool

> **Optional demo only.**  
> Product: sibling [`../create-your-own-pool/`](../create-your-own-pool/).

| | |
|--|--|
| **Role** | Live Chipnet example — not a hosted service |
| **Network** | Chipnet · `development-only` · Unaudited WIP |
| **API** | `loadInstance('chipnet-playground')` → `createKit` |
| **Instance id** | `chipnet-playground` |

## Setup (one-time)

Profile bundle (~455 MB) is **not in git**. Pin + sha256 in [`instance.json`](./instance.json).

```bash
# from monorepo root
npm run fetch-playground-bundle
# → chipnet-playground/bundle/

node create-your-own-pool/scripts/shieldkit.mjs playground doctor
```

## Play

```js
import { loadInstance, instanceToKitConfig } from '../create-your-own-pool/packages/profile/instance.mjs';
import { createKit } from '../create-your-own-pool/packages/kit/index.mjs';

const example = await loadInstance('chipnet-playground');
const kit = await createKit(instanceToKitConfig(example));
```

Then: → **[create-your-own-pool](../create-your-own-pool/)** for your genesis.
