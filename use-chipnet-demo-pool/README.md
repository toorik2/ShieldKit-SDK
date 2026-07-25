# Use Chipnet demo pool

> **Optional demo only.**  
> Product: sibling [`../create-your-own-pool/`](../create-your-own-pool/).

| | |
|--|--|
| **Role** | Live Chipnet example — not a hosted service |
| **Network** | Chipnet · `development-only` · Unaudited WIP |
| **API** | `loadInstance('use-chipnet-demo-pool')` → `createKit` |
| **Aliases** | `chipnet-playground`, `playground` |

## Setup (one-time)

Profile bundle (~455 MB) is **not in git**. Pin + sha256 in [`instance.json`](./instance.json).

```bash
# from monorepo root
npm run fetch-playground-bundle
# → use-chipnet-demo-pool/bundle/

npm run shieldkit -- playground doctor
```

## Play

```js
import { loadInstance, instanceToKitConfig } from '../create-your-own-pool/packages/profile/instance.mjs';
import { createKit } from '../create-your-own-pool/packages/kit/index.mjs';

const demo = await loadInstance('use-chipnet-demo-pool');
const kit = await createKit(instanceToKitConfig(demo));
```

Then: → **[create-your-own-pool](../create-your-own-pool/)** for your genesis.
