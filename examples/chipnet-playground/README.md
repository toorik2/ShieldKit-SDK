# Chipnet playground — live example

> **ShieldKit creates shielded pools.  
> This is our Chipnet demo instance — an example you can play with.  
> Your product path is [create your own pool](../create-your-pool/) with your genesis.**

| | |
|--|--|
| **Role** | Optional **example** — not a hosted service for third-party apps |
| **Network** | Chipnet · `development-only` · Unaudited WIP |
| **API** | Same as any pool: `loadInstance` → `createKit` |

Use this to learn deposit / transfer / withdraw / recover against a real instance, then stand up **yours**.

---

## Setup (one-time)

Profile bundle (~455 MB proving key) is **not in git**.

```bash
export SHIELDKIT_PLAYGROUND_BUNDLE=/path/to/profile-bundle
# or: examples/chipnet-playground/bundle/  or lab .cache path (maintainers)
```

```bash
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs playground profile-info
```

---

## Play (then create your own)

```js
import { loadInstance, instanceToKitConfig } from '../../packages/profile/instance.mjs';
import { createKit } from '../../packages/kit/index.mjs';

const example = await loadInstance('chipnet-playground');
const kit = await createKit(instanceToKitConfig(example));
// same verbs you will use on your pool
```

```bash
node scripts/shieldkit.mjs playground deposit --request ./prep.json
```

You supply Chipnet RPC, fee keys, proofs, broadcast. Tip comes from **your** chain view.

When you are ready: → **[create-your-pool](../create-your-pool/)**

---

## Coordinates

Pinned in [`instance.json`](./instance.json) (profileId, instanceId, category).  
Immutable for this example. A new pool = new genesis, not a hot-swap of these IDs.
