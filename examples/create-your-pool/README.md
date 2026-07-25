# Create your own pool

> **This is the product path.**  
> ShieldKit exists so you can create and run **your** shielded pool.  
> The [Chipnet playground](../chipnet-playground/) is only a live example to try first.

| | |
|--|--|
| **Who** | Anyone shipping their own instance |
| **What** | Init (dev or ceremony) → genesis → operate with the same kit as the example |
| **Not** | Depending on our playground for production |

---

## Flow

```text
init (development-only | ceremony-production)
  → profile bundle + instance.json
  → genesis (on-chain)
  → createKit / deposit | transfer | withdraw | recover
```

Same shape as the playground: **instance descriptor + profile bundle** — but **your** genesis.

---

## Steps

1. **Init**

```bash
node scripts/shieldkit.mjs init --config ./init.example.json
# or: import { init } from '../../packages/profile/init.mjs'
```

2. Write **`instance.json`** next to your bundle (mirror playground fields; `role: "custom"`).

3. **Genesis** — fund category input; plan/finalize via `packages/profile` genesis helpers.

4. **Operate**

```js
import { loadInstance, instanceToKitConfig } from '../../packages/profile/instance.mjs';
import { createKit } from '../../packages/kit/index.mjs';

const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));
```

---

## Ceremony / mainnet

Production privacy claims: `ceremony-production` + **new** genesis.  
No hot-swap onto the playground or any existing instance.

Optional first step: [try the example playground](../chipnet-playground/).
