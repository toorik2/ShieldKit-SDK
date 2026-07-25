# Create your own pool

> **ShieldKit creates shielded pools. The Chipnet playground is our pool. Your pool is the same thing with your genesis.**

| | |
|--|--|
| **Who** | **Pool creators** |
| **What** | Birth a new profile + instance (dev or ceremony), then use the **same** act/recover path |
| **Not** | A different SDK |

---

## Flow

```text
init (development-only | ceremony-production)
  → profile bundle + instance.json
  → genesis (on-chain)
  → createKit / shieldkit deposit|transfer|withdraw|recover
```

Same shape as the playground: an **instance descriptor** + **profile bundle**.

---

## Steps

1. **Init** (development-only for Chipnet lab):

```bash
# fill paths/hashes first — see init.example.json
node scripts/shieldkit.mjs init --config ./init.example.json
```

Or library: `import { init } from '../../packages/profile/init.mjs'`.

2. **Emit `instance.json`** next to your bundle (same fields as playground; `role: "custom"`).

3. **Genesis** — plan/finalize with `packages/profile` genesis helpers; fund category input.

4. **Operate** — identical to playground:

```js
import { loadInstance, instanceToKitConfig } from '../../packages/profile/instance.mjs';
import { createKit } from '../../packages/kit/index.mjs';

const mine = await loadInstance('./my-pool'); // directory with instance.json + bundle/
const kit = await createKit(instanceToKitConfig(mine));
```

---

## After ceremony

Production privacy claims require `ceremony-production` + **new** genesis (new instance).  
No hot-swap onto an existing playground or lab instance.

---

## Try ours first

→ [`../chipnet-playground/`](../chipnet-playground/)
