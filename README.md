# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

We do **not** offer a hosted pool for third-party apps. The Chipnet playground is an optional live demo only.

---

## Quick start

```bash
npm test
npm run shieldkit -- --version

# Unlock builder pin (Node-only; no sibling verifier.cash)
npm run unlock-builder:smoke

# Scaffold a pool dir from the pinned development profile
npm run create-pool -- --out ./my-pool

# Full Chipnet act spine (deposit→transfer→withdraw) via product APIs
npm run e2e:standalone
```

```js
import {
  createKit,
  completeAction,
  loadInstance,
  instanceToKitConfig,
} from './create-your-own-pool/packages/kit/index.mjs';
import { buildVerifierUnlocks, PIN_LENS } from './create-your-own-pool/packages/unlock-builder/index.mjs';

// Your pool (after create-pool / genesis)
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));

// Settlement unlocks (Node): buildVerifierUnlocks / completeAction
```

You own: **keys · frontend · RPC · broadcast**.  
Unlock compile ships in `@shieldkit/unlock-builder` (vendored C7 pin).
