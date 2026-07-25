# `@shieldkit/profile`

**Product spine:** init → build/load → genesis → `loadInstance` → hand off to `createKit`.

This package **is** “create your own pool.” There is no separate examples path for that.

```js
import { init, loadInstance, instanceToKitConfig, planGenesis } from './index.mjs';
import { createKit } from '../kit/index.mjs';

// 1) Birth a profile (development-only or ceremony-production)
const born = await init({
  mode: 'development-only', // | 'ceremony-production'
  setup: { /* r1cs, ptau, entropy… — see templates/init.development.json */ },
  bundle: { /* destination, profile, toolchain, network, genesis, artifacts */ },
  load: true,
});

// 2) Write instance.json next to your profile bundle (role: "custom"), run genesis

// 3) Operate
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));
```

```bash
node scripts/shieldkit.mjs init --config templates/init.development.json
# then: genesis, then deposit/transfer/withdraw/recover with --bundle ./my-pool
```

| Export | Role |
|--------|------|
| `init` | setup(mode) → build → load |
| `loadProfile` / `loadVerifierProfileBundle` | Authenticated bundle load |
| `loadInstance` / `instanceToKitConfig` | Instance binding (your dir or built-in playground id) |
| `initializeDevelopmentGroth16` | Dev Phase-2 (via init) |
| `initializeCeremonyGroth16` | ≥2 contribs + transcript |
| `planGenesis` / `finalizeGenesis` | Offline genesis plan |

New setup ⇒ **new profile + new genesis**. No hot-swap. Mode laundering refused.

**development-only ptau:** trusted Hermez `final_20` pin defaults to **hash-only** (skips multi-hour `powersoftau verify`) with a loud warning + metadata implications. Force full verify: `setup.verifyPtau: true` or `shieldkit init --verify-ptau`. Ceremony always full-verifies.

**Optional live demo:** monorepo-root [`02-use-chipnet-demo-pool/`](../../../02-use-chipnet-demo-pool/) — `loadInstance('02-use-chipnet-demo-pool')`. Not a second product.
