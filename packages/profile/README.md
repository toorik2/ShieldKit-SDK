# `@shieldkit/profile`

**Init spine:** setup → build → load → genesis.

```js
import { init, loadProfile, planGenesis } from './index.mjs';

// development-only or ceremony-production (same pipeline)
const result = await init({
  mode: 'development-only', // | 'ceremony-production'
  setup: { /* r1cs, ptau, entropy… */ },
  bundle: { /* destination, profile, toolchain, network, genesis, artifacts */ },
  load: true,
});
```

| Export | Role |
|--------|------|
| `init` | Single pipeline setup(mode)→build→load |
| `loadProfile` / `loadVerifierProfileBundle` | Authenticated bundle load |
| `initializeDevelopmentGroth16` | Dev Phase-2 (internal to init) |
| `initializeCeremonyGroth16` | ≥2 contribs + transcript |
| `planGenesis` / `finalizeGenesis` | Offline genesis plan (network from profile) |

New setup ⇒ **new profile + new genesis**. No hot-swap. Mode laundering refused.
