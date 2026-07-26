# `@shieldkit/profile`

init → bundle → genesis → `loadInstance` → `createKit`.

```js
import { init, loadInstance, instanceToKitConfig } from './index.mjs';
const born = await init({ mode: 'development-only', setup: {…}, bundle: {…}, load: true });
const mine = await loadInstance('./my-pool');
```

| Export | Role |
|--------|------|
| `init` | setup → build → load |
| `loadInstance` / `instanceToKitConfig` | instance binding |
| `planGenesis` / `finalizeGenesis` | genesis |
| `initializeDevelopmentGroth16` / `initializeCeremonyGroth16` | via init |

New setup ⇒ new profile + genesis. Mode laundering refused.
