# `@shieldkit/profile`

V2 attested setup → V2 development profile → V2 instance package →
`loadInstance` → `createKit`.

The historical generic `init` and setup-to-profile bridge created the V1 legacy
`shielded-action-v2` relation. They are retained only as fail-closed compatibility
boundaries and cannot create or relabel a V2 Direct profile.

```js
import { loadInstance, instanceToKitConfig } from './index.mjs';
const mine = await loadInstance('./my-pool');
```

| Export | Role |
|--------|------|
| `loadInstance` / `instanceToKitConfig` | instance binding |
| `planGenesis` / `finalizeGenesis` | genesis |
| `initializeDevelopmentGroth16` | exact attested V2 Direct development setup |
| `buildV2DevelopmentProfilePackage` | exact V2 Direct profile package |
| `init` | quarantined historical V1 creation boundary |

V1 bundles remain readable as V1. They cannot be converted, relabeled, or
migrated into V2 Direct.
