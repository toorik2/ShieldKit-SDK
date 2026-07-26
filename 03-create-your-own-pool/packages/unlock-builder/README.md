# `@shieldkit/unlock-builder`

Node-only build of **7 densFuel verifier unlocks** for settlement.

```js
import { buildVerifierUnlocks, PIN_LENS } from './index.mjs';
const out = buildVerifierUnlocks({ adapterPath, packetPath, outDir });
// out.roles[0..6]: lock/unlock hex; out.lens === PIN_LENS
```

| Pin | Value |
|-----|--------|
| `PIN_LENS` | `[8177, 6654, 7066, 7066, 8393, 7600, 9350]` |
| densFuel | `C7_DENSFUEL_DROP=1` |

Changing densFuel/stabilize/G2 table ⇒ new verifier-set + profile + genesis.

**Resolve toolchain:** `SHIELDKIT_UNLOCK_ROOT` → `vendor/verifier` + `vendor/lean`.  
**Blank machine:** root `npm install` runs `setup-unlock-toolchain.mjs` (or `npm run unlock-builder:setup`). Skip: `SHIELDKIT_SKIP_UNLOCK_SETUP=1`.  
Not for browsers (~30s compile).
