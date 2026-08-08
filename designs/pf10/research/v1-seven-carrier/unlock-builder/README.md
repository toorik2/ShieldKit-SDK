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
**Blank machine:** run root `npm ci`, then `npm run unlock-builder:setup`. The explicit setup consumes only the root npm lock plus tracked vendored Yarn/pnpm locks; root postinstall performs integrity checks and never resolves nested dependencies.
Not for browsers (~30s compile).
