# `@shieldkit/unlock-builder`

Node-only factory for **7-role verifier unlocks** used in complete settlement.

## Why this package exists

Settlement spends seven P2SH32 carriers whose **locks** live in the profile
`bch-verifier-set` and whose **unlocks** are proof-dependent. Building unlocks
used to require a sibling `verifier.cash` checkout. This package is the product
entry point so a blank machine path can call one API.

## Public API

```js
import {
  buildVerifierUnlocks,
  PIN_LENS,
} from '../unlock-builder/index.mjs';

const out = buildVerifierUnlocks({
  adapterPath: '/abs/adapter.json',   // snarkjs-groth16-pf7-adapter/v1
  packetPath: '/abs/action.packet', // 752-byte packet
  outDir: '/abs/stage',
});
// out.roles[0..6]: { name, lockHex, unlockHex, unlockLen, … }
// out.lens === PIN_LENS under the live pin
```

## Pin contract

| Item | Value |
|------|--------|
| `PIN_LENS` | `[8177, 6654, 7066, 7066, 8393, 7600, 9350]` |
| densFuel | `C7_DENSFUEL_DROP=1` |
| length stabilize | genesis 7600 / terminal 9350 |

**Changing densFuel / stabilize / fixed-G2 table changes P2SH32 locks.**  
That requires a **new verifier-set + new profile + new genesis**. Never “optimize”
flags under a stable facade.

## Toolchain resolution (Phase 1 → 2)

1. `SHIELDKIT_UNLOCK_ROOT` (or legacy `SHIELDKIT_PF7_WORKTREE`)
2. `packages/unlock-builder/vendor/` (Phase 2 — default for blank machine)
3. `.worktrees/verifier-pf7-sub62` (migration escape hatch only)

Lean fold host: `SHIELDKIT_LEANBCH` → vendor lean host → `.worktrees/leanbch-pf7`.

## Not for browsers

Unlock compile spawns `tsx` + CashScript + density packing (~30s, tens of MB).
Kit browser surfaces must fail closed if this package is missing.

## Fee / settle policy (product)

Desktop CLI may pass fee keys in-process for settlement assembly (policy A).
Prep remains external Schnorr digest signing where possible.
