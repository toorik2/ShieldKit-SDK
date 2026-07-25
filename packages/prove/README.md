# `@shieldkit/prove`

In-tree Groth16 + PF7 unlock surface (not dens-drop worktree folklore).

```js
import { adaptSnarkjsGroth16, parsePf7CarrierAuthority } from './index.mjs';
```

| Export | Role |
|--------|------|
| `adaptSnarkjsGroth16` | Parse/verify snarkjs proof → PF7 fixture fields |
| `parsePf7CarrierAuthority` | PF7 carrier authority |
| `measurePf7FixedPointCandidate` / `verifyPf7FixedPointCandidate` | Unlock sizing path |

Local proving only; kit never hosts a prover.
