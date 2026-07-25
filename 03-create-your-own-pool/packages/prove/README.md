# `@shieldkit/prove`

Local Groth16 prove/verify and PF7 unlock surface.

```js
import { adaptSnarkjsGroth16, parsePf7CarrierAuthority } from './index.mjs';
```

| Export | Role |
|--------|------|
| `adaptSnarkjsGroth16` | snarkjs proof → PF7 fields |
| `parsePf7CarrierAuthority` | PF7 carrier authority |
| unlock helpers | sizing / fixed-point path |

Lab tooling: [`lab/`](lab/). Covenant support: [`internal/`](internal/).
