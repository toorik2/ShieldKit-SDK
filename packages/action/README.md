# `@shieldkit/action`

Prep + settlement + witness + packets (no g2-* public names).

```js
import {
  planPrep, finalizePrep,
  planCompleteSettlement, assembleCompleteSettlement,
  generateFreshWitnessInputs,
} from './index.mjs';
```

| Export | Role |
|--------|------|
| `planPrep` / `finalizePrep` | Complete preparation transaction |
| `buildSettlementTransaction` | Encode 10-input settlement |
| `planCompleteSettlement` / `assembleCompleteSettlement` | Full settlement path |
| `generateFreshWitnessInputs` | Deterministic witness material |
| `encodeActionPacket` / `encodeSettlementContext` / `encodeStateNftCommitment` | Wire shapes |

Size gates: unlock ≤10k B; settlement ≤59k B; fee 1 sat/B.
