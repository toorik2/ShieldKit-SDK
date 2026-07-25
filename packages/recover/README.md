# `@shieldkit/recover`

Note recovery from seed + caller-supplied chain history.

```js
import {
  deriveRecipientAddress,
  constructRecipientOutput,
  recoverRecipientOutput,
  recoverAuthenticatedHistory,
} from './index.mjs';
```

| Export | Role |
|--------|------|
| `deriveRecipientAddress` | Address from seed + profile/instance |
| `constructRecipientOutput` | Build encrypted record |
| `recoverRecipientOutput` | Decrypt one chain output |
| `recoverAuthenticatedHistory` | Contiguous authenticated history |

No indexer; application supplies history fields.
