# `@shieldkit/kit`

**Primary app facade** — `createKit` only.

```js
import { createKit, productWarnings, PRODUCT_STATUS } from './index.mjs';

const kit = await createKit({
  network: 'chipnet', // or 'mainnet' (one config change; Unaudited WIP)
  bundleDirectory: './profile-bundle',
  expectedProfile: { network: 'chipnet', profileId, instanceId },
  mainnetAcknowledged: false,
});
console.log(kit.warnings); // always includes product status
```

## Methods

| Method | Role |
|--------|------|
| `planAction` / `planCompletePreparation` | Offline prep plan for deposit/transfer/withdrawal |
| `preparationSigningRequest` | Schnorr digest for fee input (you hold the key) |
| `finalizeCompletePreparation` | Attach signature → prep tx bytes |
| `planWitnessBoundSettlements` | Witness-bound settlement planning |
| `recoverAuthenticatedHistory` | Notes from seed + history you supply |
| `broadcastRaw` | Optional callback; mainnet gated |
| `assertCanBroadcast` | Explicit gate check |
| `explorerTxUrl` | Explorer link for network |

No private keys, sockets, or persistence. Mainnet = `network: 'mainnet'` + warnings + broadcast ack.
