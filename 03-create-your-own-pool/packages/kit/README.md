# `@shieldkit/kit`

```js
import { createKit } from './index.mjs';
const kit = await createKit({
  network: 'chipnet', // or 'mainnet' + mainnetAcknowledged
  bundleDirectory: './profile-bundle',
  expectedProfile: { network: 'chipnet', profileId, instanceId },
});
```

| Method | Role |
|--------|------|
| `planAction` / `planCompletePreparation` | prep plan |
| `preparationSigningRequest` | fee Schnorr digest |
| `finalizeCompletePreparation` | attach fee sig |
| `planWitnessBoundSettlements` | settlement plan |
| `recoverAuthenticatedHistory` | notes from seed + history |
| `broadcastRaw` / `assertCanBroadcast` | optional; mainnet gated |
| `explorerTxUrl` | explorer link |

No key storage or sockets.
