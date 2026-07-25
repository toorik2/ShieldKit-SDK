# ShieldKit

**Create and run your own BCH shielded pool.**  
Your keys. Your frontend. Your instance.

We do **not** offer a hosted pool for third-party apps. The Chipnet playground is an optional live demo only.

---

## Quick start

```bash
npm test
npm run shieldkit -- --version

# Unlock builder pin (Node-only; no sibling verifier.cash)
npm run unlock-builder:smoke

# Pin circuit artifacts (~450MB) — pack once, fetch/install to .cache
npm run pack-pin-artifacts          # from existing arts → .cache/pins/*.tar.gz
npm run fetch-pin-artifacts         # install into .cache/profile-build-live/artifacts

# Scaffold / new on-chain genesis
npm run create-pool -- --out ./my-pool
npm run create-pool -- --out ./new-pool --with-genesis \
  --fund-txid <txid> --fund-vout 1 --broadcast

# Doctor + full act against a pool dir
npm run shieldkit -- doctor --pool ./my-pool
npm run shieldkit -- deposit --pool ./my-pool --wallets … --broadcast
npm run shieldkit -- withdraw --pool ./my-pool --wallets … --broadcast

# Battery e2e (needs wallets + layer1-node SSH + tip state)
npm run e2e:standalone
```

```js
import {
  createKit,
  completeAction,
  loadInstance,
  instanceToKitConfig,
} from './create-your-own-pool/packages/kit/index.mjs';
import { buildVerifierUnlocks, PIN_LENS } from './create-your-own-pool/packages/unlock-builder/index.mjs';

// Fee: policy A feePrivateKey, or policy B feePublicKey + feeSignature
```

You own: **keys · frontend · RPC · broadcast**.  
Unlock compile: `@shieldkit/unlock-builder` (vendored C7; progress logs every 5s).

UX red team: `create-your-own-pool/docs/UX_ADVERSARIAL_REDTEAM.md`.
