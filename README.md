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

# Scaffold from local pin profile (requires .cache/profile-build-live pin arts)
npm run create-pool -- --out ./my-pool

# New on-chain instance (needs fund UTXO + BCHN + pin artifacts)
npm run create-pool -- --out ./new-pool --with-genesis \
  --fund-txid <txid> --fund-vout 1 --broadcast

# Full Chipnet act spine (needs wallets + layer1-node SSH + live tip state)
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

// Settlement unlocks (Node): buildVerifierUnlocks / completeAction
// Fee: policy A feePrivateKey, or policy B feePublicKey + feeSignature
```

You own: **keys · frontend · RPC · broadcast**.  
Unlock compile ships in `@shieldkit/unlock-builder` (vendored C7 pin).

**Honest limits:** pin circuit artifacts (zkey/r1cs) are large and currently local (`.cache/profile-build-live`); cold clone still needs that pin pack for create-pool. Live e2e needs your Chipnet RPC + wallets. UX red team: `create-your-own-pool/docs/UX_ADVERSARIAL_REDTEAM.md`.
