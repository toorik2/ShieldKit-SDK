# Create your own pool

Product path: init → genesis → operate.  
Playground (optional): [`../02-use-chipnet-demo-pool/`](../02-use-chipnet-demo-pool/).

| | |
|--|--|
| App | [`packages/kit`](packages/kit/) · `createKit` |
| Profile / instance / genesis | [`packages/profile`](packages/profile/) |
| CLI | [`scripts/shieldkit.mjs`](scripts/shieldkit.mjs) |
| Init template | [`templates/init.development.json`](templates/init.development.json) |

Protocol: [`docs/EXTERNAL_CONTRIBUTIONS.md`](docs/EXTERNAL_CONTRIBUTIONS.md).

```bash
npm test
node 03-create-your-own-pool/scripts/shieldkit.mjs --help
npm run create-pool -- --out ./my-pool --with-genesis --scan-fund --max-notes 16 --broadcast
npm run shieldkit -- deposit  --pool ./my-pool --wallets … --broadcast
npm run shieldkit -- withdraw --pool ./my-pool --wallets … --broadcast
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));
```

- New setup ⇒ new profile + new genesis (no hot-swap onto playground).
- After genesis: no admin/pause/upgrade key; capacity frozen.
- Live anonymity set = live notes at spend time (≤ `maxLiveNotes`).
- The built-in sequential contribution runner is
  `local-contribution-simulation`, not a production ceremony.
- External signed, hash-chained contribution receipts are supported, but
  production qualification additionally requires independently governed
  contributors, an audit, and a new genesis. This release creates no
  `production-qualified` profile.

```text
packages/   kit · profile · action · prove · recover · unlock-builder
scripts/    shieldkit · tests · fetch-*
docs/       CHARTER · PRIVACY · PROFILES · ARCHITECTURE · VERSIONING
```
