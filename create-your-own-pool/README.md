# Create your own pool

**This is the product.**  
ShieldKit = toolkit to birth and run **your** BCH shielded pool.

Optional live demo (sibling dir): [`../use-chipnet-demo-pool/`](../use-chipnet-demo-pool/).

## Start

| Layer | Path |
|-------|------|
| App entry | [`packages/kit`](packages/kit/) — `createKit` |
| Init / instance / genesis | [`packages/profile`](packages/profile/) |
| Init config sketch | [`templates/init.development.json`](templates/init.development.json) |
| CLI | [`scripts/shieldkit.mjs`](scripts/shieldkit.mjs) |

```bash
# from monorepo root
npm test
node create-your-own-pool/scripts/shieldkit.mjs --help
node create-your-own-pool/scripts/shieldkit.mjs init --config create-your-own-pool/templates/init.development.json
```

```js
import { createKit, loadInstance, instanceToKitConfig } from './packages/kit/index.mjs';

// after init + genesis + instance.json for your pool
const mine = await loadInstance('./my-pool');
const kit = await createKit(instanceToKitConfig(mine));
```

## Flow

```text
init (development-only | ceremony-production)
  → profile bundle
  → instance.json (role: "custom")
  → genesis (on-chain)
  → createKit / deposit | transfer | withdraw | recover
```

New setup ⇒ **new profile + new genesis**. No hot-swap onto the playground.

## Layout

```text
create-your-own-pool/
  packages/   kit · profile · action · prove · recover
  scripts/    shieldkit · tests · fetch-playground-bundle
  templates/  init.development.json
  docs/       CHARTER · PRIVACY · PLAYGROUND · ARCHITECTURE
```

Production privacy claims: `ceremony-production` + new genesis only.
