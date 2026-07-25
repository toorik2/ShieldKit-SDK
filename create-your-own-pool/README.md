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

```bash
# Privacy-ready Chipnet pool (default: 16 live notes = 1.6 BCH reserve cap)
npm run create-pool -- --out ./my-pool --with-genesis --scan-fund --max-notes 16 --broadcast

# Grow the live set (each deposit stacks an open note)
npm run shieldkit -- deposit  --pool ./my-pool --wallets … --broadcast  # openNotes=1
npm run shieldkit -- deposit  --pool ./my-pool --wallets … --broadcast  # openNotes=2
npm run shieldkit -- deposit  --pool ./my-pool --wallets … --broadcast  # openNotes=3
# Withdraw — wallet picks which of *your* notes; chain sees one of N live
npm run shieldkit -- withdraw --pool ./my-pool --wallets … --broadcast  # openNotes=2
```

New setup ⇒ **new profile + new genesis**. No hot-swap onto the playground.  
After genesis: **no admin / pause / upgrade key** — capacity and scripts are frozen.  
Live anonymity set size = live notes at spend time (≤ `maxLiveNotes`), not historical deposits alone.

## Layout

```text
create-your-own-pool/
  packages/   kit · profile · action · prove · recover
  scripts/    shieldkit · tests · fetch-playground-bundle
  templates/  init.development.json
  docs/       CHARTER · PRIVACY · PLAYGROUND · ARCHITECTURE
```

Production privacy claims: `ceremony-production` + new genesis only.
