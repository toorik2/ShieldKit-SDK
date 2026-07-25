# Demo profile (Chipnet, development-only)

ShieldKit does not ship mainnet keys. For a **local lab** profile:

## Option A — existing lab cache (this machine)

If you have already built a Chipnet development profile:

```bash
# example path used in lab runs (gitignored .cache)
export SHIELDKIT_DEMO_BUNDLE="$PWD/.cache/profile-build-live/profile-bundle"

node scripts/shieldkit.mjs profile-info --bundle "$SHIELDKIT_DEMO_BUNDLE"
node scripts/shieldkit.mjs doctor --network chipnet --mode development-only
```

## Option B — build via `init`

See `init.example.json` shape and:

```js
import { init } from '../../packages/profile/init.mjs';
// await init({ mode: 'development-only', setup: {...}, bundle: {...}, load: true })
```

Or CLI (fail-closed without config):

```bash
node scripts/shieldkit.mjs init --config ./init.example.json
# exits ok:false until you fill real r1cs/ptau/artifact paths
```

## Mainnet

One config change: `--network mainnet` / `network: 'mainnet'`.

You will always see: **Unaudited — Work In Progress**.  
Broadcast still needs `--i-understand-mainnet`. Production claims need `ceremony-production` + new genesis.
