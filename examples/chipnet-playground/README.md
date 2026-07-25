# Chipnet playground — our pool

> **ShieldKit creates shielded pools. This playground is our pool. Your pool is the same thing with your genesis.**

| | |
|--|--|
| **Who** | **App builders** connecting an app (or CLI) to a live pool |
| **What** | Official **Chipnet** instance of ShieldKit (development-only) |
| **Not** | Production privacy · mainnet · a second API |

Same `createKit` / same verbs as any pool you create. Only the **instance binding** is fixed here.

---

## Setup (one-time)

1. Obtain the **profile bundle** for this instance (~455 MB proving key — not in git).
2. Point the kit at it:

```bash
# recommended
export SHIELDKIT_PLAYGROUND_BUNDLE=/path/to/profile-bundle

# or copy/symlink to:
# examples/chipnet-playground/bundle/   (must contain manifest.json + artifacts/)
```

Maintainers with a local lab build can use:

```bash
export SHIELDKIT_PLAYGROUND_BUNDLE="$PWD/.cache/profile-build-live/profile-bundle"
```

3. Confirm:

```bash
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs playground profile-info
```

---

## Use (app builders)

```js
import { loadInstance, instanceToKitConfig } from '../../packages/profile/instance.mjs';
import { createKit } from '../../packages/kit/index.mjs';

const playground = await loadInstance('chipnet-playground');
const kit = await createKit(instanceToKitConfig(playground));

// kit.planAction / recover / broadcast — identical to your own pool
console.log(kit.profile.profileId, kit.warnings);
```

CLI:

```bash
node scripts/shieldkit.mjs playground doctor
node scripts/shieldkit.mjs playground deposit --request ./prep.json
# transfer / withdraw / recover same as global verbs, with playground binding
```

You supply: **Chipnet RPC · fee keys · proofs · broadcast**.  
State tip and UTXOs come from **your** chain view — not from this folder.

---

## Coordinates (pinned)

See [`instance.json`](./instance.json):

- network: `chipnet`
- setupMode: `development-only`
- profileId / instanceId / state NFT category (immutable for this playground)

Creating a **new** pool means a **new** genesis — never hot-swap these IDs.

---

## Create your own pool instead

→ [`../create-your-pool/`](../create-your-pool/)
