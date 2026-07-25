# ShieldKit-SDK

Offline **BCH shielded-transfer toolkit**: birth a pool, act, recover.

> **Unaudited — Work In Progress.**  
> Local setup is permanently **`development-only`** unless you run a ceremony. That is **not** production privacy.  
> **Mainnet** = one config change (`network: 'mainnet'` / `--network mainnet`) plus warnings and broadcast ack — **not** a release claim.  
> Production privacy claims need **`ceremony-production`** + **new genesis**. Default network: **Chipnet**.

## Four verbs

| Verb | CLI | Library |
|------|-----|---------|
| **init** | `shieldkit init --config init.json` | `profile.init({ mode, setup, bundle })` |
| **act** | `shieldkit deposit\|transfer\|withdraw --bundle … --request …` | `kit.planAction` → sign → finalize → prove → assemble |
| **recover** | `shieldkit recover --bundle … --history … --seed-hex …` | `kit.recoverAuthenticatedHistory` |
| **doctor** | `shieldkit doctor --network … --mode …` | `assertBroadcastAllowed` / `productWarnings` |

Missing required inputs → **`ok: false`** (fail-closed; no fake success).

```bash
# Policy freeze (g0)
npm test

# Domain/unit suite (recommended before PR)
node scripts/run-domain-tests.mjs

node scripts/shieldkit.mjs doctor
node scripts/shieldkit.mjs config-check --network chipnet
node scripts/shieldkit.mjs config-check --network mainnet   # refuse without flags
node scripts/shieldkit.mjs deposit                          # ok:false — shows required inputs
node scripts/shieldkit.mjs --help
```

## Library

```js
import { createKit, PRODUCT_STATUS } from './packages/kit/index.mjs';

const kit = await createKit({
  network: 'chipnet', // or 'mainnet' (WIP warnings always attached)
  bundleDirectory: '/path/to/profile-bundle',
  expectedProfile: {
    network: 'chipnet',
    profileId: 'sha256:…',
    instanceId: 'sha256:…',
  },
});
// kit.warnings includes "Unaudited — Work In Progress"
// kit.planAction(request) / planCompletePreparation
// kit.recoverAuthenticatedHistory({ accountSeed, history })
```

You supply: keys, RPC/broadcast, proof/PF7 unlocks. Kit holds no secrets.

### `createKit` methods

| Method | Purpose |
|--------|---------|
| `planAction` / `planCompletePreparation` | Plan prep tx for deposit/transfer/withdrawal |
| `preparationSigningRequest` | Fee-input Schnorr digest |
| `finalizeCompletePreparation` | Attach signature |
| `planWitnessBoundSettlements` | Settlement planning after prove |
| `recoverAuthenticatedHistory` | Seed + history → notes |
| `broadcastRaw` | Optional; mainnet gated |
| `assertCanBroadcast` / `explorerTxUrl` | Safety helpers |

## Mainnet (one config change)

```js
network: 'mainnet'          // app / createKit
// CLI: --network mainnet
```

Always shown: **Unaudited — Work In Progress**.  
Broadcast: `--i-understand-mainnet`.  
Production claims: `--mode ceremony-production` + ceremony-backed profile + new genesis.

## Domains

```
packages/kit/       createKit
packages/profile/   init · load · setup(dev|ceremony) · genesis
packages/action/    prep · settlement · witness
packages/prove/     groth16 · PF7 unlocks
packages/recover/   notes / history
packages/mobile/    optional
```

## Demo profile

See **[examples/demo-profile/](examples/demo-profile/)** (Chipnet lab path + `init.example.json`).

## Docs

- [Beautiful plan](docs/BEAUTIFUL_PLAN.md) · [UX red-team](docs/UX_REDTEAM_AUDIT.md)  
- [SECURITY](SECURITY.md) · [Charter](docs/CHARTER.md) · [Privacy](docs/PRIVACY.md)

## Invariants

- Fee + change @ **1 sat/B**; unlock ≤ **10 000** B; settlement ≤ **59 000** B  
- Verifier: `bn254-onetx-pf7-sub62-r1` (7 PF7)  
- New setup ⇒ new profile + new genesis (no hot-swap)
