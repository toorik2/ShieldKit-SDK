# ShieldKit

**Private notes. Public rules. Your pool.**

Fixed-denomination (0.1&nbsp;BCH) shielded pools on **Bitcoin Cash** — deposit, private transfer, withdraw — with proofs you build locally and covenants the chain enforces.

No hosted pool. No sequencer. No admin key after birth.

---

## After genesis: can’t do evil

Once a pool is born, **protocol authority is fixed**:

| Locked forever | Absent forever |
|----------------|----------------|
| Profile, scripts, VK, encodings | Admin / pause / rescue key |
| Max live capacity (`maximumReserve`) | Upgrade or hot-swap path |
| Fee law (exactly **1 sat/byte**) | Protocol fee or “maintainer cut” |
| State tip = one CashToken NFT | Hidden governance |

There is **no post-genesis control plane**. Successors require a **new profile + new genesis** and explicit user migration. Maintainers may ship software and advisories — they **cannot authorize funds**.

> **Honest bounds:** local / Chipnet setups are **`development-only`** (not multi-party ceremony). Production privacy claims need ceremony-backed material. Unaudited WIP — see [`SECURITY.md`](./SECURITY.md). Trust is **front-loaded at birth** (verify the profile you join); evil cannot be patched in later, and privilege cannot be patched in either.

---

## Three ways in

<table>
<tr>
<td width="33%" valign="top">

### 1 · Learn the system

Interactive explainer: covenants, State NFT tip, PREP → SETTLE, live anonymity set, fees, recovery.

**→ [`explainer/`](./explainer/)**

```bash
python3 -m http.server 8765 --directory explainer
# open http://127.0.0.1:8765/
```

Docs: [CHARTER](./create-your-own-pool/docs/CHARTER.md) · [PRIVACY](./create-your-own-pool/docs/PRIVACY.md) · [ARCHITECTURE](./create-your-own-pool/docs/ARCHITECTURE.md)

</td>
<td width="33%" valign="top">

### 2 · Try the live demo

Optional **Chipnet playground** — a real instance for hands-on acts. Not a product, not hosted SaaS, not your pool.

**→ [`use-chipnet-demo-pool/`](./use-chipnet-demo-pool/)**

```bash
npm run fetch-playground-bundle   # ~455MB profile arts
npm run shieldkit -- playground doctor
```

`development-only` · different `instanceId` from anything you create.

</td>
<td width="33%" valign="top">

### 3 · Create your own pool

The product: init → genesis → deposit / transfer / withdraw on **your** instance. Your keys, RPC, frontend, broadcast.

**→ [`create-your-own-pool/`](./create-your-own-pool/)**

```bash
npm run fetch-pin-artifacts
npm run create-pool -- --out ./my-pool \
  --with-genesis --scan-fund --max-notes 16 --broadcast

npm run shieldkit -- doctor  --pool ./my-pool
npm run shieldkit -- deposit --pool ./my-pool --wallets … --broadcast
```

Capacity is immutable at genesis. Grow the **live** set before privacy matters.

</td>
</tr>
</table>

---

## At a glance

| | |
|--|--|
| **Asset** | BCH only · **0.1 BCH** notes |
| **Actions** | deposit · shielded transfer · withdraw |
| **Chain machine** | PREP (fund carriers) → SETTLE (10 inputs, densFuel unlocks) |
| **State** | Single mutable **State NFT tip** · value = `1080 + reserveSats` |
| **Proofs** | Groth16 BN254, built **offline** · public input = packet digest limbs |
| **Recovery** | Seed + profile/instance + BCH history → open notes (spend `sk` · view `rk`) |
| **Default capacity** | 16 live notes (1.6 BCH reserve cap); CLI soft max 1024 |
| **Status** | Unaudited WIP · Chipnet first · mainnet not production-qualified |

---

## Repo map

```text
explainer/                 # learn — interactive system site
use-chipnet-demo-pool/     # try  — optional Chipnet demo instance
create-your-own-pool/      # build — product (kit · profile · action · prove · recover)
  packages/kit/            # createKit · completeAction
  packages/profile/        # init · genesis · loadInstance
  packages/action/         # prep · settle · witness · openNotes
  packages/prove/          # densFuel / PF7 authority
  packages/recover/        # seed + history
  scripts/                 # create-pool · shieldkit · doctor · pool-act
```

---

## Dev smoke

```bash
npm test
npm run shieldkit -- --version
npm run unlock-builder:smoke
```

```js
import {
  createKit,
  completeAction,
  loadInstance,
  instanceToKitConfig,
} from './create-your-own-pool/packages/kit/index.mjs';
```

You own: **keys · frontend · RPC · broadcast**.  
Unlock compile: `@shieldkit/unlock-builder` (Node-only pin; progress every 5s).

---

## License & security

[LICENSE](./LICENSE) · [SECURITY](./SECURITY.md) · [CHANGELOG](./CHANGELOG.md)
