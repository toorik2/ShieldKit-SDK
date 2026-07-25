# ShieldKit

**Private BCH transfers for apps that run their own pool.**

ShieldKit is an offline toolkit: you keep keys, frontend, and RPC.  
Deposit → transfer → withdraw on Bitcoin Cash, with local proving.

```text
Status:  Unaudited — Work In Progress
Network: Chipnet by default · Mainnet = one config change + warnings
Trust:   development-only setup ≠ production privacy
         Production claims need ceremony-production + new genesis
```

---

## Quick start

```bash
# Install / policy freeze
npm test

# Product CLI
node scripts/shieldkit.mjs --help
node scripts/shieldkit.mjs doctor
node scripts/shieldkit.mjs config-check --network chipnet
```

```js
import { createKit } from './packages/kit/index.mjs';

const kit = await createKit({
  network: 'chipnet', // or 'mainnet' (WIP warnings always shown)
  bundleDirectory: './path/to/profile-bundle',
  expectedProfile: {
    network: 'chipnet',
    profileId: 'sha256:…',
    instanceId: 'sha256:…',
  },
});

// kit.warnings  → includes "Unaudited — Work In Progress"
// kit.planAction(request) → prep plan (you sign)
// kit.recoverAuthenticatedHistory({ accountSeed, history })
```

You supply: **keys · proofs · fee UTXOs · broadcast**.  
ShieldKit never stores secrets or opens sockets.

---

## Four verbs

| Verb | CLI | Library |
|------|-----|---------|
| **init** | `shieldkit init --config init.json` | `profile/init` — setup → profile → load |
| **act** | `shieldkit deposit\|transfer\|withdraw --bundle … --request …` | `kit.planAction` → sign → prove → settle |
| **recover** | `shieldkit recover --bundle … --history … --seed-hex …` | `kit.recoverAuthenticatedHistory` |
| **doctor** | `shieldkit doctor` | network + honesty gates |

Missing inputs → **`ok: false`** (fail-closed). No fake success.

---

## Repository layout

This GitHub tree **is** the product surface.

```text
packages/
  kit/        createKit — only app facade
  profile/    init · ceremony/dev setup · genesis · load
  action/     preparation · settlement · witness
  prove/      Groth16 · PF7 unlocks
  recover/    notes from seed + history
scripts/
  shieldkit.mjs           CLI
  run-domain-tests.mjs    full unit suite
  check-policy.mjs        protocol freeze check
examples/demo-profile/    lab profile pointer + init example
docs/                     product + protocol authority docs
protocol/                 circuits · policy freeze · evidence · spec
research/                 lab only — not the product
```

| Open this | If you want… |
|-----------|----------------|
| `packages/kit` | App integration |
| `packages/profile` | Stand up a pool (dev or ceremony) |
| `examples/demo-profile` | Chipnet lab path |
| `docs/` | Charter, privacy, architecture |
| `research/` | Historical experiments (ignore for shipping) |

---

## Mainnet

One switch:

```js
network: 'mainnet'
// CLI: --network mainnet
```

Always: **Unaudited — Work In Progress**.  
Broadcast still requires `--i-understand-mainnet`.  
Production privacy: `--mode ceremony-production` + ceremony profile + **new genesis** (no hot-swap).

---

## Invariants

- Fee + change @ **1 sat/B** · unlock ≤ **10 000** B · settlement ≤ **59 000** B  
- Verifier topology: `bn254-onetx-pf7-sub62-r1` (7 PF7 inputs)  
- New setup ⇒ new profile + new genesis  

---

## Docs & safety

- [SECURITY.md](SECURITY.md) · [docs/PRIVACY.md](docs/PRIVACY.md) · [docs/CHARTER.md](docs/CHARTER.md)  
- Architecture: [docs/BEAUTIFUL_PLAN.md](docs/BEAUTIFUL_PLAN.md)  
- UX audit: [docs/UX_REDTEAM_AUDIT.md](docs/UX_REDTEAM_AUDIT.md)  

**Not** a hosted privacy service, wallet keystore, or generic ZK framework.

---

## License

See [LICENSE](LICENSE).
