# ShieldKit — beautiful plan (first principles)

Status: **supersedes** “park ceremony / no rename / thin facade over many packages” framing.  
Rule: **inner beauty first** — bold toward simplicity, elegance, minimalism.  
Audience: app devs (own pool + FE), operators (ceremony), agents implementing this.

---

## 0. First principles

What ShieldKit *is*, in one sentence:

> Offline tools to **birth** a typed shielded pool, **run** deposit/transfer/withdraw against it, and **recover** notes — on BCH — with local secrets and local proving.

Everything else is implementation detail or research sediment.

User cares about **four verbs**:

| Verb | Meaning |
|------|---------|
| **init** | Birth keys + profile (dev *or* ceremony) + genesis |
| **act** | deposit / transfer / withdraw |
| **recover** | notes from seed + history |
| **doctor** | am I configured honestly? |

If the tree or API does not map to those verbs, it is noise until proven necessary.

---

## 1. Holistic critique (current state)

### 1.1 User surface is not simple enough

Today the “simple path” still requires:

1. Know `profile bundle` + `profileId` + `instanceId` coordinates  
2. Run/find `local-setup` → `setup-profile-bridge` → `profile-builder` → `chipnet-genesis` (four concepts)  
3. Call prep + witness + prove + PF7 dens-drop + assemble + settle (five+ packages, some under `g2-*` names)  
4. Choose between **app-kit** and **sdk** (two facades; app-kit wraps sdk)  
5. Learn research words: PF7, G2, dens-drop, fixed-point, replacement-drill  

**Verdict:** honest banners exist; **cognitive load is research-shaped**, not product-shaped. Ceremony parked as “later” made production trust feel bolted-on instead of the other mode of `init`.

### 1.2 Folder / package sprawl (~25 packages)

| Smell | Examples |
|-------|----------|
| Gate-era IDs as product names | `g2-complete-assembler`, `pf7-verifier-generator`, `pf7-fixed-point` |
| One idea, many folders | setup: `local-setup` + `setup-profile-bridge` + `profile-builder` + `chipnet-genesis` |
| Parallel facades | `app-kit` + `sdk` (+ brand split `@shieldkit/*` vs `@shield.cash/*`) |
| Proof zoo | `snarkjs-adapter`, `native-prover-adapter`, `browser-prover`, `android-prover-harness`, `prover-artifact-budget`, `proof-corpus` |
| Drill / evidence as packages | `profile-replacement-drill`, `conformance`, `proof-corpus` |
| Opaque glue | `fresh-witness-inputs`, `settlement-context`, `action-packet` — correct pieces, wrong *public* topology |

**Verdict:** fine for a gate research monorepo; **wrong topology for a kit**. Users should not navigate 25 peers of equal visual weight.

### 1.3 Under the hood — not yet holistically beautiful

**Strengths (keep):**

- Typed verifier-profile loader (both modes in schema/core)  
- Immutable profile/instance; no hot-swap  
- Offline-first, no key custody, 1 sat/B, size gates  
- Real Chipnet E2E existence proof  

**Ugliness (fix):**

| Area | Issue |
|------|--------|
| Setup spine | Dev runner exists; ceremony only schema; bridge refuses ceremony; four steps instead of one `init` pipeline |
| Settlement spine | Logical one “complete action tx” split across packet/context/settlement/g2-assembler/prep with gate names |
| Prove spine | Product path still couples to dens-drop research tool / worktree culture |
| Dual facade | app-kit is a thin shell over sdk — not a clean single kernel |
| Naming | `shield.cash` / `shield-cash-protocol` / ShieldKit / G0 freeze brand debt |
| Scripts | Many `shieldkit-*.mjs` siblings instead of one CLI with subcommands |
| Docs | Multiple goal/polish plans; product story diluted |

**Verdict:** *pieces* are often excellent; *composition* is research archaeology. Beauty = **one spine per verb**, not more packages.

---

## 2. Target product model (simple for humans)

### 2.1 Mental model (teach once)

```
Profile  = frozen physics (circuit, VK, scripts, setup mode)
Instance = one live genesis of that profile on a network
Note     = your private claim inside an instance
Action   = deposit | transfer | withdraw  (prep + prove + settle)
```

Setup mode is a **field on the profile**, not a different product:

- `development-only` — lab / own-pool experiment  
- `ceremony-production` — multi-party phase-2; required for production privacy claims  

Same act/recover code. Different trust story. New keys ⇒ **new profile + new genesis** always.

### 2.2 One user journey

```text
shieldkit doctor
shieldkit init --mode dev|ceremony ...   → profile dir + genesis plan
shieldkit deposit | transfer | withdraw  → plan → (you sign/prove) → hex
shieldkit recover ...
```

Library:

```js
import { createKit } from '@shieldkit/kit';

const kit = await createKit({ network, profileDir, expected: { profileId, instanceId } });
await kit.deposit(...);  // same verbs
```

No second “sdk vs app-kit” choice. Advanced modules are **imports under domains**, not competing entrypoints.

### 2.3 Simplicity checklist (must pass)

| Check | Target |
|-------|--------|
| Folders a user lists | ≤ **6** top-level product packages (not 25) |
| Facades | **1** (`@shieldkit/kit`) |
| CLI | **1** binary / script tree: `shieldkit <verb>` |
| Init modes | **2** strings on one pipeline, not two product tracks |
| Names | English verbs/nouns; **zero** G-gate tokens in public paths |
| Ceremony | First-class `init --mode ceremony`; same load/act path after |
| Demo | Optional pinned Chipnet **dev** profile: try without ceremony |

---

## 3. Target tree (bold consolidation)

Collapse by **domain**, not by historical PR.

```text
shieldkit-sdk/
├── README.md · LICENSE · SECURITY.md
├── package.json                    # name: shieldkit (or @shieldkit/monorepo)
├── circuits/                       # relation source (unchanged home)
├── packages/
│   ├── kit/                        # ★ only public facade + CLI helpers
│   ├── profile/                    # load · setup(dev|ceremony) · build · genesis · replace
│   ├── action/                     # witness · prep · settle · packet · context · state
│   ├── prove/                      # groth16 prove/verify · PF7 unlock pipeline (in-tree)
│   ├── recover/                    # note + history recovery
│   └── (optional) mobile/          # android/browser adapters — not golden path
├── scripts/shieldkit.mjs           # single CLI entry (subcommands)
├── docs/                           # charter, privacy, THIS plan, kill gates
├── spec/                           # normative manifest/lifecycle (keep thin)
├── evidence/ · policy/ · examples/
└── dev/research/                       # quarantined; not product map
```

### 3.1 What merges where

| New home | Absorbs (delete as top-level packages) |
|----------|----------------------------------------|
| **profile/** | `core` (profile loader + IDs), `local-setup`, `setup-profile-bridge`, `profile-builder`, `chipnet-genesis`, `profile-replacement-drill`, ceremony runner |
| **action/** | `preparation-transaction`, `settlement-transaction`, `settlement-context`, `action-packet`, `state-nft`, `fresh-witness-inputs`, `g2-complete-assembler` |
| **prove/** | `snarkjs-adapter`, in-tree PF7 unlock path (from dens-drop / `pf7-*` product core), budgets as internal |
| **recover/** | `recovery` |
| **kit/** | `app-kit` + `sdk` (one API) |
| **dev/research/** or drop | pure gate harnesses, corpus packaging if not runtime: `proof-corpus`, `conformance` as tools under `scripts/` or `evidence/` |
| **mobile/** (late) | `browser-prover`, `android-prover-harness`, `native-prover-adapter` |

### 3.2 Naming rules (hard)

| Forbidden in public names | Prefer |
|---------------------------|--------|
| `g2-*`, `G0`, gate codes | `completeSettlement`, `assembleAction` |
| `local-setup` as only word for init | `setup` + `mode` |
| `setup-profile-bridge` | internal step of `profile.buildFromSetup` |
| `chipnet-genesis` only | `genesis` (network param) |
| Dual `@shield.cash` / `@shieldkit` | **one** scope: `@shieldkit/*` (schemas may keep stable domain strings until a versioned cut) |
| `createDesktopWalletSdk` / `createAppKit` | `createKit` |

Internal file names may keep precision (`pf7Unlock.mjs`); **package and CLI names** stay human.

### 3.3 Ceremony as first-class — not a folder empire

Inside `packages/profile/`:

```text
profile/
  load.mjs              # existing loader (move from core)
  setup/
    kernel.mjs          # ptau/r1cs/snarkjs pin, entropy FD, verify
    development.mjs     # mode development-only (today’s local-setup)
    ceremony.mjs        # multi-party rounds + transcript + finalize
    metadata.mjs        # typed setup object for both modes
  build.mjs             # manifest + artifacts (today’s profile-builder)
  genesis.mjs           # instance birth (network-parameterized)
  replace.mjs           # interface replacement checks
```

**One pipeline:**

`setup(mode) → build → genesis → (load forever)`

Ceremony is elegance: **same functions, richer provenance**, not a second monorepo narrative.

---

## 4. Under-the-hood beauty goals

### 4.1 Single spines

```text
INIT:    relation → setup(mode) → profile bundle → genesis
ACT:     load profile → witness → prove → unlocks → prep → settle → measure
RECOVER: load profile → seed + history → notes
```

No parallel “battery path” vs “product path” that reimplement assembly.

### 4.2 PF7 / dens-drop

- Product path lives in `prove/` as a **library**, not permanent spawn over research worktrees  
- Pin algorithm + inputs; cache only after core path is clean (inner beauty)  
- Research worktrees quarantined under `dev/research/`

### 4.3 Types / contracts

- Keep manifest-v1 + lifecycle replacement rules (they’re already the elegant core)  
- Expand bridge to both setup modes **inside** `profile/build`  
- Reject mode laundering forever  

### 4.4 Delete courage

Prefer **merge + delete package** over “facade re-export of 25 packages.”  
Tests move with modules; public API surface shrinks.

---

## 5. Work plan (bold sequence)

### Phase A — Architecture cut (design freeze)

1. Accept this plan as product topology.  
2. Freeze **public** API sketch: `createKit`, `shieldkit init|deposit|transfer|withdraw|recover|doctor`.  
3. Map every current package → new home (table §3.1).  
4. List **deletions** (names that vanish).  

### Phase B — Create domain packages (move code, don’t wrap)

Order: **profile → action → prove → recover → kit** (dependencies point inward).

1. **profile/**  
   - Move loader + development setup + builder + genesis  
   - Implement **ceremony** on same kernel  
   - Single `init` function: `{ mode: 'development-only' | 'ceremony-production', ... }`  
2. **action/**  
   - Merge prep/settle/packet/context/state/witness/assembler  
   - Public names: `planPrep`, `finalizePrep`, `planSettlement`, `assembleSettlement`  
   - Delete `g2-*` from export paths  
3. **prove/**  
   - snarkjs prove/verify + PF7 unlock library path  
4. **recover/**  
   - move as-is, clean exports  
5. **kit/**  
   - one facade; kill app-kit/sdk dualism  
6. **CLI**  
   - one `scripts/shieldkit.mjs` with subcommands; retire sibling scripts into subcommands or `scripts/internal/`  

### Phase C — User simplicity pass

1. README: only the four verbs + honesty banner.  
2. Pinned **dev** demo profile optional artifact path.  
3. `shieldkit doctor`: network, setup.mode, profileId, instanceId, size gates, mainnet refuse rules.  
4. Ceremony tutorial: 2 local participants → profile → genesis (offline).  
5. Docs purge: one plan (this), one charter, kill gates, privacy; archive goal-prompt sprawl.  

### Phase D — Beauty verification

| Gate | Pass |
|------|------|
| Topology | ≤6 product packages; no gate IDs in public names |
| Dual mode | tiny ceremony + dev setup both load via same `loadProfile` |
| Golden act | one deposit path using only `kit` + `prove` (no deep package tourism) |
| No second stack | golden-path-cycle imports domains, not legacy peers |
| Honesty | mainnet + development-only still refuse without lab override |
| Tests | `npm test` green; red-team on real APIs  

### Phase E — Explicit non-goals (still)

- Hosted ceremony SaaS / coordinator web app  
- Auto migration of funds across instances  
- Full wallet keystore UX  
- Claiming release/G9 PASS because ceremony code exists  
- Multi-note protocol expansion  

---

## 6. User simplicity: before → after

| Before | After |
|--------|--------|
| 25 packages, peer-ranked | 5 domains + optional mobile |
| app-kit **and** sdk | `createKit` only |
| local-setup → bridge → builder → genesis | `shieldkit init` / `profile.init` |
| ceremony “later track” | `init --mode ceremony` |
| `g2-complete-assembler` | `action.assembleSettlement` |
| dens-drop folklore | `prove.unlocks(...)` in-tree |
| many shieldkit-*.mjs | one CLI, subcommands |
| “don’t rename day one” | **rename toward truth** |

---

## 7. Definition of done (beautiful)

1. A new contributor can draw the architecture on one napkin: **profile / action / prove / recover / kit**.  
2. An app dev runs **init (dev) → deposit → transfer → withdraw → recover** without opening research packages.  
3. An operator runs **init (ceremony)** and gets a profile that **kit** loads unchanged.  
4. Under the hood, spines are singular; names match meaning; dead packages are gone, not re-exported forever.  
5. Claims stay honest: ceremony mode ≠ automatic production qualification theater.

---

## 8. Supersession

| Doc | Status |
|-----|--------|
| `docs/DEVKIT_POLISH_PLAN.md` | Historical; “no ceremony / no new packages” **void** |
| `docs/GOAL_PROMPT_DEVKIT_POLISH.md` | Historical prompt; use this plan |
| `docs/BEAUTIFUL_PLAN.md` | **Current** product architecture + ceremony membership |

When executing, update README layout section to match §3; do not maintain dual stories.
