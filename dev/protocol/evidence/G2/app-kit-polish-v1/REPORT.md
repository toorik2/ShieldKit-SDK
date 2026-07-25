# Evidence: App-kit polish + real red-team + golden path (v1)

Status: **GREEN**  
Date: 2026-07-24

## Surface

| Artifact | Role |
|----------|------|
| `packages/app-kit/` | App facade + `network.mjs` mainnet gates |
| `scripts/shieldkit.mjs` | config-check / explorer / profile-info |
| `scripts/shieldkit-plan-attach.mjs` | **app-kit plan prep + settlement size gates** |
| `scripts/golden-path-cycle.mjs` | **Public** live dep/xfer/wd runner (extracted from lab) |
| `scripts/shieldkit-smoke.mjs` | Network gate + spawns **public** golden-path-cycle |
| `scripts/shieldkit-redteam.mjs` | **Real API rejects** via settlement-transaction + app-kit |
| `scripts/shieldkit-recovery-verify.mjs` | Live recovery round-trip + wrong-seed reject |

## Plan/attach (verification step 1)

`node scripts/shieldkit-plan-attach.mjs` → `{SCRATCH}/golden-path.log`

| step | result |
|------|--------|
| app_kit_load | development-only profile `79782441…` / `d96968b8…` |
| plan_prep deposit/transfer/withdrawal | ok via `kit.planCompletePreparation` |
| settle_measure_* wire | 1444 / 1444 / 1478 (≤59000) |
| maxUnlock | 755 (≤10000) |
| feeSatoshis | equals wire @ 1 sat/B |

## Live Chipnet smoke (happy path)

`shieldkit-smoke.mjs` → `scripts/golden-path-cycle.mjs` (not `.cache/`):

| kind | settleTxid | wire | maxUnlock |
|------|------------|------|-----------|
| deposit (c17 prior) | `1eede42c…` | 56964 | 9350 |
| transfer | `97838a7373cf49f9682944bb9dfcaed9cf585f32566226f92177fae922c3174c` | 56964 | 9350 |
| withdrawal | `456b2eb034a25b2f547a050cb8b835446bfe107055076bfd26c503382ac49e4d` | 56998 | 9350 |

Explorer: https://chipnet.chaingraph.cash/tx/456b2eb034a25b2f547a050cb8b835446bfe107055076bfd26c503382ac49e4d

## Red-team (shipped builders reject)

18/18 pass including:

- wrong profileId / instanceId → `SettlementTransactionError`
- flip binding unlock (packet region) → reject
- empty fee unlock / underfunded fee → reject
- cross-action kind mismatch → reject
- state commitment flip → reject
- oversized PF7 unlock (>10000) → reject
- mainnet ACK + development-on-mainnet refuses
- createAppKit network mismatch; wrong profile bundle auth

## Recovery re-verify

`node scripts/shieldkit-recovery-verify.mjs` (not a copy of old JSON):

- app-kit exposes `recoverChainOutput` / `recoverAuthenticatedHistory`
- construct → recoverRecipientOutput commitment match
- wrong seed rejected

## Hygiene

- LICENSE, SECURITY.md, README honest
- `docs/DX_APP_OWNED_INSTANCE.md`
- HANDOVER/.cache not git-tracked
- Root `npm test` = policy g0-v3 pass
- package.json name frozen under g0 (OPEN)

## OPEN

- Root npm package name still `shield-cash-protocol` (g0 freeze)
- densFuel PF7 dens-drop remains external pinned worktree
