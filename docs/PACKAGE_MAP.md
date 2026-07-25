# Package map (BEAUTIFUL_PLAN freeze)

## Public API

| Export | Module |
|--------|--------|
| `createKit` | `@shieldkit/kit` / `packages/kit/kit.mjs` |
| `loadProfile` | `packages/profile/load.mjs` (`loadVerifierProfileBundle`) |
| `initDevelopment` / `initCeremony` | `packages/profile/setup/*` |
| `planPrep` / `assembleSettlement` / … | `packages/action/*` |
| `proveGroth16` / unlocks | `packages/prove/*` |
| recovery helpers | `packages/recover/*` |

CLI: `node scripts/shieldkit.mjs` → `init|deposit|transfer|withdraw|recover|doctor`

## Old → domain

| Old package | Domain / file |
|-------------|----------------|
| core/verifier-profile | profile/load |
| core/compare-development-profiles | profile/compare-development |
| core/local-prover-profile | profile/local-prover |
| core/shielded-transition | action/transition |
| core/pf7-authority | prove/authority |
| local-setup | profile/setup/development |
| setup-profile-bridge | profile/bridge |
| profile-builder | profile/build |
| chipnet-genesis | profile/genesis |
| profile-replacement-drill | profile/replace |
| preparation-transaction | action/prep |
| settlement-transaction | action/settlement |
| settlement-context | action/context |
| action-packet | action/packet |
| state-nft | action/state |
| fresh-witness-inputs | action/witness |
| g2-complete-assembler | action/assemble |
| snarkjs-adapter | prove/groth16 |
| pf7-fixed-point | prove/fixed-point |
| pf7-verifier-generator | prove/verifier-generator |
| prover-artifact-budget | prove/budget |
| proof-corpus | prove/corpus |
| recovery | recover/* |
| app-kit + sdk | kit/* |
| android-prover-harness, browser-prover, native-prover-adapter | mobile/* |
| conformance | tools/conformance (non-product) |

## Deleted as top-level peers

All rows in “Old package” above after move.
