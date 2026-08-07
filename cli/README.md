# ShieldKit unified CLI — ONE CLI for ALL verifier-pool designs

`shieldkit-sdk/cli/scripts/shieldkit.mjs` is the single shared CLI. It is the
original ShieldKit-Groth product CLI (pinned closure) plus a profile registry.

## The registry contract (pool-designs.json)

`cli/pool-designs.json` maps profile ids to design roots. Each design root
ships a `profile.json` manifest describing its capability + machinery paths:

```json
{ "schema": "shieldkit-pool-design-profile/v1", "id": "...", "capability": {...}, "machinery": {...} }
```

Adding a future pool design (e.g. a FRI-STARK pool):
1. create the design root (e.g. `shieldkit-sdk/shieldkit-fri-stark/`)
2. ship `profile.json` (id, capability, machinery paths)
3. add a `profile-module` entry to `cli/pool-designs.json`
4. the profile module lives at `cli/profiles/<id>.mjs` and reads
   `process.env.SHIELDKIT_DESIGN_ROOT` for the design root
5. unknown ids fail closed (UNKNOWN_PROFILE)

## Registered designs (2026-08-07)

| profile | design root | capability | status |
|---|---|---|---|
| (default) / pf10 | shieldkit-groth | PF10-FusedQGenesis, 10 roles, 13-input | original surface, unchanged |
| pf6-a3-direct-v1 | shieldkit-groth-54kb | bn254-onetx-pf6-a3-r1, 6 roles, 9-input | LIVE on chipnet (create/deposit/transfer/recover) |

## Usage

```
node shieldkit-sdk/cli/scripts/shieldkit.mjs [--profile <id>] <command> ...
node shieldkit-sdk/cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 pool create --funding-wallet <w> --funding-utxo <t:v> --data-home <dir> --json
node shieldkit-sdk/cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 deposit|transfer|withdraw --funding-wallet <w> --funding-utxo <t:v> --data-home <dir> --json
node shieldkit-sdk/cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 pool recover --data-home <dir> --scan --json
node shieldkit-sdk/cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 pool doctor --json
```

Tests: `node cli/test-profile.mjs` (8/8).

## Status notes
- The pf6 profile: pool create / deposit / transfer LIVE on chipnet; the
  chain-scan recovery recovers notes from the on-chain packets.
- The withdrawal's genesis-role residual is a lane-build witness-layout issue
  (root cause + fix proposal: shieldkit-groth-54kb/evidence/03-implementation/).
