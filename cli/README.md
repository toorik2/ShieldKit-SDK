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
1. create the design root (e.g. `shieldkit-sdk/shieldkit-fri-stark-96kb/`)
2. ship `profile.json` (id, capability, machinery paths)
3. add a `profile-module` entry to `cli/pool-designs.json`
4. the profile module lives at `cli/profiles/<id>.mjs` and reads
   `process.env.SHIELDKIT_DESIGN_ROOT` for the design root
5. unknown ids fail closed (UNKNOWN_PROFILE)

## Registered designs (2026-08-07)

| profile | design root | capability | status |
|---|---|---|---|
| (default) / pf10 | shieldkit-groth-94kb | PF10-FusedQGenesis (94,622 script bytes), 10 roles, 13-input | original surface, unchanged |
| pf6-a3-direct-v1 | shieldkit-groth-54kb | bn254-onetx-pf6-a3-r1, 6 roles, 9-input | LIVE on chipnet (create/deposit/transfer/recover) |
| fri-stark-96kb | shieldkit-fri-stark-96kb | FRI-STARK DEEP-ALI d20/b2048/n7/g30, 17 roles, 18-input, 100-bit, random-mask | LIVE on chipnet (create/deposit/transfer/withdraw/recover, wallet-driven notes) |

## Using the FRI-STARK 96KB profile (fri-stark-96kb)

The design root ships in the repo: `shieldkit-sdk/shieldkit-fri-stark-96kb/`
(source only — builds, evidence dumps, and secrets stay local).

1. **Build the prover worker** (one time):
   ```
   cd shieldkit-sdk/shieldkit-fri-stark-96kb
   cargo build --release -p shieldkit-fri-worker
   npm install
   ```
2. **Chipnet node access**: the profile talks to a BCHN chipnet node over SSH.
   Default host `layer1-node` (with `sudo -n -u bchn bitcoin-cli`); override with
   `CHIPNET_SSH=<user@host>` and adjust `BITCOIN_CLI` in
   `shieldkit-fri-stark-96kb/scripts/lib/chipnet-fund-spend.mjs` for your node.
3. **Wallet**: any chipnet wallet JSON with `privateKeyHex` (funding) +
   `lockingBytecodeHex`; a `noteMasterKeyHex` is auto-derived and stored
   alongside the wallet (0600). The wallet file must stay out of git
   (`.codex-artifacts/` is ignored).
4. **Run** (fresh pool → full lifecycle):
   ```
   node cli/scripts/shieldkit.mjs --profile fri-stark-96kb pool create  --funding-wallet <w> --data-home <dir>
   node cli/scripts/shieldkit.mjs --profile fri-stark-96kb deposit      --funding-wallet <w> --data-home <dir>
   node cli/scripts/shieldkit.mjs --profile fri-stark-96kb transfer     --funding-wallet <w> --data-home <dir>
   node cli/scripts/shieldkit.mjs --profile fri-stark-96kb withdraw     --funding-wallet <w> --data-home <dir>
   node cli/scripts/shieldkit.mjs --profile fri-stark-96kb recover      --funding-wallet <w> --data-home <dir>
   ```
   Each action = one zero-conf chipnet tx (≤ 100,000 B, fee = size+1) with a
   FRESH random-mask FRI proof; note secrets derive from the wallet note-master
   key (HMAC(master, instance, index)) — never a proof seed.

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
