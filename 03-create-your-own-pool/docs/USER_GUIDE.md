# ShieldKit pool — user guide

Unaudited work in progress. **Chipnet first.**

**Start here:** [**GOLDEN_PATH.md**](./GOLDEN_PATH.md) — install → pins → fund → deposit → withdraw.

## What you do

| Verb | Meaning |
|------|---------|
| **Private balance** | How many of *your* shielded notes you can spend |
| **Deposit** | Shield coins into the pool |
| **Withdraw** | Unshield one of *your* notes to an address |
| **Backup** | Keep `state.json` / encrypted note wallet safe |

You do **not** manage fee coin inventories, densFuel, or ECIP by hand — the client handles tip sync and fees.

## Blank machine (summary)

1. `npm install`
2. `npm run fetch-pin-artifacts` (your pool) **or** `npm run fetch-playground-bundle` (demo)
3. Fund hot wallet on Chipnet
4. Create pool *or* use playground
5. `shieldkit deposit … --broadcast`
6. `shieldkit withdraw … --broadcast`

Full commands: [GOLDEN_PATH.md](./GOLDEN_PATH.md).

## Backup

- Keep `my-pool/state.json` (or encrypted note-wallet export) offline.
- Losing wallet material without backup means notes are unspendable.
- Tip cache can be rebuilt from public chain settlements; **your note secrets cannot**.

## Not covered here

- Operator genesis internals beyond the golden path  
- Mainnet product claims  
- Research packages under unlock-builder / verifier vendor trees  
