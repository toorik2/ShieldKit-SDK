# ShieldKit pool — user guide

Unaudited work in progress. **Chipnet first.**

There is no public V2 Direct golden path while final qualification remains
open. The permitted V2 Direct topology and nonclaims are in
[`protocol/v2-direct/PROHIBITED_TOPOLOGIES.md`](./protocol/v2-direct/PROHIBITED_TOPOLOGIES.md)
and [`protocol/v2-direct/PRIVACY_AND_ROLLOUT.md`](./protocol/v2-direct/PRIVACY_AND_ROLLOUT.md).
Historical V1 instructions are not a V2 fallback and must not be followed as a
V2 workflow.

## What you do

| Verb | Meaning |
|------|---------|
| **Private balance** | How many of *your* shielded notes you can spend |
| **Deposit** | Shield coins into the pool |
| **Withdraw** | Unshield one of *your* notes to an address |
| **Backup** | Keep `state.json` / encrypted note wallet safe |

You do **not** manage fee coin inventories, densFuel, or ECIP by hand — the client handles tip sync and fees.

## Current V2 status

The V2 CLI is an explicit `--protocol v2-direct` development-only surface.
It is not the default, has no public clean-machine qualification, and must not
be represented as a public live-pool path. V1 material is distinct and requires
an explicit `--protocol v1-legacy` mutation invocation with its linkability
warning; it cannot create or migrate V2 state or artifacts.

## Backup

- Keep `my-pool/state.json` (or encrypted note-wallet export) offline.
- Losing wallet material without backup means notes are unspendable.
- Tip cache can be rebuilt from public chain settlements; **your note secrets cannot**.

## Not covered here

- Operator genesis internals
- Mainnet product claims  
- Research packages under unlock-builder / verifier vendor trees  
