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
| **Withdraw** | Unshield one of *your* notes to an **external** address |
| **Backup** | Keep `state.json` / encrypted note wallet safe |

You provide owned funding UTXOs; the client authenticates and tracks them,
handles tip synchronization and fees, and never puts a private key on the
command line. Consecutive actions require two alternating independent fee
UTXOs because an action's change transaction is also the current pool tip.

### Withdraw destination (privacy)

`shieldkit withdraw --to <bchtest-p2pkh>` is **required**. Use a **fresh external**
Chipnet P2PKH that is **not** this data-home’s fee keyring or change wallet.
Product refuses withdraw-to-funder / withdraw-to-local-change
(`BETA_WITHDRAWAL_TO_FEE_WALLET_REJECTED`).

Fee inputs and change remain public on chain (see
[`PRIVACY.md`](./PRIVACY.md)). Isolating the payout address does not hide the
fee graph; it stops the trivial “same hot in and out” identity merge.

## Current V2 status

The normal CLI exposes only the explicitly unqualified V2 beta product flow:
`pool create`, `pool add-funding`, `deposit`, `withdraw`, and bounded recovery.
Low-level V2 Direct controls are absent from normal help and require the
unmistakable `shieldkit dev` namespace. That namespace implies V2 Direct and
rejects `--protocol`; it is not an alternative end-user workflow. V1 material
is distinct and requires an explicit `--protocol v1-legacy` mutation invocation
with its linkability warning; it cannot create or migrate V2 state or artifacts.

## Backup

- Keep `my-pool/state.json` (or encrypted note-wallet export) offline.
- Losing wallet material without backup means notes are unspendable.
- Tip cache can be rebuilt from public chain settlements; **your note secrets cannot**.

## Not covered here

- Operator genesis internals
- Mainnet product claims  
- Research packages under unlock-builder / verifier vendor trees  
