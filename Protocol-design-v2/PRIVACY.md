# Privacy claim — Protocol-design-v2

## Permitted claim

For a conforming **fixed-denomination (0.1 BCH)** action on a live pool with **N ≥ 2** plausible live notes, a **passive observer with only BCH consensus-visible data** should not determine **which prior note** funded a later transfer/withdrawal, except via:

- the public deposit/withdraw **boundary** (transparent funder / payout addresses and amounts),
- the **compatible candidate set** (live notes / pool activity),
- and **prior knowledge** outside the chain.

## Required non-claims

Do **not** advertise this as:

- “anonymous,” “untraceable,” or a bare “private transaction”
- network / IP / RPC-query privacy
- protection when the candidate set collapses to one note
- protection against timing, fee-input graphs, or single-operator session clustering
- mainnet-ready privacy software (see MATURITY.md)

## What is public on chain (by design)

| Visible | Hidden (core promise) |
|---------|------------------------|
| Profile / instance / pool lineage | Which live note a withdraw spent |
| Deposit funder address + 0.1 BCH in | Mapping deposit_i → withdraw_j |
| Withdraw payout address + 0.1 BCH out | Viewing-key plaintext of notes (without secrets) |
| Tx shape, densFuel topology, fees, change | |
| SDA2 fields: roots, counters, nullifiers, leaves, encrypted records | |

## Operational leaks (not “crypto breaks”)

From Chipnet forensics on a single-pool 5-in/5-out lab session:

- **FIFO withdraw order** recovers the full matching with certainty.
- **Common fanout funding** + **shared fee-change chain** mark one operator session.
- Shuffling withdraw order restores combinatorial unlinkability (~1/N per edge) **inside** that session; session clustering remains.

Product guidance: randomize order, separate fee keys, grow multi-user sets — see forensics notes under `.cache/v2-direct-forensics-1pool-5x5/`.

## Secrets

- Shielded note secrets and funding WIFs are **local 0600 files**.
- Never commit `funding-wallet.json`, `secrets.json`, or ground-truth key dumps.
