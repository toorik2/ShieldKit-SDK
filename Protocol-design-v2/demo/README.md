# Demo / default active pool

## `chipnet-default-pool.json`

Public Chipnet **default pool** attached by the CLI on `init` (and when no `pool.json` exists).

| Field | Meaning |
|-------|---------|
| `genesisTxid` | Pool birth transaction |
| `instanceId` / category | CashToken category (= category mint parent txid) |
| `liveTip` | densFuel carriers + binding + SKS2 state tip |
| `tipSummary.liveNoteCount` | Seeded live notes (anonymity set tickets) |
| `publicDepositTxids` | The 5 seed deposit settles |

### What blank machines get

- Ability to **deposit and withdraw their own notes** into this shared pool  
- A non-empty anonymity set from the 5 seed tickets  

### What they do **not** get

- Spend keys for the 5 seed notes (ops-only under `.cache/v2-direct-default-pool-seed/`, gitignored)

### Maturity

Dev keys only — not for real-money privacy. Unaudited WIP.
