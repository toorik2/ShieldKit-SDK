# G1 BCHN v29 synchronized local-runtime observation

Observation time: 2026-07-23T15:10:57Z. Status: **G1 OPEN**.

This defensive Chipnet observation ran no-wallet BCHN `v29.0.0-89a591f`
binaries in two separate preserved local datadirs. It performed read/sync-only
P2P and RPC work: no wallet, UTXO selection, transaction construction,
`testmempoolaccept`, submission, relay, broadcast, funding, mining, or mainnet
activity occurred.

## Synchronized result

Both local daemons reached `initialblockdownload: false` and agreed exactly on
the locally validated Chipnet state:

| Field | Value |
| --- | --- |
| blocks / headers | 315,801 / 315,801 |
| best block | `0000000021bbbaa39f0ecf6fdf9f33a95b08c5a14bdb32172552cdc98d4fd646` |
| chainwork | `0000000000000000000000000000000000000000000000000d8764d32c1785df` |
| BCHN version | `v29.0.0-89a591f` |
| P2P | eight outbound IPv4 peers each; local relay disabled |

The deterministic comparison in
[raw/common-tip-comparison.json](raw/common-tip-comparison.json) records both
`commonTip: true` and `bothSynchronized: true`. The raw snapshots also record
the May 2026 Chipnet upgrade as locally activated.

## Exact runtime identity and boundary

The pinned source is BCHN `v29.0.0` commit
`89a591f7c5b1fd110c0819377ad8f2647d656800`. The no-wallet binary hashes are
`97b5d3a0f0af68dba06de6d13f5ac9ae3896b0384b2e7923a0644c6ed7b5064e`
(`bitcoind`) and
`55bc8e3f59cb8354141041940f4f1443bb863c25c1db449e295d45fa5f262f56`
(`bitcoin-cli`). The credential-free runtime arguments have SHA-256
`cc607ea9b3da7a35eaee1c04d8ed69b2482e46e1ca26a456e13458427d6ff1c1`.

Node A previously exited without a logged BCHN fatal error at its then-local
height 310,938. Restarting that exact datadir rolled it back to a safely
persisted height 113,479 and it subsequently synchronized to the common tip.
This shows recovery in this local environment; it is not an independent-node
reproduction.

Both daemons are controlled by one operator on one host and share an external
network identity. Separate datadirs and partly distinct public peers do not
establish independent operators, independent release provenance, consensus, or
relay policy. This record upgrades only the synchronized-local-runtime claim.
It does not close G1 or establish acceptance of the 10-input verifier
transaction.
