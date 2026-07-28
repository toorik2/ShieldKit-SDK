# Privacy claim (V1)

Document version: 0.3

## Claim

For a conforming **0.1 BCH** action, a passive observer with only BCH consensus-visible data should not determine which qualifying prior note funded a later transfer/withdrawal, except via the public boundary, the compatible candidate set, and prior knowledge.

Not claimed: network anonymity, traffic analysis resistance, provider-query privacy, or protection when the candidate set collapses to one.

Requires: ratified profile/instance/denomination/shapes; crypto assumptions; undisclosed secrets; no identifying app metadata.

## Transcript rules (consensus-visible SCAR packet)

- **Published on spend:** `inputNullifier` (double-spend prevention), post-state roots/counters, and for transfers a new `outputCommitment`.
- **Not published on spend:** the spent note commitment. Packet field `inputCommitment` is canonically **zero** for deposit, transfer, and withdrawal. Membership of the spent note is a private witness; it is not equality-matchable to prior public `outputCommitment` values from the packet alone.
- **Still public:** each deposit/transfer `outputCommitment` (note-tree leaf material), state commitments, and fixed denomination boundaries.

Historical on-chain settlements produced before this rule may still contain non-zero spend `inputCommitment` values; the claim applies to conforming actions under the fixed transcript.

## Leakage matrix

| Information | BCH observer | Treatment |
| --- | --- | --- |
| Profile / instance | Yes | Public |
| Txid, time, graph | Yes | Unhidden |
| Deposit/withdraw boundary scripts & values | Yes | Public boundary |
| Denomination | Yes | Fixed 0.1 BCH |
| Tx shape, I/O count, scripts, sizes | Yes | Public |
| State roots, nullifiers, counters | Yes | Public markers |
| Encrypted note-record location/length | Yes | Ciphertext on chain |
| Which candidate note is spent | No (claim) | Core unlinkability target — spent `cm` not in packet |
| Deposit→withdraw link | No (claim) | Core unlinkability target — no cleartext spent-cm equality |
| Internal sender/recipient | No (claim) | Unless boundary/external data reveals |
| Fees, fee inputs, change | Yes if present | Public |
| Timing / set size | Yes | Inference surface |
| IP / peers / traffic | Outside claim | — |
| Indexer/RPC query privacy | Outside claim | Providers untrusted |
| Compromised device/seed | Outside claim | — |

Do not call this “anonymous,” “untraceable,” or a bare “private transaction.” State what is hidden and what remains public.
