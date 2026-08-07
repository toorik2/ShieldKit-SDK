# Privacy claim (V2 Direct product)

Document version: 0.3

## Crypto claim (what the protocol targets)

For a conforming **0.1 BCH** action, a passive observer with only BCH consensus-visible data should not determine **which qualifying prior note** funded a later transfer/withdrawal, except via the public boundary, the compatible candidate set, and prior knowledge.

Not claimed: network anonymity, traffic analysis resistance, provider-query privacy, or protection when the candidate set collapses to one.

Requires: ratified profile/instance/denomination/shapes; crypto assumptions; undisclosed secrets; no identifying app metadata.

## Operational identity (what still leaks on the transparent edge)

Fees, fee inputs, change, deposit funding, and withdrawal **payout addresses** are consensus-visible. A single-key bootstrap fanout clusters fee identity for a lab session; that fee graph is a **public nonclaim** and is not redesigned here.

**Withdraw-to-funder is forbidden** in the product path: cashing out to this data-home’s fee keyring or change wallet collapses deposit funder and withdraw receiver to one identity. Product CLI rejects that destination (`BETA_WITHDRAWAL_TO_FEE_WALLET_REJECTED`). Always pass `--to` a **fresh external** Chipnet P2PKH that has never been used as a fee or change lock for this instance.

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
| Which candidate note is spent | No (claim) | Core unlinkability target |
| Deposit→withdraw note link | No (claim) | Core unlinkability target |
| Deposit→withdraw **identity** via fee/payout reuse | Yes if misused | Product rejects withdraw-to-local-fee/change; fee fanout still public |
| Internal sender/recipient | No (claim) | Unless boundary/external data reveals |
| Fees, fee inputs, change | Yes if present | Public nonclaim |
| Timing / set size | Yes | Inference surface |
| IP / peers / traffic | Outside claim | — |
| Indexer/RPC query privacy | Outside claim | Providers untrusted |
| Compromised device/seed | Outside claim | — |

## Operator checklist (payout / ops)

1. Withdraw only to a fresh external P2PKH (`--to`), never the funding/fee hot wallet or any local change address.  
2. Prefer larger concurrent live-note sets (other users) before high-value unshield.  
3. Solo empty-pool bursts maximize timing and occupancy inference.  
4. Product transfer re-notes to the same local shield account; it is not third-party privacy by itself.  
5. Fee graph privacy is out of scope for this product control surface; do not call fee-clustered lab runs “private.”

Do not call this “anonymous,” “untraceable,” or a bare “private transaction.” State what is hidden and what remains public.
