# `@shield.cash/preparation-transaction`

Deterministic local planner and finalizer for the wallet-funded transaction
that precedes one settlement action.

It spends one canonical P2PKH wallet UTXO and creates:

1. the exact binding carrier at vout 0;
2. the settlement fee P2PKH UTXO at vout 1; and
3. preparation change to the same P2PKH key at vout 2.

Deposit adds exactly 10,000,000 satoshis to the binding carrier. Transfer and
withdrawal do not. The planner sizes the fixed 100-byte Schnorr
`ALL|FORKID` unlock, charges exactly 1 satoshi per byte, and derives change
without burning a remainder. Finalization substitutes the 64-byte signature
without changing size and returns both wire-order sibling outpoints.

The input schema keeps the explicit rate field for auditability but rejects
every value other than `1`; there is no higher-rate protocol mode.

This package validates deterministic construction and byte accounting. It does
not claim that a supplied signature is cryptographically valid or that a peer
accepted, relayed, or mined the transaction; those are VM and Chipnet gates.
