# `@shield.cash/settlement-transaction`

Deterministic constructor and fail-closed envelope checker for the exact
ten-role settlement transaction:

`exec0..4, genesis, terminal, binding, state, fee`.

It binds a canonical 752-byte action packet to the independently reconstructed
settlement-context digest, preserves the mutable state NFT and state script,
checks fixed 0.1 BCH reserve transitions, keeps a profile-fixed state carrier
above the reserve so an empty pool need not create a zero-satoshi state output,
enforces transparent fee funding and positive change, and serializes the exact
BCH transaction with libauth.

The active envelope is at most 59,000 serialized bytes and at most 10,000 bytes
for every unlock, with no percentage-margin requirement. The 54,739-byte PF6
transaction remains a fee/reference baseline only.

This package does not claim VM acceptance. G2 additionally requires the real
PF7 verifier locks, real binding/state covenants, a valid transparent
signature, all-input libauth/BCHN execution, standardness, relay, and inclusion.
