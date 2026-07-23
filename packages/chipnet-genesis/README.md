# Offline Chipnet genesis constructor

`planChipnetGenesisTransaction` loads and hash-verifies a profile bundle,
requires its category-creating input at vout 0, derives the initial empty state
and state NFT, then returns exact unsigned transaction and BCH Schnorr signing
bytes. `finalizeChipnetGenesisTransaction` accepts only a 64-byte signature and
executes the funding P2PKH input in Libauth's standard BCH-2026 VM.

It has no wallet, key, RPC, broadcaster, or node interface. Both APIs return a
critical blocker because the current profile manifest does not bind the two
carrier-base constants which parameterize the state covenant. The result is
therefore offline construction evidence, never authorization to broadcast.
