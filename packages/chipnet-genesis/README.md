# Offline Chipnet genesis constructor

`planChipnetGenesisTransaction` loads and hash-verifies a profile bundle,
requires its category-creating input at vout 0, derives the initial empty state
and state NFT, then returns exact unsigned transaction and BCH Schnorr signing
bytes. `finalizeChipnetGenesisTransaction` accepts only a 64-byte signature and
executes the funding P2PKH input in Libauth's standard BCH-2026 VM.

It has no wallet, key, RPC, broadcaster, or node interface. The authenticated
PF7 verifier-set artifact commits to the carrier-base constants and exact
derived binding/helper/state-lock hashes without a profile-ID cycle. The
result remains offline construction evidence until a caller signs, broadcasts,
and confirms it.
