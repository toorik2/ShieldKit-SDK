# Development-v1 setup replacement qualification

Observed 2026-07-23. This is a pre-genesis, development-only interface
qualification. It packages no wallet, funding, ceremony, deployment, BCHN
standardness, Chipnet acceptance, broadcast, or mainnet claim.

The real v1 deposit adapter is pinned to VK
`da160f126c13550ecd302547caaf1308434574c50e76268b3b310c64203d2358` and
produced a non-composed K=9 PF7 context with 10/10 BCH-2026/libauth VM inputs
accepting. All 18 intratx mutations reject. The exact v1 result is 81,564 wire
bytes, 82,740 score bytes, and a 9,596-byte `exec0` unlock; G1 remains open.

Separately hash-pinned deposit, transfer, and withdrawal adapters each drove a
full actual ten-role PF7 build. All 30 inputs accepted. Every named role's
locking-bytecode hash, and the complete generated source-output verifier-set
hash, was invariant across those three proofs/public-inputs; see
`action-lock-invariance.json`. Unlocks and transactions appropriately differ.

The strict profile comparator accepted two external immutable bundles with the
same relation, ABI, Phase-1, toolchain, witness generator, Chipnet, and
10,000,000-satoshi reserve semantics, while requiring distinct local setup
commitments, zkeys, VKs, generated BCH verifier sets, profile IDs, instance
IDs, and deterministic **PRE-GENESIS QUALIFICATION ONLY** outpoints. Those
outpoints are labels, not constructed/funded/deployable genesis transactions.

The source-output verifier sets are generated PF7 artifacts. The bundle
profile interface does not prove a complete settlement closure, BCHN
standardness, or external verifier equivalence; this bounded comparator is
therefore not promotion evidence.
