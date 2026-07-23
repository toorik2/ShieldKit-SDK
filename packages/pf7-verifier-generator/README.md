# PF7 verifier generator

`generatePf7VerifierSet` is the only shield.cash entrypoint for the selected
seven-input PF7 research verifier. It accepts one absolute, complete,
SHA-256-pinned `shield.cash/snarkjs-groth16-pf7-adapter/v1` file and an exact
patched verifier.cash checkout. It never accepts selector-based proof fixtures,
generic/ten-role mode, or the approximately 80 KB fallback.

The caller supplies absolute paths for the verifier checkout, CashC source
root, LeanBCH checkout, adapter, and a nonexistent output directory. The
generator uses `spawn` with `shell:false`, discards ambient verifier-selection
environment variables, checks the retained base/terminal commit/tree and
format-patch hashes, rebuilds twice, requires byte-identical source/result
files, and runs normal plus standard BCH-2026 VM checks and the raw tamper
corpus. It reserves a new destination with atomic `mkdir`, writes every output
with `O_EXCL`, and writes the manifest last as the completion marker; it never
overwrites an existing destination.

The complete-candidate wire gate is **59,000 bytes** and the per-input gate is
**10,000 bytes**. The older 54,739-byte value is a fee/reference baseline only;
it is not a generator acceptance cap and no percentage-margin gate exists.

The result is a canonical `shield.cash/bch-verifier-set/v1` JSON artifact. It
contains all seven P2SH32 source locking bytecodes and their authenticated
redeem scripts, setup/proof dependency hashes, exact toolchain commits, and
the action-invariant source-set hash. It is permanently `development-only` and
is a verifier reference transaction, not a complete shield.cash settlement
transaction or a deployment/profile claim.

The retained verifier source chain is in
`provenance/verifier.cash-pf7-sub62/series.json` and `patches/`. It is part of
the reproducible authority; `/tmp` worktrees are not.
