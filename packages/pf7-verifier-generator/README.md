# PF7 verifier generator

`generatePf7VerifierSet` is the reference-transaction entrypoint for the
selected seven-input PF7 research verifier. It accepts one absolute, complete,
SHA-256-pinned `shield.cash/snarkjs-groth16-pf7-adapter/v1` file and an exact
patched verifier.cash checkout at retained reference terminal `17c6b955...`.
It never accepts selector-based proof fixtures, structural roles, or the
approximately 80 KB fallback. Its seam-off result remains byte-identical to the
historical reference chain.

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

`generatePf7ActionSeamCorpus` (or `npm run seam --
ABSOLUTE_CONFIG.json`) is a distinct evidence-experiment entrypoint. Its strict
input has exactly these fields:

```json
{
  "destination": "/nonexistent/output",
  "scratchDirectory": "/short/direct/private/scratch",
  "actions": [
    {"kind":"deposit","adapter":{"path":"/a/deposit-adapter.json","sha256":"..."},"packet":{"path":"/a/deposit.packet","sha256":"..."}},
    {"kind":"transfer","adapter":{"path":"/a/transfer-adapter.json","sha256":"..."},"packet":{"path":"/a/transfer.packet","sha256":"..."}},
    {"kind":"withdrawal","adapter":{"path":"/a/withdrawal-adapter.json","sha256":"..."},"packet":{"path":"/a/withdrawal.packet","sha256":"..."}}
  ],
  "verifier": {
    "checkout":"/exact/verifier.cash",
    "cashcRoot":"/exact/cashc/packages/cashc",
    "cashcCommit":"...",
    "leanBchRoot":"/exact/LeanBCH",
    "leanBchCommit":"..."
  }
}
```

The scratch directory must already exist, be a direct non-symlink directory,
and have a short enough path for the host's Unix-domain socket limit. All
generated scratch content is removed after success or failure.

The seam corpus requires terminal `1d543756...`, canonical 752-byte `SCAR`
packets whose SHA-256 limbs exactly match each adapter, and one setup represented
by deposit, transfer, and withdrawal in that order. It rebuilds every action
twice with all ten context inputs, evaluates only verifier roles 0 through 6 in
normal and standard BCH-2026 VMs, requires the 18-case raw-terminal battery and
a 17-case action/cross-action seam battery, checks every context unlock at or
below 10,000 bytes and each context transaction at or below 59,000 bytes, and
requires every source lock to remain identical across actions.

The resulting `shield.cash/pf7-action-seam-corpus/v1` is permanently labeled as
development-only verifier-role evidence. Inputs 7 (`packet`), 8 (`state`), and
9 (`fee`) are present but explicitly unevaluated. It is not a complete
settlement, G2 artifact, node/relay result, Chipnet result, profile, ceremony,
or release claim.

The retained verifier source chain is in
`provenance/verifier.cash-pf7-sub62/series.json`,
`provenance/verifier.cash-pf7-sub62/seam-series.json`, and `patches/`. The
historical seven-patch reference manifest remains byte-identical at its
original path; the eight-patch seam manifest is a distinct authority record.
Temporary worktrees are not authority.
