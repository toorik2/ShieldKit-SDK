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
contains all seven P2SH32 source locking bytecodes, their authenticated redeem
scripts, each role's measured source-output value, setup/proof dependency
hashes, exact toolchain commits, and the action-invariant source-set hash. The
values are decoded from the reproducible verifier.cash
`c7_candidate_srcouts.hex`; preparation builders must reproduce them exactly
and must not substitute fixture or caller-selected carrier values. The artifact
is permanently `development-only` and is a verifier reference transaction, not
a complete shield.cash settlement transaction or a deployment/profile claim.

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

## Fresh local-development path

`generatePf7FreshDevelopmentCorpus` (or `npm run fresh -- ABSOLUTE_CONFIG.json`)
is the only PF7 seam entrypoint for new local setup material. It is deliberately
separate from both historical entrypoints above: it cannot consume an adapter
file or the retained reference matrix.

Its `preProfile` has exactly a typed development-setup metadata file, R1CS, and
verification key, each absolute, regular, non-symlink, SHA-256-pinned inputs.
The metadata must bind the same two-public-input R1CS and verification key and
must remain `development-only` / `local-initialization`. Each ordered action
supplies only its raw `proof.json`, `public.json`, the same raw verification
key, and its canonical 752-byte packet. The implementation calls the trusted
`snarkjs-adapter` itself, re-derives every PF7 proof/VK/public-signal field,
and rejects any copied or forged adapter metadata.

```json
{
  "mode": "discovery",
  "destination": "/nonexistent/output",
  "scratchDirectory": "/short/direct/private/scratch",
  "preProfile": {
    "schema": "shield.cash/pf7-fresh-development-preprofile/v1",
    "setupMetadata": {"path":"/setup/setup-metadata.json","sha256":"..."},
    "r1cs": {"path":"/setup/action.r1cs","sha256":"..."},
    "verificationKey": {"path":"/setup/verification_key.json","sha256":"..."}
  },
  "actions": [
    {"kind":"deposit","proof":{"path":"/proofs/d.json","sha256":"..."},"publicSignals":{"path":"/proofs/d-public.json","sha256":"..."},"verificationKey":{"path":"/setup/verification_key.json","sha256":"..."},"packet":{"path":"/packets/d.bin","sha256":"..."}},
    {"kind":"transfer","proof":{"path":"/proofs/t.json","sha256":"..."},"publicSignals":{"path":"/proofs/t-public.json","sha256":"..."},"verificationKey":{"path":"/setup/verification_key.json","sha256":"..."},"packet":{"path":"/packets/t.bin","sha256":"..."}},
    {"kind":"withdrawal","proof":{"path":"/proofs/w.json","sha256":"..."},"publicSignals":{"path":"/proofs/w-public.json","sha256":"..."},"verificationKey":{"path":"/setup/verification_key.json","sha256":"..."},"packet":{"path":"/packets/w.bin","sha256":"..."}}
  ],
  "verifier": {"checkout":"/exact/verifier.cash","cashcRoot":"/exact/cashc","cashcCommit":"...","leanBchRoot":"/exact/LeanBCH","leanBchCommit":"..."}
}
```

Discovery rebuilds each action twice, enforces the retained seam terminal
`1d543756...`, clean pinned toolchains, 7/7 normal and BCH-2026 VM verdicts,
18 raw attacks, 17 seam/cross-action rejections, 59,000-byte context, 10,000
bytes per unlock, and identical PF7 carrier locks. The verifier.cash fresh seam
build emits a complete ten-output context file: PF7 carriers `0..6`, then
packet/state/fee context `7..9`. Fresh decoding requires canonical lowercase
hex, canonical CompactSize framing, exactly ten tokenless outputs, and no
truncation or trailing bytes. It extracts the exact raw first seven outputs,
reserializes `CompactSize(7) || outputs[0..6]`, and hashes that serialization.
Accordingly, every `sourceSetSha256` in this path means **only the ordered
seven-carrier authority**, never the ten-output context file.

The full `c7_candidate_srcouts.hex` file is still identity-checked between the
two builds of each action and recorded by SHA-256 in that action's corpus
evidence/dependencies. Structural outputs are evidence context, not profile
authority; they may differ across actions without changing the seven-carrier
source set. Discovery writes a **development-only, non-authoritative**
seven-carrier source-set hash, corpus-output hash, and a dedicated
`bch-verifier-set.json`. The stable verifier-set hash is derived only from the
fixed PF7 candidate/provenance, the pre-profile verification-key hash, the
canonical seven-carrier output serialization, and ordered source/redeem pairs;
it deliberately excludes proofs, public
signals, packets, full ten-output context serialization, and corpus-output
metadata. Inputs 7--9 remain unevaluated.

`final-replay` adds exactly `expected:{sourceSetSha256,verifierSetSha256}` and
`finalProfile:{bundleDirectory,profileId,instanceId}`. `sourceSetSha256` is the
canonical seven-carrier serialization hash described above. Both hashes and all
bundle identity coordinates are caller-pinned; final replay loads and verifies
the real local bundle and refuses any mismatch. The bundle must be
`development-only`, bind the same R1CS and verification-key artifact, and
import the exact stable `bch-verifier-set.json` by hash and bytes. The final
corpus-output hash may differ from discovery because action proof/packet data
may differ; only the stable verifier-set/source-set authority is replayed.
That linkage records a candidate for a later profile builder; it never makes
discovery or replay a
profile, G2, settlement, ceremony, node/relay, or Chipnet claim.
