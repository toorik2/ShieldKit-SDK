# snarkjs Groth16 adapter

Local-only conversion from three caller-hash-pinned snarkjs JSON files to the
exact field names consumed by verifier.cash PF7's `ELIG_INSTANCE=file` path.
It is not a setup, verifier bundle, profile, Groth16 pairing verifier, BCH
transaction, or qualification result.

Required caller records are `{ path, sha256 }` for `verification_key.json`,
`proof.json`, and `public.json`. Every path must be a regular, direct,
non-symlink file. The SHA-256 of the exact JSON bytes parsed is required to
match the caller pin; a post-read pathname hash plus device/inode/size check
then detects replacement or mutation.
The parser rejects duplicate JSON object names, trailing data, BOMs, malformed
UTF-8, unknown keys, wrong protocol/curve/arity, noncanonical field/scalar
strings, invalid affine encodings, infinity, invalid curve points, and
non-subgroup points.

PF7 proof/public-signal fixture output is exactly:

```text
Ax Ay Bxa Bxb Bya Byb Cx Cy in0 in1
```

`Ax/Ay` and `Cx/Cy` preserve snarkjs G1 affine `[x,y,1]`. `Bxa/Bxb/Bya/Byb`
preserve snarkjs G2 affine `[[x.c0,x.c1],[y.c0,y.c1],[1,0]]`; no Solidity-style
Fq2 component reversal occurs. Values remain canonical unsigned decimal JSON
strings. PF7 retains responsibility for converting them to its internal VM
number encoding.

The same result also contains `verifierCashVk`, the complete affine material
PF7 needs to rebuild its four Groth16 pairing terms: `alpha` (G1),
`beta`/`gamma`/`delta` (G2 as `x0,x1,y0,y1`), and `ic[0..2]` (G1). These use
the same component order as the proof mapping above. `vk_alphabeta_12` is
validated from snarkjs input but intentionally not exported: verifier.cash
derives the alpha/beta Miller trajectory from the affine points and consumes no
precomputed alpha-beta value.

snarkjs permits canonical infinity only for `IC[0]`, encoded as
`{ "x": "0", "y": "1", "infinity": true }` in `verifierCashVk`. The
adapter preserves that valid source material. Current verifier.cash PF7 cannot
consume an infinite IC point in its ECIP/MSM path, so its pinned importer must
reject it; it must never substitute an affine point or an identity surrogate.

More broadly, the current PF7 build entrypoint rejects every
`C7_SHIELD_ADAPTER_*` request before generator imports. Its gb3/SZ and
fixed-G2 emitters still derive chunks, alpha-beta folds, gamma/delta lines,
transcripts, and state from a static pairing-vector trajectory. Accepting an
arbitrary adapter result there would mix sources. The adapter is therefore an
interoperability conversion artifact only until an end-to-end parameterized PF7
generator exists.

`test-fixtures/two-public` is a local development-only two-public-signal
snarkjs fixture. The test first asks pinned snarkjs to verify it, then adapts
it and exercises malformed and adversarial imports. It is not ceremony or
profile material.
