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

The retained selected PF7 source chain has a narrow end-to-end parameterized
path: it accepts one complete SHA-pinned adapter result, derives the live
gamma/delta static-line material from that adapter's VK, and rejects all legacy
ELIG selectors in the same invocation. This does not make arbitrary PF7
configuration safe: shield.cash consumes it only through
`packages/pf7-verifier-generator`, which pins the exact verifier.cash base and
patch series, forces the seven-input PF7-sub62 profile, and rejects generic or
ten-role fallback modes. The adapter remains development-only material until a
new profile has complete setup, settlement, node, and release qualification.

`test-fixtures/two-public` is a local development-only two-public-signal
snarkjs fixture. The test first asks pinned snarkjs to verify it, then adapts
it and exercises malformed and adversarial imports. It is not ceremony or
profile material.
