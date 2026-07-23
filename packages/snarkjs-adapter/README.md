# snarkjs Groth16 adapter

Local-only conversion from three caller-hash-pinned snarkjs JSON files to the
exact field names consumed by verifier.cash PF7's `ELIG_INSTANCE=file` path.
It is not a setup, verifier bundle, profile, Groth16 pairing verifier, BCH
transaction, or qualification result.

Required caller records are `{ path, sha256 }` for `verification_key.json`,
`proof.json`, and `public.json`. Every path must be a regular, direct,
non-symlink file and its SHA-256 is checked before parsing and after reading.
The parser rejects duplicate JSON object names, trailing data, BOMs, malformed
UTF-8, unknown keys, wrong protocol/curve/arity, noncanonical field/scalar
strings, invalid affine encodings, infinity, invalid curve points, and
non-subgroup points.

PF7 output is exactly:

```text
Ax Ay Bxa Bxb Bya Byb Cx Cy in0 in1
```

`Ax/Ay` and `Cx/Cy` preserve snarkjs G1 affine `[x,y,1]`. `Bxa/Bxb/Bya/Byb`
preserve snarkjs G2 affine `[[x.c0,x.c1],[y.c0,y.c1],[1,0]]`; no Solidity-style
Fq2 component reversal occurs. Values remain canonical unsigned decimal JSON
strings. PF7 retains responsibility for converting them to its internal VM
number encoding.

`test-fixtures/two-public` is a local development-only two-public-signal
snarkjs fixture. The test first asks pinned snarkjs to verify it, then adapts
it and exercises malformed and adversarial imports. It is not ceremony or
profile material.
