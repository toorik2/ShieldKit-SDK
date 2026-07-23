# Two-public snarkjs test fixture

This is a local test-only BN254 Groth16 fixture. It is generated from
`circuit.circom` and `input.json` using the package-pinned `circom2` and
`snarkjs` versions. It is not verifier-bundle, ceremony, profile, or
qualification material.

The circuit exposes exactly two public signals, `in0=3` and `in1=5`; its
private witness satisfies `witness = in0 * in1`.
