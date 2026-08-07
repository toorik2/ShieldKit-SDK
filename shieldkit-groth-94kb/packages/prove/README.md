# `@shieldkit/prove`

Strict file-based adapters for pinned snarkjs BN254 Groth16 material.

## Public API

`@shieldkit/prove` is the only supported entrypoint.

- `adaptSnarkjsGroth16`: validate and normalize a pinned proof, public-signal file, and verification key
- `adaptV2DirectGroth16`: wrap that conversion in the V2 Direct adapter contract
- `V2_DIRECT_GROTH16_ADAPTER_SCHEMA`: V2 adapter schema identifier

## Boundary

These adapters do not generate a proof, build or execute a BCH verifier, perform setup, or establish standardness, deployment, or production qualification. `v2/`, `lab/`, and `internal/` source paths are not public entrypoints.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../README.md) and [product model](../../../docs/product/model.md).
