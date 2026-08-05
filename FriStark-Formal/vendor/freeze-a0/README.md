# ShieldKit Protocol V2 STARK

**Status:** A0 specification freeze for the Goldilocks DEEP-ALI FRI-STARK product profile.  
**Not** production-qualified until [REQUIREMENT_MATRIX.md](./REQUIREMENT_MATRIX.md) claims are closed by **[ShieldKit-Assurance](https://github.com/toorik2/ShieldKit-Assurance)** evidence (not by an in-repo test suite).

This profile replaces the Groth16/BN254/PF10 spine with:

- Proof system: [0zkbrewer/BCH-FRI-STARK-Verifier](https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier) (vendored pin)
- Field: Goldilocks
- Crypto: EC-free Poseidon2 (`poseidon2-ec-free-v1`)
- Trees: depth **32** / **32**
- Soundness floor: ≥100-bit conjectural production FRI params (not golf tips)

## Documents (normative freeze)

| Doc | Role |
|-----|------|
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | Product and security contract, full protocol |
| [BYTE_LAYOUTS.md](./BYTE_LAYOUTS.md) | Every wire layout |
| [PUBLIC_STATEMENT.md](./PUBLIC_STATEMENT.md) | STARK public statement ABI + binding rules |
| [CRYPTO_EC_FREE.md](./CRYPTO_EC_FREE.md) | Poseidon2 domains, keys, notes, records |
| [FRI_PARAMS.md](./FRI_PARAMS.md) | Production FRI parameters and bans |
| [TOPOLOGY.md](./TOPOLOGY.md) | Settlement input/output roles |
| [REQUIREMENT_MATRIX.md](./REQUIREMENT_MATRIX.md) | Chipnet qualification gates |
| [PROHIBITED_TOPOLOGIES.md](./PROHIBITED_TOPOLOGIES.md) | Hard bans |
| [contracts/](./contracts/) | Inter-track JSON Schema contracts |

## Relation identity

```text
relationId   = shieldkit-pool-action-v2-stark
proof.system = deep-ali-fri-stark
proof.field  = goldilocks
profileCore.crypto = poseidon2-ec-free-v1
```

Groth16 V2 Direct (`docs/protocol/v2-direct/`) remains a separate, non-migrating profile.

## Code layout (implementation tracks)

```text
packages/{action,prove,unlock-builder,kit,profile,pool,recover}/v2-stark/
vendor/bch-fri-stark/
crates/shieldkit-v2-stark-codec/
artifacts/v2-stark/
```
