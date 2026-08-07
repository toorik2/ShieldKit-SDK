# Record

Records are exact machine evidence, release pins, and source-linked decisions.
They may be dated, superseded, or narrowly scoped. They are not current setup
instructions, and a missing field never implies a pass.

## PF10

- [Release pins](../../shieldkit-groth-94kb/pins/)
- [Circuit sources](../../shieldkit-groth-94kb/circuits/v2-direct/)
- [Qualification scripts](../../shieldkit-groth-94kb/scripts/)
- [Benchmark method](../../shieldkit-groth-94kb/bench/README.md)

## PF6

- [Profile identity](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/profile.json)
- [Evidence ledger](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/LEDGER.json)
- [B-02 whole-transaction result](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/04-qualification/b02-final.json)
- [Readiness declaration](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/09-readiness/readiness-declaration.json)
- [Accepted risks](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/accepted-risks.json)

## FRI-STARK

- [Profile identity](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-fri-stark-96kb/profile.json)
- [Release verdict](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-fri-stark-96kb/evidence/release/RELEASE_VERDICT.json)
- [Qualification report](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-fri-stark-96kb/evidence/production/PRODUCTION_REPORT.json)
- [Randomness audit](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-fri-stark-96kb/evidence/production/RED_TEAM_AUDIT_20260807.json)

The FRI replacement plan remains in-tree because qualification code hashes it
as an input. It is not part of the public documentation path.

## Exclusions

- `vendor/**` documentation belongs to upstream projects.
- `archived-pool-designs/**` is historical V1 material.
- ignored local evidence, handovers, wallets, and build output are never public
  documentation.
