# FRI-STARK

`fri-stark-96kb` is an unaudited, Chipnet-only Lab design using a Goldilocks
DEEP-ALI FRI-STARK. Research records report 17 verifier roles and 18 inputs per
action. Its structural reality gate measured 96,734 bytes; the fresh masked
live-action record reports up to 99,207 bytes, below the 100,000-byte ceiling.

## What is demonstrated

- fresh masked proofs and a create, deposit, transfer, withdraw, recover
  lifecycle on Chipnet;
- fixed profile locks, structural covenant checks, adversarial corpus, scaling,
  and reproducible-package records within the declared scope;
- an experimental Lab router and a separate package-local executable.

See the [production report](https://github.com/toorik2/ShieldKit-SDK/blob/main/designs/fri/evidence/production/PRODUCTION_REPORT.json)
and [release verdict](https://github.com/toorik2/ShieldKit-SDK/blob/main/designs/fri/evidence/release/RELEASE_VERDICT.json).
The directory name `evidence/production` is historical; it does not promote the
profile beyond the verdict's permitted experimental beta claim.

## Why it is not Product

- The unified CLI can inspect the design, but no single authoritative
  content-addressed profile and note/key contract is frozen; every mutation is
  blocked.
- The Lab router requires an ignored private worker build and materialized
  assembly evidence.
- It contains a maintainer-local wallet fallback; callers must pass an explicit
  wallet path.
- The independent two-host P7 journey was not executed. Release verification
  records it as an operator-approved out-of-scope waiver.
- There is no mainnet, audited-production, encrypted-note privacy, or Groth-pool
  compatibility claim.

The in-tree replacement plan is a hashed qualification input and remains a
Record, not user guidance.

Research profile record (not unified mutation authority): [`profile.json`](https://github.com/toorik2/ShieldKit-SDK/blob/main/designs/fri/profile.json)
