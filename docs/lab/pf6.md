# PF6

`pf6-a3-direct-v1` is an evidence-backed Groth16 Lab profile. It uses six
verifier roles and nine inputs per action; its frozen reference verifier reports
54,671 script bytes.

## What is demonstrated

- create, deposit, transfer, and withdrawal transactions on Chipnet, plus
  chain-scan recovery;
- identical-transaction Libauth, BCHN, and LeanBCH acceptance for the qualified
  lifecycle corpus;
- adversarial, formal, clean-host, and artifact-provenance records.

Start with the [E2E story](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/03-implementation/e2e-story-suite.json)
and [B-02 final record](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/04-qualification/b02-final.json).

## Why it is not Product

- The root `shieldkit` binary does not route profiles.
- The Lab module contains maintainer-absolute PF10 and `snarkjs` paths.
- The frozen release manifest says `productionQualified: false` and
  `releaseQualified: false`.
- A withdrawal lane-layout failure was reproduced; a later E2E pool succeeded
  because its shard layout matched. Treat this as conditional risk, not closure.
- The setup is single-contributor and does not establish ceremony independence.

Profile identity: [`profile.json`](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/profile.json) ·
accepted risks: [`accepted-risks.json`](https://github.com/toorik2/ShieldKit-SDK/blob/main/shieldkit-groth-54kb/evidence/accepted-risks.json)
