# Live battery v1 (PARTIAL)

## Status
- **Phase A** single-cycle E2E: **GREEN** (`evidence/G2/live-chipnet-e2e-v1`)
- **Phase B** volume: **PARTIAL** — harness + multi-cycle continuity fix shipped; **3 full battery cycles** completed on same profile/instance after Phase A (targets ≥20 not yet met)

## Identity
- profileId `sha256:79782441…`
- instanceId `sha256:d96968b8…`
- category `c54c3bfe…`

## Shipped fix
`generateFreshWitnessInputs({ priorCycles })` continues note/nullifier trees and `actionSequence` across cycles (required after first withdrawal). Unit test: `priorCycles continues actionSequence…`.

## Battery results
See `summary.json` + `ledger.jsonl`.

## Failure classes observed
1. **funding_shortfall** — deposit prep needs ≥~10.1M sats (binding carries 0.1 BCH denomination)
2. **pf7_dens_fail / multiproof genesis OP_VERIFY** — rare snarkjs-valid proofs fail PF7 genesis (~198k ops); rebuild with different fee UTXO changes digest and usually succeeds
3. **driver_bug** — missing `lastCompleted` init (fixed: saveState per action + resume hooks)

## OPEN
- Scale to ≥20 full / ≥10 dep-wd / ≥10 multi-xfer chains
- Adversarial reject matrix samples
- Recovery battery every N cycles (Phase A recovery green)
- Root `npm test` after broader package touch

Cold treasury snapshot at evidence write: see summary.json.
