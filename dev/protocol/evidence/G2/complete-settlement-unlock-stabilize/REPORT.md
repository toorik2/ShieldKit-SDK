# Complete settlement — unlock-length stabilize (densFuel-DROP)

Observed: 2026-07-24T05:04:22Z

## Profile

- profileId: `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7`
- instanceId: `sha256:74770b7d277c1953842dcdf3e6a9446620b293512786dcf02c4e8a6d7641b5d6`
- network: chipnet
- setup: development-only
- unlock stabilize: genesis densFuel-DROP pad → 7600 B; terminal densFuel-DROP pad → 9350 B
- PF7 locks multiproof-identical across deposit/transfer/withdrawal

## Size + fee (1 sat/B)

| kind | wire | maxUnlock | fee | sizeOk | VM 10/10 |
|------|------:|----------:|----:|:-------:|:--------:|
| deposit | 56964 | 9350 | 56964 | True | True |
| transfer | 56964 | 9350 | 56964 | True | True |
| withdrawal | 56974 | 9350 | 56974 | True | True |

## Mutation matrix

- 9 attacks × 3 actions: flip each PF7 unlock mid-byte, flip packet byte, wrong fee key
- all attacks rejected (assemble fail or VM reject); honest 10/10 accept

## Artifact hashes

- `0017cc47bab8c26017868668b79ac95a2c3972f526b2db136ea72579911e1e80` .cache/complete-settlement-stabilize/summary-final.json
- `7ec7114d2fcc63f5df14e05ce705e37446c97c514d1b6f3cb51917bba3df8e3f` .cache/complete-settlement-stabilize/mutation-matrix.json
- `cfb1c63f4359a6b1458819e3d9dd2882d70b6413fbe72ca76b1b15c8734001f2` .cache/complete-settlement-stabilize/deposit-tx.hex
- `dc3a672ca63344bebf260ed812307bb3d54039600fcde5c6d1871162b3705fb8` .cache/complete-settlement-stabilize/transfer-tx.hex
- `859f2c86e0055c6425dbc5a616a17ff7209d26ce872143715e63e81428f8e296` .cache/complete-settlement-stabilize/withdrawal-tx.hex
- `a97647c206b1741937895de5276f466da969c935ea47d5f5677505c93d5ce171` .cache/pf7-verifier-set-stabilize/bch-verifier-set.json
- `fc1f7a063ead762ba6079df7467dce859d0b7f8b2d303adb41da04c522cdee1f` .worktrees/verifier-pf7-sub62/lanes/bn254-onetx/src/c7/build.ts

## Unlock length pins (all actions)

```
exec0..4: 8177, 6654, 7066, 7066, 8393
genesis:  7600  (densFuel-DROP stabilize)
terminal: 9350  (densFuel-DROP stabilize)
```

## Notes

- Root cause of prior oscillation: minimal Script-number encoding of proof limbs → genesis/terminal unlock lengths varied ~65 B → fee/change → SCCT digest oscillation.
- Fix: densFuel-DROP pad to fixed targets (C7_GENESIS_UNLOCK_TARGET=7600, C7_TERMINAL_UNLOCK_TARGET=9350); genesis inject OP.DROP (lock-changing → new development-only verifier-set + profile).
- SCCT fixed point: plan with seed length-stable PF7 → prove → PF7 rebuild → lengths match by construction → assemble binds → libauth 10/10.
