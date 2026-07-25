# Live Chipnet single-cycle E2E v1 (Phase A)

Development-only profile on BCHN v29 Chipnet (`layer1-node`). Desktop proving. Zero-conf posture (mempool accept = success). No keys/WIFs.

## Identity

| Field | Value |
|-------|-------|
| profileId | `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7` |
| instanceId | `sha256:d96968b889dfdcfd65f0e89953d94a2ac2f0ca60c03bfa23867ce4293b8bc1aa` |
| stateNftCategory | `c54c3bfee893dda33a0a8b1f0e1408aa95e0b0bfb31bb9a057ffeb085b3bdbcc` |
| bundle | `.cache/profile-build-live/profile-bundle` |
| verifier | `bn254-onetx-pf7-sub62-r1` densFuel-DROP pins `[8177,6654,7066,7066,8393,7600,9350]` |

## On-chain transactions (display-order txids)

| Step | txid |
|------|------|
| Category consolidate | `c54c3bfee893dda33a0a8b1f0e1408aa95e0b0bfb31bb9a057ffeb085b3bdbcc` |
| Genesis | `980f075fdc3bc807675fbcd31454e5108765715e7bb30a6adc7a3af27d1004a5` |
| Deposit prep | `9e40d9f1e031ced21f9f52516831027dafd6191013e5fde27162ec533570f69f` |
| Deposit settlement | `0d7cf1cefb38ed1850d33b6c4b0edb905390e8f08f9e785fa93397b9c6708944` |
| Cold→hot top-up | `3ef8c67760be9f694bd5c152ff2446ae443850d4f4732cbab321abd399fa4f71` |
| Transfer prep | `b53e34ecf191d221c904892926fa858cdfaf2d43fd043decfe07f22ebef69064` |
| Transfer settlement | `3f6f164b63f80d07fd248205e9ff2ede8dff0d8e7327781046a5558d29d5fb6c` |
| Cold→hot top-up2 | `60d84cc481759f7dd2cdbd5ee9164b9c68cd8d56fd10809de7ceb1c8a4ed22be` |
| Withdrawal prep | `c9b3b94e85593b4f7f387130a58eadd3d88928c49f01a0c437d286750fd6d130` |
| Withdrawal settlement | `aaf90fa125cc2561c498327c34f0d427b91bdd24e109be490ccf94be125d0a74` |

## Settlement measurements

| Action | wire B | max unlock | fee (1 sat/B) | libauth 10/10 | BCHN allowed |
|--------|--------|------------|---------------|---------------|--------------|
| deposit | ≤59k | 9350 | =wire | yes | yes |
| transfer | 56964 | 9350 | 56964 | yes | yes |
| withdrawal | 56998 | 9350 | 56998 | yes | yes |

Withdrawal payout: 0.1 BCH to hot p2pkh (`76a914233c0f9b…88ac`). Pool live notes after cycle: 0.

## Recovery

- `extractRawSettlementHistory` on BCHN raw genesis+3 settlements → kinds `[deposit,transfer,withdrawal]`, terminal liveNoteCount=0.
- `createRawSettlementJournal` append → rollback(1) → replay(withdrawal) green.
- Provider-absent: same packet bytes from `.cache/live-chipnet-e2e/*.packet` match chain-extracted history for note recovery.
- Note decrypt: domain-derived wallets from witness seed `0x42×32` via `shield.cash/fresh-witness-wallet/{deposit|transfer}/v2\\0` — deposit wallet 1 note (spent at seq 2), transfer wallet 1 note (spent at seq 3); unspent=0.

See `recovery-live.json`.

## Artifacts

- Hashes: `hashes/artifacts.sha256`
- PF7 pins: `pf7-unlock-pins.json`
- RPC: `rpc/withdrawal-settlement-mempool.json` (`allowed: true`)
- No private keys, WIFs, or HANDOVER content.

## Phase A exit

**GREEN** — single-cycle deposit→transfer→withdrawal live on Chipnet with recovery evidence.
