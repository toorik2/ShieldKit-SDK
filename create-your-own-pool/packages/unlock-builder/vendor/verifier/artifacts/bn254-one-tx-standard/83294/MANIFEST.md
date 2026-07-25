# MANIFEST - BN254 one-tx direct-state public-bench bundle

| field | value |
|---|---|
| id | `bn254-one-tx-direct-state-public-83294-local` |
| track | `bn254-one-tx-standard` |
| status | **public-bench PASS / measured / UNBANKED / NOT SUBMISSION CROWN** |
| score | **83,294 B** (`82,118 B` wire + `1,176 B` summed locking bytes + `450 B` one-tx score overhead) |
| public bench script | **82,844 B** (`1,176 B` locking + `81,668 B` unlocking) |
| inputs | `10` |
| profile | `DIRECT_FINALIZE_STATE=1`, `STRICT_DEPLOYMENT=1`, `PUBLIC_BENCH_CONTEXT=1`, `STRIPED=1`, `STRIPE_BOUNDARY=1`, `DP=1`, `KWIN=9`; fixed VK/fixed deployment; stock source value `1,000`, sequence `0` |
| source | verifier.cash commit `7cd340227b960ddc67e20eb4f9f388a6613dfb95` |
| compiler | cashc-resched `1c707c1dbf87396b30ba5e0704b1db44475ce893`, `0.14.0-next.1` |
| VM/toolkit | libauth `3.1.0-next.8`, BCH2026; LeanBCH `7270e006852db43fecca1417bf185c789e4c5132` |
| parent | `1,319 B`, txid `fbc974895947f1c014286abfc01ff738a45fbd6e9fc4a89878a33e72c8717c94` |
| public verifier-bench | **unmodified c989e93a**: script `82,844 B`, op-cost `60,335,009`, valid `10/10`, tamper rejects `10/10`, proofs `4/4`, worst-case accepted, standard/BCH green |
| rank25 real gate | `10/10` |
| rank25 A1 | `89/89` executed; global false accepts `0`; standard false accepts `0`; no-ops `0`; target-only diagnostics `3`; LeanBCH dual `155` |
| role battery | `52` cases; global accepts `0` |
| deployment battery | `12` cases; global accepts `0`; standard global accepts `0`; no-ops `0` |
| full corpus | `256/256` build/gate/seam/manual/per-input green; score range `83,294..83,557 B`; max unlock `9,591 B`; cap overflows `0`; gate throws `0` |

## Scope

- This is the separately named stock-context profile. It is not the strict `83,344 B` fixed-envelope research artifact and is not the submission crown.
- Public compatibility means the maintainer verifier-bench checkout at `c989e93a747b8edb9643799d3259d1506aafb3aa` with its VM/scorer/context code unmodified. Only the submitted implementation/vector registration is added in the isolated replay.
- Fixed VK, fixed BCH transaction topology, fixed deployment role topology, and supplied `py_ecc.bn128` corpus. Not arbitrary-VK, independently-proved, universal-completeness, finite-retry-complete, generic deployment, banked, or leaderboard-submitted.
- All scored bytes are concrete BCH VM artifacts. No filler, zero-fill, phantom input, detached acceptance channel, duplicated executable body, or synthetic state.

## Reproduction

Build the public-context source profile with `PUBLIC_BENCH_CONTEXT=1` and the exact environment recorded in `catalogue/empirical/E-onetx-direct-state-public-verifier-bench-83294-2026-07-17.md`.

Run the unmodified public bench checkout with `bch-groth16-intratx-direct-state-public`; do not apply `verifier-bench-context.patch` or any VM/scorer patch.

## File hashes

| file | sha256 |
|---|---|
| `c7_candidate_tx.hex` | `bf98c9214b4383cdd05214595334efca0c4ca71661ee88e90ea4eb9d90366678` |
| `c7_candidate_srcouts.hex` | `eb311a5fa5c8c3e48d54464d1daff465d0ce42bd226f0da2aeef62fb6a0e7348` |
| `inputs_dump.json` | `9371eeae819d2b40d7149f6f70171e81dbd1c5d972db91c42f89c65777fb1f11` |
| `result.json` | `0a9e7d66e430f48ade01502aff6e05e3c4fc7e04f3e7195e05887f8be6c60c97` |
| `envelope-manifest.json` | `a9754db353ce9ab9713413d2b574342aef11c92664c5901f9d06c7401724a57e` |
| `a1-results.json` | `762aaa6cdcfa28053ee32b0f5eeccd0c28c5a5c007c62463474d2b60b7cfbc9e` |
| `a1-summary.json` | `1615484014ac9c62017df7846dea7754ccea174771c7b94aef3a10dc35f80f9b` |
| `role-battery.json` | `78555b9d8bbf2debbeff76c2cc161c977fc4d03fd05cf5357a70b48754d5fdbd` |
| `strict-deployment-battery.json` | `8bc8fd0f604db71c88eba7385947aef7b7530b0c56a35b96077d0e820a38808f` |
| `full-corpus-aggregate.json` | `05c55e14ec5bd84bd129a6b1565f25897386871f6f67c64d05ecf58c35231d1c` |
| `lock-invariance.json` | `06533756f6fae71be3174ac0b2ad72923e7749a2673dd8139c61441d423e91ac` |
| `verifier-bench-output.txt` | `43bdcbf82d701662c02eb5a39df7891310e3cdb9677c30da160eb7db6f160661` |
| `verifier-bench-vectors.json` | `548a149b3512586a3dd43508004c32e946c740a937d97c82e7ac8271a1f191e3` |

## Catalogue links

- `catalogue/empirical/E-onetx-direct-state-public-verifier-bench-83294-2026-07-17.md` - public-bench empirical record
- `catalogue/empirical/E-onetx-direct-state-strict-verifier-bench-83344-2026-07-17.md` - separate strict research profile
- `catalogue/research/R-onetx-promotion-normalization-2026-07-17.md` - promotion obligations
