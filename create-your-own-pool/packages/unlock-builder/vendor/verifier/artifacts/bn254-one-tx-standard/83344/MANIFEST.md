# MANIFEST - BN254 one-tx direct-state hardened strict rank25 bundle

| field | value |
|---|---|
| id | `bn254-one-tx-direct-state-hardened-83344-local` |
| track | `bn254-one-tx-standard` |
| status | **measured / persisted / UNBANKED / NOT A SOUND CROWN** |
| score | **83,344 B** (`82,168 B` wire + `1,176 B` summed locking bytes; `81,718 B` summed unlocking bytes) |
| wire | **82,168 B** |
| inputs | `10` |
| profile | `DIRECT_FINALIZE_STATE=1`, `STRICT_DEPLOYMENT=1`, `STRIPED=1`, `STRIPE_BOUNDARY=1`, `DP=1`, `KWIN=9`, rank25 fixed-VK/fixed-deployment |
| source | verifier.cash commit `22ecb02093cacfe07e73d075c08010cd3a579ed3` |
| compiler | cashc-resched `1c707c1dbf87396b30ba5e0704b1db44475ce893`, `0.14.0-next.1` |
| VM/toolkit | libauth `3.1.0-next.8`, BCH2026; LeanBCH `7270e006852db43fecca1417bf185c789e4c5132` |
| parent | `1,319 B`, txid `9fccadd0fc91b57db64df72276b3a527b9de4d283980a5c5547ad8ac76a18bfd` |
| gates | local real VM `10/10`; LeanBCH/op-cost parity `10/10`; vmbconf `11/11`; A1 `89/89`; role `52/global0`; deployment `12/global0/noOps0` |
| verifier-bench | strict context-capable replay: script `82,894 B`, serialized score `83,344 B` (`+450 B` tx overhead), op-cost `60,335,223`, `10/10` rejects, `4/4` proofs, worst-case accepted, standard/BCH green |
| benchmark context | source value `10,000` satoshis and sequence `0xffffffff`; replay uses `verifier-bench-context.patch`, sha256 `0341912bdd138e5e9ff37bf23fa446d71f8457ad59ae3df5b310da41d745d6e3` |

## Scope

- Fixed canonical VK, fixed deployment envelope, fixed BCH transaction topology, and supplied `py_ecc.bn128` corpus.
- Current-source sweep: `256/256` builds, real gates, seam chains, manual accepts, and per-input accepts; score range `83,344..83,607 B`; max unlock `9,591 B`; no cap overflow/gate throw.
- Local A1 target-only accepts: `3`; complete-transaction/global accepts: `0`; standard-global accepts: `0`; no-op mutations: `0`. Target-only cases are not treated as global soundness passes.
- Public verifier-bench compatibility has two measured forms: this strict profile passes after the explicit context extension above; the unmodified maintainer context is represented by the separate portable profile, which measures `82,636 B` script bytes / `83,086 B` serialized score and passes on `c989e93a747b8edb9643799d3259d1506aafb3aa`.
- Not arbitrary-VK, independently-proved, universal-completeness, finite-retry-complete, generic deployment, banked, or submitted.

## Reproduction

Exact strict build, UTXO replay, A1, role, and deployment commands are recorded in:
`catalogue/empirical/E-onetx-direct-state-hardened-83344-2026-07-17.md`.

## File hashes

| file | sha256 |
|---|---|
| `c7_candidate_tx.hex` | `4cf185ad799c64308d7b0576e90876ece6a3d832e5d564a21252610ca9e1da36` |
| `c7_candidate_srcouts.hex` | `26591a63f8683dac80d826468fc1b99cce69901d722de7d5b147de8caa323d0d` |
| `inputs_dump.json` | `23a9aa0659e13e0448e013de57df8ea5cd19ec9c2e12bb318745e5c28f42b7cc` |
| `result.json` | `ca1e8a2bc6f9a261f0f38074304eb5afd6893e4b4eede6ee56b5bbe32839d734` |
| `boundary_parts.json` | `f42fbf7cc08e0137437a08acf8716d33f562de0f48a83df1780ac0a92ee3c3f5` |
| `c7_opmargin.json` | `d66c2e4454756660af925662e5da7ca6bdc6ef2cabde30e442e3258ee02166c0` |
| `envelope-manifest.json` | `6a9dc724490e558959984e5c761254230de833f8a2367ba39f9a185aa2aa1e9d` |
| `a1-results.json` | `8491f514ab0ebc55bb26a435ef588eb26d594056ba6122068b920583bd75a0c3` |
| `a1-summary.json` | `a22a600abc8f4e6f66b8e3c0f8aa0a0f8f3bc350977541c62d4e25ac141c037f` |
| `role-battery.json` | `57614cd55f591e9af400e5168bd8f48bc1c5c8ef4f6d7e4d16d11d3fba46dac2` |
| `strict-deployment-battery.json` | `4a3a6025596f6b30d79560a5f3923770cbbca52d2e2115a662ae7f6230d957f1` |
| `full-corpus-aggregate.json` | `940218322743aeae6b34017ee42360d5f14adf49dd80c26205d136424ebb99bd` |
| `lock-invariance.json` | `32fc1bb23dd66319e3362f925de47988fa5774dddba34577dfb86adfd85c04b7` |
| `verifier-bench-output.txt` | `1b60d61309d2d7921958e706abfb8f1e896498a17ee4dfcdb3dd13fc100ecee3` |
| `verifier-bench-vectors.json` | `6c747ec57285e06a7d062b2b7da4ef6b683494007bfa7c5422328a497b6bf975` |
| `verifier-bench-strict-output.txt` | `f026da875dcd58c225bc46939e35af448049cff41d115b32a1b9e2d7268f76d2` |
| `verifier-bench-strict-vectors.json` | `05b725bcf8800e43f8d9fa8eda75cd9a59c93738cae37b7aa4a72a0142580d2b` |
| `verifier-bench-context.patch` | `0341912bdd138e5e9ff37bf23fa446d71f8457ad59ae3df5b310da41d745d6e3` |

## Catalogue links

- `catalogue/RESULT.md` - canonical numeric status
- `catalogue/empirical/E-onetx-direct-state-hardened-83344-2026-07-17.md` - strict fixed-profile evidence
- `catalogue/empirical/E-onetx-direct-state-strict-verifier-bench-83344-2026-07-17.md` - strict context-capable verifier-bench evidence
- `catalogue/empirical/E-onetx-direct-state-verifier-bench-83086-2026-07-17.md` - portable public-harness evidence
- `catalogue/research/R-onetx-promotion-normalization-2026-07-17.md` - promotion obligations
