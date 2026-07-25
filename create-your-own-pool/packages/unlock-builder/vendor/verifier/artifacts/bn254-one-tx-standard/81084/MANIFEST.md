# MANIFEST - BN254 one-tx direct-state rank25 measured bundle, 81,084 B

| field | value |
|---|---|
| id | `bn254-one-tx-direct-state-81084-local` |
| track | `bn254-one-tx-standard` |
| status | **measured / persisted / UNBANKED / NOT A SOUND CROWN** |
| score | **81,084 B** (`80,634` raw score component + `450` tx overhead) |
| wire | **79,719 B** |
| inputs | `10` |
| profile | `DIRECT_FINALIZE_STATE=1`, `STRICT_DEPLOYMENT=1`, rank25 fixed-VK/deployment profile |
| source | verifier.cash detached `9ee774faf3e5d58a02aff55fc67b08749d4cdf6` |
| compiler | cashc-resched `bf02a4b641d5d03c035d052247a545109c17b708`, `0.14.0-next.1` |
| VM | libauth `3.1.0-next.8`, BCH2026; LeanBCH overlay `46d89489e668faa8aaafb35517796c842bed87f5` |
| parent | `1,508 B`, txid `cacc406c2dba61e15ac8db081d65c08ec4c965d2a955a2b5f60ac70e1f07b47b` |
| gates | real VM `10/10`; UTXO/vmbconf `11/11`; A1 `89/89`; role `52/global0`; deployment `12/global0`; all A1 encoding classes exercised |

## Scope limits

- Fixed VK, fixed deployment, fixed BCH transaction envelope, and empirical dense corpus only.
- Not arbitrary-VK, generic, universal-completeness, live-normalized, submitted, or independently certified.
- The persisted 256-row sweep is separate artifact evidence; the exact-source clean rank25 rerun and fresh clean full-corpus VM replay are both recorded. The full-corpus replay is real-build/VM evidence, not a full-corpus A1 battery or universal-completeness proof.
- `targetOnlyFalseAccepts=3` in the A1 deployment battery are intentionally targeted mutation outcomes; `globalFalseAccepts=0`, `standardGlobalFalseAccepts=0`, and `noOps=0`.
- Local `raw`/`wire` decomposition is not yet normalized to the upstream leaderboard's `scriptBytes` field.

## Reproduction

Exact commands and environment are recorded in:
`catalogue/empirical/E-onetx-direct-state-clean-leanbch-r25-2026-07-17.md`.

Fresh clean overlay gates:

- `lake build`: exit 0, 30 jobs; log sha256 `784e1bba06c1b8731f420681ca56292aa601942956b333cd7779ba97aab487e6`
- target build: exit 0, 123 jobs; log sha256 `2cab7cf50000ab5d3c38e676ab04db858572c96774bc43e2eab23845684cc0a0`
- `bash tools/opt-ci/verify.sh`: exit 0, `ALL CHECKS PASS`; log sha256 `3a4a75f58ca6119821bbf0547285dfdb1160e600d6e0cb0525640e0bc3a3f82a`

## Files and hashes

| file | sha256 |
|---|---|
| `c7_candidate_tx.hex` | `1e4f13a4c7917bceb455c0336150b2e91be3a6ba431f9b5d0c7bac7f0602c789` |
| `c7_candidate_srcouts.hex` | `3d03a37136e01ffb64d46b5622b34934a4c1b287630158ca3f4e3f9117c9c6b9` |
| `spend_tx.hex` | `50f302f425911eede82a09344c9d74a7a725423531074782c69eda57930644e7` |
| `spend_srcouts.hex` | `3d03a37136e01ffb64d46b5622b34934a4c1b287630158ca3f4e3f9117c9c6b9` |
| `parent_tx.hex` | `7cfa6621cf963ada0a332854bb748a5f66fbb1686d2242226c94396a9e5261d7` |
| `parent_srcouts.hex` | `5078f2aa423b77eddc58516324a4dab034e963b74992153d0eef9b5a6fcf62d9` |
| `funding_srcout.hex` | `5078f2aa423b77eddc58516324a4dab034e963b74992153d0eef9b5a6fcf62d9` |
| `inputs_dump.json` | `3de5119e3b1f79dfd468317e1e602b4cd9fa608e76095ae99efba90dc529aa75` |
| `result.json` | `5b69f6f654fdf42a81f7d6b31da1c5a527afa4ea073f653ca45eac2a71805a65` |
| `boundary_parts.json` | `0f61192a97659904b9857b1087642d56a4dade0e845a2df88c442b573c77a599` |
| `c7_opmargin.json` | `68cc70feb5aa2ac4d743c0abd092579e3803992d422ac2a921ac68d48b625c41` |
| `envelope-manifest.json` | `ad420c419ff2fcbc98789822eaab5963eacdee4dcdb0d6532f77968d0a5ae170` |
| `a1-results.json` | `76beaf5c26f66d6e9a84e54ab863fae0d39915fdd582aed5e9289c9157940a29` |
| `a1-summary.json` | `7a21da11ecea672a5ef31abb1d07290839917bc5cea2c3f6fc08a2cd62e8a3db` |
| `role-battery.json` | `f4ea440fdb28fee08020682902cf84c5fde730741c85f6cedacc55228b548511` |
| `strict-deployment-battery.json` | `c3d296acff2132154bb736171c23f42b2b4a34c768dc18c6dc5564571286e165` |
| `full-corpus-clean-aggregate.json` | `6479ab1e5ea885cbcf782f8db679f47864cd4605dc492cb591d86253d5ec6c63` |
| `full-corpus-clean-index.json` | `832944ea5909b507b00b67c3ab1988d303636f451381a3eb4cc50fef4a945bd9` |

## Catalogue links

- `catalogue/RESULT.md` - canonical numeric status
- `catalogue/empirical/E-onetx-direct-state-81084-2026-07-17.md` - full fixed-profile evidence
- `catalogue/empirical/E-onetx-direct-state-clean-leanbch-r25-2026-07-17.md` - exact-source clean replay
- `catalogue/empirical/E-onetx-direct-state-clean-full-corpus-2026-07-17.md` - exact-source full-corpus replay
- `catalogue/research/R-onetx-promotion-normalization-2026-07-17.md` - promotion gates and open obligations
