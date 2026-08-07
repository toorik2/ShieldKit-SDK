# HANDOVER §7 Final Report — ShieldKit-Groth Beta

## Verdict: **READY**

All definition-of-ready rows green for Chipnet beta (unqualified). No tag/publish.

## Identity

- Final HEAD (pack fix): `9b8e4ee9107c1bdab8a2dbcb064335d074b056d8`
- Live packed-CLI base: `d06632c8dc76efae6a5a520b8d7b7cc4a308e50c` + package-lock present in install root (fix shipped in HEAD)
- Pin: `shieldkit-v2-beta-20260802-r3`
- Manifest: `6aa1a3b8670b414e2beb4f8e08cd93519883f7920a899b73eacd743a28d780a0`
- Install receipt: `af749cba3caf8d825e5199294c01c004727cb97c11b59975883dfcf4d2cc5875`
- Instance: `e5b310e8bdb4e666cf9acfddf5bf5e15a55373f2038b206f7fb53f04d610c6c4`
- Source: `c4c610d6043fb57f6f208b03f27353a5155ebff5ddcf9acf66e6b4bde810b3e5`
- Genesis: `dd269eed7c5745f9815709a06b68ce24a286276c2f60d85dfe7c321ec9e56d7d`
- Payout (external, not fee): `bchtest:qqtn75vs9ah3tuj40es2y8w7f93zg3hxxug5cvc9pk`
- Entrypoint: packed tgz CLI `/home/toorik/.local/share/shieldkit-packed-cli-d06632c/run/node_modules/shieldkit/shieldkit-groth/scripts/shieldkit.mjs`

## Actions (full txids) — packed CLI

| Kind | Txid | commandTotalMs |
|------|------|----------------|
| deposit | `2e6139d0f652adeb214a44b662558c0e0d3ef46c9a26955099b32f58169bdeec` | 9355.462309 |
| deposit | `6e09b9a85b9fa91be35a84232cc04c53b5e361b43baafa01e0a0d286ec946831` | 10263.950267 |
| deposit | `571b567d9c1c2d84beef69b7c2eb0a000ce2e05e007d73914494df39c10fcec0` | 10819.40893 |
| deposit | `7214631da7c14183f854932b128884256c4b9368476b6016dadbdc96c7ad6f79` | 10470.179198 |
| deposit | `74ea154a31260ad4bdad7fb9cf4129f2cc8da414121ee70d3c25a48e7d2aa460` | 10349.806138 |
| transfer | `08391dc1a8416a3eb821a111d08d56266c5b2e528ddda2e5c0e9296d82fb8fde` | 10932.999257 |
| withdraw | `8d6eb25514b1718ce032011660788571539fa0aad7575ce0dd7063e321212175` | 10605.033166 |
| withdraw | `e3c66e3bfed010f136a3fbc9e52da972c34e09dc8f83c74d0e005d1e7c43f60b` | 10720.225170000002 |
| withdraw | `4e534963e828391216a29b197ce9476570cee9ba1365349fd8a7588c7ff56496` | 10582.870042 |
| withdraw | `d2052a1fce5f1790a734ff59ef628efde4de3de15f7842a09fccb901e58d66ef` | 10406.73359 |
| withdraw | `323ab967c35aaaabffe48db6882a22e10df4acc4d63a10487050308dd7273b8c` | 10817.960297 |

## Latency

- n=11 p50=10582.870042 p95=10819.40893 max=10932.999257 all≤15s=True

## Limits / multi-verifier

- maxUnlockBytecodeBytes **exactly 10000** (zero margin) — disclosed
- Libauth BCH_2026_STANDARD: allActionLibauthOk=True actionTxs=11 totalTxs=13
- BCHN presence: 13/13 raw dumps under `packed-live/raw/` + decoded JSON
- LeanBCH: formal suite is vendor/conformance, not a per-live-txid consensus re-eval binary; independent multi-verifier capture is Libauth + BCHN + product VM allInputsAccepted
- Privacy passive payout gate: **PASS** (payout≠funding-like; collisions=[])

## Local gates (criterion 1)

- Isolated blank-clone path `/home/toorik/.local/share/shieldkit-blank-clone-d06632c` @ d06632c
- Sequence: private worktree → npm ci → qualification:beta **PASS** (log `blank-clone/isolated-blank-clone-gates.log`)
- Pool-create unit tests after pack fix: 13/13 pass

## Pack / runtime

- Root cause fixed: pack allowlist omitted `package-lock.json` → runtime source fingerprint failed → false `BETA_POOL_RUNTIME_REJECTED`
- Fix: `package.json` files includes `package-lock.json`; clearer source-unavailable error in pool-create
- Authenticated PF10 artifacts installed under data-home (receipt above); trust outside tgz bundle

## Publication

- **Not tagged / not published**

## Secrets

- None in this report

Generated UTC: 2026-08-05T19:20:21.369821+00:00
