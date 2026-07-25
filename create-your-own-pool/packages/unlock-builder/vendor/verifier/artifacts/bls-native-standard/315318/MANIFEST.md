# MANIFEST — BLS12-381 Groth16 grouped-residue native-standard crown, 315,318 B

| field | value |
|---|---|
| crown id | `bls-native-crown-315318-local` |
| track | `bls-native-standard` |
| method | grouped-residue (4 groups `[9,9,9,9]` / 36 inputs) |
| deployment | P2SH32, CashToken-threaded (intra-tx within a group, NFT commitment across groups) |
| curve | BLS12-381 |
| **totalBytes** | **315,318** (Σ locking+unlocking over 36 valid steps) |
| **full score** | **316,946** (totalBytes + 1,628 intra-tx tx-overhead) |
| totalOperationCost | 246,630,270 |
| maxStepOperationCost | 7,435,167 (budget/input 8,032,800 — all fit) |
| groupBytes | 80,922 / 82,431 / 82,043 / 70,494 (all < 100,000 → standard) |
| lever stack | g2-fold (fused G2-subgroup test) + ECIP divisor-cert vk_x + L10 affine-slope offload of pair-0 + L01 |
| status | **a1-certified** |
| beats | mr-zwets #1 native-STANDARD BLS 339,297 by −22,351 (full score) |

## Source / provenance

- **Source repo:** github.com/toorik2 verifier.cash (local `/home/toorik/Projects/verifier.cash`),
  branch `bls-crown`.
- **Crown (vectors) commit:** `afc4bc49` — "bls-crown: L10 affine-with-witnessed-slope offload of
  pair-0 G2 trajectory". Vectors byte-identical since (banked at HEAD `eb736b11`, an intel-only
  commit on top; `git diff afc4bc49 HEAD -- <vectors>` is empty).
- **Generator:** `build/chunked/grouped/build_vectors_residue_bls.mjs` (imports
  `bls12-381/gen_vkx_ecip_bls.mjs`, `gen_miller_residue.mjs`, `gen_finalexp_residue.mjs`,
  `_affmath_bls.mjs`, `intratx/transform.mjs`).
- **Build command:** `node build/chunked/grouped/build_vectors_residue_bls.mjs`
  → `harness/src/bch/groth16-bls12381-grouped-residue-vectors.json`. NOT rebuilt for this
  certification — bytes are frozen at `afc4bc49`.
- **Compiler:** vendored mr-zwets/cashscript rescheduling fork
  (`vendor/cashc-resched`, cashc `0.14.0-next.1`; registry pin
  `1c707c1dbf87396b30ba5e0704b1db44475ce893`).
- **VM:** libauth `@bitauth/libauth` 3.1.0-next.8 `createVirtualMachineBch2026(false)` (real
  consensus) + `createLoosenedVm` (harness). Second oracle: LeanBCH machine-checked BCH-2026 VM
  (`/home/toorik/Projects/LeanBCH`, `xcheck` binary).

## The crown bytes (canonical location — pointer, not duplicated)

The 2.55 MB vectors file is NOT duplicated here (byte-exact-copy discipline: it already lives,
committed and frozen, in-repo). Pointer:

| path | sha256 | commit |
|---|---|---|
| `harness/src/bch/groth16-bls12381-grouped-residue-vectors.json` | `5463649d0d79d9697e1c71deb8db78781681f47b5a86ce846b1eeb388ab54025` | `afc4bc49` |

`steps.json` in this directory carries the full per-step metadata derived from those vectors
(label, group, checkpoint, locking/unlocking bytes, real-VM op-cost, `lockingSpk`, `redeemSha256`,
and each group's inToken/outToken/outLocking) plus the totals — sufficient to identify and re-verify
every chunk without the full witness blobs.

## Files in this artifact

| file | sha256 | what |
|---|---|---|
| `MANIFEST.md` | (this file) | provenance + totals |
| `A1-CERTIFICATE.md` | — | soundness verdict + full forge table + dual-VM |
| `steps.json` | `26c1d9ea5aae1686011bf21ec6c1ee37fcb9bc4ef7a2037544385939a01ac7d4` | per-step metadata + vectors pointer |
| `verify_bls_crown.mjs` | `8ae182880aba771c388436878b145940ad5f395cdd9cda3c2f6a8b30a70fd17d` | harness A1 + score reproducer |
| `forge_battery.mjs` | `0b157c9b8f49dd6826e2626cda31f5cdc64505695bdf60868bb2ba80b019476a` | independent forge battery (17 attacks) |
| `hashpin.mjs` | `f05954e6632c055ad2ac520fa77b76fb19b8bae18009b331954f224719084b8b` | redeem→locking hash-pin proof |
| `xcheck_export.mjs` | `c5385873fe171593c91f45f1195cb1aff0293d0b2eedf870c8cdbc25c4a4d84b` | serialize group tx for LeanBCH |
| `xcheck_forge.mjs` | `5fb1ecd7d7564c000a64c4bf9a405222803f740e55d92dc9da70c925cc32ccfd` | serialize forged group0 for LeanBCH |
| `transcript-harness-verify.log` | `3625ead299213aeefd9063b8efb3f11ab09751354c99254e271f1d58f0324ed2` | 36/36 accept, score 315,318 / 316,946 |
| `transcript-forge-battery.log` | `fe14ba97e8afe3a9462b35d87d31feba8fbc41dd70cdfe8cc62ef9c8f7b3e7b8` | 17/17 soundness forgeries reject |
| `transcript-hashpin.log` | `0d6c9e059a20778095f5cce1add13da6e06210d14767600c7f2c9d052ee8a6a4` | 36/36 redeems pinned |
| `transcript-dualvm-leanbch.log` | `7949a4abed1f8c94e38c9ef9ecfbb0602bd848ed36f2d8675efebaa18d48ebe0` | libauth == LeanBCH (accept + op-cost) |
| `transcript-generator-forge-gates.log` | `71c9ced7f6491a7f7b7e8948dc123be37b133bf79da0566780e70d669fd90110` | miller + ECIP semantic gates |

## Reproduce

```
# harness A1 + score (needs repo node_modules on PATH; a node_modules symlink suffices)
node verify_bls_crown.mjs        # -> 36/36 accept both VMs; totalBytes 315,318; full score 316,946
node forge_battery.mjs           # -> 17/17 soundness forgeries reject; controls accept
node hashpin.mjs                 # -> 36/36 redeems hash256-pinned to lockings
# dual-VM (needs LeanBCH xcheck binary)
node xcheck_export.mjs <0..3>    # writes /tmp/xcheck_{tx,srcouts}.hex ; then run LeanBCH xcheck
```

All scripts read the frozen vectors at
`harness/src/bch/groth16-bls12381-grouped-residue-vectors.json`. They are read-only w.r.t. the crown.
