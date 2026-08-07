# Upstream pin — 0zkbrewer/BCH-FRI-STARK-Verifier

This directory is a **byte-for-byte vendor pin** of the external research repository:

| Field | Value |
|-------|--------|
| Origin | https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier |
| Pinned commit | see `VENDORED_COMMIT` (full 40-char SHA-1) |
| Pin date (git author) | see `VENDORED_LOG.txt` |
| License / terms | as published upstream (research code; use at own risk) |

## What it is

A **Goldilocks DEEP-ALI FRI-STARK** verifier intended to run on the unmodified BCH-2026 VM as a multi-input P2SH32 standard transaction. Statement = Poseidon2 hash-chain AIR. Prover is off-chain Python; on-chain checks are covenant programs in a token IR plus a libauth harness under `cashscript/native_shard/`.

Upstream-reported sizes (not independently re-scored by this repo's judge yet):

- Demo spend (chipnet): 28 inputs, **92191** bytes on chain
- Same demo in harness: **92167** bytes
- Fully soundness-wired (same demo proving config): **120537** bytes

## What this pin is *not*

- Not a promoted verifier.cash crown or lane frontier
- Not wired into `npm run check:frontiers` or the public maintainer bench
- Not a claim that scores, standardness, or A1 gates pass under this repository's contracts
- Not the same artifact as the quarantined M31 Circle-STARK trees `fri_stark/` / `fri_stark55/`

## Re-sync

```bash
# from repository root
git clone --depth 1 https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier.git .vc/upstream-probe/BCH-FRI-STARK-Verifier
rsync -a --delete --exclude '.git' \
  .vc/upstream-probe/BCH-FRI-STARK-Verifier/ \
  lanes/goldilocks-98k/upstream/
git -C .vc/upstream-probe/BCH-FRI-STARK-Verifier rev-parse HEAD \
  > lanes/goldilocks-98k/upstream/VENDORED_COMMIT
# then refresh SOURCE.md / candidate provenance hashes and re-run architecture check
```

Keep `node_modules` out of this pin. Install deps only under an isolated run or local sandbox when exercising the cashscript harness.
