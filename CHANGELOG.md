# Changelog — ShieldKit toolkit

Toolkit code only (`create-your-own-pool/`, root glue).  
**Not** a profile/instance changelog. Profile pins: [create-your-own-pool/docs/PROFILES.md](create-your-own-pool/docs/PROFILES.md).

Format: [Keep a Changelog](https://keepachangelog.com/)-ish · SemVer **0.y.z** until 1.0 (MINOR may break).

## [Unreleased]

### Changed

- **development-only setup:** skip multi-hour `snarkjs powersoftau verify` when ptau matches trusted Hermez `final_20` pin (SHA-256). Loud stderr warning + metadata `ptau.verification` implications. Force full verify with `setup.verifyPtau: true` or CLI `--verify-ptau`. Ceremony path unchanged (always full verify).
- Setup phase logs to stderr; snarkjs stdout/stderr streamed for long steps.

## [0.1.0] — 2026-07-25

### Added

- Formal versioning hygiene: single toolkit version in root `package.json`.
- `CHANGELOG.md`, `create-your-own-pool/docs/VERSIONING.md`, `PROFILES.md`.
- CLI prints `toolkitVersion` on doctor / profile-info / JSON envelopes; `--version`.
- Product layout: `create-your-own-pool/` + `use-chipnet-demo-pool/`.

### Notes

- **Baseline release** for hygiene — not Chipnet/mainnet qualified, not production privacy.
- Status: Unaudited — Work In Progress.
- Demo blob tag remains `playground-bundle-v1` (artifact tag, not toolkit semver).

[0.1.0]: https://github.com/toorik2/ShieldKit-SDK/releases/tag/v0.1.0
