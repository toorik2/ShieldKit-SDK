# Changelog

Toolkit only. Profile pins: [docs/PROFILES.md](03-create-your-own-pool/docs/PROFILES.md).

## [Unreleased]

### Fixed
- Blank-machine unlock toolchain install (`setup-unlock-toolchain`); surface spawn ENOENT.
- Tip discovery: listunspent-first, smaller history window, correct seq ranking; keep local tip if newer.
- `OPEN_SET_DESYNC` when local openNotes ≠ chain tip live count.

### Changed
- Playground → multi-note instance (`bb27e427…`, cap 16); bundle **`playground-bundle-v2`**.
- Doc shelf trimmed (facts only).
- `SECURITY.md`: vibe-coder pre-launch map + operator ship gate (secrets, fail-closed, N/A SaaS items).

### Added
- CLI request-template / genesis-plan / genesis-finalize; createKit planGenesis/finalizeGenesis.
- Unlock toolchain postinstall path.

## [0.1.0] — 2026-07-25

Toolkit hygiene baseline. Status: Unaudited WIP. (Historical demo blob tag was `playground-bundle-v1`; current pin is v2 — see PROFILES.)

[0.1.0]: https://github.com/toorik2/ShieldKit-SDK/releases/tag/v0.1.0
