# Changelog

Toolkit only. Profile pins: [docs/PROFILES.md](03-create-your-own-pool/docs/PROFILES.md).

## [Unreleased]

### Fixed
- Blank-machine unlock toolchain install (`setup-unlock-toolchain`); surface spawn ENOENT.
- Tip discovery: listunspent-first, smaller history window, correct seq ranking; keep local tip if newer.
- `OPEN_SET_DESYNC` when local openNotes ≠ chain tip live count.
- Mainnet was hardcoded chipnet in packet/state NFT/witness/genesis/create-pool/RPC — now `chipnet|mainnet` (default chipnet).
- Genesis fund floor: drop 12M lab pad; size from category + 1 sat/B wire pads; default category = min for state carrier.
- Fee floors: settlementFeeFunding 100k→59.5k; deposit/withdraw scan floors from exact prep formula (no 1.5M/11.5M lab pads).
- Blank playground join: auto tip→genesis settlementLog walk + public tipForest rebuild (no residual journal).
- `install-deps` always pins `action` libauth and hard-gates required modules after install.
- densFuel unlock phase JSON quiet by default (use `SHIELDKIT_VERBOSE=1` / `--verbose`).
- ECIP diversity uses larger fee-funding steps; short product retry line instead of internal dumps.
- `wallets.json` gitignored at repo root.

### Changed
- Playground → multi-note instance (`bb27e427…`, cap 16); bundle **`playground-bundle-v2`**.
- Doc shelf trimmed (facts only).
- `SECURITY.md`: vibe-coder pre-launch map + operator ship gate (secrets, fail-closed, N/A SaaS items).
- `createChainRpc({ network })` + public mainnet Fulcrum; `create-pool --network mainnet`.
- GOLDEN_PATH / playground docs: multi-history blank join is product path, not a lab ritual.

### Added
- CLI request-template / genesis-plan / genesis-finalize; createKit planGenesis/finalizeGenesis.
- Unlock toolchain postinstall path.
- `packages/pool/chain-settlement-log.mjs` — Electrum tip ancestry → settlementLog.


## [0.1.0] — 2026-07-25

Toolkit hygiene baseline. Status: Unaudited WIP. (Historical demo blob tag was `playground-bundle-v1`; current pin is v2 — see PROFILES.)

[0.1.0]: https://github.com/toorik2/ShieldKit-SDK/releases/tag/v0.1.0
