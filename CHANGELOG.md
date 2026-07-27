# Changelog

Toolkit only. Profile pins: [docs/PROFILES.md](03-create-your-own-pool/docs/PROFILES.md).

## [Unreleased]

### Changed
- Playground switched to the real Chipnet-qualified 32-note instance
  (`cfe741f6…`, 3.2 BCH reserve cap) and hash-pinned bundle
  **`playground-bundle-v3`**.

### Fixed
- Custom pool instances now publish their State NFT category and category
  outpoint; tip discovery also recovers this identity from the verified bundle
  manifest for older instance descriptors.

### Added
- Real Chipnet 32-note qualification: category/genesis
  `a42804c7…` / `6a9fe6f6…`, deposit settlement `9191f189…`
  (56,964 bytes), and withdrawal settlement `b2fcc9e7…` (56,998 bytes).

## [0.2.0] — 2026-07-27

Status: **Unaudited WIP**. This release is Chipnet-qualified; it is not
production-qualified or approved for mainnet use.

### Fixed
- All pool lifecycle broadcasts now pass through one network/setup gate and a
  durable operation journal. Consolidation only prepares transactions.
- Pool operations now separate prepare, broadcast, and atomic state/ledger
  commit, including resumable idempotent recovery.
- Secret state, journals, ledgers, and installation receipts are written with
  mode `0600`; destructive path guards reject broad replacement targets.
- Electrum TLS verifies certificates, JSON-RPC rejects non-loopback HTTP, and
  SSH RPC arguments are method-validated and shell-quoted.
- Electrum fee discovery reuses one authoritative `listunspent` snapshot rather
  than rescanning once per candidate.
- The recursive test runner now includes all first-party covenant tests.
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
- Root workspaces and one tracked lockfile are authoritative; installs use
  immutable `npm ci`, with tracked immutable Yarn/pnpm locks for vendored tools.
- Local ceremony execution is named `local-contribution-simulation` and cannot
  be relabeled as a production ceremony.
- Playground → multi-note instance (`bb27e427…`, cap 16); bundle **`playground-bundle-v2`** (superseded by v3).
- Doc shelf trimmed (facts only).
- `SECURITY.md`: vibe-coder pre-launch map + operator ship gate (secrets, fail-closed, N/A SaaS items).
- `createChainRpc({ network })` + public mainnet Fulcrum; `create-pool --network mainnet`.
- GOLDEN_PATH / playground docs: multi-history blank join is product path, not a lab ritual.

### Added
- Hash-pinned artifact manifest and verification-before-extraction, including
  exact archive members, per-file hashes, and traversal/link rejection.
- Signed, hash-chained external-contribution receipts for independently
  transported ceremony transcripts.
- Mandatory CI for immutable install, dependency audit, source policy,
  portable/qualification tests, unlock setup, and LeanBCH formal gates.
- Real Chipnet qualification: category/genesis, gated fee consolidation,
  deposit settlement `d74d2e3c…24f28d6` (56,964 bytes), and withdrawal
  settlement `0800a1c0…be6f694` (56,998 bytes).
- CLI request-template / genesis-plan / genesis-finalize; createKit planGenesis/finalizeGenesis.
- Unlock toolchain postinstall path.
- `packages/pool/chain-settlement-log.mjs` — Electrum tip ancestry → settlementLog.


## [0.1.0] — 2026-07-25

Toolkit hygiene baseline. Status: Unaudited WIP. (Historical demo blob tag was `playground-bundle-v1`; current pin is v2 — see PROFILES.)

[0.1.0]: https://github.com/toorik2/ShieldKit-SDK/releases/tag/v0.1.0
[0.2.0]: https://github.com/toorik2/ShieldKit-SDK/releases/tag/v0.2.0
