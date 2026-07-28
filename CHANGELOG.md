# Changelog

Toolkit only. Profile pins: [docs/PROFILES.md](03-create-your-own-pool/docs/PROFILES.md).

## [Unreleased]

### Fixed
- **Privacy:** spend packets no longer publish the spent note commitment on the
  consensus SCAR transcript (`inputCommitment` is canonically zero). Membership
  stays a private witness; nullifiers remain public for double-spend prevention.
  Passive deposit→withdraw equality linking fails under the fixed transcript.
- Pin artifacts **v2** (development-only Groth16 setup) match the privacy
  relation and rebound densFuel locks. Fetch with
  `npm run fetch-pin-artifacts` (default manifest is now v2). **Not** a
  multi-party ceremony; Chipnet research/demo only. Existing v1 pools cannot
  prove spends against the new JS without the v2 pin (and vice versa).
- Custom pool instances now publish their State NFT category and category
  outpoint; tip discovery also recovers this identity from the verified bundle
  manifest for older instance descriptors.

### Changed
- Live Chipnet playground is **playground-bundle-v4** on privacy pin v2
  (genesis `97f5bb61…`, instance `f4fdcbe3…`, 32 × 0.1 BCH). Supersedes
  playground-bundle-v3 (v1 pin / linkable spent-cm transcript).
- Default pin trust manifest is
  `03-create-your-own-pool/pins/shieldkit-pin-artifacts-v2.manifest.json`.

### Added
- Offline `analyze-packet-linkability.mjs` for settlement-log privacy checks.
- `rebind-verifier-set-from-unlock-dump.mjs` to rebind densFuel locks after a
  verification-key change.
- Pin-v2 playground qualification: category/genesis
  `127401ae…` / `97f5bb61…`, deposit settlement `11b8137c…`.

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
