# ShieldKit-Groth Beta — release staging

**Status:** local candidate staging (do not publish tag/release without explicit approval)  
**Product:** ShieldKit-Groth  
**Release name:** ShieldKit-Groth Beta  
**Version:** `0.3.0-beta.1`  
**Product root:** `shieldkit-groth-94kb/`  
**Executable:** `shieldkit`

## Scope

- PF10 Groth16 Chipnet pool create / deposit / transfer / withdraw / recovery.
- Zero-conf completion only (no mining/confirmation waits).
- Unaudited. No mainnet product claim.

## Out of beta (still required for production later)

- D-01 / D-02 ceremony + independent audits.
- Q-08 / Q-09 clean-host pair + 30-day Chipnet campaign.
- Five-party ceremony / beacon / independent reproductions.

## Local gates

```sh
npm ci
npm run check:no-seven-carrier-release   # alias: check:no-seven-carrier-release
npm run check:source
npm run check:type:v2
npm audit --omit=dev --audit-level=high
npm run test:beta-product:security
npm run test:rust:v2
npm test
npm pack --dry-run --json
npm run qualification:beta
```

## Packaging

- Minimal CLI tarball via root `files` allowlist (no `vendor/`, no `.codex-build`, no wallets).
- PF10 proving/runtime artifacts remain a **separate** authenticated offline bundle (`beta:offline:pack` / install path).
- Root trust must not be only a manifest inside a downloaded bundle.

## Live Chipnet final candidate (after clean final commit)

Using the **exact packed CLI + exact runtime bundle + exact commit**:

1. Fresh pool create from user-funded UTXO.
2. ≥5 deposits and ≥5 withdrawals, zero-conf admission + exact readback.
3. One transfer in the cross-verifier record.
4. p95 ≤ 15_000 ms; unlock ≤ 10_000 bytes; tx ≤ 100_000 bytes; VM ≤ 100%.
5. Bind evidence to commit SHA + release manifest SHA-256.

## Publication (blocked without approval)

Suggested tag: `shieldkit-groth-beta-0.3.0-beta.1`  
Do **not** `git tag` / `gh release` / npm publish without explicit user approval.
