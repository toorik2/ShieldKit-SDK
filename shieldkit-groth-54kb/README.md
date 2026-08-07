# ShieldKit-Groth-54KB — pf6 verifier-pool design root

The **bn254-onetx-pf6-a3-r1** ("54KB") verifier-pool design: the pinned
PairFold-6 dens-rich a3 Groth16 verifier (**54,671 script bytes**, score
54,949, 6 roles genesis/exec0-3/terminal, 9-input actions) as the replacement
for the PF10 verifier (the sibling design root `../shieldkit-groth-94kb/`,
94,622 script bytes, 10 roles, 13-input actions).

## Status (2026-08-07)

**PRODUCTION-READY (chipnet-scoped, per the revised goal: no soak, no new
ceremony).** Unqualified beta: single-contributor ceremony (d38f3cfc VK),
`productionQualified: false` throughout the runtime claims; see docs/STATUS.md. All ten work packages WP-0..WP-9 are closed with host-observable
evidence:

- WP-1 pin reproduction: scriptBytes 54,671 / score 54,949 / 6 in / 1 tx;
  off-subgroup fixture rejected by the lane build.
- WP-3 lifecycle: THREE full chains mined on chipnet (pool 11 at 20-22 conf,
  pool 13 at 8 conf, the VPS clean-host chain at 4-5 conf) — deposit,
  transfer, withdrawal, recover all green with 9 inputs.
- WP-4 B-02-final: libauth + BCHN testmempoolaccept + mined BCHN + LeanBCH
  (27/27 full-redeem) accept the identical txs; ceilings measured (59,275 B
  tx / 9,853 B unlock / 7.09M op); tamper scoped 0/2,088 + consensus flips
  rejected.
- WP-5 clean hosts: 2nd host (layer1-node VPS) completed the full lifecycle;
  32-note playground campaign complete; erase/recovery/recovered-note spend
  demonstrated.
- WP-6 formal: 9/9 Groth16-Formal diff_* gates green; forge 48 reject / 0
  accept; dual-VM role oracle 6/6; LeanBCH full-redeem 27/27.
- WP-7 red team: attack matrix executed (9/10 classes rejected + the densDrop
  filler characterized + RT-2026-0807-01 documented); 4 audit scopes
  blocker-complete.
- WP-8 release: fail-closed scans green; offline bundle + release pin
  `shieldkit-54kb-pf6-20260807-r1` (manifest 9b3d3d26…); no remote
  publication.
- WP-9 declaration: evidence ledger (44 entries), accepted-risks register,
  maintainer.json, readiness declaration in evidence/09-readiness/.

## Unified CLI

This design root is driven by the shared CLI at `../cli/` (shieldkit-sdk/cli):
one CLI for all pool designs, `--profile pf6-a3-direct-v1` selects this design
through the registry (../cli/pool-designs.json + this root's profile.json).
Live through the CLI: pool create a0dbf93f, deposit 9f28dba6, transfer
15e0c460 (all mined), chain-scan recovery 2/2.

Known residual: the CLI withdrawal path is blocked by a lane-build witness-
layout artifact (root cause + fix proposal: evidence/03-implementation/
cli-withdrawal-root-cause.json + lane-source-fix-proposal.json); the
withdrawal action itself is proven on the mined chains.

## Layout

| Path | Purpose |
|------|---------|
| `PLAN.md` | Master plan: work packages (all closed; kept as the gate record) |
| `design/` | Frozen protocol/architecture design docs |
| `docs/` | Working notes, decisions, requirement matrix deltas |
| `src/` | First-party code (topology, covenants port, prove, assemble, profile) |
| `vendor/` | Hash-pinned copies of upstream material (pf6 lane, fixtures, product) |
| `evidence/` | Qualification evidence (schema + sha256 + command) |
| `pins/` | The release pin + offline bundle |

## Policy

- Chipnet-only; zero mainnet claims; the release posture is
  pinned-beta-unqualified (productionQualified=false).
- Toolchain pins: cashc `1c707c1dbf87396b30ba5e0704b1db44475ce893`, libauth
  `3.1.0-next.8`, leanbch `51201015fdaef4562debf2a2b1cab4013a45e8b4`,
  BCH-2026, Node v22.23.1.
- Read-only imports from `../shieldkit-groth-94kb/`, `../verifier.cash/`,
  `../Groth16-Formal/` are allowed; no writes to those trees.
