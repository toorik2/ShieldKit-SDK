# Core Chipnet goal (no stretch)

Paste as one message:

```text
/goal Build ShieldKit-SDK to a working end-to-end BCH Chipnet instance for fixed 0.1 BCH notes: deposit → one-note shielded transfer → withdrawal, plus seed+chain recovery — desktop/local proving only. Browser and Android proving are out of scope.

Naming: product/repo name is **ShieldKit-SDK**. `shield.cash` is sunsetting — treat remaining shield.cash strings in docs/packages/paths as legacy identity debt to migrate opportunistically when touching a surface; do not reintroduce shield.cash branding, domains, or product claims. New artifacts, profiles, packages, evidence titles, and user-facing text prefer ShieldKit-SDK. Frozen g0-v3 technical content still binds; rename ≠ reopen G0 unless a locked decision/text hash must change (then CHANGE_CONTROL.md).

Binding: AGENTS.md, policy/g0-lock.json (g0-v3), docs/CHARTER.md, docs/KILL_GATES.md, docs/PRIVACY.md, docs/BUILD_PLAN.md, docs/CHANGE_CONTROL.md. Evidence archives and sibling repos (incl. legacy shield.cash) are read-only without provenance. Mainnet unauthorized. Never commit HANDOVER.md, keys, WIFs, or seeds. Keep all worktrees under .worktrees/ inside this repo only.

Invariants: wallet-first; local secrets/proving; no hosted authority; transparent fee + change @ 1 sat/B; no pool subsidy; no post-genesis admin/pause/upgrade; typed verifier-profile bundles; local setup = development-only forever; ceremony replacement = new profile + new genesis only (no hot-swap). Verifier = exact bn254-onetx-pf7-sub62-r1 (7 PF7 inputs); settlement = 10 inputs (PF7 0–6, binding 7, state 8, fee 9); unlock ≤10k B; complete tx ≤59k B; no ~82k generic fallback; no fabricated % headroom.

Start from HEAD: strict-Fr Num2Bits_strict repair is committed; pre-repair R1CS/witness/setup/proofs are INVALIDATED. Do not setup from old artifacts.

Execute in order (parallelize only disjoint non-overlapping work):
1) Freeze V2 relation: recompile twice (byte-identical R1CS/WASM/sym), full witnesses (deposit/transfer/withdraw), mutation/adversarial + alias probes, independent review; freeze source+toolchain hashes.
2) Fresh development-only setup → zkey/VK → profile builder → genesis manifests (hash-bound, network=chipnet).
3) Regenerate PF7 fixed-point + binding/state covenants against current V2; assembly complete preparation+settlement; all-byte accounting; libauth BCH-2026 VM accept + mutation matrix reject.
4) LeanBCH cross-check + unmodified BCHN v29 policy/standardness (testmempoolaccept); no patched nodes.
5) Desktop/local prover: real Groth16 for all three actions within G0 desktop budgets where claimed; pin commands, RSS, times, hashes.
6) Recovery: raw confirmed history → note decrypt → spend rebuild; reorg rollback; provider-absent path; evidence for this profile.
7) Live Chipnet only when candidate is ready: fresh local address + exact amount/plan → ask user fund → wait confirm → genesis → prep/settlement deposit → transfer → withdrawal → seed+chain recovery. Record txids, raw txs, node verdicts, artifact hashes. Never log/expose keys.
8) Close gates with real evidence packages (G1→G2 then G3/G5/G6 as applicable for this candidate; G4 desktop-only; browser/Android deferred). Root npm test + package suites green for touched surface.

Hard bans: placeholders, OP_TRUE/synthetic accept, digest-only “proofs”, projections as measurements, silent G0 edits, hash rewrites to silence policy, mainnet, stretching into browser/Android, weakening kill gates, new shield.cash product branding.

Root agent = architect/integrator. Spawn bounded subagents for disjoint tasks; prefer isolation:none or git worktree under .worktrees/<label> only. Validate independently; commit coherent increments; maintain evidence ledger. Continue until live Chipnet E2E + recovery pass for one frozen development-only ShieldKit-SDK profile, or a blocker truly needs user authority (document exact handoff).
```
