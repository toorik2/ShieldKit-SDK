# Complete settlement progress (ShieldKit-SDK V2 strict-Fr)

Observed: 2026-07-24T04:20:12Z

## Done

- Relation freeze, development-only setup, desktop prove/verify for three actions
- PF7-sub62 fresh corpus (original packets): roles 0–6, 18/18 attacks, seam pass
- Structural prep+settlement: roles 7–9 accept with covenant stack
- Near-complete assembly with real PF7 unlocks (~56.8 kB wire, unlock ≤9277): **9/10 inputs accept**, only terminal (input 6) fails when SCCT/packet not length-aligned with real unlocks
- Fixed-point packets+proofs generated; deposit/transfer PF7 rebuilds gateOk

## Remaining for 10/10 + Chipnet

1. SCCT ↔ unlock-length fixed point (change amount depends on wire which depends on unlock lengths)
2. Withdrawal PF7 genesis accept for that fixed point
3. Full mutation matrix + optional BCHN
4. Funding request with exact address/amount

**Do not fund yet.**
