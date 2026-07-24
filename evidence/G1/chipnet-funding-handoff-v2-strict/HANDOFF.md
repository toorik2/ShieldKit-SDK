# Chipnet funding handoff — ShieldKit-SDK V2 strict-Fr

Observed: 2026-07-24T03:57:44Z

## Ready engineering surface

| Item | Status |
| --- | --- |
| V2 relation freeze (Num2Bits_strict) | done — dual-compile + witnesses + adversarial |
| development-only setup/zkey/VK | done |
| Desktop prove+verify 3 actions | done (~9–10 s/action snarkjs) |
| PF7-sub62 fresh corpus (roles 0–6) | done — 18/18 attacks reject, seam pass |
| Profile+instance (chipnet, development-only) | `sha256:34d907599331997dfc67083742f0fcbb37b971687b1ae420658a172de2119c49` / `sha256:1cce04acbd7b6b9fd9f40aac36edaf18024e7e77bbd23d044d9785692850cb3b` |
| Recovery package (local V2) | 29/29 pass |
| Complete ten-input settlement (binding+state+fee) | **remaining** before live funding |
| Unmodified BCHN testmempoolaccept / live Chipnet | **remaining** |

## User-only blocker for live E2E

Do **not** fund yet. Engineering still needs complete preparation+settlement assembly with inputs 7–9 (binding, state, fee) under ≤10k unlock / ≤59k wire, then funding plan with:

1. fresh local Chipnet address
2. exact satoshi amount and fee breakdown
3. genesis + deposit/transfer/withdrawal transaction plan

When that is ready, root will ask for funding with exact numbers. Mainnet unauthorized. Never commit keys/WIFs/HANDOVER.md.
