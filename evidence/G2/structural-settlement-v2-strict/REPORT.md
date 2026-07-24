# Structural ten-role settlement (ShieldKit-SDK V2)

Observed: 2026-07-24T03:59:27Z

Profile `sha256:34d907599331997dfc67083742f0fcbb37b971687b1ae420658a172de2119c49` / instance `sha256:1cce04acbd7b6b9fd9f40aac36edaf18024e7e77bbd23d044d9785692850cb3b`.

- Preparation hand-off constructs exact ten-output prep transactions
- `assembleCompleteG2Settlement` builds complete settlements with 1 sat/byte fee
- Libauth BCH-2026 standard VM: roles **7–9 accept**; roles **0–6 fail** with deliberate invalid PF7 unlocks
- Wire ≤59k and unlock ≤10k asserted

**Next for complete settlement:** inject real PF7 unlocking bytecode from the fresh corpus builds into roles 0–6 and re-run 10/10 VM + mutation matrix.
