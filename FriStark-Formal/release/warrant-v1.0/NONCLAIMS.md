# Non-claims (Warrant pride bar)

## Cryptography
- Empty residual / STARK soundness from ℤ
- SHA-256 CR or RO proved
- FriSecurityGame / capacity regime from field arithmetic alone
- Constructing `ResidualBreakEvidence` / `WarrantOutcome.broken` without a real collision (or similar adversary material)

## Statement (PHI **out**)
- A6 note tree membership/append
- A7 nullifier tree inserts
- A8 full EC-free note crypto beyond Poseidon packet commit
- S12 statementId SHA256 encoding
- T4 funding P2PKH economics

## UTXO / script
- **Full BCH script interpreter ≡ CovenantAccept**
  - Modeled: role-order `unpack`, topology wf, binding wf, `verify∘unpack` / verify lean, product Φ
  - **Not** modeled: script opcodes, sighash, CashToken consensus beyond ProductV1 transition, fee paths
- Dual-VM host agreement is evidence only (corollary flag), not the accept definition
- Bundle structural BEq identity lean≡kernel when blob present (spine uses unpack kernel only)

## Process
- Prover correctness; private-trace re-derive; mathlib on hot verify path
