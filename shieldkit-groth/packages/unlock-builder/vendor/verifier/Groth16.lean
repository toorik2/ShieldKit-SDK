-- Groth16 — the verifier.cash BN254 "crown" arithmetic soundness (application code).
--
-- Circuit-specific proofs that the singleton verifier's on-chain constant-derivations compute
-- the right values, composed with the LeanBCH.Opt recompiler's whole-program refinement:
--   • Groth16.Ederive          — E = (p^12-1)/r, inv2 = (p+1)/2, twist b2 (over ℤ)
--   • Groth16.Fermat           — verified modexp + Fermat-for-82 (the twist inverse)
--   • Groth16.CrownComposition — recompiled crown ≡ baked-constant baseline
-- Built on the tools it imports (require leanbch): LeanBCH.Opt (optimizer) + LeanBCH (VM).
import Groth16.CrownComposition
