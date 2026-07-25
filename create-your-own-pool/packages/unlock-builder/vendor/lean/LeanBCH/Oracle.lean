/-
  LeanBCH.Oracle — the ONE assumed-trust surface of the whole model, isolated to a single file.

  Everything else in LeanBCH is either PROVEN (kernel-checked) or VALIDATED (differential-tested
  against libauth + the vmb corpus). This file holds the sole exception: elliptic-curve signature
  verification, left deliberately OPAQUE as an explicit parameter — never an axiom, never
  `native_decide`. A skeptic auditing "what must I take on faith?" reads exactly this file.

  Kept in the `LeanBCH.Crypto` namespace (the name `LeanBCH.Crypto.Secp256k1` is unchanged) and
  re-exported by `LeanBCH.Crypto`, so every existing importer resolves it transitively — this split
  is a pure trust-legibility move, not an interface change. See TRUST_MANIFEST.md, Tier 3.
-/
import LeanBCH.Core

namespace LeanBCH.Crypto

/--
  The EXPLICIT secp256k1 verification oracle.

  This is a PARAMETER, not an axiom and not `native_decide`: elliptic-curve point
  verification is deliberately left opaque. It is the one validated-not-proven seam of the
  model. Both fields return `Bool` and, by design, feed ONLY the VM's accept/reject decision
  — they are NEVER read by any cost metric (`hashDigestIterations`, sig-check budgets, etc.).

  The VM's `OP_CHECKSIG*` arm receives a `Secp256k1` value and calls the appropriate field.
  No honest implementation is provided in-Lean; consensus verification lives in libsecp256k1.
-/
structure Secp256k1 where
  /-- **BCH-2019 Schnorr** signature verification — **NOT BIP-340**. `sig` is the 64-byte body,
      `pubkey` is a **standard SEC point (33-byte compressed or 65-byte uncompressed)**, `digest`
      is 32 bytes.

      The distinction is consensus-critical and easy to get wrong when binding a real backend.
      BCH-2026 verifies via `secp256k1_schnorr_verify` from the module
      `src/secp256k1/src/modules/schnorr` in BCHN's **vendored fork**; upstream libsecp256k1's
      BIP-340 entry point is the differently-named `secp256k1_schnorrsig_verify` in module
      `schnorrsig`, and it takes a 32-byte **x-only** key. Binding that one instead — or truncating
      a SEC key to 32 bytes to fit it — yields a verifier that disagrees with the network.

      Source of truth (verified 2026-07-21): BCHN `src/pubkey.cpp:199-217` `CPubKey::VerifySchnorr`
      parses the key with `secp256k1_ec_pubkey_parse(ctx, &pubkey, &(*this)[0], size())` — i.e. the
      full SEC encoding, at its natural length — and only then calls `secp256k1_schnorr_verify`.
      `LeanBCH/VM/Extended.lean:148` matches this: it passes the stack item unmodified. -/
  verifySchnorr : (sig pubkey digest : Bytes) → Bool
  /-- Strict-DER, low-S ECDSA verification: `sig`, SEC `pubkey`, 32-byte `digest`. -/
  verifyDERLowS : (sig pubkey digest : Bytes) → Bool

/-- A trivial always-reject oracle, for tests / totality of the accept/reject seam.
    NOT a real verifier — it rejects every signature. -/
def Secp256k1.reject : Secp256k1 :=
  ⟨fun _ _ _ => false, fun _ _ _ => false⟩

end LeanBCH.Crypto
