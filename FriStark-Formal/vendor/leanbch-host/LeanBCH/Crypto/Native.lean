/-
  LeanBCH.Crypto.Native — the REAL secp256k1 oracle, bound over FFI to BCHN's vendored libsecp256k1.

  `LeanBCH.Crypto.Secp256k1` (LeanBCH/Oracle.lean) is a PARAMETER structure. Until this file
  existed, `Secp256k1.reject` — which rejects every signature — was its only inhabitant, so LeanBCH
  could not verify a single real signature. This file provides the second inhabitant.

  ## What this does and does not cost in trust

  The three headline theorems are universally quantified over the oracle, so they hold for ANY
  value of `Secp256k1`, this one included. Adding it therefore invalidates exactly zero proofs and
  introduces exactly zero axioms — verify that claim rather than believing it: the axiom footprints
  in `Meta/necessity.json` are unchanged by this file, because nothing in the headline closure
  imports it.

  What IS assumed is narrow and, unusually, testable: that the pinned archive named in
  `ffi/build.sh` computes the same accept/reject verdict as the network. That is a DIFFERENTIAL
  claim about a specific binary, not a mathematical claim about elliptic curves.

  ## Why this file is not imported by the library

  **`LeanBCH.lean` does not import this module, and must never import it.** The 313 known-answer
  tests run at BUILD TIME via `#eval` guards, i.e. inside the elaborator, and the elaborator cannot
  call an `@[extern]` opaque — it reports `Could not find native implementation of external
  declaration`. That is a hard error, not a silent fallback, which makes the arrangement fail-closed:
  a stray `#eval` against this oracle breaks the build rather than quietly invoking C. The KATs stay
  FFI-free and `Secp256k1.reject` remains their oracle, exactly as before.

  Consequently this module is reachable only from the compiled RUNNERS. `tools/health/map.mjs`
  reports it as an orphan (not reachable from the `LeanBCH.lean` root) — that is the intended
  design, not an oversight: it is precisely the property that keeps C out of the elaborator.

  Linking is per-executable via `moreLinkArgs` in `lakefile.toml`; run `ffi/build.sh` first. An
  executable that uses this oracle without those link args fails at link time
  (`undefined symbol: leanbch_schnorr_verify`), so an accidentally-unlinked binary cannot ship.

  ## The layer boundary

  Only POINT VERIFICATION crosses the FFI, mirroring BCHN's own split (see ffi/secp256k1_shim.c).
  The encoding gates BCHN performs interpreter-side — strict-DER, low-S, pubkey-encoding policy,
  sighash-type validity — are Lean's job and are NOT yet implemented; `LeanBCH/VM/Extended.lean:113-115`
  records them as deferred. Under the native oracle those gaps are live: the VM will accept some
  signatures BCHN rejects for malformed encoding. The gaps are pure-Lean work, provable, and do not
  involve this file.
-/
import LeanBCH.Oracle

namespace LeanBCH.Crypto

/-! ## The FFI declarations

  ABI: `ByteArray` is a `lean_sarray_object`, read in C with `lean_sarray_size` / `lean_sarray_cptr`;
  `Bool` returns as `uint8_t` 0/1; arguments are borrowed. Both C functions are total — every input,
  however malformed, yields a `Bool` with no side effect and no abort path. See ffi/secp256k1_shim.c.

  These are `opaque`, not `axiom`: they have no defining equation a proof could unfold, so no
  theorem can come to depend on their VALUE. -/

/-- BCH-2019 Schnorr point verification — `secp256k1_schnorr_verify` from the BCHN vendored fork's
    `schnorr` module (**not** BIP-340's `secp256k1_schnorrsig_verify`, which is absent from the
    pinned archive). `sig` is the 64-byte body, `pubkey` a full SEC point (33 or 65 bytes),
    `digest` 32 bytes. Mirrors `CPubKey::VerifySchnorr`, BCHN `src/pubkey.cpp:199-217`. -/
@[extern "leanbch_schnorr_verify"]
opaque nativeSchnorrVerify (sig pubkey digest : ByteArray) : Bool

/-- ECDSA point verification — lax-DER parse, then `secp256k1_ecdsa_signature_normalize`, then
    `secp256k1_ecdsa_verify`. Mirrors `CPubKey::VerifyECDSA`, BCHN `src/pubkey.cpp:174-197`.
    Note this does NOT enforce strict-DER or low-S: BCHN enforces both interpreter-side, and so
    must LeanBCH. See the field docstring on `Secp256k1.verifyDERLowS` and the objection recorded
    below. -/
@[extern "leanbch_ecdsa_verify"]
opaque nativeEcdsaVerify (sig pubkey digest : ByteArray) : Bool

/-! ## Bytes → ByteArray at the shim boundary

  `Bytes` is `List UInt8` (LeanBCH/Core.lean:14) — a boxed linked list, chosen because it is
  kernel-reducible, which is what makes `by decide` witnesses and `#eval` conformance runs share one
  representation. The FFI needs a flat buffer, so the conversion happens HERE, at the edge, and the
  `Bytes` type is left alone: changing it would touch every proof in the tree.

  The cost is irrelevant in context — signature verification runs a handful of times per input, and
  each conversion is over at most 65 bytes for keys and 72 for signatures, next to an elliptic-curve
  operation costing orders of magnitude more. -/

/-- Flatten a model byte string into the buffer representation the shim reads. -/
@[inline] def toByteArray (bs : Bytes) : ByteArray := ⟨bs.toArray⟩

/-- The REAL secp256k1 oracle: point verification delegated to the pinned BCHN libsecp256k1.

    Both fields are total and return `false` on every malformed input rather than trapping — the VM
    feeds these adversarial, attacker-chosen stack items by design. -/
def realSecp256k1 : Secp256k1 where
  verifySchnorr sig pubkey digest :=
    nativeSchnorrVerify (toByteArray sig) (toByteArray pubkey) (toByteArray digest)
  verifyDERLowS sig pubkey digest :=
    nativeEcdsaVerify (toByteArray sig) (toByteArray pubkey) (toByteArray digest)

/-! ## Oracle selection

  Every runner picks its oracle at RUNTIME from `LEANBCH_SECP`, defaulting to `reject`. Two
  properties matter and both are deliberate:

  * **The default is unchanged.** With the variable unset, every runner computes exactly what it
    computed before this binding existed, so every previously recorded result stays reproducible.
  * **An unrecognised value is an ERROR, never a silent fallback.** A typo (`LEANBCH_SECP=nativ`)
    must not quietly produce reject-oracle numbers that then get written down as native-oracle
    results. Fail loudly instead. -/

/-- The oracle names accepted in `LEANBCH_SECP`. -/
inductive OracleChoice
  /-- `Secp256k1.reject` — rejects every signature. The historical default. -/
  | reject
  /-- `realSecp256k1` — the FFI binding to the pinned libsecp256k1. -/
  | native
deriving DecidableEq, Repr

/-- Parse an `LEANBCH_SECP` value. `none` means "unrecognised" and callers must fail. -/
def OracleChoice.ofString? (s : String) : Option OracleChoice :=
  match s.trim.toLower with
  | "" | "reject" | "none" => some .reject
  | "native" | "real"      => some .native
  | _                      => none

/-- The oracle value for a choice. -/
def OracleChoice.oracle : OracleChoice → Secp256k1
  | .reject => Secp256k1.reject
  | .native => realSecp256k1

/-- A short label for logging. Every runner prints this, so no recorded measurement is ambiguous
    about which oracle produced it. -/
def OracleChoice.name : OracleChoice → String
  | .reject => "reject"
  | .native => "native(libsecp256k1/BCHN-vendored)"

/-- Read `LEANBCH_SECP` and return the selected oracle together with its label.

    Unset ⇒ `reject`, preserving the pre-binding behaviour of every runner.
    Unrecognised ⇒ `IO.userError`, so a mistyped selector can never be mistaken for a measurement. -/
def oracleFromEnv : IO (Secp256k1 × String) := do
  let raw := (← IO.getEnv "LEANBCH_SECP").getD "reject"
  match OracleChoice.ofString? raw with
  | some c => pure (c.oracle, c.name)
  | none   =>
      throw (IO.userError
        s!"LEANBCH_SECP='{raw}': unknown oracle. Expected 'reject' (default) or 'native'.")

end LeanBCH.Crypto
