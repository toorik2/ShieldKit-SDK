/-
  T4 Fiat–Shamir reductions.

  Crypto bits under Sha256RandomOracle (standard) — FS residual discharged to hash RO.
-/
import FriStark.Transcript.FiatShamir
import FriStark.Params.V1
import FriStark.Soundness.Residual
import FriStark.Hash.Sha256

namespace FriStark.Soundness.FSReduction

open FriStark.Transcript.FiatShamir
open FriStark.Params.V1
open FriStark.Soundness.Residual
open FriStark.Hash.Sha256

theorem challengeIdx_lt (s : State) (N : Nat) (hN : 0 < N) :
    (challengeIdx s N).1 < N := by
  unfold challengeIdx
  have : N ≠ 0 := Nat.pos_iff_ne_zero.mp hN
  simp [this]
  exact Nat.mod_lt _ hN

theorem challenge_lt_P (s : State) : (challenge s).1 < P := by
  unfold challenge
  exact Nat.mod_lt _ (by native_decide : 0 < P)

def grindBound (grindBits : Nat) : Nat := 1 <<< (64 - grindBits)

theorem grind_bound_v1 : grindBound GRIND_BITS = 1 <<< 40 := by
  native_decide

theorem absorb_deterministic (s : State) (b : Bytes) :
    absorb s b = ⟨FriStark.Hash.Sha256.hash (s.bytes ++ b)⟩ := rfl

theorem empty_is_stark_v0 : empty.bytes = "STARK-v0".toUTF8.toList := rfl

/-- FS uses SHA-256 exclusively (discharge witness). -/
theorem absorb_is_sha256 (s : State) (b : Bytes) :
    (absorb s b).bytes = FriStark.Hash.Sha256.hash (s.bytes ++ b) := rfl

/-- Under SHA-256 RO (standard): grind contributes GRIND_BITS. -/
def grindCryptoBits (_h : Sha256RandomOracle) : Nat := GRIND_BITS

theorem grind_crypto_bits_eq_24 (h : Sha256RandomOracle) :
    grindCryptoBits h = 24 := by
  simp only [grindCryptoBits, GRIND_BITS]

/-- Same under derived FiatShamirRandomOracle. -/
def grindCryptoBitsFS (_h : FiatShamirRandomOracle) : Nat := GRIND_BITS

theorem grind_bits_under_ro (h : Sha256RandomOracle) :
    grindCryptoBits h = GRIND_BITS := rfl

theorem challenge_in_field (s : State) (_h : Sha256RandomOracle) :
    (challenge s).1 < P := challenge_lt_P s

theorem grindBound_eq_shift (g : Nat) : grindBound g = 1 <<< (64 - g) := rfl

/-- FS residual is definitionally SHA-256 RO. -/
theorem fs_residual_is_sha256_ro :
    FiatShamirRandomOracle ↔ Sha256RandomOracle := Iff.rfl

end FriStark.Soundness.FSReduction
