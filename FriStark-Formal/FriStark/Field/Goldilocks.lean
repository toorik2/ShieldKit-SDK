/-
  Goldilocks field F_p with p = 2^64 - 2^32 + 1.
  Arithmetic matches vendor native_gf_p2 / base field ops.
-/
import FriStark.Params.V1

namespace FriStark.Field.Goldilocks

open FriStark.Params.V1 (P)

abbrev F := Nat  -- representatives in [0, P)

@[inline] def ofNat (n : Nat) : F := n % P
@[inline] def add (a b : F) : F := (a + b) % P
@[inline] def sub (a b : F) : F := (a + P - b % P) % P
@[inline] def mul (a b : F) : F := (a * b) % P
@[inline] def neg (a : F) : F := (P - a % P) % P

/-- Modular inverse via Fermat: a^(P-2) mod P. Zero maps to 0 (caller must reject). -/
def pow (a : F) (e : Nat) : F :=
  Id.run do
    let mut result : F := 1
    let mut base := a % P
    let mut exp := e
    while exp > 0 do
      if exp % 2 == 1 then
        result := mul result base
      base := mul base base
      exp := exp / 2
    return result

def inv (a : F) : Option F :=
  if a % P == 0 then none else some (pow (a % P) (P - 2))

def inv! (a : F) : F := (inv a).getD 0

-- basic laws as computational facts used by later modules
theorem add_comm (a b : F) : add a b = add b a := by
  simp [add, Nat.add_comm]

end FriStark.Field.Goldilocks
