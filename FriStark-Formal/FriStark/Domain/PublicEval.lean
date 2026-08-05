/-
  Public-column evaluation from H-values via INTT + Horner.
  Matches native_ntt.intt + base Horner / native_ct_air_stark._ood_public_at.
-/
import FriStark.Field.NTT
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.Domain.PublicEval

open FriStark.Field.NTT
open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)

/-- Domain point x = (off * oN^k) mod P on the FRI coset. -/
def domainPoint (off oN k : Nat) : F :=
  mul (off % P) (pow (oN % P) k)

/-- Interpolate H-values (len T on <oT>) → coefficients. -/
def coeffsFromH (hVals : List F) (oT : F) : List F :=
  intt hVals oT

/-- Evaluate public column at base-field domain point x. -/
def evalAtBase (hVals : List F) (oT x : F) : F :=
  hornerBase (coeffsFromH hVals oT) x

/-- GF(p²) Horner matching _ood_horner. -/
def hornerExt (coeffs : List F) (z : E) : E := Id.run do
  let mut acc := zero
  for c in coeffs.reverse do
    acc := add (mul z acc) (fromBase c)
  pure acc

/-- OOD public eval at z ∈ GF(p²): intt then Horner — _ood_public_at. -/
def evalAtExt (hVals : List F) (oT : F) (z : E) : E :=
  hornerExt (coeffsFromH hVals oT) z

/-- Ext power by Nat exponent. -/
def powerE (a : E) (e : Nat) : E := Id.run do
  let mut result := one
  let mut base := a
  let mut exp := e
  while exp > 0 do
    if exp % 2 == 1 then
      result := mul result base
    base := mul base base
    exp := exp / 2
  pure result

/-- Z_H(z)^-1 = 1/(z^T − 1). -/
def zhInv (z : E) (T : Nat) : Option E :=
  inv (sub (powerE z T) one)

end FriStark.Domain.PublicEval
