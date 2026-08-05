/-
  Radix-2 NTT / INTT over Goldilocks matching vendor native_ntt.py.
  Used for degree-T public column interpolation (T=512), not full N=2^20 LDE tables.
-/
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.Field.NTT

open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P)

/-- Bit-reverse index for power-of-two n. -/
def bitReverse (i logn : Nat) : Nat := Id.run do
  let mut x := i
  let mut r := 0
  for _ in [0:logn] do
    r := r * 2 + x % 2
    x := x / 2
  pure r

def bitReverseList (a : Array F) : Array F := Id.run do
  let n := a.size
  if n ≤ 1 then return a
  let logn := Nat.log2 n  -- floor log2; require power of two
  let mut out := a
  for i in [0:n] do
    let j := bitReverse i logn
    if i < j then
      let vi := out[i]!
      let vj := out[j]!
      out := out.set! i vj
      out := out.set! j vi
  pure out

/-- In-place DIT NTT: coeffs → evaluations at ω^0..ω^(n-1). -/
def nttInplace (a0 : Array F) (omega : F) : Array F := Id.run do
  let n := a0.size
  let mut a := bitReverseList a0
  let mut m : Nat := 2
  while m ≤ n do
    let wm := pow omega (n / m)
    let mut s : Nat := 0
    while s < n do
      let mut w : F := 1
      let half := m / 2
      for k in [0:half] do
        let t := mul w (a[s + k + half]!)
        let u := a[s + k]!
        a := a.set! (s + k) (add u t)
        a := a.set! (s + k + half) (sub u t)
        w := mul w wm
      s := s + m
    m := m * 2
  pure a

def ntt (coeffs : List F) (omega : F) : List F :=
  (nttInplace coeffs.toArray omega).toList

/-- Inverse NTT: values on <ω> → coefficients. -/
def intt (values : List F) (omega : F) : List F := Id.run do
  let n := values.length
  let omegaInv := pow (omega % P) (P - 2)
  let res := nttInplace values.toArray omegaInv
  match inv n with
  | none => res.toList  -- n=0 degenerate
  | some ninv => res.toList.map (fun v => mul v ninv)

/-- Base-field Horner: sum c_i x^i (coeffs low→high). -/
def hornerBase (coeffs : List F) (x : F) : F := Id.run do
  let mut acc : F := 0
  for c in coeffs.reverse do
    acc := add (mul x acc) c
  pure acc

end FriStark.Field.NTT
