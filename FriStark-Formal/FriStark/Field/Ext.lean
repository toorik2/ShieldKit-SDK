/-
  GF(p^2) = F_p[u]/(u^2 - 7) matching native_gf_p2.py (Plonky3 binomial).
-/
import FriStark.Field.Goldilocks
import FriStark.Params.V1

namespace FriStark.Field.Ext

open FriStark.Field.Goldilocks
open FriStark.Params.V1 (P EXT_NONRES)

/-- Extension element a0 + a1·u. -/
structure E where
  a0 : F
  a1 : F
  deriving DecidableEq, Repr, Inhabited

def zero : E := ⟨0, 0⟩
def one : E := ⟨1, 0⟩
def u : E := ⟨0, 1⟩

def fromBase (a : F) : E := ⟨a % P, 0⟩
def eq (a b : E) : Bool := (a.a0 % P == b.a0 % P) && (a.a1 % P == b.a1 % P)

def add (a b : E) : E := ⟨Goldilocks.add a.a0 b.a0, Goldilocks.add a.a1 b.a1⟩
def sub (a b : E) : E := ⟨Goldilocks.sub a.a0 b.a0, Goldilocks.sub a.a1 b.a1⟩
def neg (a : E) : E := ⟨Goldilocks.neg a.a0, Goldilocks.neg a.a1⟩

/-- Karatsuba: t0=a0*b0, t1=a1*b1, t2=(a0+a1)(b0+b1); c0=t0+W*t1, c1=t2-t0-t1. -/
def mul (a b : E) : E :=
  let a0 := a.a0 % P; let a1 := a.a1 % P
  let b0 := b.a0 % P; let b1 := b.a1 % P
  let t0 := Goldilocks.mul a0 b0
  let t1 := Goldilocks.mul a1 b1
  let t2 := Goldilocks.mul (Goldilocks.add a0 a1) (Goldilocks.add b0 b1)
  let c0 := Goldilocks.add t0 (Goldilocks.mul EXT_NONRES t1)
  let c1 := Goldilocks.sub (Goldilocks.sub t2 t0) t1
  ⟨c0, c1⟩

def scalar (s : F) (a : E) : E :=
  ⟨Goldilocks.mul s a.a0, Goldilocks.mul s a.a1⟩

def conj (a : E) : E := ⟨a.a0 % P, Goldilocks.neg a.a1⟩

def norm (a : E) : F :=
  Goldilocks.sub (Goldilocks.mul a.a0 a.a0) (Goldilocks.mul EXT_NONRES (Goldilocks.mul a.a1 a.a1))

def inv (a : E) : Option E :=
  let n := norm a
  if n == 0 then none
  else
    match Goldilocks.inv n with
    | none => none
    | some ninv => some ⟨Goldilocks.mul a.a0 ninv, Goldilocks.mul (Goldilocks.neg a.a1) ninv⟩

/-- FRI fold step: (v+w)/2 + beta * (v-w)/(2x)  matching native_ct_air_stark._fold_once form. -/
def friFold (v w : E) (beta : E) (xpos : F) : Option E :=
  match Goldilocks.inv (Goldilocks.mul 2 xpos) with
  | none => none
  | some i2x =>
    let inv2 := Goldilocks.inv! 2
    let halfSum := scalar inv2 (add v w)
    let diff := sub v w
    let term := mul beta (scalar i2x diff)
    some (add halfSum term)

end FriStark.Field.Ext
