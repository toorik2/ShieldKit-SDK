/-
  MUTATION TEST (non-vacuity). This is a COPY of Recompiler/Basic.lean's `step` with ONE op
  deliberately CORRUPTED: SWAP is made a NO-OP (leaves the stack unchanged instead of swapping
  the top two). It reuses the identical eval + JSON pipeline and writes lean_results_mut.json.
  Running diff.mjs against it MUST flag mismatches on exactly SWAP -- proving the harness has teeth.
  This file never touches the real Basic.lean.
-/
import Lean.Data.Json
open Lean

namespace RecompilerMut
abbrev State (α : Type) := List α × List α
def removeNth {α : Type} (l : List α) (n : Nat) : List α := l.take n ++ l.drop (n + 1)
inductive Op (α : Type) where
  | DUP | DROP | OVER | SWAP | ROT | NIP | TUCK
  | PICK (n : Nat) | ROLL (n : Nat) | TOALT | FROMALT
  | TWODROP | TWODUP | THREEDUP | TWOOVER | TWOROT | TWOSWAP
  | PUSH (v : α) | CALL (nin : Nat) (sem : List α → List α)
open Op
def step {α : Type} : Op α → State α → Option (State α)
  | DUP,     (x :: s,           a) => some (x :: x :: s, a)
  | DROP,    (_ :: s,           a) => some (s, a)
  | OVER,    (x :: y :: s,      a) => some (y :: x :: y :: s, a)
  | SWAP,    (x :: y :: s,      a) => some (x :: y :: s, a)   -- <<< CORRUPTED: no-op (should be y::x::s)
  | ROT,     (x :: y :: z :: s, a) => some (z :: x :: y :: s, a)
  | NIP,     (x :: _ :: s,      a) => some (x :: s, a)
  | TUCK,    (x :: y :: s,      a) => some (x :: y :: x :: s, a)
  | PICK n,  (s,                a) => (s[n]?).map (fun v => (v :: s, a))
  | ROLL n,  (s,                a) => match s[n]? with
      | some v => some (v :: removeNth s n, a)
      | none   => none
  | TOALT,   (x :: s,           a) => some (s, x :: a)
  | FROMALT, (s,           x :: a) => some (x :: s, a)
  | TWODROP, (_ :: _ :: s,      a) => some (s, a)
  | TWODUP,  (x :: y :: s,      a) => some (x :: y :: x :: y :: s, a)
  | THREEDUP,(x :: y :: z :: s, a) => some (x :: y :: z :: x :: y :: z :: s, a)
  | TWOOVER, (x :: y :: z :: w :: s, a) => some (z :: w :: x :: y :: z :: w :: s, a)
  | TWOROT,  (x :: y :: z :: w :: u :: v :: s, a) => some (u :: v :: x :: y :: z :: w :: s, a)
  | TWOSWAP, (x :: y :: z :: w :: s, a) => some (z :: w :: x :: y :: s, a)
  | PUSH v,  (s,                a) => some (v :: s, a)
  | CALL nin f, (s,             a) =>
      if nin ≤ s.length then some ((f ((s.take nin).reverse)).reverse ++ s.drop nin, a) else none
  | _,       _                     => none
end RecompilerMut

open RecompilerMut RecompilerMut.Op

def CONF : String := "/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/conformance"
def opOfName (name : String) (n : Nat) : Option (Op Nat) :=
  match name with
  | "DUP" => some DUP | "DROP" => some DROP | "OVER" => some OVER | "SWAP" => some SWAP
  | "ROT" => some ROT | "NIP" => some NIP | "TUCK" => some TUCK
  | "PICK" => some (PICK n) | "ROLL" => some (ROLL n)
  | "TOALT" => some TOALT | "FROMALT" => some FROMALT
  | "2DROP" => some TWODROP | "2DUP" => some TWODUP | "3DUP" => some THREEDUP
  | "2OVER" => some TWOOVER | "2ROT" => some TWOROT | "2SWAP" => some TWOSWAP
  | _ => none
def jarr (l : List Nat) : String := "[" ++ String.intercalate "," (l.map toString) ++ "]"
def q : String := "\""
def kv (k v : String) : String := q ++ k ++ q ++ ":" ++ v
def getNatArr (j : Json) : List Nat :=
  match j.getArr? with
  | .ok a => a.toList.filterMap (fun x => (x.getNat?).toOption)
  | .error _ => []

def main : IO Unit := do
  let raw ← IO.FS.readFile (CONF ++ "/cases.json")
  match Json.parse raw with
  | .error e => IO.eprintln s!"parse error: {e}"
  | .ok j =>
    let cases := (j.getObjVal? "cases").toOption.get!.getArr?.toOption.get!
    let mut out : Array String := #[]
    for c in cases do
      let id   := (c.getObjVal? "id").toOption.get!.getNat?.toOption.get!
      let name := (c.getObjVal? "op").toOption.get!.getStr?.toOption.get!
      let n    := ((c.getObjVal? "n").toOption.bind (·.getNat?.toOption)).getD 0
      let main := getNatArr ((c.getObjVal? "main").toOption.get!)
      let alt  := getNatArr ((c.getObjVal? "alt").toOption.get!)
      let res  := match opOfName name n with
                  | some op => step op (main, alt)
                  | none    => none
      let line := match res with
        | none        => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "true" ++ "}"
        | some (m, a) => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "false"
                         ++ "," ++ kv "main" (jarr m) ++ "," ++ kv "alt" (jarr a) ++ "}"
      out := out.push line
    IO.FS.writeFile (CONF ++ "/lean_results_mut.json") ("[" ++ String.intercalate "," out.toList ++ "]")
    IO.println s!"lean(MUT): evaluated {out.size} cases"
