/-
  Lean side of the conformance harness. Imports the REAL Recompiler.Basic and applies the
  REAL `step` (instantiated at α = Nat) to every case in cases.json, emitting
  lean_results.json = per-case {id, fail, main, alt} (main/alt TOP-FIRST int lists).
  Run:  export PATH=$HOME/.elan/bin:$PATH
        cd /home/toorik/Projects/verifier.cash/tools/lean-recompiler-spike
        lake env lean --run <this file>
-/
import Recompiler.Basic
import Lean.Data.Json
open Lean Recompiler Recompiler.Op

def CONF : String := "/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/conformance"

/-- Build the Op from its name + optional depth n. -/
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

def main (args : List String) : IO Unit := do
  let inFile  := args.getD 0 "cases.json"
  let outFile := args.getD 1 "lean_results.json"
  let raw ← IO.FS.readFile (CONF ++ "/" ++ inFile)
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
    IO.FS.writeFile (CONF ++ "/" ++ outFile) ("[" ++ String.intercalate "," out.toList ++ "]")
    IO.println s!"lean: evaluated {out.size} cases -> {outFile}"
