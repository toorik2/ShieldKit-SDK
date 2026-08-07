/-
  Lean CONTROL side. Imports the REAL Recompiler.Control and runs the REAL `runProg`
  (instantiated at α = Nat, isT := (· != 0) — the FAITHFUL truthiness for the 0/1/sentinel
  encodings the generator uses; see gen_ctrl.mjs) over each structured case in ctrl_cases.json.
  Emits ctrl_lean_results.json = per-case {id, fail, main, alt} (main/alt TOP-FIRST int lists).
  Run:  export PATH=$HOME/.elan/bin:$PATH
        cd /home/toorik/Projects/verifier.cash/tools/lean-recompiler-spike
        lake env lean --run <this file> [ctrl_cases.json] [ctrl_lean_results.json]
-/
import Recompiler.Control
import Lean.Data.Json
open Lean Recompiler Recompiler.Op

def CONF : String := "/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/conformance"

/-- Faithful truthiness for the generator's value encoding (0 => empty item => FALSE; anything
    else => single nonzero non-0x80 byte => TRUE). -/
def isT : Nat → Bool := fun v => v != 0

/-- Dummy block: `runProg`/`runItem` IGNORE the DAG `b` and the entry depths at a block leaf
    (`runItem (.block ops _ _ _) st = run ops st`), so any well-typed Block value is fine. -/
def dummyB : Block Nat := ⟨0, 0, [], [], []⟩

def opOfName (name : String) (n v : Nat) : Option (Op Nat) :=
  match name with
  | "PUSH" => some (PUSH v)
  | "DUP" => some DUP | "DROP" => some DROP | "OVER" => some OVER | "SWAP" => some SWAP
  | "ROT" => some ROT | "NIP" => some NIP | "TUCK" => some TUCK
  | "PICK" => some (PICK n) | "ROLL" => some (ROLL n)
  | "TOALT" => some TOALT | "FROMALT" => some FROMALT
  | "2DROP" => some TWODROP | "2DUP" => some TWODUP | "3DUP" => some THREEDUP
  | "2OVER" => some TWOOVER | "2ROT" => some TWOROT | "2SWAP" => some TWOSWAP
  | _ => none

def jNat (j : Json) (k : String) (d : Nat) : Nat :=
  ((j.getObjVal? k).toOption.bind (·.getNat?.toOption)).getD d
def jStr (j : Json) (k : String) : String :=
  ((j.getObjVal? k).toOption.bind (·.getStr?.toOption)).getD ""
def jArr (j : Json) (k : String) : List Json :=
  match (j.getObjVal? k).toOption.bind (·.getArr?.toOption) with
  | some a => a.toList | none => []
def jBool (j : Json) (k : String) : Bool :=
  ((j.getObjVal? k).toOption.bind (·.getBool?.toOption)).getD false

def parseOp (j : Json) : Option (Op Nat) :=
  opOfName (jStr j "op") (jNat j "n" 0) (jNat j "v" 0)

instance : Inhabited (Item Nat) := ⟨Item.verify⟩

mutual
partial def parseProg (js : List Json) : Prog Nat :=
  js.map parseItem
partial def parseItem (j : Json) : Item Nat :=
  match jStr j "t" with
  | "block"  => Item.block ((jArr j "ops").filterMap parseOp) 0 0 dummyB
  | "ifte"   => Item.ifte (jBool j "neg") (parseProg (jArr j "then")) (parseProg (jArr j "else"))
  | "loop"   => Item.loop (parseProg (jArr j "body"))
  | "verify" => Item.verify
  | _        => Item.verify
end

def getNatArr (j : Json) : List Nat :=
  match j.getArr? with
  | .ok a => a.toList.filterMap (fun x => (x.getNat?).toOption)
  | .error _ => []

def jarr (l : List Nat) : String := "[" ++ String.intercalate "," (l.map toString) ++ "]"
def q : String := "\""
def kv (k v : String) : String := q ++ k ++ q ++ ":" ++ v

def main (args : List String) : IO Unit := do
  let inFile  := args.getD 0 "ctrl_cases.json"
  let outFile := args.getD 1 "ctrl_lean_results.json"
  let raw ← IO.FS.readFile (CONF ++ "/" ++ inFile)
  match Json.parse raw with
  | .error e => IO.eprintln s!"parse error: {e}"
  | .ok j =>
    let cases := (j.getObjVal? "cases").toOption.get!.getArr?.toOption.get!
    let mut out : Array String := #[]
    for c in cases do
      let id   := jNat c "id" 0
      let fuel := jNat c "fuel" 2000
      let main := getNatArr ((c.getObjVal? "main").toOption.get!)
      let alt  := getNatArr ((c.getObjVal? "alt").toOption.get!)
      let prog := parseProg (jArr c "prog")
      let res  := runProg isT fuel prog (main, alt)
      let line := match res with
        | none        => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "true" ++ "}"
        | some (m, a) => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "false"
                         ++ "," ++ kv "main" (jarr m) ++ "," ++ kv "alt" (jarr a) ++ "}"
      out := out.push line
    IO.FS.writeFile (CONF ++ "/" ++ outFile) ("[" ++ String.intercalate "," out.toList ++ "]")
    IO.println s!"lean: evaluated {out.size} control cases -> {outFile}"
