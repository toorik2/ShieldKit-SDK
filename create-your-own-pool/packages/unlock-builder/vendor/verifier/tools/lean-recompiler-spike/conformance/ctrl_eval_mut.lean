/-
  MUTATION TEST (non-vacuity) — ★ POLARITY MUTATION. A COPY of Control.lean's structured control
  semantics that carries the `neg` polarity flag but IGNORES it: `mrunItem .ifte` branches the
  then-arm on `isT c` REGARDLESS of `neg` (i.e. it models OP_NOTIF as OP_IF — the exact pre-fix
  bug). Imports the REAL Recompiler.Basic (block leaves still use the real `run`); only the CONTROL
  rules are the local (mutated) copy. If the harness is non-vacuous, the differ must now FLAG
  mismatches on the NOTIF-bearing cases (falsy/truthy conds select the OPPOSITE arm) and ONLY those
  — plain OP_IF cases still agree, confirming the differential pins the polarity fix specifically.
-/
import Recompiler.Dag
import Lean.Data.Json
open Lean Recompiler Recompiler.Op

def CONF : String := "/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/conformance"
def isT : Nat → Bool := fun v => v != 0
def dummyB : Block Nat := ⟨0, 0, [], [], []⟩

-- ---- COPY of Control.lean Item/Prog + big-step semantics, ifte MUTATED ----
inductive MItem (α : Type) where
  | block (ops : List (Op α)) (ed ea : Nat) (b : Block α)
  | ifte  (neg : Bool) (thenB elseB : List (MItem α))
  | loop  (body : List (MItem α))
  | verify
abbrev MProg (α : Type) := List (MItem α)

mutual
def mrunProg {α} (isT : α → Bool) : Nat → MProg α → State α → Option (State α)
  | _,      [],         st => some st
  | 0,      _ :: _,     _  => none
  | fuel+1, it :: rest, st =>
      match mrunItem isT fuel it st with
      | some st' => mrunProg isT fuel rest st'
      | none     => none
  termination_by fuel _ _ => fuel*3 + 1
def mrunItem {α} (isT : α → Bool) : Nat → MItem α → State α → Option (State α)
  | _,    .block ops _ _ _, st => run ops st
  | fuel, .ifte _neg t e,   st =>
      match st with
      -- ★ POLARITY MUTATION: `_neg` IGNORED — always branch then-arm on `isT c` (models NOTIF as IF)
      | (c :: m, a) => if isT c then mrunProg isT fuel t (m, a) else mrunProg isT fuel e (m, a)
      | ([], _)     => none
  | fuel, .loop body,       st => mrunLoop isT fuel body st
  | _,    .verify,          st =>
      match st with
      | (c :: m, a) => if isT c then some (m, a) else none
      | ([], _)     => none
  termination_by fuel _ _ => fuel*3 + 2
def mrunLoop {α} (isT : α → Bool) : Nat → MProg α → State α → Option (State α)
  | 0,      _,    _  => none
  | fuel+1, body, st =>
      match mrunProg isT fuel body st with
      | some (c :: m, a) => if isT c then some (m, a) else mrunLoop isT fuel body (m, a)
      | some ([], _)     => none
      | none             => none
  termination_by fuel _ _ => fuel*3 + 0
end

instance : Inhabited (MItem Nat) := ⟨MItem.verify⟩

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
def parseOp (j : Json) : Option (Op Nat) := opOfName (jStr j "op") (jNat j "n" 0) (jNat j "v" 0)

mutual
partial def parseProg (js : List Json) : MProg Nat := js.map parseItem
partial def parseItem (j : Json) : MItem Nat :=
  match jStr j "t" with
  | "block"  => MItem.block ((jArr j "ops").filterMap parseOp) 0 0 dummyB
  | "ifte"   => MItem.ifte (jBool j "neg") (parseProg (jArr j "then")) (parseProg (jArr j "else"))
  | "loop"   => MItem.loop (parseProg (jArr j "body"))
  | "verify" => MItem.verify
  | _        => MItem.verify
end

def getNatArr (j : Json) : List Nat :=
  match j.getArr? with | .ok a => a.toList.filterMap (fun x => (x.getNat?).toOption) | .error _ => []
def jarr (l : List Nat) : String := "[" ++ String.intercalate "," (l.map toString) ++ "]"
def q : String := "\""
def kv (k v : String) : String := q ++ k ++ q ++ ":" ++ v

def main (args : List String) : IO Unit := do
  let inFile  := args.getD 0 "ctrl_cases.json"
  let outFile := args.getD 1 "ctrl_lean_results_mut.json"
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
      let res  := mrunProg isT fuel prog (main, alt)
      let line := match res with
        | none        => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "true" ++ "}"
        | some (m, a) => "{" ++ kv "id" (toString id) ++ "," ++ kv "fail" "false"
                         ++ "," ++ kv "main" (jarr m) ++ "," ++ kv "alt" (jarr a) ++ "}"
      out := out.push line
    IO.FS.writeFile (CONF ++ "/" ++ outFile) ("[" ++ String.intercalate "," out.toList ++ "]")
    IO.println s!"MUTANT lean: evaluated {out.size} control cases -> {outFile}"
