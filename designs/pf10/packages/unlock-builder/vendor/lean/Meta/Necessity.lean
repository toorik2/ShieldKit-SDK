/-
  Meta.Necessity — the NECESSITY ANALYZER. Computes, at build time, the transitive PROOF-TERM
  closure of the declared `headlines` over the kernel constant-dependency DAG, and classifies every
  LeanBCH declaration's module as LOAD-BEARING (≥1 decl in a headline's closure) or REFERENCE
  (import-reachable, 0 decls in closure — must carry a banner). Writes `Meta/necessity.json`.

  This turns the hand-written "★ NOT LOAD-BEARING" banners into a COMPUTED, diff-gated fact, and its
  `closure` set is the refactoring invariant: a legal restructuring leaves it byte-identical.
  (Uses the direct `.thmInfo v => v.value` access because `ConstantInfo.value?` excludes theorems.)
-/
import LeanBCH
import LeanBCH.Opt
import LeanBCH.Validation
import Meta.Headlines
import Lean.Elab.Command
import Lean.Data.Json
open Lean

namespace LeanBCH.Meta

/-- Constants a declaration DIRECTLY references — type for all, plus the proof/body term for
    def/thm/opaque (the load-bearing part; `ConstantInfo.value?` drops theorem proofs, so match directly).
    The `inductInfo` case follows the constructors as well (`++ v.ctors`), matching the kernel's
    `CollectAxioms` traversal — otherwise an axiom reachable only through a constructor's type would be
    invisible to this analyzer while `#print axioms` still sees it (red-team finding, closed here). -/
def constDeps (env : Environment) (n : Name) : Array Name :=
  match env.find? n with
  | some (.axiomInfo v)  => v.type.getUsedConstants
  | some (.defnInfo v)   => v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.thmInfo v)    => v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.opaqueInfo v) => v.type.getUsedConstants ++ v.value.getUsedConstants
  | some (.inductInfo v) => v.type.getUsedConstants ++ v.ctors.toArray
  | some (.ctorInfo v)   => v.type.getUsedConstants
  | some (.recInfo v)    => v.type.getUsedConstants
  | some (.quotInfo v)   => v.type.getUsedConstants
  | none => #[]

/-- The source module (file) a constant was imported from. -/
def moduleOf (env : Environment) (n : Name) : Option Name :=
  (env.getModuleIdxFor? n).map (fun idx => env.header.moduleNames[idx.toNat]!)

def isLeanBCHMod (m : Name) : Bool := m == `LeanBCH || (`LeanBCH).isPrefixOf m

def isAxiom (env : Environment) (n : Name) : Bool :=
  match env.find? n with | some (.axiomInfo _) => true | _ => false

/-- Transitive proof-term closure of a root set over the kernel constant-dependency DAG. -/
def closureOf (env : Environment) (starts : Array Name) : NameSet := Id.run do
  let mut visited : NameSet := {}
  let mut work := starts
  while 0 < work.size do
    let n := work.back!
    work := work.pop
    if !visited.contains n then
      visited := visited.insert n
      for d in constDeps env n do
        if !visited.contains d then work := work.push d
  return visited

run_cmd do
  let env ← getEnv
  -- headline roots (report any missing, non-fatal)
  let mut notFound : Array Name := #[]
  let mut roots : Array Name := #[]
  for h in headlines do
    if (env.find? h).isNone then notFound := notFound.push h else roots := roots.push h
  -- union closure + its axiom footprint (the PROVEN trust base, minus the axiom filter of #print axioms)
  let visited := closureOf env roots
  let axioms := (visited.toList.filter (isAxiom env)).toArray.qsort (·.toString < ·.toString)
  -- per-headline axiom footprint (each promised theorem → the axioms it actually rests on)
  let headlineAxioms := roots.toList.map (fun h =>
    let ax := ((closureOf env #[h]).toList.filter (isAxiom env)).map (·.toString)
    (h.toString, Json.arr ((ax.toArray.qsort (· < ·)).map Json.str)))
  -- per-module tallies over all LeanBCH constants: (total, loadBearing, theorems, defs)
  let tally : NameMap (Nat × Nat × Nat × Nat) :=
    env.constants.fold (init := {})
      (fun acc cn ci =>
        match moduleOf env cn with
        | some m =>
          if isLeanBCHMod m then
            let (t, l, th, df) := acc.getD m (0, 0, 0, 0)
            let l := if visited.contains cn then l + 1 else l
            let th := match ci with | .thmInfo _ => th + 1 | _ => th
            let df := match ci with | .defnInfo _ => df + 1 | _ => df
            acc.insert m (t + 1, l, th, df)
          else acc
        | none => acc)
  -- classify modules (sorted for stable diffs). A non-load-bearing module with theorems=0 is a
  -- validated EXECUTABLE surface (model/codec/policy checked by conformance); with theorems>0 it is
  -- a kept PROOF surface (proven, but not in any headline's proof-term closure).
  let modRows := (tally.toList.toArray.qsort (fun a b => a.1.toString < b.1.toString)).map
    (fun (m, (tot, l, th, df)) =>
      let bucket := if l > 0 then "LOAD-BEARING" else if th > 0 then "REFERENCE-PROOF" else "VALIDATED-EXECUTABLE"
      (m.toString, Json.mkObj [("total", toJson tot), ("loadBearing", toJson l),
                               ("theorems", toJson th), ("defs", toJson df),
                               ("bucket", Json.str bucket)]))
  let closureNames := visited.toList.filterMap (fun n =>
    (moduleOf env n).bind (fun m => if isLeanBCHMod m then some n.toString else none))
  let out := Json.mkObj [
    ("headlinesTotal", toJson headlines.length),
    ("notFoundHeadlines", Json.arr (notFound.map (fun n => Json.str n.toString))),
    ("closureSizeAll", toJson visited.size),
    ("axioms", Json.arr (axioms.map (fun n => Json.str n.toString))),
    ("headlineAxioms", Json.mkObj headlineAxioms),
    ("closureLeanBCH", Json.arr ((closureNames.toArray.qsort (· < ·)).map Json.str)),
    ("modules", Json.mkObj modRows.toList) ]
  IO.FS.writeFile "Meta/necessity.json" (out.pretty ++ "\n")
  let refMods := modRows.filterMap (fun (m, j) =>
    match j.getObjVal? "bucket" with | .ok (.str b) => if b != "LOAD-BEARING" then some m else none | _ => none)
  logInfo m!"necessity: closure={visited.size} · axioms={axioms.map (·.toString)} · LeanBCH-decls={closureNames.length} · non-load-bearing modules={refMods} · notFound={notFound}"

end LeanBCH.Meta
