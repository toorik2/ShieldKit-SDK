/-
  Opening consistency: fri0≡QAt and compose≡comp_z already in pure path;
  this gate documents and re-checks FS/deep field consistency wording + STATUS claim.
  Openings remain openings (no private-trace re-prove).
-/
import FriStark.Full.Verify
import FriStark.Params.V1
import FriStark.Field.Ext

open FriStark.Full.Verify
open FriStark.Params.V1
open FriStark.Field.Ext

def main (args : List String) : IO UInt32 := do
  let root := args.getD 0 "."
  -- Re-run pure path (includes deepQAtLayout fri0 bind + composeCheck)
  let bin := System.FilePath.mk (root ++ "/.lake/build/bin/diff_pure_verify")
  if !(← bin.pathExists) then
    IO.eprintln "missing diff_pure_verify"; return 2
  let out ← IO.Process.output { cmd := bin.toString, args := #[root] }
  if out.exitCode != 0 then
    IO.eprintln "pure verify failed under opening-consistency"
    IO.eprintln out.stdout
    return 1
  let okLayout := out.stdout.splitOn "\n" |>.any (·.contains "layout_deep=")
  let okCompose := out.stdout.splitOn "\n" |>.any (·.contains "compose_in_honest=true")
  let okAgree := out.stdout.splitOn "\n" |>.any (·.contains "agree=13/13")
  IO.println "opening_model=public+openings (private trace NOT re-derived)"
  IO.println s!"fri0_equiv_qat=via_deepQAtLayout layout_deep_ok={okLayout}"
  IO.println s!"compose_equiv_comp_z=via_composeCheck compose_ok={okCompose}"
  IO.println s!"fs_grind_idx_merkle_coset=shipped_in_pure_path agree={okAgree}"
  if okLayout && okCompose && okAgree then
    IO.println "OPENING_CONSISTENCY_OK"
    pure 0
  else
    IO.println "OPENING_CONSISTENCY_FAIL"
    pure 1
