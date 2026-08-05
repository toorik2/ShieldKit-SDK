import FriStark.Verify.Executable
import FriStark.Verify.Types
import FriStark.Field.Ext
import FriStark.Hash.Sha256
import FriStark.Hash.Merkle
import FriStark.Binding.Forges
import FriStark.Params.V1
import FriStark.Transcript.FiatShamir

open FriStark.Verify.Executable
open FriStark.Verify.Types
open FriStark.Field.Ext
open FriStark.Hash.Sha256
open FriStark.Hash.Merkle
open FriStark.Binding.Forges
open FriStark.Params.V1
open FriStark.Transcript.FiatShamir

def mkForge (label : String) (checks : List AtomicCheck)
    (blowup := BLOWUP) (queries := QUERIES) (grind := GRIND_BITS) (fold := FOLD) : ProofBundle :=
  { checks := checks, accept := false, label := label, eligibility := "product",
    blowup := blowup, queries := queries, grindBits := grind, fold := fold }

def main (_args : List String) : IO UInt32 := do
  let leaf := "hello-fri".toUTF8.toList
  let leafDig := FriStark.Hash.Sha256.hash leaf
  let rootD := leafDig  -- single-leaf tree root = leaf digest for stark-style empty path
  -- structures_merkle style: root = hash(leaf)
  let layers := buildTree [leaf]
  let rootRaw := root layers
  let v : E := ⟨2, 3⟩; let w : E := ⟨4, 5⟩; let beta : E := ⟨6, 7⟩; let xpos : Nat := 9
  let folded := (friFold v w beta xpos).getD zero
  -- grindCheck: craft state||nonce that passes (grindBits=24 means top 24 bits of LE u64 zero-ish)
  -- Use known-passing: empty search — call grindOk and if false use grindBits=0 for honest demo only
  -- Production honest uses real exported grindCheck; this suite uses fold/merkle/params only.
  let honest : ProofBundle := {
    checks := [
      AtomicCheck.merkleOpen rootRaw leaf 0 (proof layers 0),
      AtomicCheck.merkleOpenDigest rootD leafDig [],
      AtomicCheck.friFold v w beta folded xpos,
      AtomicCheck.extEq folded folded,
      AtomicCheck.natEq 1 1,
      AtomicCheck.natListEq [1,2] [1,2],
      AtomicCheck.bytesEq leafDig leafDig
    ]
    accept := true
    label := "honest-structural"
    eligibility := "product"
    blowup := BLOWUP
    queries := QUERIES
    grindBits := GRIND_BITS
    fold := FOLD
  }
  -- 12 real structural forges (no reject tags)
  let forges : List ProofBundle := [
    mkForge "forge-bad-merkle-raw" [AtomicCheck.merkleOpen rootRaw ("wrong".toUTF8.toList) 0 (proof layers 0)],
    mkForge "forge-bad-merkle-digest" [AtomicCheck.merkleOpenDigest rootD ("wrong".toUTF8.toList) []],
    mkForge "forge-bad-fold" [AtomicCheck.friFold v w beta (add folded (fromBase 1)) xpos],
    mkForge "forge-bad-exteq" [AtomicCheck.extEq folded (add folded (fromBase 1))],
    mkForge "forge-params-blowup" honest.checks (blowup := 8),
    mkForge "forge-params-queries" honest.checks (queries := 1),
    mkForge "forge-params-grind" honest.checks (grind := 2),
    mkForge "forge-params-fold" honest.checks (fold := 1),
    mkForge "forge-nateq" [AtomicCheck.natEq 1 2],
    mkForge "forge-natlist" [AtomicCheck.natListEq [1] [2]],
    mkForge "forge-bytes" [AtomicCheck.bytesEq leafDig ("xx".toUTF8.toList)],
    mkForge "forge-grindcheck" [AtomicCheck.grindCheck [] (List.replicate 8 (255 : UInt8)) 24]
  ]
  let mut honestOk := 0; let mut forgeRej := 0; let mut leanAccForge := 0; let mut agree := 0
  if (verify honest).isOk then honestOk := 1
  if agreesWithOracle honest then agree := agree + 1
  for f in forges do
    if (verify f).isOk then leanAccForge := leanAccForge + 1 else forgeRej := forgeRej + 1
    if agreesWithOracle f then agree := agree + 1
  let bindingOk := allForgesRejected
  let forgeN := forges.length
  IO.println s!"honest={honestOk}/1 forge_reject={forgeRej}/{forgeN} lean_acc_forge={leanAccForge} agree={agree}/{forgeN+1} binding={bindingOk}"
  -- ensure no reject constructor used: forges all structural
  if honestOk == 1 && leanAccForge == 0 && forgeRej == forgeN && forgeN ≥ 10 && bindingOk && agree == forgeN + 1 then
    IO.println "DIFF_VERIFY_OK"; pure 0
  else
    IO.println "DIFF_VERIFY_FAIL"; pure 1
