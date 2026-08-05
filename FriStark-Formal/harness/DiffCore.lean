import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Hash.Poseidon2.Perm
import FriStark.Hash.Poseidon2.Sponge
import FriStark.Hash.Merkle
import FriStark.FRI.Verify
import FriStark.Params.V1

open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Hash.Poseidon2.Perm
open FriStark.Hash.Poseidon2.Sponge
open FriStark.Hash.Merkle
open FriStark.FRI.Verify

def main (_args : List String) : IO UInt32 := do
  let mut fails : Nat := 0
  let mut checks : Nat := 0

  -- Poseidon official KAT (shipped Perm #guard also)
  let kat := permutation (Array.ofFn (fun i : Fin 12 => (i.val : Nat)))
  let expect : Array Nat := #[
    138186169299091649, 2237493815125627916, 7098449130000758157, 16681569560651424230,
    2885694034573886267, 1987263728465303211, 4895658260063552408, 16782691522897809445,
    6250362358359317026, 8723968546836371205, 17025428646788054631, 7660698892044183277]
  checks := checks + 1
  if kat != expect then fails := fails + 1; IO.eprintln "poseidon KAT fail"
  else IO.println "poseidon KAT ok"

  checks := checks + 1
  if hashTo1 [0,1,2,3] != 6276405055127055335 then fails := fails + 1; IO.eprintln "hashTo1 fail"
  else IO.println "hashTo1 ok"

  -- Field mul vs Python vector seed batch (a=(3,5),b=(7,11) self-check)
  let m := mul ⟨3,5⟩ ⟨7,11⟩
  let t0 := FriStark.Field.Goldilocks.mul 3 7
  let t1 := FriStark.Field.Goldilocks.mul 5 11
  let t2 := FriStark.Field.Goldilocks.mul (FriStark.Field.Goldilocks.add 3 5) (FriStark.Field.Goldilocks.add 7 11)
  let c0 := FriStark.Field.Goldilocks.add t0 (FriStark.Field.Goldilocks.mul 7 t1)
  let c1 := FriStark.Field.Goldilocks.sub (FriStark.Field.Goldilocks.sub t2 t0) t1
  checks := checks + 1
  if !(eq m ⟨c0,c1⟩) then fails := fails + 1; IO.eprintln "field mul fail"
  else IO.println "field mul ok"

  -- inv
  match inv ⟨3,5⟩ with
  | none => fails := fails + 1
  | some i =>
    checks := checks + 1
    if !(eq (mul ⟨3,5⟩ i) one) then fails := fails + 1; IO.eprintln "inv fail"
    else IO.println "field inv ok"

  -- merkle
  let leaf := "abc".toUTF8.toList
  let layers := buildTree [leaf]
  let r := root layers
  checks := checks + 1
  if !(verify r leaf 0 (proof layers 0)) then fails := fails + 1; IO.eprintln "merkle fail"
  else IO.println "merkle ok"
  -- adversarial: wrong leaf
  checks := checks + 1
  if verify r "abx".toUTF8.toList 0 (proof layers 0) then fails := fails + 1; IO.eprintln "merkle false accept"
  else IO.println "merkle forge rejected"

  -- fri fold (python folded for (2,3)(4,5)(6,7) xpos=9)
  let v : E := ⟨2,3⟩; let w : E := ⟨4,5⟩; let beta : E := ⟨6,7⟩; let xpos : Nat := 9
  match friFold v w beta xpos with
  | none => fails := fails + 1; IO.eprintln "fold none"
  | some folded =>
    checks := checks + 1
    if !(verifyFoldStep v w folded beta xpos) then fails := fails + 1
    else IO.println "fri fold ok"
    checks := checks + 1
    if verifyFoldStep v w (add folded (fromBase 1)) beta xpos then fails := fails + 1; IO.eprintln "fold forge accept"
    else IO.println "fri fold forge rejected"

  -- multi-leaf merkle
  let leaves := ["a".toUTF8.toList, "b".toUTF8.toList, "c".toUTF8.toList, "d".toUTF8.toList]
  let layers2 := buildTree leaves
  let r2 := root layers2
  for idx in [0:4] do
    checks := checks + 1
    if !(verify r2 leaves[idx]! idx (proof layers2 idx)) then
      fails := fails + 1
      IO.eprintln s!"merkle multi fail {idx}"
  IO.println "merkle multi ok"

  IO.println s!"checks={checks} fails={fails}"
  if fails == 0 && checks ≥ 10 then
    IO.println "DIFF_CORE_OK"; pure 0
  else
    IO.println "DIFF_CORE_FAIL"; pure 1
