
import FriStark.AIR.PublicInputs
import FriStark.AIR.ProductV1

open FriStark.AIR.PublicInputs
open FriStark.AIR.ProductV1

def main (_args : List String) : IO UInt32 := do
  let mut fails := 0
  -- GDig32 of 32×0x01
  let bs := List.replicate 32 (1 : UInt8)
  let got := gdig32FromBytes bs
  -- LE u64 limbs of 0x0101...01
  let limb : Nat :=
    Id.run do
      let mut n := 0
      for j in [0:8] do n := n + 1 * (256 ^ j)
      pure n
  let exp := [limb, limb, limb, limb]
  if got != exp then
    IO.eprintln s!"gdig32 fail {got}"
    fails := fails + 1
  else IO.println "gdig32 ok"
  -- hash56 of bytes 0..31
  let H := (List.range 32).map (fun i => UInt8.ofNat i)
  let hgot := hashBytesToFE H
  if hgot.length != 5 then fails := fails + 1
  else IO.println s!"hash56 ok len={hgot.length}"
  if !mutationRejected encodeDemo { encodeDemo with packetCommit := [9,9,9,9] } then
    fails := fails + 1
  else IO.println "mutation reject ok"
  if encodeDemo.flatten.length != 4+16+16+4+4+5 then fails := fails + 1
  if fails == 0 then
    IO.println "DIFF_STATEMENT_OK"
    pure 0
  else pure 1
