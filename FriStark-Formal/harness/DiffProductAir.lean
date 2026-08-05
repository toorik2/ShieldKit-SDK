/-
  Diff harness for product AIR (shieldkit-v2-stark-statement-v1).
  Runs real ProductV1.verifyProductAir on honest + mutation suites.
  Prints PRODUCT_AIR_OK on success (exit 0).
-/
import FriStark.AIR.ProductV1
import FriStark.AIR.PublicInputs
import FriStark.Hash.Poseidon2.Sponge

open FriStark.AIR.ProductV1
open FriStark.AIR.PublicInputs
open FriStark.Hash.Poseidon2.Sponge

def main (_args : List String) : IO UInt32 := do
  let mut fails : Nat := 0
  let mut checks : Nat := 0

  -- SKS3 encode length + roundtrip
  checks := checks + 1
  let gen := genesisSks3
  let enc := encodeSks3 gen
  if enc.length != 128 then
    fails := fails + 1
    IO.eprintln s!"sks3 length {enc.length}"
  else
    match decodeSks3? enc with
    | none => fails := fails + 1; IO.eprintln "sks3 decode none"
    | some d =>
      if d.noteCount != 0 || d.actionSequence != 0 then
        fails := fails + 1; IO.eprintln "sks3 roundtrip fields"
      else IO.println "sks3 encode/decode ok"

  -- 16 FE words
  checks := checks + 1
  let words := sks3ToWordsStruct gen
  if words.length != 16 then
    fails := fails + 1; IO.eprintln s!"sks3 words {words.length}"
  else IO.println "sks3 words=16 ok"

  -- packet length + rate limbs
  checks := checks + 1
  let (stD, wD) := honestDeposit
  if wD.packetBytes.length != 552 then
    fails := fails + 1; IO.eprintln s!"packet len {wD.packetBytes.length}"
  else
    let limbs := packetToRateElements wD.packetBytes
    -- 78×7 + 6 remainder → 79 limbs
    if limbs.length != 79 then
      fails := fails + 1; IO.eprintln s!"rate limbs {limbs.length}"
    else IO.println "packet 552 / rate limbs 79 ok"

  -- packetCommit = hashTo4(DOM_PACKET :: limbs)
  checks := checks + 1
  let recomputed := computePacketCommit wD.packetBytes
  if recomputed != stD.packetCommit || stD.packetCommit.length != 4 then
    fails := fails + 1; IO.eprintln "packetCommit bind fail"
  else IO.println "packetCommit Poseidon2 sponge ok"

  -- StatementFE flatten length from product
  checks := checks + 1
  let fe := toStatementFE stD
  if fe.flatten.length != 4 + 16 + 16 + 4 + 4 + 5 then
    fails := fails + 1; IO.eprintln s!"FE flatten {fe.flatten.length}"
  else IO.println "StatementFE flatten ok"

  -- Honest accept: deposit / transfer / withdrawal
  for label in ["deposit", "transfer", "withdrawal"] do
    checks := checks + 1
    let ok :=
      match label with
      | "deposit" =>
        let (s, w) := honestDeposit; verifyProductAir s w
      | "transfer" =>
        let (s, w) := honestTransfer; verifyProductAir s w
      | _ =>
        let (s, w) := honestWithdrawal; verifyProductAir s w
    if !ok then
      fails := fails + 1
      IO.eprintln s!"honest {label} REJECTED"
    else IO.println s!"honest {label} accept"

  if !honestAllAccepted then
    fails := fails + 1
    IO.eprintln "honestAllAccepted false"

  -- Mutation suite: each must reject
  for m in allMutations do
    checks := checks + 1
    let accepted := verifyProductAir m.stmt m.wit
    if accepted then
      fails := fails + 1
      IO.eprintln s!"mutation {m.name} FALSE ACCEPT"
    else IO.println s!"mutation {m.name} rejected"

  checks := checks + 1
  if !mutationsAllRejected then
    fails := fails + 1
    IO.eprintln "mutationsAllRejected false"
  else IO.println "mutationsAllRejected ok"

  -- hashTo4 length sanity (sponge available)
  checks := checks + 1
  if (hashTo4 [DOM_PACKET, 1, 2, 3]).length != 4 then
    fails := fails + 1; IO.eprintln "hashTo4 len"
  else IO.println "hashTo4 ok"

  IO.println s!"checks={checks} fails={fails}"
  if fails == 0 then
    IO.println "PRODUCT_AIR_OK"
    pure 0
  else
    IO.println "PRODUCT_AIR_FAIL"
    pure 1
