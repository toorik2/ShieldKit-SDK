/-
  Product AIR constraints for shieldkit-v2-stark-statement-v1 (beyond FE packing).

  Normative refs (vendor/freeze-a0):
  - PUBLIC_STATEMENT.md — statement ABI + kind-active / transition claims
  - BYTE_LAYOUTS.md — SKS3 (128B), SDA3 (552B), packetToRateElements (7-byte BE limbs)
  - CRYPTO_EC_FREE.md — DOM_PACKET=16, GDig32 = 4× FE BE limbs, denomination

  Scope of this module (KAT-sufficient, not full Merkle/note crypto):
  1. Kind codes deposit=1 / transfer=2 / withdrawal=3
  2. Kind-active inactive-zero rules for nullifier / leaf / withdrawal hash
  3. SKS3 pre→post transition (counts, roots change, sequence, capacity, reserve)
  4. packetCommit = Poseidon2 sponge(DOM_PACKET || packetToRateElements(SDA3))
-/
import FriStark.AIR.PublicInputs
import FriStark.Field.Goldilocks
import FriStark.Hash.Poseidon2.Sponge
import FriStark.Params.V1

namespace FriStark.AIR.ProductV1

open FriStark.AIR.PublicInputs
open FriStark.Field.Goldilocks
open FriStark.Hash.Poseidon2.Sponge
open FriStark.Params.V1 (P)

/-- Domain tag for packet commitment (CRYPTO_EC_FREE.md). -/
def DOM_PACKET : F := 16

/-- Fixed denomination (sats) — profile pin, not serialized in SKS3. -/
def DENOMINATION_SATS : Nat := 10_000_000

/-- Kind codes: 1 deposit / 2 transfer / 3 withdrawal. -/
inductive Kind where
  | deposit
  | transfer
  | withdrawal
  deriving DecidableEq, Repr

def Kind.toU8 : Kind → UInt8
  | .deposit => 1
  | .transfer => 2
  | .withdrawal => 3

def Kind.ofU8? : UInt8 → Option Kind
  | 1 => some .deposit
  | 2 => some .transfer
  | 3 => some .withdrawal
  | _ => none

def Kind.toNat (k : Kind) : Nat := k.toU8.toNat

/-- Zero GDig32 as four FE limbs. -/
def zeroGDig32 : List F := [0, 0, 0, 0]

def isZeroGDig32 (xs : List F) : Bool :=
  xs.length == 4 && xs.all (fun x => x % P == 0)

def isZeroBytes32 (bs : List UInt8) : Bool :=
  bs.length == 32 && bs.all (· == 0)

def isZeroBytes128 (bs : List UInt8) : Bool :=
  bs.length == 128 && bs.all (· == 0)

/-- GDig32 wire: 4 FE as unsigned big-endian 8-byte limbs (CRYPTO). -/
def feToBytesBE (x : F) : List UInt8 := Id.run do
  let mut n := x % P
  let mut out : Array UInt8 := Array.replicate 8 0
  for i in [0:8] do
    out := out.set! (7 - i) (UInt8.ofNat (n % 256))
    n := n / 256
  return out.toList

def gdig32ToBytes (fes : List F) : List UInt8 :=
  (fes.take 4).foldl (fun acc f => acc ++ feToBytesBE f) []

def bytesToFeBE (bs : List UInt8) : F := Id.run do
  let mut n : Nat := 0
  for b in bs do
    n := n * 256 + b.toNat
  return n % P

def gdig32FromBytesBE (bs : List UInt8) : List F := Id.run do
  let mut out : List F := []
  for i in [0:4] do
    let limb := (List.range 8).map (fun j => bs.getD (i * 8 + j) 0)
    out := out ++ [bytesToFeBE limb]
  return out

/-- Encode u32 / u64 little-endian (SKS3 counters). -/
def u32le (n : Nat) : List UInt8 :=
  [ UInt8.ofNat (n % 256)
  , UInt8.ofNat ((n / 256) % 256)
  , UInt8.ofNat ((n / 65536) % 256)
  , UInt8.ofNat ((n / 16777216) % 256) ]

def u64le (n : Nat) : List UInt8 :=
  u32le (n % (2 ^ 32)) ++ u32le (n / (2 ^ 32))

def readU32le (bs : List UInt8) (off : Nat) : Nat :=
  (bs.getD off 0).toNat +
  (bs.getD (off + 1) 0).toNat * 256 +
  (bs.getD (off + 2) 0).toNat * 65536 +
  (bs.getD (off + 3) 0).toNat * 16777216

def readU64le (bs : List UInt8) (off : Nat) : Nat :=
  readU32le bs off + readU32le bs (off + 4) * (2 ^ 32)

/-- SKS3 magic ASCII "SKS3". -/
def sks3Magic : List UInt8 := [0x53, 0x4b, 0x53, 0x33]

/-- SDA3 magic ASCII "SDA3". -/
def sda3Magic : List UInt8 := [0x53, 0x44, 0x41, 0x33]

/-!
  ## SKS3 layout (128 bytes) — BYTE_LAYOUTS.md

  | Off | Sz | Field |
  | 0   | 4  | magic SKS3 |
  | 4   | 32 | profileId (raw) |
  | 36  | 32 | noteRoot GDig32 |
  | 68  | 32 | nullifierRoot GDig32 |
  | 100 | 4  | noteCount u32le |
  | 104 | 4  | nullifierCount u32le |
  | 108 | 4  | maximumLiveNotes u32le |
  | 112 | 8  | reserveSats u64le |
  | 120 | 8  | actionSequence u64le |
-/
structure Sks3 where
  profileId : List UInt8       -- 32
  noteRoot : List F            -- 4 FE
  nullifierRoot : List F       -- 4 FE
  noteCount : Nat
  nullifierCount : Nat
  maximumLiveNotes : Nat
  reserveSats : Nat
  actionSequence : Nat
  deriving DecidableEq, Repr

def Sks3.liveNoteCount (s : Sks3) : Nat := s.noteCount - s.nullifierCount

/-- SKS3 invariants (BYTE_LAYOUTS + state.mjs). -/
def sks3Invariants (s : Sks3) (denom : Nat := DENOMINATION_SATS) : Bool :=
  s.profileId.length == 32 &&
  s.noteRoot.length == 4 &&
  s.nullifierRoot.length == 4 &&
  s.nullifierCount ≤ s.noteCount &&
  s.maximumLiveNotes ≥ 1 &&
  s.liveNoteCount ≤ s.maximumLiveNotes &&
  s.reserveSats == s.liveNoteCount * denom &&
  s.actionSequence ≥ max s.noteCount s.nullifierCount &&
  s.actionSequence ≤ s.noteCount + s.nullifierCount &&
  s.actionSequence < (2 ^ 33) &&
  s.noteCount ≤ 0xffffffff &&
  s.nullifierCount ≤ 0xfffffffe

def encodeSks3 (s : Sks3) : List UInt8 :=
  sks3Magic ++
  s.profileId ++
  gdig32ToBytes s.noteRoot ++
  gdig32ToBytes s.nullifierRoot ++
  u32le s.noteCount ++
  u32le s.nullifierCount ++
  u32le s.maximumLiveNotes ++
  u64le s.reserveSats ++
  u64le s.actionSequence

def decodeSks3? (bs : List UInt8) : Option Sks3 :=
  if bs.length != 128 then none
  else if bs.take 4 != sks3Magic then none
  else
    let s : Sks3 := {
      profileId := bs.drop 4 |>.take 32
      noteRoot := gdig32FromBytesBE (bs.drop 36 |>.take 32)
      nullifierRoot := gdig32FromBytesBE (bs.drop 68 |>.take 32)
      noteCount := readU32le bs 100
      nullifierCount := readU32le bs 104
      maximumLiveNotes := readU32le bs 108
      reserveSats := readU64le bs 112
      actionSequence := readU64le bs 120
    }
    if sks3Invariants s then some s else none

/-- 16 FE word packing of SKS3: 16× LE u64 of the 128 raw bytes, reduced mod P.
    Matches PUBLIC_STATEMENT "16 FE from 128 bytes under the same w < P rule"
    via modular reduction (opaque byte regions). -/
def sks3ToWords (bs : List UInt8) : List F := Id.run do
  let mut out : List F := []
  for i in [0:16] do
    let mut n : Nat := 0
    for j in [0:8] do
      let b := bs.getD (i * 8 + j) 0
      n := n + b.toNat * (256 ^ j)
    out := out ++ [n % P]
  return out

def sks3ToWordsStruct (s : Sks3) : List F := sks3ToWords (encodeSks3 s)

/-!
  ## Product statement (logical) + witness packet
-/
structure ProductStatement where
  networkId : UInt8            -- 1 or 2
  kind : Kind
  profileId : List UInt8       -- 32
  instanceId : List UInt8      -- 32
  packetCommit : List F        -- 4 FE GDig32
  preState : Sks3
  postState : Sks3
  publicNullifier : List F     -- 4 FE; zero if inactive
  outputNoteLeaf : List F      -- 4 FE; zero if inactive
  withdrawalHash : List UInt8  -- 32 raw; zero if inactive
  transactionContextHash : List UInt8 -- 32 raw
  deriving DecidableEq, Repr

/-- Full SDA3 packet bytes (552) as private witness material for binding. -/
structure ProductWitness where
  packetBytes : List UInt8
  encryptedRecord : List UInt8  -- 128 (active for deposit/transfer)
  deriving DecidableEq, Repr

/-!
  ## Kind-active field rules (BYTE_LAYOUTS.md)

  | Kind       | publicNullifier | outputNoteLeaf | withdrawal hash |
  | Deposit    | inactive zero   | active         | inactive zero   |
  | Transfer   | active          | active         | inactive zero   |
  | Withdrawal | active          | inactive zero  | active          |
-/
def kindActiveOk (st : ProductStatement) : Bool :=
  match st.kind with
  | .deposit =>
      isZeroGDig32 st.publicNullifier &&
      isZeroBytes32 st.withdrawalHash &&
      st.outputNoteLeaf.length == 4
  | .transfer =>
      isZeroBytes32 st.withdrawalHash &&
      st.publicNullifier.length == 4 &&
      st.outputNoteLeaf.length == 4
  | .withdrawal =>
      isZeroGDig32 st.outputNoteLeaf &&
      st.publicNullifier.length == 4 &&
      st.withdrawalHash.length == 32

/-- Inactive fields that must be zero — used by mutation tests. -/
def inactiveFieldsZero (st : ProductStatement) : Bool := kindActiveOk st

/-!
  ## State transition rules (transition.mjs / BYTE_LAYOUTS invariants)

  Always:
  - profileId, maximumLiveNotes unchanged
  - actionSequence = pre + 1
  - pre/post satisfy SKS3 invariants
  Per kind:
  - Deposit: noteCount+1, noteRoot changes, nullifierRoot/count unchanged,
    reserve = (live+1)*D, capacity live < max
  - Transfer: noteCount+1, nullifierCount+1, both roots change, live unchanged
  - Withdrawal: nullifierCount+1, nullifierRoot changes, noteRoot/count unchanged,
    reserve = (live-1)*D, live ≥ 1
-/
def stateTransitionOk (kind : Kind) (pre post : Sks3)
    (denom : Nat := DENOMINATION_SATS) : Bool :=
  sks3Invariants pre denom &&
  sks3Invariants post denom &&
  pre.profileId == post.profileId &&
  pre.maximumLiveNotes == post.maximumLiveNotes &&
  post.actionSequence == pre.actionSequence + 1 &&
  match kind with
  | .deposit =>
      pre.liveNoteCount < pre.maximumLiveNotes &&
      post.noteCount == pre.noteCount + 1 &&
      post.nullifierCount == pre.nullifierCount &&
      post.nullifierRoot == pre.nullifierRoot &&
      post.noteRoot != pre.noteRoot &&
      post.reserveSats == (pre.liveNoteCount + 1) * denom
  | .transfer =>
      pre.liveNoteCount ≥ 1 &&
      post.noteCount == pre.noteCount + 1 &&
      post.nullifierCount == pre.nullifierCount + 1 &&
      post.noteRoot != pre.noteRoot &&
      post.nullifierRoot != pre.nullifierRoot &&
      post.reserveSats == pre.liveNoteCount * denom
  | .withdrawal =>
      pre.liveNoteCount ≥ 1 &&
      post.noteCount == pre.noteCount &&
      post.nullifierCount == pre.nullifierCount + 1 &&
      post.noteRoot == pre.noteRoot &&
      post.nullifierRoot != pre.nullifierRoot &&
      post.reserveSats == (pre.liveNoteCount - 1) * denom

/-!
  ## packetToRateElements + packetCommit
  Canonical packing (BYTE_LAYOUTS.md):
  552 bytes → 78 full 7-byte BE limbs + 1 final limb from remaining 6 bytes.
  packetCommit = GDig32(Poseidon2Sponge(DOM_PACKET || limbs))
-/
def packetToRateElements (bs : List UInt8) : List F := Id.run do
  let mut limbs : List F := []
  let mut offset : Nat := 0
  -- 78 full 7-byte limbs
  while offset + 7 ≤ 552 do
    let mut n : Nat := 0
    for j in [0:7] do
      n := n * 256 + (bs.getD (offset + j) 0).toNat
    limbs := limbs ++ [n % P]
    offset := offset + 7
  -- remaining 6 bytes (offset should be 546)
  if offset < 552 then
    let mut n : Nat := 0
    while offset < 552 do
      n := n * 256 + (bs.getD offset 0).toNat
      offset := offset + 1
    limbs := limbs ++ [n % P]
  return limbs

def computePacketCommit (packetBytes : List UInt8) : List F :=
  hashTo4 (DOM_PACKET :: packetToRateElements packetBytes)

def packetCommitOk (stmtCommit : List F) (packetBytes : List UInt8) : Bool :=
  packetBytes.length == 552 &&
  stmtCommit.length == 4 &&
  stmtCommit == computePacketCommit packetBytes

/-- Encode SDA3 from statement + witness record. -/
def encodePacket (st : ProductStatement) (rec : List UInt8) : List UInt8 :=
  let preB := encodeSks3 st.preState
  let postB := encodeSks3 st.postState
  let nfB := gdig32ToBytes st.publicNullifier
  let leafB := gdig32ToBytes st.outputNoteLeaf
  let recPad :=
    if rec.length == 128 then rec else List.replicate 128 0
  sda3Magic ++
  [st.networkId, st.kind.toU8, 0, 0] ++
  st.instanceId ++
  preB ++
  postB ++
  nfB ++
  leafB ++
  recPad ++
  st.withdrawalHash ++
  st.transactionContextHash

/-- Parse kind / network / instance from raw SDA3 and check statement binding. -/
def packetBindsStatement (st : ProductStatement) (packet : List UInt8) : Bool :=
  packet.length == 552 &&
  packet.take 4 == sda3Magic &&
  packet.getD 4 0 == st.networkId &&
  packet.getD 5 0 == st.kind.toU8 &&
  packet.getD 6 0 == 0 &&
  packet.getD 7 0 == 0 &&
  (packet.drop 8 |>.take 32) == st.instanceId &&
  (packet.drop 40 |>.take 128) == encodeSks3 st.preState &&
  (packet.drop 168 |>.take 128) == encodeSks3 st.postState &&
  (packet.drop 296 |>.take 32) == gdig32ToBytes st.publicNullifier &&
  (packet.drop 328 |>.take 32) == gdig32ToBytes st.outputNoteLeaf &&
  (packet.drop 488 |>.take 32) == st.withdrawalHash &&
  (packet.drop 520 |>.take 32) == st.transactionContextHash

/-- Network id must be mainnet(1) or chipnet(2). -/
def networkOk (n : UInt8) : Bool := n == 1 || n == 2

/-- Full product AIR checklist (structural, KAT-sufficient). -/
def verifyProductAir (st : ProductStatement) (w : ProductWitness) : Bool :=
  networkOk st.networkId &&
  st.profileId.length == 32 &&
  st.instanceId.length == 32 &&
  st.packetCommit.length == 4 &&
  st.publicNullifier.length == 4 &&
  st.outputNoteLeaf.length == 4 &&
  st.withdrawalHash.length == 32 &&
  st.transactionContextHash.length == 32 &&
  st.preState.profileId == st.profileId &&
  st.postState.profileId == st.profileId &&
  kindActiveOk st &&
  stateTransitionOk st.kind st.preState st.postState &&
  w.packetBytes.length == 552 &&
  packetBindsStatement st w.packetBytes &&
  packetCommitOk st.packetCommit w.packetBytes &&
  -- deposit/transfer require 128-byte record present in packet (may be nonzero);
  -- withdrawal record region must be zero
  (match st.kind with
   | .withdrawal => isZeroBytes128 (w.packetBytes.drop 360 |>.take 128)
   | _ => (w.packetBytes.drop 360 |>.take 128).length == 128)

/-- Convenience: build honest statement+witness from logical fields + record.
    (Named productWithCommit — `seal` is a Lean keyword.) -/
def productWithCommit (st0 : ProductStatement) (rec : List UInt8) : ProductStatement × ProductWitness :=
  let pkt := encodePacket st0 rec
  let commit := computePacketCommit pkt
  let st := { st0 with packetCommit := commit }
  (st, { packetBytes := pkt, encryptedRecord :=
    if rec.length == 128 then rec else List.replicate 128 0 })

/-!
  ## Synthetic KAT fixtures
-/
def demoProfileId : List UInt8 := List.replicate 32 0xaa
def demoInstanceId : List UInt8 := List.replicate 32 0xbb
def demoTxCtx : List UInt8 := List.replicate 32 0xcc
def demoNoteRoot1 : List F := [1, 2, 3, 4]
def demoNoteRoot2 : List F := [5, 6, 7, 8]
def demoNfRoot1 : List F := [9, 10, 11, 12]
def demoNfRoot2 : List F := [13, 14, 15, 16]
def demoLeaf : List F := [21, 22, 23, 24]
def demoNullifier : List F := [31, 32, 33, 34]
def demoWithdrawHash : List UInt8 := List.replicate 32 0xdd
def demoRecord : List UInt8 := List.replicate 128 0xee

def genesisSks3 (maxLive : Nat := 32) : Sks3 where
  profileId := demoProfileId
  noteRoot := zeroGDig32
  nullifierRoot := zeroGDig32
  noteCount := 0
  nullifierCount := 0
  maximumLiveNotes := maxLive
  reserveSats := 0
  actionSequence := 0

def afterDeposit : Sks3 where
  profileId := demoProfileId
  noteRoot := demoNoteRoot1
  nullifierRoot := zeroGDig32
  noteCount := 1
  nullifierCount := 0
  maximumLiveNotes := 32
  reserveSats := DENOMINATION_SATS
  actionSequence := 1

def afterTransfer : Sks3 where
  profileId := demoProfileId
  noteRoot := demoNoteRoot2
  nullifierRoot := demoNfRoot1
  noteCount := 2
  nullifierCount := 1
  maximumLiveNotes := 32
  reserveSats := DENOMINATION_SATS
  actionSequence := 2

def afterWithdrawal : Sks3 where
  profileId := demoProfileId
  noteRoot := demoNoteRoot2
  nullifierRoot := demoNfRoot2
  noteCount := 2
  nullifierCount := 2
  maximumLiveNotes := 32
  reserveSats := 0
  actionSequence := 3

def honestDeposit : ProductStatement × ProductWitness :=
  productWithCommit {
    networkId := 2
    kind := .deposit
    profileId := demoProfileId
    instanceId := demoInstanceId
    packetCommit := zeroGDig32  -- filled by seal
    preState := genesisSks3
    postState := afterDeposit
    publicNullifier := zeroGDig32
    outputNoteLeaf := demoLeaf
    withdrawalHash := List.replicate 32 0
    transactionContextHash := demoTxCtx
  } demoRecord

def honestTransfer : ProductStatement × ProductWitness :=
  productWithCommit {
    networkId := 2
    kind := .transfer
    profileId := demoProfileId
    instanceId := demoInstanceId
    packetCommit := zeroGDig32
    preState := afterDeposit
    postState := afterTransfer
    publicNullifier := demoNullifier
    outputNoteLeaf := demoLeaf
    withdrawalHash := List.replicate 32 0
    transactionContextHash := demoTxCtx
  } demoRecord

def honestWithdrawal : ProductStatement × ProductWitness :=
  productWithCommit {
    networkId := 2
    kind := .withdrawal
    profileId := demoProfileId
    instanceId := demoInstanceId
    packetCommit := zeroGDig32
    preState := afterTransfer
    postState := afterWithdrawal
    publicNullifier := demoNullifier
    outputNoteLeaf := zeroGDig32
    withdrawalHash := demoWithdrawHash
    transactionContextHash := demoTxCtx
  } (List.replicate 128 0)

/-!
  ## Mutation suite — each must reject under verifyProductAir
-/
structure MutationCase where
  name : String
  stmt : ProductStatement
  wit : ProductWitness
  deriving Repr

def mutWrongKind : MutationCase :=
  let (st, w) := honestDeposit
  { name := "wrong_kind"
    stmt := { st with kind := .transfer }  -- deposit packet claimed as transfer
    wit := w }

def mutWrongRoots : MutationCase :=
  let (st, w) := honestTransfer
  -- post note root equals pre → fails "roots change on transfer"
  { name := "wrong_roots"
    stmt := { st with postState := { st.postState with noteRoot := st.preState.noteRoot } }
    wit := w }

def mutNonzeroInactive : MutationCase :=
  let (st, w) := honestDeposit
  { name := "nonzero_inactive_nullifier"
    stmt := { st with publicNullifier := demoNullifier }
    wit := w }

def mutPacketCommitMismatch : MutationCase :=
  let (st, w) := honestDeposit
  { name := "packet_commit_mismatch"
    stmt := { st with packetCommit := [9, 9, 9, 9] }
    wit := w }

def mutWrongSequence : MutationCase :=
  let (st, w) := honestDeposit
  { name := "wrong_sequence"
    stmt := { st with postState := { st.postState with actionSequence := 99 } }
    wit := w }

def mutCapacityOverflow : MutationCase :=
  let pre := { genesisSks3 with
    noteCount := 32, nullifierCount := 0
    reserveSats := 32 * DENOMINATION_SATS
    actionSequence := 32
    noteRoot := demoNoteRoot1 }
  let post := { pre with
    noteCount := 33
    noteRoot := demoNoteRoot2
    reserveSats := 33 * DENOMINATION_SATS
    actionSequence := 33
    maximumLiveNotes := 32 }
  -- Build without seal so we can force capacity-breaking transition
  let st0 : ProductStatement := {
    networkId := 2
    kind := .deposit
    profileId := demoProfileId
    instanceId := demoInstanceId
    packetCommit := zeroGDig32
    preState := pre
    postState := post
    publicNullifier := zeroGDig32
    outputNoteLeaf := demoLeaf
    withdrawalHash := List.replicate 32 0
    transactionContextHash := demoTxCtx
  }
  let (st, w) := productWithCommit st0 demoRecord
  { name := "capacity_overflow", stmt := st, wit := w }

def allMutations : List MutationCase :=
  [ mutWrongKind
  , mutWrongRoots
  , mutNonzeroInactive
  , mutPacketCommitMismatch
  , mutWrongSequence
  , mutCapacityOverflow ]

/-- True iff every mutation is rejected. -/
def mutationsAllRejected : Bool :=
  allMutations.all (fun m => !(verifyProductAir m.stmt m.wit))

/-- True iff all three honest kinds accept. -/
def honestAllAccepted : Bool :=
  let (sd, wd) := honestDeposit
  let (st, wt) := honestTransfer
  let (sw, ww) := honestWithdrawal
  verifyProductAir sd wd &&
  verifyProductAir st wt &&
  verifyProductAir sw ww

/-- Encode StatementFE public boundary from product statement (field counts). -/
def toStatementFE (st : ProductStatement) : StatementFE where
  packetCommit := st.packetCommit
  preState := sks3ToWordsStruct st.preState
  postState := sks3ToWordsStruct st.postState
  publicNullifier := st.publicNullifier
  outputNoteLeaf := st.outputNoteLeaf
  withdrawalHash := hashBytesToFE st.withdrawalHash

/-- Mutation rejects for DiffStatement compatibility: altered FE flatten must differ. -/
def rootsEqual (a b : List F) : Bool := a == b

def mutationRejected (honest mut_ : StatementFE) : Bool :=
  !(rootsEqual honest.flatten mut_.flatten)

#guard mutationRejected encodeDemo { encodeDemo with packetCommit := [9, 9, 9, 9] }

end FriStark.AIR.ProductV1
