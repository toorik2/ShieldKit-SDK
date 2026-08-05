/-
  Executable atomic-check verifier: re-runs shipped primitives only.
-/
import FriStark.Verify.Types
import FriStark.Hash.Merkle
import FriStark.FRI.Verify
import FriStark.Field.Ext
import FriStark.Field.Goldilocks
import FriStark.Params.V1
import FriStark.Transcript.FiatShamir

namespace FriStark.Verify.Executable

open FriStark.Verify.Types
open FriStark.Hash.Merkle
open FriStark.FRI.Verify
open FriStark.Field.Ext
open FriStark.Field.Goldilocks
open FriStark.Params.V1
open FriStark.Transcript.FiatShamir

def runCheck (c : AtomicCheck) : VerifyResult :=
  match c with
  | .merkleOpen root leaf index path =>
      if verify root leaf index path then .ok else .err "merkleOpen"
  | .merkleOpenDigest root leafDig path =>
      if verifyDigest root leafDig path then .ok else .err "merkleOpenDigest"
  | .friFold v0 v1 beta folded xpos =>
      if verifyFoldStep v0 v1 folded beta xpos then .ok else .err "friFold"
  | .fieldEq a b => if a % P == b % P then .ok else .err "fieldEq"
  | .extEq a b => if eq a b then .ok else .err "extEq"
  | .grindCheck state nonce bits =>
      if FriStark.Transcript.FiatShamir.grindOk state nonce bits then .ok else .err "grindCheck"
  | .natListEq a b => if a == b then .ok else .err "natListEq"
  | .natEq a b => if a == b then .ok else .err "natEq"
  | .bytesEq a b => if a == b then .ok else .err "bytesEq"

def verify (bundle : ProofBundle) : VerifyResult := Id.run do
  if bundle.eligibility == "product" then
    if bundle.blowup != BLOWUP || bundle.queries != QUERIES ||
       bundle.grindBits != GRIND_BITS || bundle.fold != FOLD then
      return .err "non-production params in product corpus"
  if bundle.checks.isEmpty then
    return .err "empty checks"
  for c in bundle.checks do
    match runCheck c with
    | .ok => pure ()
    | .err w => return .err w
  return .ok

def agreesWithOracle (bundle : ProofBundle) : Bool :=
  (verify bundle).isOk == bundle.accept

end FriStark.Verify.Executable
