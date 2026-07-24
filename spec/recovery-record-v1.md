# Recipient addresses and recovery records v1 (invalidated historical draft)

Status: **INVALIDATED.** This was the pre-V2 X25519/HKDF/ChaCha20-Poly1305
draft. It is retained only to explain why old vectors, manifests, and Chipnet
research evidence cannot qualify the current relation. It MUST NOT be used to
construct an address, record, witness, profile, setup, genesis, or deployment.
The active G1 candidate is [recovery-record-v2.md](recovery-record-v2.md).

The old circuit did not prove the X25519 or AEAD construction described below;
therefore its byte-bound record was not a context-bound recovery construction.
No `recipient-address/v1` or `shielded-action-v1` material is compatible with
the current V2 relation. This historical text makes no deployment, privacy,
proof, BCH-VM, relay, or Chipnet claim.

## 1. Scope and constants

This draft defines local wallet derivation, a public recipient-address object,
and the fixed 192-byte active-output recovery record already bound as bytes by
the G1 relation. It applies to the fixed 0.1 BCH denomination and Chipnet
network discriminator `2` used by the current candidate.

`profileId` and `instanceId` are canonical lowercase 32-byte hexadecimal
strings, without a `sha256:` prefix. `ak`, `rho`, `r`, and `cm` are canonical,
nonzero, 32-byte big-endian BN254 scalar-field encodings. Every API object in
this draft rejects missing and unknown properties.

The historical V1 circuit bound record bytes only. It did not verify X25519,
HKDF, or AEAD. A wallet MUST decrypt and recompute every field below before it
accepts a discovered note.

## 2. Wallet derivation and public address

Given a private 32-byte seed `S`, `profileId` `P`, and `instanceId` `I`, derive
the one account-static V1 recipient keypair:

```
sk = 1 + OS2IP(SHA256("shield.cash/wallet-spend/v1\\0" || S || P || I)) mod (Fr - 1)
rk = SHA256("shield.cash/wallet-recovery-x25519/v1\\0" || S || P || I)
ak = Poseidon(1001, limbs(P), limbs(I), sk)
R  = X25519Public(rk)
```

The public recipient address object is exactly:

```
{
  schema: "shield.cash/recipient-address/v1",
  profileId: P,
  instanceId: I,
  ak: ak,
  recoveryPublicKey: R
}
```

It MUST NOT contain `S`, `sk`, `rk`, or any scan secret. The address's profile
and instance binding prevents cross-profile or cross-instance output
construction. V1 has exactly one recipient address per `(S,P,I)`, so recovery
from seed, profile, instance, and chain history requires no address-gap scan.
A multi-address hierarchy is outside this V1 profile and requires a new address
version and profile definition.

### 2.1 SDK account-seed boundary

The SDK recovery input named `accountSeed` is exactly the `S` in this section.
It is not a standardized root seed, account index, derivation path, or address
gap-scan interface. A wallet that has a master seed and derives several account
seeds MUST reproduce and retain its own versioned derivation policy, then run
this V1 recovery procedure once for each resulting account seed. The SDK MUST
NOT guess child paths or silently scan a multiple-address hierarchy.

The current `fresh-witness-inputs` development fixture derives two independent
test account seeds as `SHA256("shield.cash/fresh-witness-wallet/deposit/v1\\0"
|| rootSeed)` and `SHA256("shield.cash/fresh-witness-wallet/transfer/v1\\0" ||
rootSeed)`. Those exact domains are fixture-local inputs for a deterministic
relation witness; they are not a V1 wallet root hierarchy, deployed derivation
standard, or recovery promise. Standardizing root-to-account derivation, or
allowing more than one recipient address for one account seed/profile/instance,
requires a new address version and profile.

## 3. Sender output construction

For an active `deposit` or `transfer` output, a sender needs only the public
address and randomness. It samples canonical nonzero `rho` and `r` by rejection
sampling CSPRNG 32-byte values below `Fr`, then calculates:

```
cm = Poseidon(1002, limbs(P), limbs(I), 10000000, ak, rho, r)
```

The sender-local output witness material is exactly `{ak, rho, r, cm}`. A
sender MUST NOT require or derive a recipient spend secret to construct it.
Only `cm` is serialized in the action packet; `ak`, `rho`, and `r` are private
witness material and are not chain output fields. Test-only deterministic RNG
injection is permitted only through an explicit `bytes(length)` interface;
ordinary operation MUST use a CSPRNG and fail closed on RNG failure.

## 4. Exact 192-byte record

For action kind code `k` (`deposit=1`, `transfer=2`, `withdrawal=3`) and output
slot `s`, the record is:

| Offset | Length | Value |
| ---: | ---: | --- |
| 0 | 1 | version `1` |
| 1 | 1 | output slot `s` |
| 2 | 32 | ephemeral X25519 public key `E` |
| 34 | 12 | nonce `N` |
| 46 | 16 | Poly1305 tag `T` |
| 62 | 128 | ciphertext `C` |
| 190 | 2 | zero padding `00 00` |

The sender samples a fresh X25519 private input `e` and nonce `N` from the same
CSPRNG interface, computes `E = X25519Public(e)` and `Z = X25519(e, R)`, and
uses:

```
A = "shield.cash/recovery-record/v1\\0SCAR" || 01 || 02 || k || 00 || s || P || I || cm
K = HKDF-SHA-256(ikm=Z, salt=P, info=A, length=32)
M = P || I || rho || r
(C, T) = ChaCha20-Poly1305-Seal(K, N, A, M)
```

`M` and `C` are exactly 128 bytes. The two padding bytes MUST be zero; any
version, slot, record length, AEAD, or padding mismatch is rejected.

`withdrawal` has no active recipient output in the current action shape and
therefore carries the all-zero inactive record; output construction MUST reject
an attempt to construct a withdrawal recipient record.

## 5. Recipient recovery

From seed, `P`, and `I`, the recipient derives `(sk,rk,ak)`, reads only the
serialized packet `outputCommitment` and 192-byte record, then opens the record
with `X25519(rk,E)` and the exact AAD containing `outputCommitment`. It MUST
reject unless all of the following hold:

1. the tag verifies and `M` contains the expected `P` and `I`;
2. decoded `rho` and `r` are canonical nonzero field values;
3. `Poseidon(1002, limbs(P), limbs(I), 10000000, ak, rho, r)` equals the
   serialized `outputCommitment`; and
4. `deriveNote(P,I,sk,rho,r)` has the same `ak` and `outputCommitment`.

Failure at any step produces no accepted note. The resulting note may be used
only after the separate chain/state/membership checks required by the protocol.

## 6. Portable authenticated packet-history reconstruction

The portable SDK exposes `recoverAuthenticatedChainHistory` for local
reconstruction from caller-supplied action-packet bytes. Its exact input is one
V1 `accountSeed`, `P`, `I`, and an `authenticated history` with three byte
strings/collections:

- `initialState`: the exact 192 serialized pre-state bytes;
- `packets`: contiguous, ordered, exact 752-byte action packets; and
- `terminalState`: the exact 192 serialized terminal-state bytes.

For applications already holding decoded action fields, `packets` may instead
be `actions`; each action has every serialized field with no defaults and is
encoded to the same canonical 752-byte packet before recovery. The SDK also
exposes this strict conversion separately as `serializeChainHistoryActions`.
The caller MUST authenticate BCH provenance, packet order, and both state
anchors before calling this API. The API verifies packet syntax, profile and
instance binding, state continuity, action counters, duplicate packets, the
terminal anchor, encrypted-record ownership, derived commitments, and owned
nullifier matches. It returns each owned note with its append index, creation
sequence, and either `null` or the sequence where its nullifier was spent.

The current action shape has one active output in slot `0`; `withdrawal` has no
active output. An unauthenticated record-opening failure is ignored as a record
for another recipient; malformed packet bytes, conflicting owned commitment or
nullifier use, sequence discontinuity, or anchor mismatch fails closed.

This helper does not fetch BCH blocks, authenticate a node response, establish
raw-node synchronization, detect or roll back reorgs, prove archive/pruning
availability, demonstrate a 10,000-transition history, or constitute an
independent implementation. Those remain G5 requirements.
