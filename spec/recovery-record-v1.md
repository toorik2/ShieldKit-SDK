# Recipient addresses and recovery records v1 (draft)

Status: G1 candidate implementation specification. This document does not
freeze a G2 profile, establish a deployed address format, or make a privacy,
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

The current G1 circuit binds record bytes only. It does not verify X25519,
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
