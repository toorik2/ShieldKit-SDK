# Recipient addresses and recovery records v2

Status: G1 candidate implementation specification. This document defines the
current recovery construction used by `shielded-action-v2`; it is not a G2
freeze, profile, setup, proof, BCH-VM, relay, privacy, or Chipnet claim.

## 1. Compatibility boundary

The relation identity is `shielded-action-v2`. Its public-input ABI remains
`shielded-action-public-input-v1`: exactly two ordered field inputs formed from
the two big-endian `u128` halves of `SHA256` over the unchanged 752-byte `SCAR`
action-packet v1. The packet's version byte remains `1`. V2 changes the
private relation, recipient-address schema, and 192-byte record semantics; it
does not reinterpret or extend the packet's byte layout.

`profileId` `P` and `instanceId` `I` are lowercase 32-byte hexadecimal
strings without `sha256:`. `ak`, `rho`, `r`, `cm`, and `nf` are canonical,
nonzero 32-byte big-endian BN254 scalar-field encodings for an active note.
`c_rho`, `c_r`, and the authenticator are canonical field encodings and MAY be
zero. Let `Fr` be the BN254 scalar field, `L` the BabyJubJub prime subgroup
order, and `B` circomlib's `BabyPbk` base point. A compressed point is the
canonical 32-byte little-endian-y, high-bit-x-sign encoding accepted by
circomlib `Bits2Point_Strict`. It MUST decode to a nonidentity on-curve point
in the prime subgroup.

Every API object defined here rejects absent or unknown properties. All scalar
derivations and sender randomness use rejection sampling or the stated modular
map and fail closed when the local CSPRNG is unavailable or malformed.

## 2. Wallet derivation and public address

Given a private 32-byte account seed `S`, `P`, and `I`, derive independent
nonzero subgroup scalars:

```
sk = 1 + OS2IP(SHA256("shield.cash/wallet-spend/v2\\0" || S || P || I)) mod (L - 1)
rk = 1 + OS2IP(SHA256("shield.cash/wallet-recovery/v2\\0" || S || P || I)) mod (L - 1)
SP = [sk]B
RP = [rk]B
ak = Poseidon(1004, P_hi, P_lo, I_hi, I_lo, SP.x, SP.y, RP.x, RP.y)
```

`P_hi`, `P_lo`, `I_hi`, and `I_lo` are the big-endian `u128` halves of the
identifier bytes. `sk` and `rk` are distinct derivations, although equality
for a particular seed is not a security assumption. A public address is
exactly:

```
{
  schema: "shield.cash/recipient-address/v2",
  profileId: P,
  instanceId: I,
  ak: ak,
  spendPublicKey: encode(SP),
  recoveryPublicKey: encode(RP)
}
```

The address MUST NOT contain `S`, `sk`, or `rk`. A constructor validates both
points and recomputes `ak`; it rejects any point substitution. There is exactly
one address per `(S,P,I)` in this candidate. A wallet with a master seed owns
its separate versioned master-to-account policy and supplies each resulting
account seed explicitly; this protocol does not define an account path or a
gap scan.

## 3. Note authority

For a deposit or transfer, the sender samples canonical nonzero `rho` and `r`
in `Fr` and derives:

```
cm = Poseidon(1002, P_hi, P_lo, I_hi, I_lo, 10000000, ak, rho, r)
nf = Poseidon(1003, P_hi, P_lo, I_hi, I_lo, sk, rho)
```

`nf` is recipient-private and is reconstructed only after record recovery.
The spend relation receives `sk` and `RP` privately, derives `SP = [sk]B`,
requires the exact `ak` formula above, and derives both `cm` and `nf`. It also
requires `0 < sk < L`; accepting `sk + L` would permit distinct nullifiers
for the same BabyJubJub public key.

## 4. Exact active 192-byte record

For action kind code `k` (`deposit=1`, `transfer=2`) and output slot `s=0`,
the active record is exactly:

| Offset | Length | Value |
| ---: | ---: | --- |
| 0 | 1 | version `2` |
| 1 | 1 | output slot `0` |
| 2 | 32 | canonical compressed ephemeral point `E=[e]B` |
| 34 | 32 | canonical field `c_rho` |
| 66 | 32 | canonical field `c_r` |
| 98 | 32 | canonical field authenticator `a` |
| 130 | 62 | all-zero padding |

The sender chooses `0 < e < L`, computes `E=[e]B` and `Z=[e]RP`, then computes
the following native-field masks:

```
q       = Poseidon(1101, RP.x, RP.y, E.x, E.y, Z.x, Z.y, cm, k)
m_rho   = Poseidon(1102, q, P_hi, P_lo, I_hi, I_lo)
m_r     = Poseidon(1103, q, P_hi, P_lo, I_hi, I_lo)
c_rho   = (rho + m_rho) mod Fr
c_r     = (r + m_r) mod Fr
a       = Poseidon(1104, q, c_rho, c_r, ak, P_hi, P_lo, I_hi, I_lo)
```

All field values are serialized big-endian; only compressed BabyJubJub points
use their named point encoding. The record contains neither `SP` nor `RP`.
Serializing either stable address point in every record would make receipts to
one address publicly linkable. A withdrawal has no recipient output and MUST
carry the all-zero inactive 192-byte record.

The V2 relation validates every active record component: version, slot, point
canonicality/curve/subgroup membership, `0 < e < L`, `E=[e]B`, `Z=[e]RP`, both
masks, ciphertext fields, authenticator, and zero padding. It requires every
withdrawal record bit to be zero. These checks are SHA-bound through the
unchanged action packet and hence through its two public Groth16 inputs.

## 5. Recipient recovery

From `S`, `P`, and `I`, the wallet derives `(sk,rk,SP,RP,ak)`. For an active
record it decodes `E`, computes `Z=[rk]E`, recomputes `q`, the masks and `a`,
then obtains:

```
rho = (c_rho - m_rho) mod Fr
r   = (c_r - m_r) mod Fr
```

It accepts only if every encoding is canonical, the authenticator matches,
`rho` and `r` are nonzero, and recomputed `ak`, `cm`, and `nf` agree with the
packet's commitment and local keys. An authentication failure is intentionally
indistinguishable from an unrelated recipient record. Recovery does not by
itself establish BCH provenance, state membership, confirmation, or
spendability; those are separate chain and state checks.

## 6. History and profile rules

`recoverAuthenticatedChainHistory` version 2 accepts caller-authenticated
contiguous packet bytes plus exact initial and terminal state anchors. It uses
the V2 recovery algorithm above, reconstructs owned notes and nullifier status,
and rejects malformed, duplicate, reordered, or truncated supplied history.
It never fetches a chain, trusts an indexer, stores secrets, or authenticates a
provider response.

No V1 record, address, setup, relation artifact, or profile is compatible with
this construction. A V2 setup or ceremony replacement changes profile and
genesis as required by the verifier-bundle lifecycle; it never hot-swaps an
existing instance.
