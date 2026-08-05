# V2 STARK — Public statement ABI

**Status:** normative. Exactly one statement schema for product proofs.

## Design choice (frozen)

- STARK public statement is **Poseidon2-native**.
- Full **SDA3 packet bytes** remain private witness material for the AIR and are re-bound by the **binding covenant** on chain.
- There is **no** dual path that uses SHA-256 packet limbs as STARK publics (that is the Groth16 V2 Direct ABI).

## Statement object

Schema id: `shieldkit-v2-stark-statement-v1`

| Field | Type | Meaning |
|-------|------|---------|
| `schema` | string | exact schema id |
| `networkId` | u8 | 1 or 2 |
| `kind` | u8 | 1 deposit / 2 transfer / 3 withdrawal |
| `profileId` | bytes32 | pool profile |
| `instanceId` | bytes32 | state token category |
| `packetCommit` | GDig32 | Poseidon2 sponge commitment to full SDA3 |
| `preState` | SKS3 (128B) | exact pre-state |
| `postState` | SKS3 (128B) | exact post-state |
| `publicNullifier` | GDig32 | zero if inactive |
| `outputNoteLeaf` | GDig32 | zero if inactive |
| `withdrawalLockingBytecodeHash` | bytes32 | zero if inactive |
| `transactionContextHash` | bytes32 | binds settlement tx skeleton |
| `friParamId` | bytes32 | production FRI pin |
| `airId` | bytes32 | constraint system pin |

Canonical JSON encoding for hashing uses RFC 8785 with bytes as lowercase hex strings of fixed length.

```text
statementId = SHA256( "SKSTMT1" || RFC8785(statement) )
```

## AIR public boundary

The STARK verifier’s public inputs are exactly the field-element encoding of:

1. `packetCommit` (4 FE)
2. `preState` word packing (16 FE from 128 bytes under the same `w < P` rule)
3. `postState` word packing (16 FE)
4. `publicNullifier` (4 FE)
5. `outputNoteLeaf` (4 FE)
6. `withdrawalLockingBytecodeHash` as 4 FE (BE u64 words &lt; P — hashes are 32B; packing uses four BE u64; if a word ≥ P, AIR uses a fixed split into 4×56-bit limbs documented in AIR pin — **product freeze:** store the 32-byte hash in statement as bytes; AIR absorbs as four FE via **right-pad 7-byte chunks**: see below)

### Hash-bytes → FE (for SHA-256 fields)

For any raw 32-byte cryptographic hash `H` appearing in the statement:

```text
for i in 0..4:
  limb_i = BE_u64( 0x00 || H[7*i : 7*i+7] )   # 56-bit, always < P
```

Four limbs encode 28 bytes; remaining 4 bytes of H:

```text
limb_4 = BE_u64( 0x00000000 || H[28:32] )
```

Five limbs total for each 32-byte hash. Domain-separated absorb in AIR when reconstructing `statementId` components. Codecs and AIR must share this rule (KAT-enforced).

GDig32 fields use the native 4×8-byte FE packing (CRYPTO).

## What the proof asserts

Given public statement S and private witness W:

1. `S.packetCommit` equals Poseidon2 sponge of the full 552-byte packet in W.
2. Packet magic `SDA3`, network, kind, flags, instanceId match S.
3. Packet pre/post state bytes equal S.preState / S.postState.
4. Kind-active field rules hold; inactive fields are zero.
5. State transition from pre→post matches kind (counts, roots, reserve, sequence, capacity).
6. Note tree depth-32 membership/append proofs hold for spend/output as required by kind.
7. Nullifier tree depth-32 insert proofs hold when kind spends.
8. EC-free note cryptography holds (CRYPTO_EC_FREE.md).
9. `S.transactionContextHash` equals the hash of the context message fixed by the settlement skeleton (bound again by binding covenant).
10. `S.friParamId` / `S.airId` match the proof system pin.

## On-chain binding (product)

Settlement transaction includes:

| Role | Responsibility |
|------|----------------|
| FRI verifier inputs | Check STARK proof for statement S |
| Binding input | Recompute packetCommit from packet in unlock/witness; compare to S; equate instance/pre/post/nullifier/leaf/withdrawal/tx-context with state NFT and outputs |
| State input | Enforce SKS3 transition and token fields against transparent value conservation |
| Funding input | Wallet P2PKH fee |

The FRI layer alone does not know about CashTokens; **binding + state** are mandatory product roles. Omitting them is a prohibited topology.

## Compatibility

Groth16 V2 Direct public inputs (`publicInput0/1` SHA-256 limbs) are **not** accepted by this profile.
