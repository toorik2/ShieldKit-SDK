# ShieldKit Protocol V2 Direct — Binary Layouts

Status: implementation reference for the currently checked-in V2 Direct codecs.
It records byte layouts and local validation boundaries; it is not an on-chain
qualification claim. In particular, the BCH covenants and BCH-VM execution path
described in the implementation plan are not implemented or VM-qualified here.

## Shared rules

- Network IDs are one byte: mainnet is `1`, Chipnet is `2`.
- `profileId`, `instanceId`, SHA-256 digests, and transaction-context hashes use
  raw hash byte order. They are displayed as lowercase hexadecimal without a
  byte reversal.
- A CashToken category used as `instanceId` is in token-prefix/wire byte order.
  Explorer transaction-ID display order is a UI-only conversion and must never
  enter state, packet, address, or context bytes.
- A canonical BN254 scalar is a 32-byte unsigned big-endian integer strictly
  less than
  `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
  Zero is canonical. Codec APIs represent such values as exactly 64 lowercase
  hexadecimal characters.
- Unsigned integer fields marked `le` are fixed-width little-endian. There are
  no varints in these layouts.
- Reserved flags are encoded as zero and decoding rejects any nonzero value.

## `SKS2`: native state-NFT commitment (128 bytes)

The 128 bytes are the complete state commitment, not a preimage of another
state hash. `instanceId` is deliberately absent: it is the mutable state NFT
category, carried in the enclosing CashToken prefix.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SKS2` |
| 4 | 32 | `profileId` | raw SHA-256 bytes |
| 36 | 32 | `noteRoot` | canonical BN254 Fr, big-endian |
| 68 | 32 | `nullifierRoot` | canonical BN254 Fr, big-endian |
| 100 | 4 | `noteCount` | `u32le` |
| 104 | 4 | `nullifierCount` | `u32le` |
| 108 | 4 | `maximumLiveNotes` | `u32le` |
| 112 | 8 | `reserveSats` | `u64le` |
| 120 | 8 | `actionSequence` | `u64le` |
| 128 | 0 | end | exactly 128 bytes |

The codec rejects wrong length or magic, noncanonical roots, non-canonical
decimal API inputs, unknown object keys, and any failure of these invariants:

```text
nullifierCount <= noteCount
liveNoteCount = noteCount - nullifierCount
reserveSats = liveNoteCount * denominationSats
1 <= maximumLiveNotes <= floor(MAX_MONEY_SATS / denominationSats)
liveNoteCount <= maximumLiveNotes
max(noteCount, nullifierCount) <= actionSequence <= noteCount + nullifierCount
noteCount <= 0xffffffff
nullifierCount <= 0xfffffffe
actionSequence < 2^33
```

`denominationSats` is an explicit, profile-pinned codec context; it is not
serialized into `SKS2`.

## `SDA2`: action packet (552 bytes)

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SDA2` |
| 4 | 1 | `networkId` | `1` or `2` |
| 5 | 1 | action kind | deposit=`1`, transfer=`2`, withdrawal=`3` |
| 6 | 2 | flags | `u16le(0)` |
| 8 | 32 | `instanceId` | token-prefix category byte order |
| 40 | 128 | `preState` | complete `SKS2` bytes |
| 168 | 128 | `postState` | complete `SKS2` bytes |
| 296 | 32 | `publicNullifier` | canonical BN254 Fr, big-endian |
| 328 | 32 | `outputNoteLeaf` | canonical BN254 Fr, big-endian |
| 360 | 128 | `encryptedRecord` | exact encrypted-record bytes |
| 488 | 32 | `withdrawalLockingBytecodeHash` | raw SHA-256 bytes |
| 520 | 32 | `transactionContextHash` | raw SHA-256 bytes |
| 552 | 0 | end | exactly 552 bytes |

Kind-specific inactive fields are canonical zeroes:

| Kind | `publicNullifier` | `outputNoteLeaf` / `encryptedRecord` | withdrawal hash |
|---|---|---|---|
| Deposit | zero | active | zero |
| Transfer | active | active | zero |
| Withdrawal | active | zero / all 128 bytes zero | active |

An active field may still equal zero if that is its valid derived value. The
codec also requires equal pre/post `profileId` and `maximumLiveNotes`. It does
not by itself know the source and successor CashToken categories: the intended
binding covenant must compare both categories to `packet.instanceId`.

The complete 552-byte packet is hashed without a prefix:

```text
digest = SHA256(SDA2 bytes)
publicInput0 = OS2IP_BE(digest[0..15])
publicInput1 = OS2IP_BE(digest[16..31])
```

Both limbs are unsigned 128-bit big-endian values. No digest truncation,
modular reduction, or alternate packet hash is permitted.

## `SKA2`: binary recipient address (168 bytes)

`SKA2` is a binary codec. A future user-facing text/checksum wrapper must not
give the fields a second binary meaning.

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SKA2` |
| 4 | 1 | `networkId` | `1` or `2` |
| 5 | 3 | flags | all zero |
| 8 | 32 | `profileId` | raw SHA-256 bytes |
| 40 | 32 | `instanceId` | token-prefix category byte order |
| 72 | 32 | spend public key `S` | canonical compressed BabyJub point |
| 104 | 32 | incoming-view public key `V` | canonical compressed BabyJub point |
| 136 | 32 | `authority` | canonical BN254 Fr, big-endian |
| 168 | 0 | end | exactly 168 bytes |

The checked-in address validation rejects an unsupported schema/network,
noncanonical or non-subgroup points, and an `authority` that does not equal the
domain-separated Poseidon binding of `profileId`, `instanceId`, `S`, and `V`.

## `SDC2`: transaction-context preimage

The context is an unambiguous variable-length preimage. Its SHA-256 digest is
the packet's `transactionContextHash`. The exact header is 100 bytes; each
ordered input is 116 bytes; each ordered output is 76 bytes.

### Header (100 bytes)

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SDC2` |
| 4 | 1 | `networkId` | `1` or `2` |
| 5 | 1 | action kind | same codes as `SDA2` |
| 6 | 2 | flags | `u16le(0)` |
| 8 | 32 | `profileId` | raw SHA-256 bytes |
| 40 | 32 | `instanceId` | token-prefix category byte order |
| 72 | 4 | transaction version | `u32le` |
| 76 | 4 | locktime | `u32le` |
| 80 | 2 | input count | `u16le` |
| 82 | 2 | output count | `u16le` |
| 84 | 8 | pre-action sequence | `u64le` |
| 92 | 8 | post-action sequence | `u64le` |

The context codec requires nonempty `u16`-sized input/output lists and
`postActionSequence = preActionSequence + 1`.

### Input record (116 bytes, in transaction input order)

```text
role code u8 || verifier ordinal u8 || zero flags u16le ||
outpoint transaction hash in BCH wire byte order[32] ||
outpoint index u32le || input sequence u32le || source value u64le ||
SHA256(source locking bytecode)[32] ||
SHA256(exact source token prefix, or empty bytes)[32]
```

### Output record (76 bytes, in transaction output order)

```text
role code u8 || verifier ordinal u8 || zero flags u16le ||
value u64le || SHA256(locking bytecode)[32] ||
SHA256(exact token prefix, or empty bytes)[32]
```

Role codes are verifier=`1`, binding=`2`, state=`3`, funding=`4`,
withdrawal=`5`, change=`6`. Only verifier roles may have a nonzero ordinal.
The optional local topology validator checks counts, ordered roles, and which
roles are tokenless for a supplied carrier count. This context excludes every
unlocking bytecode, proof, packet, signature, and the current transaction ID.

## Enforcement map and present boundary

| Rule | Local codecs/model | Circuit relation | BCH covenant / VM |
|---|---|---|---|
| lengths, magic, offsets, endianness, zero flags, canonical fields | implemented in JS and independent TypeScript codecs | packet/state fields are represented in the relation | development-only structural covenant sources exist; no final lock or VM qualification |
| `SKS2` arithmetic invariants and packet inactive-zero rules | implemented | state/action constraints are implemented in the checked-in circuit sources | development-only structural covenant sources exist; no final lock or VM qualification |
| note ownership, Merkle membership, output construction, nullifier insertion | witness/model code validates inputs | implemented as circuit constraints | must be bound to a final transaction; no VM qualification |
| exact `SDA2` digest and two public limbs | implemented, including independent TS SHA-256 | two public inputs are implemented | development-only carrier/binding sources exist; no final lock or VM qualification |
| state NFT category, mutable capability, zero fungible amount, exact source/successor bundle and BCH role topology | context can locally encode/check a proposed topology | outside the proof relation except committed packet values | development-only structural covenant sources exist; no final lock or VM qualification |

Do not treat a passing local codec, circuit-model test, or TypeScript/JavaScript
parity result as a proof setup, covenant audit, BCH-VM acceptance test, or
production qualification.
