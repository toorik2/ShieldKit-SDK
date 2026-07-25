# Action packet v1

Status: candidate encoding; frozen only with the complete G2 profile

The action packet is exactly 752 bytes. All fixed-width integers below are
unsigned little-endian. Hashes and BN254 field encodings are raw 32-byte
big-endian values.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `SCAR` |
| 4 | 1 | version `1` |
| 5 | 1 | network `2` (Chipnet candidate discriminator) |
| 6 | 1 | action: deposit `1`, transfer `2`, withdrawal `3` |
| 7 | 1 | reserved zero |
| 8 | 192 | pre-state |
| 200 | 192 | post-state |
| 392 | 32 | consumed note commitment or zero |
| 424 | 32 | consumed nullifier or zero |
| 456 | 32 | created note commitment or zero |
| 488 | 192 | encrypted output record or zero |
| 680 | 8 | public boundary amount |
| 688 | 32 | SHA-256 of withdrawal locking bytecode or zero |
| 720 | 32 | transaction-context digest |

Each state is:

| Relative offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 32 | profile identifier |
| 32 | 32 | instance identifier |
| 64 | 32 | note-tree root |
| 96 | 32 | nullifier-tree root |
| 128 | 4 | next leaf index |
| 132 | 8 | action sequence |
| 140 | 4 | live note count |
| 144 | 8 | reserve satoshis |
| 152 | 8 | immutable maximum reserve |
| 160 | 32 | state commitment |

The profile identifier, instance identifier, and maximum reserve must be equal
in both states. Deposit has zero consumed commitment/nullifier, a nonzero
created commitment, a 10,000,000-satoshi boundary amount, and a zero withdrawal
hash. Transfer has nonzero consumed and created fields with zero boundary and
withdrawal fields. Withdrawal has nonzero consumed fields, zero created record
fields, a 10,000,000-satoshi boundary amount, and a nonzero withdrawal hash.

The verifier public inputs are exactly:

```
digest = SHA256(packet)
in0 = unsigned_big_endian_u128(digest[0..15])
in1 = unsigned_big_endian_u128(digest[16..31])
```

No double-SHA-256, field reduction, truncation beyond the exact halves, padded
carrier, alternate push encoding, or additional public input is permitted.
