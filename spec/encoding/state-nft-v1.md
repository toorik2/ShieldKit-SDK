# State NFT commitment v1

Status: candidate encoding; frozen only with the complete G2 profile

The sole mutable pool-state NFT uses an exact 80-byte commitment:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `SHST` |
| 4 | 1 | version `1` |
| 5 | 1 | network `2` (Chipnet candidate discriminator) |
| 6 | 2 | reserved zero |
| 8 | 32 | profile identifier |
| 40 | 32 | BN254 state commitment |
| 72 | 8 | action sequence, unsigned little-endian |

The source token commitment encodes the action packet's pre-state commitment
and sequence. Output 0 encodes its post-state commitment and sequence. The
category is unchanged, capability is mutable, fungible amount is zero, locking
bytecode is unchanged, and actual BCH value is `S + reserve`, where `S` is one
immutable profile-fixed state-carrier value.
