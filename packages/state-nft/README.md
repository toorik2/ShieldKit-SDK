# `@shield.cash/state-nft`

Strict codec for the 80-byte mutable state-NFT commitment:

```
SHST || u8(1) || u8(2) || u16le(0) ||
instanceId[32] || stateCommitment[32] || u64le(actionSequence)
```

The commitment is below the profile's 120-byte project gate and the BCH-2026
128-byte consensus limit. Token category, mutable capability, zero fungible
amount, source/successor value, and locking-bytecode preservation are enforced
by the settlement builder and state covenant, not this codec.
