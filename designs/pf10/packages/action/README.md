# `@shieldkit/action`

Wire codecs and settlement-context primitives used by ShieldKit-Groth.

## Public API

Only the package export-map entrypoints below are supported.

### `@shieldkit/action`

- Packet: `encodeActionPacket`, `decodeActionPacket`, `DENOMINATION_SATS`
- Settlement: `encodeSettlementContext`, `INPUT_ROLES`
- State: `encodeStateNftCommitment`
- Network: `NETWORK_MAINNET`, `NETWORK_CHIPNET`, `networkIdFromName`, `networkNameFromId`, `isSupportedNetworkId`

### `@shieldkit/action/v2`

- State: `encodePoolStateV2`, `decodePoolStateV2`
- Packet: `encodeActionPacketV2`, `decodeActionPacketV2`

## Boundary

This package encodes and decodes data; it does not plan, prove, sign, verify, or broadcast an action. The unsuffixed and V2 codecs are distinct contracts and must not be interchanged.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../../README.md) and [product model](../../../../docs/product/model.md).
