# `@shieldkit/recover`

Portable recipient records and deterministic note recovery from authenticated action history.

## Public API

`@shieldkit/recover` is the only supported entrypoint.

- Recipient: `deriveRecipientWallet`, `deriveRecipientAddress`, `constructRecipientOutput`, `recoverRecipientOutput`
- History: `recoverAuthenticatedChainHistory`, aliased as `recoverAuthenticatedHistory`
- Serialization: `serializeChainHistoryActions`, aliased as `serializeHistoryActions`

## Boundary

This package performs no chain, indexer, storage, or network I/O. The caller must authenticate BCH provenance, ordering, and both state anchors before recovery.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../../README.md) and [product model](../../../../docs/product/model.md).
