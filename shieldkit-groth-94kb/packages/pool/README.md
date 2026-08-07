# `@shieldkit/pool`

Local pool state: public tip reconstruction, private note storage, settlement-log replay, and the durable V2 store.

## Public API

Only the package export-map entrypoints below are supported.

### `@shieldkit/pool`

- Public tip: `PUBLIC_TIP_SCHEMA`, `TipRebuildError`, `emptyPublicTip`, `publicTipEventFromPacket`, `rebuildPublicTip`, `rebuildPublicTipFromHistory`, `rebuildPublicTipFromRawTransactions`, `publicTipToWitnessForest`, `decodeTipNftFields`
- Note wallet: `NOTE_WALLET_SCHEMA`, `NOTE_WALLET_BACKUP_SCHEMA`, `NoteWalletError`, `createNoteWallet`, `importEncryptedNoteWallet`, `ownedNoteFromOpenMeta`
- Action merge and sync: `mergeTipForestForAct`, `assertNoGlobalOpenSetGate`, `syncTipForestFromSettlementLog`
- Settlement log: `SettlementLogFetchError`, `fetchSettlementLogFromTip`, `settlementLogLooksComplete`, `applySettlementLog`

### `@shieldkit/pool/v2`

`openExistingV2DirectStore`, `openV2DirectStore`, `V2DirectStore`, `V2StoreError`, `V2_OPERATION_STATES`

## Boundary

The root API reconstructs local views from caller-supplied chain data. The V2 entrypoint provides local SQLite durability; it is not a covenant, scanner, network gate, or qualification result. Node.js 22.5 or later is required.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../README.md) and [product model](../../../docs/product/model.md).
