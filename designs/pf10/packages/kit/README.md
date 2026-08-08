# `@shieldkit/kit`

Application composition, network policy, capacity helpers, chain transports, and the V2 action lifecycle.

## Public API

Only the package export-map entrypoints below are supported.

### `@shieldkit/kit`

- Facade: `createKit`, `KitError`
- Instance: `loadInstance`, `instanceToKitConfig`, `CHIPNET_PLAYGROUND_ID`, `InstanceError`
- Network: `resolveNetwork`, `NETWORKS`, `PRODUCT_STATUS`, `productWarnings`, `AppKitNetworkError`, `assertBroadcastAllowed`, `explorerTxUrl`, `defaultNetworkName`
- Capacity: `DENOMINATION_SATS`, `DEFAULT_MAX_NOTES`, `resolvePoolCapacity`, `capacityFromReserveCap`, `capacitySummary`
- Chain: `createChainRpc`, `createChipnetRpc`, `createLayer1BchnChipnetRpc`, `assertLayer1BchnChipnetRpc`, `LAYER1_BCHN_CHIPNET_BACKEND`, `PUBLIC_CHIPNET_ELECTRUM`, `PUBLIC_MAINNET_ELECTRUM`, `CHIPNET_GENESIS_HASH`, `MAINNET_GENESIS_HASH`, `discoverStateTip`

### Direct entrypoints

- `@shieldkit/kit/kit.mjs`: `createKit`, `KitError`, plus every export from `@shieldkit/kit/network.mjs`
- `@shieldkit/kit/network.mjs`: `resolveNetwork`, `NETWORKS`, `PRODUCT_STATUS`, `productWarnings`, `AppKitNetworkError`, `assertBroadcastAllowed`, `explorerTxUrl`, `defaultNetworkName`
- `@shieldkit/kit/chipnet-rpc.mjs`: `BCHN_CHIPNET_BACKEND`, `CHIPNET_GENESIS_HASH`, `LAYER1_BCHN_CHIPNET_BACKEND`, `MAINNET_GENESIS_HASH`, `PUBLIC_CHIPNET_ELECTRUM`, `PUBLIC_CHIPNET_ELECTRUM_METHODS`, `PUBLIC_MAINNET_ELECTRUM`, `assertBchnChipnetRpc`, `assertChipnetProductRpc`, `assertLayer1BchnChipnetRpc`, `createChainRpc`, `createChipnetRpc`, `createLayer1BchnChipnetRpc`, `createPublicChipnetFulcrumRpc`, `electrumScriptHash`, `isBchnChipnetBackend`, `isChipnetProductBackend`, `observeBchnChipnetRpc`, `observeChipnetProductRpc`, `observeLayer1BchnChipnetRpc`; test hooks: `createLayer1BchnChipnetRpcForTest`, `createPublicChipnetFulcrumRpcForTest`, `openPublicElectrumSessionForTest`
- `@shieldkit/kit/v2`: `createV2BetaChipnetActionLifecycle`, `createV2DirectActionLifecycle`, `createV2ChipnetChainClient`, `recoverPool`, `inspectV2OperationProofRecord`, `inspectV2BetaChipnetOperationProofRecord`, `V2ActionLifecycleError`, `V2ActionLifecycleCrash`, `V2ChainClientError`, `V2RecoverPoolError`, `V2_ACTION_LIFECYCLE_SCHEMA`, `V2_OPERATION_PROOF_RECORD_SCHEMA`, `V2_BETA_OPERATION_PROOF_RECORD_SCHEMA`, `V2_BETA_CHIPNET_ACTION_ACKNOWLEDGEMENT`, `V2_ACTION_PREFLIGHT_SCHEMA`, `V2_HIGH_FEE_SIGNING_CONFIRMATION_SCHEMA`, `V2_HIGH_FEE_SIGNING_ACKNOWLEDGEMENT`

## Boundary

`createKit` is callback-driven; chain transports are separate, opt-in Node entrypoints. Mainnet gates are safety controls, not a mainnet qualification claim.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../../README.md) and [product model](../../../../docs/product/model.md).
