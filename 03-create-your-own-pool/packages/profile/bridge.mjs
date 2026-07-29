import {
  LegacyProfileCreationQuarantinedError,
  refuseLegacyProfileCreation,
} from './legacy.mjs';

/**
 * Historical V1 setup-to-profile bridge.
 *
 * V1 loading and inspection remain available, but creation is deliberately
 * disabled. The old bridge hard-pinned `shielded-action-v2`, which is a V1
 * legacy relation and must never be used as an alias for V2 Direct.
 */
export async function bridgeLocalSetupToProfile() {
  refuseLegacyProfileCreation('the historical setup-to-profile bridge');
}

export {
  LegacyProfileCreationQuarantinedError as SetupProfileBridgeError,
};
