/**
 * Primary ShieldKit facade (createKit only).
 * No private keys, no sockets, no persistence, no automatic broadcast.
 * Desktop composition loads lazily; product entry is createKit.
 */
import {
  AppKitNetworkError,
  assertBroadcastAllowed,
  defaultNetworkName,
  explorerTxUrl,
  resolveNetwork,
  NETWORKS,
  PRODUCT_STATUS,
  productWarnings,
} from './network.mjs';

export {
  AppKitNetworkError,
  assertBroadcastAllowed,
  defaultNetworkName,
  explorerTxUrl,
  resolveNetwork,
  NETWORKS,
  PRODUCT_STATUS,
  productWarnings,
};

export class KitError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'KitError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new KitError(code, message);
};

/**
 * @param {object} config
 * @param {string} [config.network]
 * @param {string} config.bundleDirectory
 * @param {object} config.expectedProfile
 * @param {boolean} [config.mainnetAcknowledged]
 * @param {boolean} [config.allowDevelopmentOnMainnet]
 * @param {(hex: string) => Promise<string>|string} [config.broadcast]
 */
export async function createKit(config) {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    fail('INVALID_CONFIG', 'createKit config must be an object');
  }
  const networkName = config.network ?? defaultNetworkName();
  const network = resolveNetwork(networkName);

  if (typeof config.bundleDirectory !== 'string' || !config.bundleDirectory) {
    fail('BUNDLE_REQUIRED', 'bundleDirectory is required');
  }
  if (!config.expectedProfile || typeof config.expectedProfile !== 'object') {
    fail('PROFILE_REQUIRED', 'expectedProfile is required');
  }

  const expected = {
    network: config.expectedProfile.network ?? network.name,
    profileId: config.expectedProfile.profileId,
    instanceId: config.expectedProfile.instanceId,
  };
  if (typeof expected.network === 'string' && expected.network !== network.name) {
    fail(
      'NETWORK_MISMATCH',
      `expectedProfile.network (${expected.network}) !== config.network (${network.name})`,
    );
  }

  const { createDesktopComposition } = await import('./desktop.mjs');
  const desktop = await createDesktopComposition({
    bundleDirectory: config.bundleDirectory,
    expectedProfile: expected,
  });

  if (
    network.name === 'mainnet'
    && desktop.profile.setupMode === 'development-only'
    && !config.allowDevelopmentOnMainnet
  ) {
    throw new AppKitNetworkError(
      'DEVELOPMENT_PROFILE_ON_MAINNET',
      'development-only profile refused on mainnet (not production privacy); '
        + 'ceremony-backed profile + new genesis required, or lab --allow-development-on-mainnet',
    );
  }

  const flags = Object.freeze({
    mainnetAcknowledged: Boolean(config.mainnetAcknowledged),
    allowDevelopmentOnMainnet: Boolean(config.allowDevelopmentOnMainnet),
  });

  const warnings = productWarnings({
    network: network.name,
    setupMode: desktop.profile.setupMode,
  });

  return Object.freeze({
    schema: 'shieldkit/kit/v1',
    productStatus: PRODUCT_STATUS,
    warnings,
    network,
    profile: desktop.profile,
    qualification: desktop.qualification,
    flags,
    assertCanBroadcast() {
      return assertBroadcastAllowed({
        network: network.name,
        setupMode: desktop.profile.setupMode,
        mainnetAcknowledged: flags.mainnetAcknowledged,
        allowDevelopmentOnMainnet: flags.allowDevelopmentOnMainnet,
      });
    },
    explorerTxUrl(txid) {
      return explorerTxUrl(network.name, txid);
    },
    async broadcastRaw(hex) {
      this.assertCanBroadcast();
      if (typeof config.broadcast !== 'function') {
        fail('BROADCAST_CALLBACK_REQUIRED', 'config.broadcast callback not provided');
      }
      if (typeof hex !== 'string' || !/^[0-9a-fA-F]+$/.test(hex)) {
        fail('MALFORMED_HEX', 'raw transaction hex required');
      }
      return config.broadcast(hex);
    },
    /** Plan deposit/transfer/withdraw preparation (offline). Requires funding request object. */
    planAction: desktop.planCompletePreparation.bind(desktop),
    planCompletePreparation: desktop.planCompletePreparation.bind(desktop),
    preparationSigningRequest: desktop.preparationSigningRequest.bind(desktop),
    finalizeCompletePreparation: desktop.finalizeCompletePreparation.bind(desktop),
    planWitnessBoundSettlements: desktop.planWitnessBoundSettlements.bind(desktop),
    deriveRecipientAddress: desktop.deriveRecipientAddress.bind(desktop),
    constructRecipientOutput: desktop.constructRecipientOutput.bind(desktop),
    recoverChainOutput: desktop.recoverChainOutput.bind(desktop),
    recoverAuthenticatedHistory: desktop.recoverAuthenticatedHistory.bind(desktop),
    serializeHistoryActions: desktop.serializeHistoryActions.bind(desktop),
    requireLocalProver: desktop.requireLocalProver,
  });
}
