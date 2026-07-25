/**
 * Network config + mainnet refuse-by-default gates.
 * Pure functions — no I/O.
 *
 * Mainnet is one config change (`network: 'mainnet'`) but remains
 * **Unaudited — Work In Progress** until ceremony + release gates say otherwise.
 */

export class AppKitNetworkError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AppKitNetworkError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new AppKitNetworkError(code, message);
};

/** Product status banner for user-facing flows. */
export const PRODUCT_STATUS = Object.freeze({
  status: 'Unaudited — Work In Progress',
  defaultNetwork: 'chipnet',
  mainnet: 'config-ready; not release-qualified; not production privacy by default',
});

/** @typedef {'chipnet' | 'mainnet'} NetworkName */

/**
 * Canonical network table. Golden path must use this — no Chipnet-only hardcodes elsewhere.
 * networkId matches shielded-action network field used in live Chipnet (2).
 */
export const NETWORKS = Object.freeze({
  chipnet: Object.freeze({
    name: 'chipnet',
    networkId: 2,
    cashAddrPrefix: 'bchtest',
    explorerTxTemplate: 'https://chipnet.chaingraph.cash/tx/{txid}',
    default: true,
  }),
  mainnet: Object.freeze({
    name: 'mainnet',
    networkId: 1,
    cashAddrPrefix: 'bitcoincash',
    explorerTxTemplate: 'https://explorer.bitcoinunlimited.info/tx/{txid}',
    default: false,
  }),
});

/**
 * @param {string} [name]
 * @returns {typeof NETWORKS.chipnet}
 */
export function resolveNetwork(name = 'chipnet') {
  if (typeof name !== 'string' || !NETWORKS[name]) {
    fail('UNKNOWN_NETWORK', `network must be one of: ${Object.keys(NETWORKS).join(', ')}`);
  }
  return NETWORKS[name];
}

/**
 * @param {string} networkName
 * @param {string} txid
 */
export function explorerTxUrl(networkName, txid) {
  const net = resolveNetwork(networkName);
  if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/i.test(txid)) {
    fail('MALFORMED_TXID', 'txid must be 32-byte hex');
  }
  return net.explorerTxTemplate.replace('{txid}', txid.toLowerCase());
}

/**
 * Gate any broadcast / sendraw path.
 *
 * @param {object} opts
 * @param {string} opts.network - chipnet | mainnet
 * @param {string} [opts.setupMode] - profile setup.mode (e.g. development-only)
 * @param {boolean} [opts.mainnetAcknowledged] - --i-understand-mainnet
 * @param {boolean} [opts.allowDevelopmentOnMainnet] - lab override only
 */
export function assertBroadcastAllowed(opts) {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) {
    fail('INVALID_OBJECT', 'assertBroadcastAllowed input must be an object');
  }
  const network = resolveNetwork(opts.network ?? 'chipnet');
  if (network.name === 'chipnet') return Object.freeze({ ok: true, network: network.name });

  // mainnet
  if (!opts.mainnetAcknowledged) {
    fail(
      'MAINNET_ACK_REQUIRED',
      'mainnet broadcast refused: pass mainnetAcknowledged / --i-understand-mainnet',
    );
  }
  const setupMode = opts.setupMode ?? 'development-only';
  if (setupMode === 'development-only' && !opts.allowDevelopmentOnMainnet) {
    fail(
      'DEVELOPMENT_PROFILE_ON_MAINNET',
      'development-only profile refused on mainnet (not production privacy); '
        + 'ceremony-backed profile + new genesis required, or lab --allow-development-on-mainnet',
    );
  }
  return Object.freeze({ ok: true, network: 'mainnet', setupMode, lab: Boolean(opts.allowDevelopmentOnMainnet) });
}

/** Default network name for apps that omit config. */
export function defaultNetworkName() {
  return 'chipnet';
}

/**
 * User-facing warnings for the selected network / setup mode.
 * Always include product WIP status; escalate on mainnet.
 *
 * @param {{ network?: string, setupMode?: string }} opts
 * @returns {readonly string[]}
 */
export function productWarnings(opts = {}) {
  const warnings = [
    PRODUCT_STATUS.status,
    'ShieldKit is offline-first; you supply keys, proofs, RPC, and broadcast.',
  ];
  const network = opts.network ?? defaultNetworkName();
  if (network === 'mainnet') {
    warnings.push(
      'MAINNET: Unaudited — Work In Progress. One config change (network=mainnet) enables the path; it is not a production release.',
      'MAINNET: Broadcast still requires --i-understand-mainnet / mainnetAcknowledged.',
    );
    const setupMode = opts.setupMode ?? 'development-only';
    if (setupMode === 'development-only') {
      warnings.push(
        'MAINNET + development-only: not production privacy; ceremony-production profile + new genesis required for production claims (or lab --allow-development-on-mainnet).',
      );
    } else if (setupMode === 'ceremony-production') {
      warnings.push(
        'MAINNET + ceremony-production: syntactic/ceremony packaging is not automatic G9/release qualification.',
      );
    }
  }
  if ((opts.setupMode ?? 'development-only') === 'development-only' && network !== 'mainnet') {
    warnings.push('development-only setup is not multi-party ceremony and not production privacy.');
  }
  return Object.freeze(warnings);
}
