/**
 * Network config + mainnet refuse-by-default gates.
 * Pure functions — no I/O.
 *
 * Default network: chipnet. Mainnet is the same path with `network: 'mainnet'`
 * (or CLI `--network mainnet`). Broadcast on mainnet still requires
 * `--i-understand-mainnet`; development-only pins also need
 * `--allow-development-on-mainnet`. Unaudited WIP until ceremony + release gates.
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

/** Product status banner for user-facing flows. Toolkit version is separate (see version.mjs). */
export const PRODUCT_STATUS = Object.freeze({
  status: 'Unaudited — Work In Progress',
  maturityLabel: 'evidence experiment',
  defaultNetwork: 'chipnet',
  mainnet: 'implemented for lab qualification; no production-qualified profile exists',
  note: 'Toolkit semver ≠ profileId ≠ instanceId ≠ production/privacy qualification',
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
    // SCAR wire byte for current development pin is still 2 (circuit hardcode).
    // BCH mainnet is selected by `name` / RPC / CashAddr — not by a distinct SCAR id yet.
    networkId: 2,
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
  if (setupMode !== 'production-qualified' && !opts.allowDevelopmentOnMainnet) {
    fail(
      'UNQUALIFIED_PROFILE_ON_MAINNET',
      `${setupMode} profile refused on mainnet; no production-qualified profile exists. `
        + 'Use Chipnet, or the explicit lab-only --allow-development-on-mainnet override',
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
    if (setupMode !== 'production-qualified') {
      warnings.push(
        `MAINNET + ${setupMode}: refused unless the explicit lab-only --allow-development-on-mainnet override is supplied.`,
      );
    }
  }
  if ((opts.setupMode ?? 'development-only') !== 'production-qualified' && network !== 'mainnet') {
    warnings.push(`${opts.setupMode ?? 'development-only'} setup is not production privacy qualification.`);
  }
  return Object.freeze(warnings);
}
