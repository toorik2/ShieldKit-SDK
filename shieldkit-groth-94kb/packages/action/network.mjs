/**
 * SCAR wire network byte (packet + state NFT) vs BCH chain config.
 *
 * BCH network (`chipnet` | `mainnet`) is kit/RPC/CashAddr only — one config change.
 * The pinned g1_relation circuit **hardcodes network byte = 2** in the reconstructed
 * SCAR packet (g1_relation.circom). Until a new ceremony/pin, all proofs must use
 * PIN_SCAR_NETWORK_ID = 2 on both Chipnet and mainnet BCH.
 *
 * Future pins may set mainnet SCAR id = 1; do not assume id maps 1:1 to BCH network yet.
 */

export const NETWORK_MAINNET = 1; // reserved for future pin / docs alignment with kit/network.mjs
export const NETWORK_CHIPNET = 2;

/** Current development pin: circuit freezes SCAR network byte to 2. */
export const PIN_SCAR_NETWORK_ID = NETWORK_CHIPNET;

/** @type {ReadonlySet<number>} */
export const SUPPORTED_NETWORK_IDS = Object.freeze(new Set([PIN_SCAR_NETWORK_ID]));

/** @type {Readonly<Record<string, number>>} */
export const NETWORK_NAME_TO_ID = Object.freeze({
  // Both BCH networks use pin SCAR id until circuit recompile.
  mainnet: PIN_SCAR_NETWORK_ID,
  chipnet: PIN_SCAR_NETWORK_ID,
});

/** @type {Readonly<Record<number, string>>} */
export const NETWORK_ID_TO_NAME = Object.freeze({
  [PIN_SCAR_NETWORK_ID]: 'chipnet', // wire label only; BCH chain is separate
});

export function isSupportedNetworkId(networkId) {
  return SUPPORTED_NETWORK_IDS.has(networkId);
}

/**
 * @param {number} networkId
 * @param {(msg: string) => never} [fail]
 */
export function assertSupportedNetworkId(networkId, fail = (m) => { throw new Error(m); }) {
  if (!isSupportedNetworkId(networkId)) {
    fail(
      `unsupported SCAR networkId ${networkId} (pin requires ${PIN_SCAR_NETWORK_ID}; `
      + 'BCH mainnet uses the same wire id until a new circuit pin)',
    );
  }
  return networkId;
}

/**
 * @param {string} name BCH network name chipnet|mainnet
 * @param {(msg: string) => never} [fail]
 * @returns {number} SCAR wire networkId for current pin
 */
export function networkIdFromName(name, fail = (m) => { throw new Error(m); }) {
  if (typeof name !== 'string' || (name !== 'chipnet' && name !== 'mainnet')) {
    fail(`network name must be chipnet|mainnet, got ${name}`);
  }
  return PIN_SCAR_NETWORK_ID;
}

/**
 * @param {number} networkId
 * @returns {string}
 */
export function networkNameFromId(networkId) {
  assertSupportedNetworkId(networkId);
  return NETWORK_ID_TO_NAME[networkId];
}

/** @deprecated use NETWORK_CHIPNET / PIN_SCAR_NETWORK_ID */
export const CHIPNET_NETWORK_ID = NETWORK_CHIPNET;
