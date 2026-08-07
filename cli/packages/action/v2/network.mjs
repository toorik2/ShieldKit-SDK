export const DIRECT_V2_NETWORK_MAINNET = 1;
export const DIRECT_V2_NETWORK_CHIPNET = 2;

export const DIRECT_V2_NETWORKS = Object.freeze({
  mainnet: DIRECT_V2_NETWORK_MAINNET,
  chipnet: DIRECT_V2_NETWORK_CHIPNET,
});

export function isSupportedDirectV2NetworkId(value) {
  return value === DIRECT_V2_NETWORK_MAINNET || value === DIRECT_V2_NETWORK_CHIPNET;
}

export function directV2NetworkIdFromName(value) {
  if (!Object.hasOwn(DIRECT_V2_NETWORKS, value)) {
    throw new Error('V2 network name must be mainnet or chipnet');
  }
  return DIRECT_V2_NETWORKS[value];
}

export function directV2NetworkNameFromId(value) {
  if (value === DIRECT_V2_NETWORK_MAINNET) return 'mainnet';
  if (value === DIRECT_V2_NETWORK_CHIPNET) return 'chipnet';
  throw new Error('V2 network ID is unsupported');
}
