/**
 * @shieldkit/action — PF10 / V2 Direct product surface.
 * Legacy seven-carrier prep/assembly lives under designs/pf10/research/v1-seven-carrier/.
 */

export { encodeActionPacket, decodeActionPacket, DENOMINATION_SATS } from './packet.mjs';
export { encodeSettlementContext, INPUT_ROLES } from './context.mjs';
export { encodeStateNftCommitment } from './state.mjs';
export {
  NETWORK_MAINNET,
  NETWORK_CHIPNET,
  networkIdFromName,
  networkNameFromId,
  isSupportedNetworkId,
} from './network.mjs';
