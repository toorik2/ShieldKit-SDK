/** V2 Direct protocol constants (IMPLEMENTATION_PLAN.md). */

export const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DENOMINATION_SATS = 10_000_000n;
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;

export const NOTE_TREE_DEPTH = 32;
export const NULLIFIER_TREE_DEPTH = 32;

export const POOL_STATE_BYTES = 128;
export const ACTION_PACKET_BYTES = 552;
export const ENCRYPTED_RECORD_BYTES = 128;

export const STATE_MAGIC = Buffer.from('SKS2', 'ascii');
export const PACKET_MAGIC = Buffer.from('SDA2', 'ascii');

export const NETWORK_MAINNET = 1;
export const NETWORK_CHIPNET = 2;
export const SUPPORTED_NETWORK_IDS = Object.freeze(new Set([NETWORK_MAINNET, NETWORK_CHIPNET]));

export const ACTION_KIND = Object.freeze({
  deposit: 1,
  transfer: 2,
  withdrawal: 3,
});

export const ACTION_KIND_BY_CODE = Object.freeze({
  1: 'deposit',
  2: 'transfer',
  3: 'withdrawal',
});

/** Domain tags as canonical Fr integers (V2 Direct — distinct from legacy G1). */
export const DOMAIN = Object.freeze({
  ADDRESS: 2004n,
  RHO: 2005n,
  NOTE: 2002n,
  NULLIFIER: 2003n,
  NOTE_LEAF: 2010n,
  NOTE_NODE: 2011n,
  NOTE_EMPTY: 2012n,
  NULLIFIER_LEAF: 2020n,
  NULLIFIER_NODE: 2021n,
  NULLIFIER_EMPTY: 2022n,
  RECORD: 2030n,
  TX_CONTEXT: 2040n,
});

/** Indexed-nullifier leaf type tags (conceptual). */
export const NF_LEAF_TYPE = Object.freeze({
  empty: 0n,
  minSentinel: 1n,
  normal: 2n,
  maxSentinel: 3n,
});

export const ZERO_32_HEX = '0'.repeat(64);
export const ZERO_32 = Buffer.alloc(32);

export const RELATION_ID = 'pool-action-v2-direct';
export const PUBLIC_INPUT_ABI_ID = 'pool-action-v2-direct-public-input-v1';
export const STATE_ENCODING_VERSION = 'sks2-v1';
export const PACKET_ENCODING_VERSION = 'sda2-v1';

/**
 * Resource envelopes for V2 Direct.
 *
 * USER DIRECTIVE (2026-07-28): ignore plan soft caps (tx ≤90kB, unlock ≤9500B,
 * VM ≤90%). Product / foundation / carrier selection use **full BCH VM power**.
 * Hard ceiling = network standardness (consensus/standard limits), never the
 * historical research soft targets. Soft fields below are measurement-only and
 * MUST NOT reject candidates or fail gates.
 */
export const LIMITS = Object.freeze({
  /** Historical plan soft targets — measure/report only; never reject. */
  planSoftMaxTransactionBytes: 90_000,
  planSoftMaxUnlockBytes: 9_500,
  planSoftMaxVmResourceFraction: 0.9,
  /** Product / foundation selection: full VM power (network headroom). */
  maxTransactionBytes: 1_000_000,
  maxUnlockBytes: 100_000,
  maxVmResourceFraction: 1.0,
  defaultFeeRateSatPerByte: 1n,
  feeConfirmThresholdSatPerByte: 10n,
  maxAutoConflicts: 3,
  reorgUndoBlocks: 100,
});

export const PLAYGROUND_MAXIMUM_LIVE_NOTES = 32;
export const GENERAL_MAXIMUM_LIVE_NOTES = 210_000_000;

export function isSupportedNetworkId(networkId) {
  return SUPPORTED_NETWORK_IDS.has(networkId);
}
