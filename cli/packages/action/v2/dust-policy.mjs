import {
  encodeTransactionOutput,
} from '@bitauth/libauth';

export const BCHN_2026_DUST_RELAY_FEE_SATS_PER_KB = 1_000n;
export const BCHN_2026_DUST_MULTIPLIER = 3n;
export const BCHN_2026_DUST_SPEND_INPUT_BYTES = 148n;
export const V2_ROLLING_BASE_MINIMUM_SATS = 1_000n;
export const V2_ROLLING_BASE_ROUNDING_SATS = 100n;

export class DirectV2DustPolicyError extends Error {
  constructor(message, options = undefined) {
    super(message, options);
    this.name = 'DirectV2DustPolicyError';
  }
}

const fail = (message, options) => {
  throw new DirectV2DustPolicyError(message, options);
};

function canonicalOutput(value) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || !(value.lockingBytecode instanceof Uint8Array)
    || value.lockingBytecode.length === 0
    || value.lockingBytecode.length > 10_000
  ) {
    fail('dust-policy output must contain 1 through 10,000 locking bytes');
  }
  const output = {
    valueSatoshis: 0n,
    lockingBytecode: Uint8Array.from(value.lockingBytecode),
  };
  if (value.token !== undefined && value.token !== null) {
    output.token = value.token;
  }
  return output;
}

/**
 * BCHN 2026 GetDustThreshold for a spendable output at the pinned default
 * dust relay fee. The serialized output includes any CashTokens prefix and
 * NFT commitment.
 */
export function pinnedBchn2026DustThresholdSats(value) {
  let serializedBytes;
  try {
    serializedBytes = BigInt(
      encodeTransactionOutput(canonicalOutput(value)).length,
    );
  } catch (error) {
    fail(
      `dust-policy output cannot be serialized: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const virtualSpendBytes =
    serializedBytes + BCHN_2026_DUST_SPEND_INPUT_BYTES;
  const relayFee = (
    virtualSpendBytes * BCHN_2026_DUST_RELAY_FEE_SATS_PER_KB
  ) / 1_000n;
  return BCHN_2026_DUST_MULTIPLIER * relayFee;
}

export function roundUpV2RollingBaseSats(value) {
  if (typeof value !== 'bigint' || value < 0n) {
    fail('rolling base candidate must be a nonnegative bigint');
  }
  return (
    (value + V2_ROLLING_BASE_ROUNDING_SATS - 1n)
    / V2_ROLLING_BASE_ROUNDING_SATS
  ) * V2_ROLLING_BASE_ROUNDING_SATS;
}

/**
 * Protocol-required rolling base:
 * roundUpTo100(max(1000, 2 * pinnedBchnDustThreshold(finalOutput))).
 */
export function deriveV2RollingBaseSats(value) {
  const doubledDust = 2n * pinnedBchn2026DustThresholdSats(value);
  return roundUpV2RollingBaseSats(
    doubledDust > V2_ROLLING_BASE_MINIMUM_SATS
      ? doubledDust
      : V2_ROLLING_BASE_MINIMUM_SATS,
  );
}
