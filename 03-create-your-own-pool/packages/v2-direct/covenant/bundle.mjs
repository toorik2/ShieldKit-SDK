/**
 * Rolling settlement bundle topology for V2 Direct (self-funded, one-tx).
 *
 * Topology (N verifier carriers):
 * Inputs:  0..N-1 carriers, N binding, N+1 state NFT, N+2 wallet P2PKH funding
 * Outputs: 0 state NFT, 1..N carriers, N+1 binding, [withdrawal payout], change
 *
 * This module builds and validates the *shape* and value conservation.
 * Covenant locking bytecode is profile-pinned; foundation gate measures sizes.
 */
import { createHash } from 'node:crypto';
import {
  DENOMINATION_SATS,
  LIMITS,
  POOL_STATE_BYTES,
} from '../constants.mjs';
import { encodePoolStateV2 } from '../state.mjs';

export class BundleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BundleError';
  }
}

const fail = (m) => {
  throw new BundleError(m);
};

export const FUNDING_UTXO_REQUIRED = 'FUNDING_UTXO_REQUIRED';

/**
 * Plan a rolling action transaction skeleton (unsigned).
 */
export function planRollingAction({
  kind,
  carrierCount,
  preState,
  postState,
  instanceIdCategory, // 32-byte category hex (token category = instanceId)
  sourceOutpoints, // { state, carriers: [], binding } each { txid, vout, value }
  fundingUtxo, // { txid, vout, value, lockingBytecode }
  changeLockingBytecode,
  withdrawalLockingBytecode, // required for withdrawal
  feeRateSatPerByte = LIMITS.defaultFeeRateSatPerByte,
  stateBaseSats,
  carrierBaseSats,
  bindingBaseSats,
  estimatedTxBytes = 8_000,
}) {
  const N = carrierCount;
  if (!Number.isInteger(N) || N < 1) fail('carrierCount must be ≥ 1');
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) fail('invalid kind');
  if (!fundingUtxo) fail(FUNDING_UTXO_REQUIRED);

  const postReserve = BigInt(postState.reserveSats);
  const stateOutValue = BigInt(stateBaseSats) + postReserve;
  const carrierOutValue = BigInt(carrierBaseSats);
  const bindingOutValue = BigInt(bindingBaseSats);

  const outputs = [];
  // 0: state NFT
  outputs.push({
    role: 'state',
    value: stateOutValue,
    token: {
      category: instanceIdCategory,
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: encodePoolStateV2(postState),
      },
    },
  });
  // 1..N carriers
  for (let i = 0; i < N; i += 1) {
    outputs.push({
      role: `carrier:${i}`,
      value: carrierOutValue,
      token: undefined,
    });
  }
  // N+1 binding
  outputs.push({
    role: 'binding',
    value: bindingOutValue,
    token: undefined,
  });

  if (kind === 'withdrawal') {
    if (!withdrawalLockingBytecode) fail('withdrawal requires locking bytecode');
    outputs.push({
      role: 'withdrawal',
      value: DENOMINATION_SATS,
      lockingBytecode: withdrawalLockingBytecode,
      token: undefined,
    });
  }

  // Fee + change
  const fee = BigInt(estimatedTxBytes) * BigInt(feeRateSatPerByte);
  if (feeRateSatPerByte > LIMITS.feeConfirmThresholdSatPerByte) {
    // Caller must have confirmed; we only flag
  }

  const inputSum = BigInt(fundingUtxo.value)
    + BigInt(sourceOutpoints.state.value)
    + sourceOutpoints.carriers.reduce((a, c) => a + BigInt(c.value), 0n)
    + BigInt(sourceOutpoints.binding.value)
    + (kind === 'deposit' ? DENOMINATION_SATS : 0n);
  // Deposit: funding carries D+fee+change; state input already has pre reserve.
  // Simpler conservation: funding must cover fee + (post state base delta) + carrier/binding bases already in pool.
  // For self-funded model:
  // - deposit funding covers D + fee + change dust
  // - transfer/withdraw funding covers fee + change dust
  // - withdrawal adds D payout from pool reserve (already in state value transition)

  const nonChangeOut = outputs.reduce((a, o) => a + o.value, 0n);
  // Inputs: all rolling + funding (deposit value enters via funding only as sats)
  const rollingIn = BigInt(sourceOutpoints.state.value)
    + sourceOutpoints.carriers.reduce((a, c) => a + BigInt(c.value), 0n)
    + BigInt(sourceOutpoints.binding.value);
  const totalIn = rollingIn + BigInt(fundingUtxo.value);
  const changeValue = totalIn - nonChangeOut - fee;
  if (changeValue < 0n) fail(`${FUNDING_UTXO_REQUIRED}: insufficient funding for fee and outputs`);

  outputs.push({
    role: 'change',
    value: changeValue,
    lockingBytecode: changeLockingBytecode,
    token: undefined,
  });

  const plan = Object.freeze({
    kind,
    carrierCount: N,
    fee,
    feeRateSatPerByte: BigInt(feeRateSatPerByte),
    inputs: Object.freeze({
      carriers: sourceOutpoints.carriers,
      binding: sourceOutpoints.binding,
      state: sourceOutpoints.state,
      funding: fundingUtxo,
    }),
    outputs: Object.freeze(outputs.map((o) => Object.freeze({ ...o }))),
    limits: Object.freeze({
      maxTxBytes: LIMITS.maxTransactionBytes,
      maxUnlockBytes: LIMITS.maxUnlockBytes,
    }),
  });

  validatePlanSizes(plan, estimatedTxBytes);
  return plan;
}

export function validatePlanSizes(plan, estimatedTxBytes) {
  if (estimatedTxBytes > LIMITS.maxTransactionBytes) {
    fail(`transaction exceeds ${LIMITS.maxTransactionBytes} bytes`);
  }
}

/**
 * Carrier selection: among candidates under full-VM / network LIMITS, choose
 * smallest complete tx; ties by smallest max unlock, then lowest VM cost.
 * Plan soft caps (90kB / 9500B / 90% VM) are not selection criteria.
 */
export function selectCarrierCandidate(candidates) {
  const passing = candidates.filter((c) => (
    c.txBytes <= LIMITS.maxTransactionBytes
    && c.maxUnlockBytes <= LIMITS.maxUnlockBytes
    && c.vmResourceFraction <= LIMITS.maxVmResourceFraction
  ));
  if (passing.length === 0) return null;
  passing.sort((a, b) => {
    if (a.txBytes !== b.txBytes) return a.txBytes - b.txBytes;
    if (a.maxUnlockBytes !== b.maxUnlockBytes) return a.maxUnlockBytes - b.maxUnlockBytes;
    return a.vmCost - b.vmCost;
  });
  return passing[0];
}

/**
 * Transaction context hash domain (excludes unlocks, proof, packet, signature, txid).
 */
export function computeTransactionContextHash({
  networkId,
  profileId,
  instanceId,
  kind,
  version = 2,
  locktime = 0,
  inputRoles,
  outputRoles,
}) {
  const h = createHash('sha256');
  h.update('SKTX2');
  h.update(Buffer.from([networkId]));
  h.update(Buffer.from(profileId, 'hex'));
  h.update(Buffer.from(instanceId, 'hex'));
  h.update(Buffer.from(kind, 'utf8'));
  h.update(Buffer.from([version]));
  h.update(Buffer.alloc(4));
  // locktime u32le
  const lt = Buffer.alloc(4);
  lt.writeUInt32LE(locktime);
  h.update(lt);
  h.update(Buffer.from(JSON.stringify({ inputRoles, outputRoles }), 'utf8'));
  return h.digest();
}

/** Adversarial checks that must fail closed at assembly time. */
export function assertBundleSecurityInvariants({
  category,
  outputs,
  mintingAuthorityPresent = false,
  carrierCount,
}) {
  if (mintingAuthorityPresent) fail('minting authority must not remain');
  const stateOuts = outputs.filter((o) => o.role === 'state');
  if (stateOuts.length !== 1) fail('exactly one successor state NFT required');
  if (stateOuts[0].token?.commitment?.length !== POOL_STATE_BYTES) {
    fail('state commitment must be 128 bytes');
  }
  if (stateOuts[0].token?.category !== category) fail('state category mismatch');
  const carriers = outputs.filter((o) => String(o.role).startsWith('carrier:'));
  if (carriers.length !== carrierCount) fail('carrier successor count mismatch');
}
