/**
 * Independent, secret-free post-command Chipnet-provider attestation for a public V2 beta
 * action projection. This deliberately uses a caller-supplied RPC capability
 * distinct from the CLI process that produced the result.
 */
import { createHash } from 'node:crypto';

import { CHIPNET_GENESIS_HASH, isChipnetProductBackend } from '../packages/kit/chipnet-rpc.mjs';
import { parseV2RawTransaction, parseSerializedSourceOutput } from '../packages/kit/v2/transaction-policy.mjs';

export const V2_BETA_LIVE_ACTION_CHAIN_ATTESTATION_SCHEMA =
  'shieldkit-v2-beta-live-action-chain-attestation-v1';

const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export class V2BetaLiveActionChainAttestationError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaLiveActionChainAttestationError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaLiveActionChainAttestationError(code, message, options);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('ACTION_CHAIN_ATTESTATION_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('ACTION_CHAIN_ATTESTATION_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function decimalSatoshis(value) {
  if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) {
    return value.valueSatoshis;
  }
  if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) {
    const satoshis = Math.round(value.value * 100_000_000);
    if (Number.isSafeInteger(satoshis) && satoshis / 100_000_000 === value.value) {
      return String(satoshis);
    }
  }
  fail('ACTION_CHAIN_ATTESTATION_STATE_INVALID', 'Chipnet provider state output has no exact safe satoshi value');
}

function actionIdentity(action, expectedInstanceId) {
  if (action === null || Array.isArray(action) || typeof action !== 'object'
    || !HASH.test(action.transactionId) || !HASH.test(expectedInstanceId)
    || !HASH.test(action?.readback?.rawTransactionSha256)
    || !HASH.test(action?.readback?.stateCategoryWire)
    || !HASH.test(action?.readback?.stateCommitmentSha256)
    || action?.readback?.stateOutpoint?.txid !== action.transactionId
    || action?.readback?.stateOutpoint?.vout !== 0) {
    fail('ACTION_CHAIN_ATTESTATION_INPUT_INVALID', 'public action projection or expected pool instance is malformed');
  }
  const expectedCategoryWire = Buffer.from(expectedInstanceId, 'hex').reverse().toString('hex');
  if (action.readback.stateCategoryWire !== expectedCategoryWire) {
    fail('ACTION_CHAIN_ATTESTATION_INPUT_INVALID', 'action projection is not bound to the planned pool instance');
  }
  return Object.freeze({ transactionId: action.transactionId, expectedCategoryWire });
}

/** Validate a persisted secret-free action attestation without a network call. */
export function inspectV2BetaLiveActionChainAttestation(attestation, {
  action,
  expectedInstanceId,
} = {}) {
  const identity = actionIdentity(action, expectedInstanceId);
  exact(attestation, [
    'backend', 'genesis', 'rawTransactionSha256', 'schema', 'stateCategoryWire',
    'stateCommitmentSha256', 'stateOutpoint', 'stateValueSatoshis',
    'transactionId',
  ], 'action chain attestation');
  exact(attestation.stateOutpoint, ['txid', 'vout'], 'action chain attestation state outpoint');
  if (attestation.schema !== V2_BETA_LIVE_ACTION_CHAIN_ATTESTATION_SCHEMA
    || !isChipnetProductBackend(attestation.backend)
    || attestation.genesis !== CHIPNET_GENESIS_HASH
    || attestation.transactionId !== identity.transactionId
    || attestation.rawTransactionSha256 !== action.readback.rawTransactionSha256
    || attestation.stateOutpoint.txid !== identity.transactionId
    || attestation.stateOutpoint.vout !== 0
    || attestation.stateCategoryWire !== identity.expectedCategoryWire
    || attestation.stateCommitmentSha256 !== action.readback.stateCommitmentSha256
    || typeof attestation.stateValueSatoshis !== 'string'
    || !DECIMAL.test(attestation.stateValueSatoshis)) {
    fail('ACTION_CHAIN_ATTESTATION_INVALID', 'persisted chain attestation differs from the public action projection');
  }
  return Object.freeze({
    schema: attestation.schema,
    backend: attestation.backend,
    genesis: attestation.genesis,
    transactionId: attestation.transactionId,
    rawTransactionSha256: attestation.rawTransactionSha256,
    stateOutpoint: Object.freeze({ ...attestation.stateOutpoint }),
    stateCategoryWire: attestation.stateCategoryWire,
    stateCommitmentSha256: attestation.stateCommitmentSha256,
    stateValueSatoshis: attestation.stateValueSatoshis,
  });
}

/** Query a separate Chipnet product capability and bind raw bytes and output 0 exactly. */
export async function attestV2BetaLiveActionChainReadback({ rpc, action, expectedInstanceId }) {
  if (rpc === null || typeof rpc !== 'object'
    || !isChipnetProductBackend(rpc.backend) || rpc.genesis !== CHIPNET_GENESIS_HASH
    || typeof rpc.getrawtransaction !== 'function' || typeof rpc.gettxout !== 'function') {
    fail('ACTION_CHAIN_ATTESTATION_RPC_REQUIRED', 'independent Chipnet provider raw/state read capability is required');
  }
  const identity = actionIdentity(action, expectedInstanceId);
  let rawValue;
  let state;
  try {
    [rawValue, state] = await Promise.all([
      rpc.getrawtransaction(identity.transactionId, true),
      rpc.gettxout(identity.transactionId, 0),
    ]);
  } catch (error) {
    fail('ACTION_CHAIN_ATTESTATION_READ_FAILED', 'independent Chipnet provider action readback failed', { cause: error });
  }
  const rawHex = typeof rawValue === 'string' ? rawValue : rawValue?.hex;
  const reportedTxid = typeof rawValue === 'object' && rawValue !== null
    ? rawValue.txid : identity.transactionId;
  if (reportedTxid !== identity.transactionId || typeof rawHex !== 'string') {
    fail('ACTION_CHAIN_ATTESTATION_RAW_INVALID', 'independent Chipnet provider raw response does not bind the action txid');
  }
  let transaction;
  let sourceOutput;
  try {
    transaction = parseV2RawTransaction(rawHex);
    sourceOutput = transaction.outputs[0] === undefined
      ? null : parseSerializedSourceOutput(transaction.outputs[0].serializedHex);
  } catch (error) {
    fail('ACTION_CHAIN_ATTESTATION_RAW_INVALID', 'independent Chipnet provider raw transaction is not the exact V2 action bytes', { cause: error });
  }
  const token = state?.tokenData ?? state?.token;
  const stateValueSatoshis = decimalSatoshis(state);
  if (transaction.txid !== identity.transactionId
    || sha256(Buffer.from(rawHex, 'hex')) !== action.readback.rawTransactionSha256
    || sourceOutput === null
    || sourceOutput.token?.categoryWire !== expectedInstanceId
    || sourceOutput.token?.amount !== '0'
    || sourceOutput.token?.nft?.capability !== 'mutable'
    || token?.category !== identity.expectedCategoryWire
    || String(token?.amount) !== '0'
    || token?.nft?.capability !== 'mutable'
    || typeof token?.nft?.commitment !== 'string'
    || !/^[0-9a-f]{256}$/u.test(token.nft.commitment)
    || sha256(Buffer.from(token.nft.commitment, 'hex')) !== action.readback.stateCommitmentSha256
    || sourceOutput.token.nft.commitmentHex !== token.nft.commitment
    || typeof state?.scriptPubKey?.hex !== 'string'
    || state.scriptPubKey.hex.toLowerCase() !== sourceOutput.lockingBytecodeHex
    || sourceOutput.valueSatoshis.toString() !== stateValueSatoshis) {
    fail('ACTION_CHAIN_ATTESTATION_STATE_INVALID', 'independent Chipnet provider raw/output-0 state differs from the action projection');
  }
  return inspectV2BetaLiveActionChainAttestation(Object.freeze({
    schema: V2_BETA_LIVE_ACTION_CHAIN_ATTESTATION_SCHEMA,
    backend: rpc.backend,
    genesis: rpc.genesis,
    transactionId: identity.transactionId,
    rawTransactionSha256: action.readback.rawTransactionSha256,
    stateOutpoint: Object.freeze({ txid: identity.transactionId, vout: 0 }),
    stateCategoryWire: identity.expectedCategoryWire,
    stateCommitmentSha256: action.readback.stateCommitmentSha256,
    stateValueSatoshis,
  }), { action, expectedInstanceId });
}
