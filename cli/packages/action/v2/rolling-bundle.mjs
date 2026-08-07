import { encodeTokenPrefix } from '@bitauth/libauth';

import { validateDirectV2RoleTopology } from './context.mjs';
import { isSupportedDirectV2NetworkId } from './network.mjs';
import {
  encodeStateNftCommitment,
  MAX_MONEY_SATS,
  validateStateNftCommitment,
} from './state.mjs';

export const DIRECT_V2_ROLLING_BUNDLE_MODEL_SCHEMA =
  'shieldkit-v2-direct-rolling-bundle-model-only-v1';

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_BYTECODE = 10_000;
const KINDS = new Set(['deposit', 'transfer', 'withdrawal']);
const INPUT_KEYS = Object.freeze([
  'lockingBytecode',
  'outpointIndex',
  'outpointTransactionHash',
  'role',
  'sequence',
  'token',
  'valueSats',
]);
const OUTPUT_KEYS = Object.freeze([
  'lockingBytecode',
  'role',
  'token',
  'valueSats',
]);

export class DirectV2RollingBundleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2RollingBundleError';
  }
}

const fail = (message) => {
  throw new DirectV2RollingBundleError(message);
};

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function uint(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function bytes(value, label) {
  if (
    !(value instanceof Uint8Array)
    || value.length === 0
    || value.length > MAX_BYTECODE
  ) {
    fail(`${label} must be a nonempty Uint8Array of at most ${MAX_BYTECODE} bytes`);
  }
  return Buffer.from(value);
}

function equalBytes(left, right) {
  return left.length === right.length && left.equals(right);
}

function p2pkh(value, label) {
  const lockingBytecode = bytes(value, label);
  if (
    lockingBytecode.length !== 25
    || lockingBytecode[0] !== 0x76
    || lockingBytecode[1] !== 0xa9
    || lockingBytecode[2] !== 0x14
    || lockingBytecode[23] !== 0x88
    || lockingBytecode[24] !== 0xac
  ) {
    fail(`${label} must be canonical P2PKH locking bytecode`);
  }
  return lockingBytecode;
}

function role(value, label) {
  exactKeys(value, label, ['kind', 'ordinal']);
  if (
    !['verifier', 'binding', 'state', 'funding', 'withdrawal', 'change']
      .includes(value.kind)
  ) {
    fail(`${label}.kind is unsupported`);
  }
  const ordinal = uint(value.ordinal, 0xffn, `${label}.ordinal`);
  if (value.kind !== 'verifier' && ordinal !== 0n) {
    fail(`${label}.ordinal must be zero for non-verifier roles`);
  }
  return Object.freeze({
    kind: value.kind,
    ordinal: ordinal.toString(),
  });
}

function token(value, label) {
  if (value === null) return null;
  exactKeys(value, label, ['amount', 'category', 'nft']);
  exactKeys(value.nft, `${label}.nft`, ['capability', 'commitment']);
  if (!(value.nft.commitment instanceof Uint8Array)) {
    fail(`${label}.nft.commitment must be a Uint8Array`);
  }
  return Object.freeze({
    category: identifier(value.category, `${label}.category`),
    amount: uint(value.amount, MAX_U64, `${label}.amount`).toString(),
    nft: Object.freeze({
      capability: value.nft.capability,
      commitment: Buffer.from(value.nft.commitment),
    }),
  });
}

function monetaryValue(value, label) {
  return uint(value, MAX_MONEY_SATS, label);
}

function stateToken(value, expectedCategory, expectedCommitment, label) {
  const parsed = token(value, label);
  if (parsed === null) fail(`${label} must contain the state NFT`);
  if (
    parsed.category !== expectedCategory
    || parsed.amount !== '0'
    || parsed.nft.capability !== 'mutable'
    || parsed.nft.commitment.length !== 128
    || !parsed.nft.commitment.equals(expectedCommitment)
  ) {
    fail(`${label} must be the unique mutable state NFT with exact commitment`);
  }
  return parsed;
}

function tokenPrefix(value) {
  if (value === null) return new Uint8Array();
  return Uint8Array.from(encodeTokenPrefix({
    // `value.category` is the protocol's token-prefix byte order. Libauth's
    // transaction model uses explorer/display order and reverses the category
    // while serializing, so reverse here to preserve the frozen V2 wire ABI.
    category: Uint8Array.from(Buffer.from(value.category, 'hex').reverse()),
    amount: BigInt(value.amount),
    nft: {
      capability: value.nft.capability,
      commitment: Uint8Array.from(value.nft.commitment),
    },
  }));
}

function input(value, index) {
  exactKeys(value, `input ${index}`, INPUT_KEYS);
  return Object.freeze({
    role: role(value.role, `input ${index}.role`),
    outpointTransactionHash: identifier(
      value.outpointTransactionHash,
      `input ${index}.outpointTransactionHash`,
    ),
    outpointIndex: uint(
      value.outpointIndex,
      MAX_U32,
      `input ${index}.outpointIndex`,
    ).toString(),
    sequence: uint(value.sequence, MAX_U32, `input ${index}.sequence`).toString(),
    valueSats: monetaryValue(
      value.valueSats,
      `input ${index}.valueSats`,
    ).toString(),
    lockingBytecode: bytes(value.lockingBytecode, `input ${index}.lockingBytecode`),
    token: token(value.token, `input ${index}.token`),
  });
}

function output(value, index) {
  exactKeys(value, `output ${index}`, OUTPUT_KEYS);
  return Object.freeze({
    role: role(value.role, `output ${index}.role`),
    valueSats: monetaryValue(
      value.valueSats,
      `output ${index}.valueSats`,
    ).toString(),
    lockingBytecode: bytes(value.lockingBytecode, `output ${index}.lockingBytecode`),
    token: token(value.token, `output ${index}.token`),
  });
}

function pin(value, index) {
  exactKeys(value, `pins.verifierCarriers[${index}]`, [
    'baseValueSats',
    'lockingBytecode',
  ]);
  const baseValue = monetaryValue(
    value.baseValueSats,
    `pins.verifierCarriers[${index}].baseValueSats`,
  );
  if (baseValue === 0n) fail('verifier carrier base values must be nonzero');
  return Object.freeze({
    baseValueSats: baseValue,
    lockingBytecode: bytes(
      value.lockingBytecode,
      `pins.verifierCarriers[${index}].lockingBytecode`,
    ),
  });
}

function normalizePins(value, carrierCount) {
  exactKeys(value, 'pins', [
    'bindingBaseSats',
    'bindingLockingBytecode',
    'previousBundleTransactionHash',
    'stateBaseSats',
    'stateLockingBytecode',
    'verifierCarriers',
  ]);
  if (
    !Array.isArray(value.verifierCarriers)
    || value.verifierCarriers.length !== carrierCount
  ) {
    fail('pins.verifierCarriers must contain exactly carrierCount entries');
  }
  const stateBaseSats = monetaryValue(
    value.stateBaseSats,
    'pins.stateBaseSats',
  );
  const bindingBaseSats = monetaryValue(
    value.bindingBaseSats,
    'pins.bindingBaseSats',
  );
  if (stateBaseSats === 0n || bindingBaseSats === 0n) {
    fail('state and binding base values must be nonzero');
  }
  return Object.freeze({
    previousBundleTransactionHash: identifier(
      value.previousBundleTransactionHash,
      'pins.previousBundleTransactionHash',
    ),
    stateBaseSats,
    stateLockingBytecode: bytes(
      value.stateLockingBytecode,
      'pins.stateLockingBytecode',
    ),
    bindingBaseSats,
    bindingLockingBytecode: bytes(
      value.bindingLockingBytecode,
      'pins.bindingLockingBytecode',
    ),
    verifierCarriers: Object.freeze(value.verifierCarriers.map(pin)),
  });
}

function assertRole(record, kind, ordinal, label) {
  if (record.role.kind !== kind || record.role.ordinal !== String(ordinal)) {
    fail(`${label} has the wrong canonical role`);
  }
}

function assertTokenless(record, label) {
  if (record.token !== null) fail(`${label} must be tokenless`);
}

function assertPinnedRecord(record, pinnedLock, pinnedValue, label) {
  if (
    !equalBytes(record.lockingBytecode, pinnedLock)
    || BigInt(record.valueSats) !== pinnedValue
  ) {
    fail(`${label} differs from its pinned lock or base value`);
  }
}

function contextRecord(record) {
  return Object.freeze({
    role: record.role,
    valueSats: record.valueSats,
    lockingBytecode: Uint8Array.from(record.lockingBytecode),
    tokenPrefix: tokenPrefix(record.token),
  });
}

function contextInput(record) {
  return Object.freeze({
    ...contextRecord(record),
    outpointTransactionHash: record.outpointTransactionHash,
    outpointIndex: record.outpointIndex,
    sequence: record.sequence,
  });
}

function assertExactStateTransition(kind, preState, postState) {
  const preNoteCount = BigInt(preState.noteCount);
  const postNoteCount = BigInt(postState.noteCount);
  const preNullifierCount = BigInt(preState.nullifierCount);
  const postNullifierCount = BigInt(postState.nullifierCount);
  const outputActive = kind === 'deposit' || kind === 'transfer' ? 1n : 0n;
  const spendActive = kind === 'transfer' || kind === 'withdrawal' ? 1n : 0n;

  if (
    postNoteCount !== preNoteCount + outputActive
    || postNullifierCount !== preNullifierCount + spendActive
  ) {
    fail(`${kind} note/nullifier counter delta is invalid`);
  }
  if (postState.maximumLiveNotes !== preState.maximumLiveNotes) {
    fail('postState changes immutable maximumLiveNotes');
  }
  if (kind === 'deposit' && postState.nullifierRoot !== preState.nullifierRoot) {
    fail('deposit changes the nullifier root');
  }
  if (kind === 'withdrawal' && postState.noteRoot !== preState.noteRoot) {
    fail('withdrawal changes the note root');
  }
}

/**
 * Validate a complete V2 Direct rolling-bundle descriptor and return the exact
 * role records consumed by context.mjs. This is a pure topology/value model:
 * it does not serialize, sign, execute, or qualify a BCH transaction.
 */
export function validateDirectV2RollingBundle(value) {
  exactKeys(value, 'rolling bundle', [
    'carrierCount',
    'denominationSats',
    'feeSats',
    'inputs',
    'instanceId',
    'kind',
    'locktime',
    'networkId',
    'outputs',
    'pins',
    'postState',
    'preState',
    'profileId',
    'transactionVersion',
  ]);
  if (
    !Number.isInteger(value.carrierCount)
    || value.carrierCount < 1
    || value.carrierCount > 0xff
  ) {
    fail('carrierCount must be an integer from 1 to 255');
  }
  const carrierCount = value.carrierCount;
  if (!KINDS.has(value.kind)) fail('kind is unsupported');
  if (!isSupportedDirectV2NetworkId(value.networkId)) {
    fail('networkId is unsupported');
  }
  const profileId = identifier(value.profileId, 'profileId');
  const instanceId = identifier(value.instanceId, 'instanceId');
  const denominationSats = uint(
    value.denominationSats,
    MAX_MONEY_SATS,
    'denominationSats',
  );
  if (denominationSats === 0n) fail('denominationSats must be nonzero');
  const feeSats = monetaryValue(value.feeSats, 'feeSats');
  const transactionVersion = uint(
    value.transactionVersion,
    MAX_U32,
    'transactionVersion',
  );
  const locktime = uint(value.locktime, MAX_U32, 'locktime');
  const stateContext = Object.freeze({
    denominationSats: denominationSats.toString(),
  });
  let preState;
  let postState;
  try {
    preState = validateStateNftCommitment(value.preState, stateContext);
    postState = validateStateNftCommitment(value.postState, stateContext);
  } catch (error) {
    fail(`state is invalid: ${error.message}`);
  }
  if (preState.profileId !== profileId || postState.profileId !== profileId) {
    fail('state profileId differs from the bundle profileId');
  }
  assertExactStateTransition(value.kind, preState, postState);
  if (BigInt(postState.actionSequence) !== BigInt(preState.actionSequence) + 1n) {
    fail('postState actionSequence must increment by one');
  }
  const preReserve = BigInt(preState.reserveSats);
  const postReserve = BigInt(postState.reserveSats);
  const expectedPostReserve = value.kind === 'deposit'
    ? preReserve + denominationSats
    : value.kind === 'withdrawal'
      ? preReserve - denominationSats
      : preReserve;
  if (expectedPostReserve < 0n || postReserve !== expectedPostReserve) {
    fail(`${value.kind} reserve delta is invalid`);
  }
  const pins = normalizePins(value.pins, carrierCount);
  if (!Array.isArray(value.inputs) || value.inputs.length !== carrierCount + 3) {
    fail('rolling bundle input count is wrong');
  }
  const expectedOutputs = carrierCount + (value.kind === 'withdrawal' ? 4 : 3);
  if (!Array.isArray(value.outputs) || value.outputs.length !== expectedOutputs) {
    fail('rolling bundle output count is wrong');
  }
  const inputs = Object.freeze(value.inputs.map(input));
  const outputs = Object.freeze(value.outputs.map(output));
  const preCommitment = encodeStateNftCommitment(preState, stateContext);
  const postCommitment = encodeStateNftCommitment(postState, stateContext);

  for (let index = 0; index < carrierCount; index += 1) {
    const source = inputs[index];
    const successor = outputs[index + 1];
    const pinned = pins.verifierCarriers[index];
    assertRole(source, 'verifier', index, `input ${index}`);
    assertRole(successor, 'verifier', index, `output ${index + 1}`);
    assertTokenless(source, `input ${index}`);
    assertTokenless(successor, `output ${index + 1}`);
    assertPinnedRecord(source, pinned.lockingBytecode, pinned.baseValueSats, `input ${index}`);
    assertPinnedRecord(
      successor,
      pinned.lockingBytecode,
      pinned.baseValueSats,
      `output ${index + 1}`,
    );
    if (
      source.outpointTransactionHash !== pins.previousBundleTransactionHash
      || source.outpointIndex !== String(index + 1)
    ) {
      fail(`input ${index} is not the exact previous verifier output`);
    }
  }

  const bindingInput = inputs[carrierCount];
  const stateInput = inputs[carrierCount + 1];
  const fundingInput = inputs[carrierCount + 2];
  const stateOutput = outputs[0];
  const bindingOutput = outputs[carrierCount + 1];
  assertRole(bindingInput, 'binding', 0, 'binding input');
  assertRole(stateInput, 'state', 0, 'state input');
  assertRole(fundingInput, 'funding', 0, 'funding input');
  assertRole(stateOutput, 'state', 0, 'state output');
  assertRole(bindingOutput, 'binding', 0, 'binding output');
  assertTokenless(bindingInput, 'binding input');
  assertTokenless(fundingInput, 'funding input');
  assertTokenless(bindingOutput, 'binding output');
  assertPinnedRecord(
    bindingInput,
    pins.bindingLockingBytecode,
    pins.bindingBaseSats,
    'binding input',
  );
  assertPinnedRecord(
    bindingOutput,
    pins.bindingLockingBytecode,
    pins.bindingBaseSats,
    'binding output',
  );
  if (
    bindingInput.outpointTransactionHash !== pins.previousBundleTransactionHash
    || bindingInput.outpointIndex !== String(carrierCount + 1)
  ) {
    fail('binding input is not the exact previous binding output');
  }
  if (
    stateInput.outpointTransactionHash !== pins.previousBundleTransactionHash
    || stateInput.outpointIndex !== '0'
  ) {
    fail('state input is not exact previous output 0');
  }
  if (
    !equalBytes(stateInput.lockingBytecode, pins.stateLockingBytecode)
    || !equalBytes(stateOutput.lockingBytecode, pins.stateLockingBytecode)
    || BigInt(stateInput.valueSats) !== pins.stateBaseSats + preReserve
    || BigInt(stateOutput.valueSats) !== pins.stateBaseSats + postReserve
  ) {
    fail('state lock, base value, or reserve value is invalid');
  }
  stateToken(
    stateInput.token,
    instanceId,
    preCommitment,
    'state input token',
  );
  stateToken(
    stateOutput.token,
    instanceId,
    postCommitment,
    'state output token',
  );
  const fundingLock = p2pkh(fundingInput.lockingBytecode, 'funding input lock');

  let payoutValue = 0n;
  let changeOutput;
  if (value.kind === 'withdrawal') {
    const payout = outputs[carrierCount + 2];
    changeOutput = outputs[carrierCount + 3];
    assertRole(payout, 'withdrawal', 0, 'withdrawal output');
    assertTokenless(payout, 'withdrawal output');
    p2pkh(payout.lockingBytecode, 'withdrawal output lock');
    payoutValue = BigInt(payout.valueSats);
    if (payoutValue !== denominationSats) {
      fail('withdrawal payout must equal denominationSats');
    }
  } else {
    changeOutput = outputs[carrierCount + 2];
  }
  assertRole(changeOutput, 'change', 0, 'change output');
  assertTokenless(changeOutput, 'change output');
  const changeLock = p2pkh(changeOutput.lockingBytecode, 'change output lock');
  if (equalBytes(changeLock, fundingLock)) {
    fail('change output must use a fresh P2PKH lock');
  }
  if (BigInt(changeOutput.valueSats) === 0n) {
    fail('change output must be nonzero');
  }
  if (
    value.kind === 'withdrawal'
    && equalBytes(changeLock, outputs[carrierCount + 2].lockingBytecode)
  ) {
    fail('withdrawal payout and change locks must differ');
  }

  const fundingValue = BigInt(fundingInput.valueSats);
  const expectedFunding = BigInt(changeOutput.valueSats)
    + feeSats
    + (value.kind === 'deposit' ? denominationSats : 0n);
  if (fundingValue !== expectedFunding) {
    fail(`${value.kind} funding input does not exactly fund boundary value, fee, and change`);
  }
  const inputTotal = inputs.reduce(
    (sum, record) => sum + BigInt(record.valueSats),
    0n,
  );
  const outputTotal = outputs.reduce(
    (sum, record) => sum + BigInt(record.valueSats),
    0n,
  );
  if (inputTotal !== outputTotal + feeSats) {
    fail('bundle value conservation excluding fee is invalid');
  }

  const context = Object.freeze({
    networkId: value.networkId,
    kind: value.kind,
    profileId,
    instanceId,
    transactionVersion: transactionVersion.toString(),
    locktime: locktime.toString(),
    preActionSequence: preState.actionSequence,
    postActionSequence: postState.actionSequence,
    inputs: Object.freeze(inputs.map(contextInput)),
    outputs: Object.freeze(outputs.map(contextRecord)),
  });
  try {
    validateDirectV2RoleTopology(context, carrierCount);
  } catch (error) {
    fail(`context role descriptors are invalid: ${error.message}`);
  }
  return Object.freeze({
    schema: DIRECT_V2_ROLLING_BUNDLE_MODEL_SCHEMA,
    modelOnly: true,
    claims: Object.freeze({
      transactionQualified: false,
      covenantQualified: false,
      bchVmQualified: false,
    }),
    carrierCount,
    kind: value.kind,
    denominationSats: denominationSats.toString(),
    feeSats: feeSats.toString(),
    preState,
    postState,
    context,
    totals: Object.freeze({
      inputSats: inputTotal.toString(),
      outputSats: outputTotal.toString(),
      feeSats: feeSats.toString(),
      withdrawalPayoutSats: payoutValue.toString(),
    }),
  });
}
