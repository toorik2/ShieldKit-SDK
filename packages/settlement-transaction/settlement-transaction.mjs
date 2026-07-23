import { createHash } from 'node:crypto';
import { encodeTokenPrefix, encodeTransaction } from '@bitauth/libauth';
import {
  ACTION_PACKET_BYTES,
  CHIPNET_NETWORK_ID,
  decodeActionPacket,
  DENOMINATION_SATS,
} from '../action-packet/action-packet.mjs';
import {
  encodeSettlementContext,
  INPUT_ROLES,
} from '../settlement-context/settlement-context.mjs';
import {
  encodeStateNftCommitment,
  STATE_NFT_COMMITMENT_LIMIT_BYTES,
} from '../state-nft/state-nft.mjs';

export const COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES = 59_000;
export const INPUT_UNLOCKING_LIMIT_BYTES = 10_000;
export const PROJECT_P2S_LOCKING_LIMIT_BYTES = 190;
export const PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE = 1n;
// Conservative common cap derived from the worst measured PF7 transfer seam,
// the current 88-byte state trampoline, state NFT output, P2PKH change, and
// exact fee unlock. Complete wire size remains the authoritative final gate.
export const STATE_HELPER_UNLOCKING_LIMIT_BYTES = 3_286;
export { STATE_NFT_COMMITMENT_LIMIT_BYTES };

const HEX = /^[0-9a-f]*$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_TOKEN_AMOUNT = 9_223_372_036_854_775_807n;
const BINDING_INPUT_INDEX = 7;
const STATE_INPUT_INDEX = 8;
const FEE_INPUT_INDEX = 9;

export class SettlementTransactionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SettlementTransactionError';
  }
}

const fail = (message) => {
  throw new SettlementTransactionError(message);
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

function decimal(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function hexBytes(value, length, label) {
  if (
    typeof value !== 'string'
    || !HEX.test(value)
    || value.length % 2 !== 0
    || (length !== undefined && value.length !== length * 2)
  ) {
    fail(`${label} must be canonical lowercase hexadecimal`);
  }
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function parseToken(value, label) {
  if (value === null) return undefined;
  exactKeys(value, label, ['amount', 'category', 'nft']);
  const amount = decimal(value.amount, MAX_TOKEN_AMOUNT, `${label}.amount`);
  const category = hexBytes(value.category, 32, `${label}.category`);
  let nft;
  if (value.nft !== null) {
    exactKeys(value.nft, `${label}.nft`, ['capability', 'commitment']);
    if (!['none', 'mutable', 'minting'].includes(value.nft.capability)) {
      fail(`${label}.nft.capability is invalid`);
    }
    const commitment = hexBytes(value.nft.commitment, undefined, `${label}.nft.commitment`);
    if (commitment.length > 128) fail(`${label}.nft.commitment exceeds the BCH consensus limit`);
    nft = { capability: value.nft.capability, commitment };
  }
  if (amount === 0n && nft === undefined) fail(`${label} must use null for no token`);
  return { amount, category, ...(nft === undefined ? {} : { nft }) };
}

function parseOutput(value, label) {
  exactKeys(value, label, ['lockingBytecode', 'token', 'valueSatoshis']);
  return {
    valueSatoshis: decimal(value.valueSatoshis, MAX_U64, `${label}.valueSatoshis`),
    lockingBytecode: hexBytes(value.lockingBytecode, undefined, `${label}.lockingBytecode`),
    token: parseToken(value.token, `${label}.token`),
  };
}

function parseInput(value, label) {
  exactKeys(value, label, [
    'outpointIndex',
    'outpointTransactionHashWire',
    'sequenceNumber',
    'unlockingBytecode',
  ]);
  return {
    // Libauth transaction objects use display/hash order and reverse this
    // field during wire serialization. SCCT deliberately stores serialized
    // wire order, so convert exactly once at this boundary.
    outpointTransactionHash: hexBytes(
      value.outpointTransactionHashWire,
      32,
      `${label}.outpointTransactionHashWire`,
    ).reverse(),
    outpointIndex: Number(decimal(value.outpointIndex, MAX_U32, `${label}.outpointIndex`)),
    sequenceNumber: Number(decimal(value.sequenceNumber, MAX_U32, `${label}.sequenceNumber`)),
    unlockingBytecode: hexBytes(value.unlockingBytecode, undefined, `${label}.unlockingBytecode`),
  };
}

function assertP2sh32(lockingBytecode, index) {
  if (
    lockingBytecode.length !== 35
    || lockingBytecode[0] !== 0xaa
    || lockingBytecode[1] !== 0x20
    || lockingBytecode[34] !== 0x87
  ) {
    fail(`sourceOutputs[${index}] is not a canonical P2SH32 verifier lock`);
  }
}

function tokenToJson(token) {
  if (token === undefined) return null;
  return {
    category: Buffer.from(token.category).toString('hex'),
    amount: token.amount.toString(),
    nft: token.nft === undefined
      ? null
      : {
          capability: token.nft.capability,
          commitment: Buffer.from(token.nft.commitment).toString('hex'),
        },
  };
}

function outputToJson(output) {
  return {
    valueSatoshis: output.valueSatoshis.toString(),
    lockingBytecode: Buffer.from(output.lockingBytecode).toString('hex'),
    token: tokenToJson(output.token),
  };
}

function assertStateToken(token, label, instanceId, state, expectedCategory) {
  if (
    token === undefined
    || token.amount !== 0n
    || token.nft === undefined
    || token.nft.capability !== 'mutable'
  ) {
    fail(`${label} must contain only the mutable state NFT with zero fungible amount`);
  }
  if (
    expectedCategory !== undefined
    && !Buffer.from(token.category).equals(Buffer.from(expectedCategory))
  ) {
    fail(`${label} changes the state NFT category`);
  }
  const expected = encodeStateNftCommitment({
    networkId: CHIPNET_NETWORK_ID,
    instanceId,
    stateCommitment: state.stateCommitment,
    actionSequence: state.actionSequence,
  });
  if (!Buffer.from(token.nft.commitment).equals(expected)) {
    fail(`${label} state NFT commitment does not encode the packet state`);
  }
  if (token.nft.commitment.length > STATE_NFT_COMMITMENT_LIMIT_BYTES) {
    fail(`${label} state NFT commitment exceeds the project limit`);
  }
  return token.category;
}

function assertNoToken(output, label) {
  if (output.token !== undefined) fail(`${label} must not contain a token`);
}

function hash160(bytes) {
  const sha = createHash('sha256').update(bytes).digest();
  return createHash('ripemd160').update(sha).digest();
}

function assertCanonicalPreparationPair(rawInputs, sources, outputs, parsedInputs) {
  if (
    rawInputs[BINDING_INPUT_INDEX].outpointTransactionHashWire
      !== rawInputs[FEE_INPUT_INDEX].outpointTransactionHashWire
    || rawInputs[BINDING_INPUT_INDEX].outpointIndex !== '7'
    || rawInputs[FEE_INPUT_INDEX].outpointIndex !== '8'
  ) {
    fail('binding and fee inputs must spend canonical preparation sibling outputs 7 and 8');
  }
  const feeLock = Buffer.from(sources[FEE_INPUT_INDEX].lockingBytecode);
  if (
    feeLock.length !== 25
    || feeLock[0] !== 0x76
    || feeLock[1] !== 0xa9
    || feeLock[2] !== 0x14
    || feeLock[23] !== 0x88
    || feeLock[24] !== 0xac
  ) {
    fail('fee source must use canonical P2PKH locking bytecode');
  }
  const changeLock = Buffer.from(outputs.at(-1).lockingBytecode);
  if (!changeLock.equals(feeLock)) {
    fail('canonical change must preserve the exact fee-input P2PKH lock');
  }
  const feeUnlock = Buffer.from(parsedInputs[FEE_INPUT_INDEX].unlockingBytecode);
  if (
    feeUnlock.length !== 100
    || feeUnlock[0] !== 0x41
    || feeUnlock[65] !== 0x41
    || feeUnlock[66] !== 0x21
    || ![0x02, 0x03].includes(feeUnlock[67])
  ) {
    fail('fee input must use a canonical Schnorr P2PKH ALL|FORKID unlock');
  }
  const publicKey = feeUnlock.subarray(67, 100);
  if (!hash160(publicKey).equals(feeLock.subarray(3, 23))) {
    fail('fee input public key does not match its P2PKH source lock');
  }
}

function sumValues(outputs) {
  return outputs.reduce((total, output) => total + output.valueSatoshis, 0n);
}

export function buildSettlementTransaction(value) {
  exactKeys(value, 'settlement', [
    'actionPacket',
    'bindingCarrierBaseValueSatoshis',
    'inputs',
    'instanceId',
    'kind',
    'minimumFeeRateSatoshisPerByte',
    'outputs',
    'profileId',
    'sourceOutputs',
    'stateCarrierBaseValueSatoshis',
  ]);
  if (!['deposit', 'transfer', 'withdrawal'].includes(value.kind)) {
    fail('kind is unsupported');
  }
  if (typeof value.profileId !== 'string' || !HEX_32.test(value.profileId)) {
    fail('profileId must be 32 lowercase hexadecimal bytes');
  }
  if (typeof value.instanceId !== 'string' || !HEX_32.test(value.instanceId)) {
    fail('instanceId must be 32 lowercase hexadecimal bytes');
  }
  const bindingBase = decimal(
    value.bindingCarrierBaseValueSatoshis,
    MAX_U64,
    'bindingCarrierBaseValueSatoshis',
  );
  const stateBase = decimal(
    value.stateCarrierBaseValueSatoshis,
    MAX_U64,
    'stateCarrierBaseValueSatoshis',
  );
  const minimumFeeRate = decimal(
    value.minimumFeeRateSatoshisPerByte,
    MAX_U64,
    'minimumFeeRateSatoshisPerByte',
  );
  if (minimumFeeRate !== PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE) {
    fail('minimumFeeRateSatoshisPerByte must equal the protocol rate of 1');
  }

  if (!Array.isArray(value.inputs) || value.inputs.length !== INPUT_ROLES.length) {
    fail('inputs must contain exactly ten ordered roles');
  }
  if (!Array.isArray(value.sourceOutputs) || value.sourceOutputs.length !== INPUT_ROLES.length) {
    fail('sourceOutputs must contain exactly ten ordered roles');
  }
  const expectedOutputCount = value.kind === 'withdrawal' ? 3 : 2;
  if (!Array.isArray(value.outputs) || value.outputs.length !== expectedOutputCount) {
    fail(`${value.kind} must contain exactly ${expectedOutputCount} canonical outputs`);
  }
  const inputs = value.inputs.map((input, index) => parseInput(input, `inputs[${index}]`));
  const sources = value.sourceOutputs.map((output, index) => parseOutput(output, `sourceOutputs[${index}]`));
  const outputs = value.outputs.map((output, index) => parseOutput(output, `outputs[${index}]`));
  if (inputs.some((input) => input.sequenceNumber !== 0)) {
    fail('all settlement input sequence numbers must be zero');
  }
  for (let index = 0; index < 7; index += 1) {
    assertP2sh32(sources[index].lockingBytecode, index);
    assertNoToken(sources[index], `sourceOutputs[${index}]`);
  }
  for (const index of [BINDING_INPUT_INDEX, FEE_INPUT_INDEX]) {
    assertNoToken(sources[index], `sourceOutputs[${index}]`);
  }
  if (
    sources[BINDING_INPUT_INDEX].lockingBytecode.length === 0
    || sources[BINDING_INPUT_INDEX].lockingBytecode.length > PROJECT_P2S_LOCKING_LIMIT_BYTES
  ) {
    fail('binding P2S locking bytecode must contain 1 to 190 bytes');
  }
  if (
    sources[STATE_INPUT_INDEX].lockingBytecode.length === 0
    || sources[STATE_INPUT_INDEX].lockingBytecode.length > PROJECT_P2S_LOCKING_LIMIT_BYTES
  ) {
    fail('state P2S locking bytecode must contain 1 to 190 bytes');
  }
  if (
    !Buffer.from(outputs[0].lockingBytecode)
      .equals(Buffer.from(sources[STATE_INPUT_INDEX].lockingBytecode))
  ) {
    fail('successor state must preserve the exact state locking bytecode');
  }

  const packetBytes = hexBytes(value.actionPacket, ACTION_PACKET_BYTES, 'actionPacket');
  const packet = decodeActionPacket(packetBytes);
  if (
    packet.kind !== value.kind
    || packet.preState.profileId !== value.profileId
    || packet.preState.instanceId !== value.instanceId
  ) {
    fail('action packet kind or identity does not match the settlement');
  }
  const canonicalPacketUnlock = Buffer.concat([
    Buffer.from([0x4d, 0xf0, 0x02]),
    Buffer.from(packetBytes),
  ]);
  if (
    !Buffer.from(inputs[BINDING_INPUT_INDEX].unlockingBytecode)
      .equals(canonicalPacketUnlock)
  ) {
    fail('binding input must contain exactly PUSHDATA2(752) and the action packet');
  }

  const stateCategory = assertStateToken(
    sources[STATE_INPUT_INDEX].token,
    'source state',
    value.instanceId,
    packet.preState,
  );
  assertStateToken(
    outputs[0].token,
    'successor state',
    value.instanceId,
    packet.postState,
    stateCategory,
  );
  for (let index = 1; index < outputs.length; index += 1) {
    assertNoToken(outputs[index], `outputs[${index}]`);
  }

  const preReserve = BigInt(packet.preState.reserveSats);
  const postReserve = BigInt(packet.postState.reserveSats);
  if (sources[STATE_INPUT_INDEX].valueSatoshis !== stateBase + preReserve) {
    fail('source state value must equal the fixed state carrier plus pre-reserve');
  }
  if (outputs[0].valueSatoshis !== stateBase + postReserve) {
    fail('successor state value must equal the fixed state carrier plus post-reserve');
  }
  const expectedBinding = bindingBase + (value.kind === 'deposit' ? DENOMINATION_SATS : 0n);
  if (sources[BINDING_INPUT_INDEX].valueSatoshis !== expectedBinding) {
    fail('binding source value does not match the action contribution');
  }
  if (value.kind === 'deposit') {
    if (postReserve !== preReserve + DENOMINATION_SATS) fail('deposit reserve delta is invalid');
  } else if (value.kind === 'transfer') {
    if (postReserve !== preReserve) fail('transfer reserve delta is invalid');
  } else {
    if (
      preReserve < DENOMINATION_SATS
      || postReserve !== preReserve - DENOMINATION_SATS
      || outputs[1].valueSatoshis !== DENOMINATION_SATS
      || createHash('sha256').update(outputs[1].lockingBytecode).digest('hex')
        !== packet.withdrawalScriptHash
    ) {
      fail('withdrawal reserve or recipient output is invalid');
    }
  }
  const change = outputs.at(-1);
  if (change.valueSatoshis === 0n) fail('canonical change output must be positive');
  assertCanonicalPreparationPair(value.inputs, sources, outputs, inputs);

  const contextMaterials = {
    kind: value.kind,
    profileId: value.profileId,
    instanceId: value.instanceId,
    transaction: {
      version: '2',
      locktime: '0',
      inputs: value.inputs.map((input) => ({
        outpointTransactionHashWire: input.outpointTransactionHashWire,
        outpointIndex: input.outpointIndex,
        sequenceNumber: input.sequenceNumber,
      })),
      outputs: outputs.map(outputToJson),
    },
    sourceOutputs: sources.map(outputToJson),
  };
  const context = encodeSettlementContext(contextMaterials);
  if (context.digestHex !== packet.transactionContextDigest) {
    fail('packet transaction-context digest does not match the exact settlement');
  }

  const transaction = {
    version: 2,
    inputs,
    outputs,
    locktime: 0,
  };
  const encodedTransaction = Buffer.from(encodeTransaction(transaction));
  const wireBytes = encodedTransaction.length;
  const maximumUnlockingBytes = Math.max(...inputs.map((input) => input.unlockingBytecode.length));
  if (wireBytes > COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES) {
    fail(`complete transaction is ${wireBytes} bytes, exceeding 59000`);
  }
  if (maximumUnlockingBytes > INPUT_UNLOCKING_LIMIT_BYTES) {
    fail(`largest unlocking bytecode is ${maximumUnlockingBytes} bytes, exceeding 10000`);
  }
  if (inputs[STATE_INPUT_INDEX].unlockingBytecode.length > STATE_HELPER_UNLOCKING_LIMIT_BYTES) {
    fail(
      `state helper unlocking bytecode is ${inputs[STATE_INPUT_INDEX].unlockingBytecode.length}`
      + ` bytes, exceeding ${STATE_HELPER_UNLOCKING_LIMIT_BYTES}`,
    );
  }
  const inputValue = sumValues(sources);
  const outputValue = sumValues(outputs);
  if (inputValue <= outputValue) fail('settlement fee must be positive');
  const feeSatoshis = inputValue - outputValue;
  const minimumFeeSatoshis = BigInt(wireBytes) * PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE;
  if (feeSatoshis !== minimumFeeSatoshis) {
    fail(
      `settlement fee ${feeSatoshis} must equal the fixed one-satoshi-per-byte fee`
      + ` ${minimumFeeSatoshis}`,
    );
  }
  const sourceLockingBytecodeBytes = sources
    .reduce((total, output) => total + output.lockingBytecode.length, 0);
  const sourceTokenPrefixBytes = sources
    .reduce((total, output) => total + encodeTokenPrefix(output.token).length, 0);

  return Object.freeze({
    schema: 'shield.cash/settlement-transaction/v1',
    kind: value.kind,
    transaction,
    encodedTransaction,
    transactionHex: encodedTransaction.toString('hex'),
    context,
    measurements: Object.freeze({
      wireBytes,
      maximumUnlockingBytes,
      feeSatoshis: feeSatoshis.toString(),
      minimumFeeSatoshis: minimumFeeSatoshis.toString(),
      sourceLockingBytecodeBytes,
      sourceTokenPrefixBytes,
      wirePlusSourceLockAndTokenBytes:
        wireBytes + sourceLockingBytecodeBytes + sourceTokenPrefixBytes,
      completeTransactionWireLimitBytes: COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES,
      inputUnlockingLimitBytes: INPUT_UNLOCKING_LIMIT_BYTES,
      stateHelperUnlockingLimitBytes: STATE_HELPER_UNLOCKING_LIMIT_BYTES,
      percentageHeadroomRequired: false,
    }),
  });
}
