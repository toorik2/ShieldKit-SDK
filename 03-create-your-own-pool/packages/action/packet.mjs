import { createHash } from 'node:crypto';

import {
  CHIPNET_NETWORK_ID,
  NETWORK_CHIPNET,
  NETWORK_MAINNET,
  isSupportedNetworkId,
} from './network.mjs';

export const ACTION_PACKET_BYTES = 752;
export const ACTION_PACKET_VERSION = 1;
/** @deprecated prefer NETWORK_CHIPNET from network.mjs */
export { CHIPNET_NETWORK_ID, NETWORK_CHIPNET, NETWORK_MAINNET };
export const STATE_BYTES = 192;
export const OUTPUT_RECORD_BYTES = 192;
export const DENOMINATION_SATS = 10_000_000n;

export const ACTION_KIND_CODES = Object.freeze({
  deposit: 1,
  transfer: 2,
  withdrawal: 3,
});

export const ACTION_PACKET_OFFSETS = Object.freeze({
  magic: 0,
  version: 4,
  network: 5,
  kind: 6,
  reserved: 7,
  preState: 8,
  postState: 200,
  inputCommitment: 392,
  inputNullifier: 424,
  outputCommitment: 456,
  outputRecord: 488,
  boundaryAmount: 680,
  withdrawalScriptHash: 688,
  transactionContextDigest: 720,
  end: 752,
});

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ZERO_32 = '0'.repeat(64);
const STATE_KEYS = Object.freeze([
  'profileId',
  'instanceId',
  'noteRoot',
  'nullifierRoot',
  'nextLeafIndex',
  'actionSequence',
  'liveNoteCount',
  'reserveSats',
  'maximumReserve',
  'stateCommitment',
]);

export class ActionPacketError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ActionPacketError';
  }
}

const fail = (message) => {
  throw new ActionPacketError(message);
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

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function uint(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}

function u32le(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(Number(value));
  return out;
}

function u64le(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
}

function readU32le(bytes, offset) {
  return BigInt(bytes.readUInt32LE(offset)).toString();
}

function readU64le(bytes, offset) {
  return bytes.readBigUInt64LE(offset).toString();
}

function encodeState(state, label) {
  exactKeys(state, label, STATE_KEYS);
  return Buffer.concat([
    hex32(state.profileId, `${label}.profileId`),
    hex32(state.instanceId, `${label}.instanceId`),
    hex32(state.noteRoot, `${label}.noteRoot`),
    hex32(state.nullifierRoot, `${label}.nullifierRoot`),
    u32le(uint(state.nextLeafIndex, 0xffff_ffffn, `${label}.nextLeafIndex`)),
    u64le(uint(state.actionSequence, 0xffff_ffff_ffff_ffffn, `${label}.actionSequence`)),
    u32le(uint(state.liveNoteCount, 0xffff_ffffn, `${label}.liveNoteCount`)),
    u64le(uint(state.reserveSats, 0xffff_ffff_ffff_ffffn, `${label}.reserveSats`)),
    u64le(uint(state.maximumReserve, 0xffff_ffff_ffff_ffffn, `${label}.maximumReserve`)),
    hex32(state.stateCommitment, `${label}.stateCommitment`),
  ]);
}

function decodeState(bytes, offset) {
  const readHex = (start) => bytes.subarray(offset + start, offset + start + 32).toString('hex');
  return Object.freeze({
    profileId: readHex(0),
    instanceId: readHex(32),
    noteRoot: readHex(64),
    nullifierRoot: readHex(96),
    nextLeafIndex: readU32le(bytes, offset + 128),
    actionSequence: readU64le(bytes, offset + 132),
    liveNoteCount: readU32le(bytes, offset + 140),
    reserveSats: readU64le(bytes, offset + 144),
    maximumReserve: readU64le(bytes, offset + 152),
    stateCommitment: readHex(160),
  });
}

function checkCanonicalActionFields(decoded) {
  const outputRecordIsZero = decoded.outputRecord.equals(Buffer.alloc(OUTPUT_RECORD_BYTES));
  // inputCommitment is inactive (zero) for all kinds; spends prove membership
  // in-circuit and publish the nullifier on the consensus transcript.
  if (decoded.kind === 'deposit') {
    if (
      decoded.inputCommitment !== ZERO_32
      || decoded.inputNullifier !== ZERO_32
      || decoded.outputCommitment === ZERO_32
      || decoded.boundaryAmount !== DENOMINATION_SATS.toString()
      || decoded.withdrawalScriptHash !== ZERO_32
    ) {
      fail('deposit packet contains noncanonical action fields');
    }
  } else if (decoded.kind === 'transfer') {
    if (
      decoded.inputCommitment !== ZERO_32
      || decoded.inputNullifier === ZERO_32
      || decoded.outputCommitment === ZERO_32
      || decoded.boundaryAmount !== '0'
      || decoded.withdrawalScriptHash !== ZERO_32
    ) {
      fail('transfer packet contains noncanonical action fields');
    }
  } else if (
    decoded.inputCommitment !== ZERO_32
    || decoded.inputNullifier === ZERO_32
    || decoded.outputCommitment !== ZERO_32
    || decoded.boundaryAmount !== DENOMINATION_SATS.toString()
    || decoded.withdrawalScriptHash === ZERO_32
    || !outputRecordIsZero
  ) {
    fail('withdrawal packet contains noncanonical action fields');
  }
}

function checkStateContinuity(decoded) {
  if (
    decoded.preState.profileId !== decoded.postState.profileId
    || decoded.preState.instanceId !== decoded.postState.instanceId
    || decoded.preState.maximumReserve !== decoded.postState.maximumReserve
  ) {
    fail('packet changes an immutable state field');
  }
}

export function decodeActionPacket(value) {
  const bytes = exactBytes(value, ACTION_PACKET_BYTES, 'action packet');
  if (!bytes.subarray(0, 4).equals(Buffer.from('SCAR', 'ascii'))) {
    fail('action packet magic is invalid');
  }
  if (bytes[ACTION_PACKET_OFFSETS.version] !== ACTION_PACKET_VERSION) {
    fail('action packet version is unsupported');
  }
  if (!isSupportedNetworkId(bytes[ACTION_PACKET_OFFSETS.network])) {
    fail('action packet network is unsupported');
  }
  if (bytes[ACTION_PACKET_OFFSETS.reserved] !== 0) {
    fail('action packet reserved byte must be zero');
  }
  const kind = Object.entries(ACTION_KIND_CODES)
    .find(([, code]) => code === bytes[ACTION_PACKET_OFFSETS.kind])?.[0];
  if (kind === undefined) fail('action packet kind is unsupported');
  const decoded = Object.freeze({
    kind,
    networkId: bytes[ACTION_PACKET_OFFSETS.network],
    preState: decodeState(bytes, ACTION_PACKET_OFFSETS.preState),
    postState: decodeState(bytes, ACTION_PACKET_OFFSETS.postState),
    inputCommitment: bytes.subarray(392, 424).toString('hex'),
    inputNullifier: bytes.subarray(424, 456).toString('hex'),
    outputCommitment: bytes.subarray(456, 488).toString('hex'),
    outputRecord: Buffer.from(bytes.subarray(488, 680)),
    boundaryAmount: readU64le(bytes, ACTION_PACKET_OFFSETS.boundaryAmount),
    withdrawalScriptHash: bytes.subarray(688, 720).toString('hex'),
    transactionContextDigest: bytes.subarray(720, 752).toString('hex'),
  });
  checkCanonicalActionFields(decoded);
  checkStateContinuity(decoded);
  return decoded;
}

export function encodeActionPacket(value) {
  exactKeys(value, 'action packet', [
    'kind',
    'networkId',
    'preState',
    'postState',
    'inputCommitment',
    'inputNullifier',
    'outputCommitment',
    'outputRecord',
    'boundaryAmount',
    'withdrawalScriptHash',
    'transactionContextDigest',
  ]);
  const kindCode = ACTION_KIND_CODES[value.kind];
  if (kindCode === undefined) fail('action packet kind is unsupported');
  if (!isSupportedNetworkId(value.networkId)) fail('action packet network is unsupported');
  const packet = Buffer.concat([
    Buffer.from('SCAR', 'ascii'),
    Buffer.from([ACTION_PACKET_VERSION, value.networkId, kindCode, 0]),
    encodeState(value.preState, 'preState'),
    encodeState(value.postState, 'postState'),
    hex32(value.inputCommitment, 'inputCommitment'),
    hex32(value.inputNullifier, 'inputNullifier'),
    hex32(value.outputCommitment, 'outputCommitment'),
    exactBytes(value.outputRecord, OUTPUT_RECORD_BYTES, 'outputRecord'),
    u64le(uint(value.boundaryAmount, 0xffff_ffff_ffff_ffffn, 'boundaryAmount')),
    hex32(value.withdrawalScriptHash, 'withdrawalScriptHash'),
    hex32(value.transactionContextDigest, 'transactionContextDigest'),
  ]);
  if (packet.length !== ACTION_PACKET_BYTES) fail('internal action packet length mismatch');
  decodeActionPacket(packet);
  return packet;
}

export function digestActionPacket(value) {
  const bytes = exactBytes(value, ACTION_PACKET_BYTES, 'action packet');
  decodeActionPacket(bytes);
  return createHash('sha256').update(bytes).digest();
}

export function actionPacketPublicLimbs(value) {
  const digest = digestActionPacket(value);
  return Object.freeze([
    BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(),
    BigInt(`0x${digest.subarray(16, 32).toString('hex')}`).toString(),
  ]);
}
