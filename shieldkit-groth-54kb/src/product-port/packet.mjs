import { createHash } from 'node:crypto';

import { isSupportedDirectV2NetworkId } from './network.mjs';
import {
  canonicalFrHex,
  decodeStateNftCommitment,
  encodeStateNftCommitment,
  STATE_NFT_COMMITMENT_BYTES,
  validateStateNftCommitment,
} from './state.mjs';

export const ACTION_PACKET_BYTES = 552;
export const STATE_BYTES = STATE_NFT_COMMITMENT_BYTES;
export const ENCRYPTED_RECORD_BYTES = 128;
/** @deprecated V2 calls this field encryptedRecord. */
export const OUTPUT_RECORD_BYTES = ENCRYPTED_RECORD_BYTES;

export const ACTION_KIND_CODES = Object.freeze({
  deposit: 1,
  transfer: 2,
  withdrawal: 3,
});

export const ACTION_PACKET_OFFSETS = Object.freeze({
  magic: 0,
  networkId: 4,
  kind: 5,
  flags: 6,
  instanceId: 8,
  preState: 40,
  postState: 168,
  publicNullifier: 296,
  outputNoteLeaf: 328,
  encryptedRecord: 360,
  withdrawalLockingBytecodeHash: 488,
  transactionContextHash: 520,
  end: 552,
});

const HEX_32 = /^[0-9a-f]{64}$/;
const ZERO_32 = '0'.repeat(64);
const PACKET_KEYS = Object.freeze([
  'kind',
  'networkId',
  'instanceId',
  'preState',
  'postState',
  'publicNullifier',
  'outputNoteLeaf',
  'encryptedRecord',
  'withdrawalLockingBytecodeHash',
  'transactionContextHash',
]);

export class ActionPacketError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ActionPacketError';
  }
}

const fail = (message) => { throw new ActionPacketError(message); };

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}

function state(value, context, label) {
  try {
    return validateStateNftCommitment(value, context);
  } catch (error) {
    if (error instanceof Error) fail(`${label} is invalid: ${error.message}`);
    throw error;
  }
}

function kindFromCode(code) {
  return Object.entries(ACTION_KIND_CODES).find(([, value]) => value === code)?.[0];
}

function checkActionFields(packet) {
  const encryptedRecordIsZero = packet.encryptedRecord.equals(Buffer.alloc(ENCRYPTED_RECORD_BYTES));
  if (packet.kind === 'deposit') {
    if (packet.publicNullifier !== ZERO_32 || packet.withdrawalLockingBytecodeHash !== ZERO_32) {
      fail('deposit packet contains nonzero inactive fields');
    }
  } else if (packet.kind === 'transfer') {
    if (packet.withdrawalLockingBytecodeHash !== ZERO_32) {
      fail('transfer packet contains nonzero inactive fields');
    }
  } else if (packet.outputNoteLeaf !== ZERO_32 || !encryptedRecordIsZero) {
    fail('withdrawal packet contains nonzero inactive fields');
  }
}

function checkStateContinuity(packet) {
  if (packet.preState.profileId !== packet.postState.profileId) {
    fail('packet changes the profileId');
  }
  if (packet.preState.maximumLiveNotes !== packet.postState.maximumLiveNotes) {
    fail('packet changes maximumLiveNotes');
  }
}

function normalisePacket(value, context) {
  exactKeys(value, 'action packet', PACKET_KEYS);
  const kindCode = ACTION_KIND_CODES[value.kind];
  if (kindCode === undefined) fail('action packet kind is unsupported');
  if (!isSupportedDirectV2NetworkId(value.networkId)) fail('action packet network is unsupported');
  const packet = {
    kind: value.kind,
    networkId: value.networkId,
    instanceId: hex32(value.instanceId, 'instanceId').toString('hex'),
    preState: state(value.preState, context, 'preState'),
    postState: state(value.postState, context, 'postState'),
    publicNullifier: canonicalFrHex(value.publicNullifier, 'publicNullifier'),
    outputNoteLeaf: canonicalFrHex(value.outputNoteLeaf, 'outputNoteLeaf'),
    encryptedRecord: exactBytes(value.encryptedRecord, ENCRYPTED_RECORD_BYTES, 'encryptedRecord'),
    withdrawalLockingBytecodeHash: hex32(value.withdrawalLockingBytecodeHash, 'withdrawalLockingBytecodeHash').toString('hex'),
    transactionContextHash: hex32(value.transactionContextHash, 'transactionContextHash').toString('hex'),
  };
  checkActionFields(packet);
  checkStateContinuity(packet);
  return Object.freeze(packet);
}

/** Validate a decoded V2 packet using the profile-pinned denomination context. */
export function validateActionPacket(value, context) {
  return normalisePacket(value, context);
}

export function encodeActionPacket(value, context) {
  const packet = normalisePacket(value, context);
  const encoded = Buffer.alloc(ACTION_PACKET_BYTES);
  Buffer.from('SDA2', 'ascii').copy(encoded, ACTION_PACKET_OFFSETS.magic);
  encoded[ACTION_PACKET_OFFSETS.networkId] = packet.networkId;
  encoded[ACTION_PACKET_OFFSETS.kind] = ACTION_KIND_CODES[packet.kind];
  encoded.writeUInt16LE(0, ACTION_PACKET_OFFSETS.flags);
  Buffer.from(packet.instanceId, 'hex').copy(encoded, ACTION_PACKET_OFFSETS.instanceId);
  encodeStateNftCommitment(packet.preState, context).copy(encoded, ACTION_PACKET_OFFSETS.preState);
  encodeStateNftCommitment(packet.postState, context).copy(encoded, ACTION_PACKET_OFFSETS.postState);
  Buffer.from(packet.publicNullifier, 'hex').copy(encoded, ACTION_PACKET_OFFSETS.publicNullifier);
  Buffer.from(packet.outputNoteLeaf, 'hex').copy(encoded, ACTION_PACKET_OFFSETS.outputNoteLeaf);
  packet.encryptedRecord.copy(encoded, ACTION_PACKET_OFFSETS.encryptedRecord);
  Buffer.from(packet.withdrawalLockingBytecodeHash, 'hex').copy(encoded, ACTION_PACKET_OFFSETS.withdrawalLockingBytecodeHash);
  Buffer.from(packet.transactionContextHash, 'hex').copy(encoded, ACTION_PACKET_OFFSETS.transactionContextHash);
  return encoded;
}

export function decodeActionPacket(value, context) {
  const bytes = exactBytes(value, ACTION_PACKET_BYTES, 'action packet');
  if (!bytes.subarray(0, 4).equals(Buffer.from('SDA2', 'ascii'))) fail('action packet magic is invalid');
  if (!isSupportedDirectV2NetworkId(bytes[ACTION_PACKET_OFFSETS.networkId])) fail('action packet network is unsupported');
  const kind = kindFromCode(bytes[ACTION_PACKET_OFFSETS.kind]);
  if (kind === undefined) fail('action packet kind is unsupported');
  if (bytes.readUInt16LE(ACTION_PACKET_OFFSETS.flags) !== 0) fail('action packet flags must be zero');
  const packet = {
    kind,
    networkId: bytes[ACTION_PACKET_OFFSETS.networkId],
    instanceId: bytes.subarray(8, 40).toString('hex'),
    preState: decodeStateNftCommitment(bytes.subarray(40, 168), context),
    postState: decodeStateNftCommitment(bytes.subarray(168, 296), context),
    publicNullifier: bytes.subarray(296, 328).toString('hex'),
    outputNoteLeaf: bytes.subarray(328, 360).toString('hex'),
    encryptedRecord: Buffer.from(bytes.subarray(360, 488)),
    withdrawalLockingBytecodeHash: bytes.subarray(488, 520).toString('hex'),
    transactionContextHash: bytes.subarray(520, 552).toString('hex'),
  };
  return normalisePacket(packet, context);
}

export function digestActionPacket(value, context) {
  const packet = exactBytes(value, ACTION_PACKET_BYTES, 'action packet');
  decodeActionPacket(packet, context);
  return createHash('sha256').update(packet).digest();
}

export function actionPacketPublicLimbs(value, context) {
  const digest = digestActionPacket(value, context);
  return Object.freeze([
    BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(),
    BigInt(`0x${digest.subarray(16, 32).toString('hex')}`).toString(),
  ]);
}
