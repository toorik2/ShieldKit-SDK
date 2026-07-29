/**
 * SDA2 — 552-byte action packet.
 * Layout from IMPLEMENTATION_PLAN.md §2.
 */
import { createHash } from 'node:crypto';
import {
  ACTION_KIND,
  ACTION_KIND_BY_CODE,
  ACTION_PACKET_BYTES,
  ENCRYPTED_RECORD_BYTES,
  PACKET_MAGIC,
  POOL_STATE_BYTES,
  ZERO_32_HEX,
  isSupportedNetworkId,
} from './constants.mjs';
import { sha256DigestLimbs } from './crypto/fr.mjs';
import {
  decodePoolStateV2,
  encodePoolStateV2,
  normalizePoolStateV2,
  poolStatesEqual,
} from './state.mjs';

export class ActionPacketV2Error extends Error {
  constructor(message) {
    super(message);
    this.name = 'ActionPacketV2Error';
  }
}

const fail = (message) => {
  throw new ActionPacketV2Error(message);
};

const HEX_32 = /^[0-9a-f]{64}$/;

export const PACKET_OFFSETS = Object.freeze({
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

const PACKET_KEYS = Object.freeze([
  'networkId',
  'kind',
  'flags',
  'instanceId',
  'preState',
  'postState',
  'publicNullifier',
  'outputNoteLeaf',
  'encryptedRecord',
  'withdrawalLockingBytecodeHash',
  'transactionContextHash',
]);

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((k, i) => k !== wanted[i])) {
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

/**
 * Kind-specific canonical field activity.
 * Inactive fields must be zero. Active fields may hold any valid canonical value (including zero Fr).
 */
function checkKindFields(decoded) {
  const zeroRecord = Buffer.alloc(ENCRYPTED_RECORD_BYTES);
  const recordZero = decoded.encryptedRecord.equals(zeroRecord);
  const nfZero = decoded.publicNullifier === ZERO_32_HEX;
  const leafZero = decoded.outputNoteLeaf === ZERO_32_HEX;
  const wZero = decoded.withdrawalLockingBytecodeHash === ZERO_32_HEX;

  if (decoded.kind === 'deposit') {
    if (!nfZero || leafZero || !wZero) {
      fail('deposit packet has noncanonical inactive/active fields');
    }
  } else if (decoded.kind === 'transfer') {
    // nullifier and output leaf active; withdrawal inactive
    if (leafZero || !wZero) {
      fail('transfer packet has noncanonical inactive/active fields');
    }
    // publicNullifier active — may be zero Fr; no check for nfZero
  } else if (decoded.kind === 'withdrawal') {
    if (!leafZero || wZero || !recordZero) {
      fail('withdrawal packet has noncanonical inactive/active fields');
    }
  }
}

function checkStateContinuity(decoded) {
  if (decoded.preState.profileId !== decoded.postState.profileId) {
    fail('packet changes profileId');
  }
  if (decoded.preState.maximumLiveNotes !== decoded.postState.maximumLiveNotes) {
    fail('packet changes maximumLiveNotes');
  }
}

export function encodeActionPacketV2(value) {
  exactKeys(value, 'action packet', PACKET_KEYS);
  const kindCode = ACTION_KIND[value.kind];
  if (kindCode === undefined) fail('action packet kind is unsupported');
  if (!isSupportedNetworkId(value.networkId)) fail('action packet network is unsupported');
  if (value.flags !== 0 && value.flags !== '0') fail('action packet flags must be zero');

  const preState = encodePoolStateV2(value.preState);
  const postState = encodePoolStateV2(value.postState);
  const record = exactBytes(value.encryptedRecord, ENCRYPTED_RECORD_BYTES, 'encryptedRecord');

  const packet = Buffer.alloc(ACTION_PACKET_BYTES);
  PACKET_MAGIC.copy(packet, 0);
  packet[PACKET_OFFSETS.networkId] = value.networkId;
  packet[PACKET_OFFSETS.kind] = kindCode;
  packet.writeUInt16LE(0, PACKET_OFFSETS.flags);
  hex32(value.instanceId, 'instanceId').copy(packet, PACKET_OFFSETS.instanceId);
  preState.copy(packet, PACKET_OFFSETS.preState);
  postState.copy(packet, PACKET_OFFSETS.postState);
  hex32(value.publicNullifier, 'publicNullifier').copy(packet, PACKET_OFFSETS.publicNullifier);
  hex32(value.outputNoteLeaf, 'outputNoteLeaf').copy(packet, PACKET_OFFSETS.outputNoteLeaf);
  record.copy(packet, PACKET_OFFSETS.encryptedRecord);
  hex32(value.withdrawalLockingBytecodeHash, 'withdrawalLockingBytecodeHash')
    .copy(packet, PACKET_OFFSETS.withdrawalLockingBytecodeHash);
  hex32(value.transactionContextHash, 'transactionContextHash')
    .copy(packet, PACKET_OFFSETS.transactionContextHash);

  if (packet.length !== ACTION_PACKET_BYTES) fail('internal packet length mismatch');
  // Round-trip validation enforces kind fields + continuity
  decodeActionPacketV2(packet);
  return packet;
}

export function decodeActionPacketV2(value) {
  const bytes = exactBytes(value, ACTION_PACKET_BYTES, 'action packet');
  if (!bytes.subarray(0, 4).equals(PACKET_MAGIC)) {
    fail('action packet magic is invalid (expected SDA2)');
  }
  if (!isSupportedNetworkId(bytes[PACKET_OFFSETS.networkId])) {
    fail('action packet network is unsupported');
  }
  const flags = bytes.readUInt16LE(PACKET_OFFSETS.flags);
  if (flags !== 0) fail('action packet flags must be zero');
  const kind = ACTION_KIND_BY_CODE[bytes[PACKET_OFFSETS.kind]];
  if (kind === undefined) fail('action packet kind is unsupported');

  const preState = decodePoolStateV2(bytes.subarray(
    PACKET_OFFSETS.preState,
    PACKET_OFFSETS.preState + POOL_STATE_BYTES,
  ));
  const postState = decodePoolStateV2(bytes.subarray(
    PACKET_OFFSETS.postState,
    PACKET_OFFSETS.postState + POOL_STATE_BYTES,
  ));

  const decoded = Object.freeze({
    networkId: bytes[PACKET_OFFSETS.networkId],
    kind,
    flags: 0,
    instanceId: bytes.subarray(PACKET_OFFSETS.instanceId, PACKET_OFFSETS.instanceId + 32).toString('hex'),
    preState,
    postState,
    publicNullifier: bytes.subarray(296, 328).toString('hex'),
    outputNoteLeaf: bytes.subarray(328, 360).toString('hex'),
    encryptedRecord: Buffer.from(bytes.subarray(360, 488)),
    withdrawalLockingBytecodeHash: bytes.subarray(488, 520).toString('hex'),
    transactionContextHash: bytes.subarray(520, 552).toString('hex'),
  });
  checkKindFields(decoded);
  checkStateContinuity(decoded);
  return decoded;
}

export function digestActionPacketV2(value) {
  const bytes = value instanceof Uint8Array && value.length === ACTION_PACKET_BYTES
    ? Buffer.from(value)
    : encodeActionPacketV2(value);
  decodeActionPacketV2(bytes);
  return createHash('sha256').update(bytes).digest();
}

/** Two 128-bit public-input limbs as decimal strings (circuit Fr encoding). */
export function actionPacketPublicLimbsV2(value) {
  const digest = digestActionPacketV2(value);
  const [hi, lo] = sha256DigestLimbs(digest);
  return Object.freeze([hi.toString(), lo.toString()]);
}

/** Hex Fr encodings padded to 32 bytes for snarkjs public signals. */
export function actionPacketPublicLimbsHexV2(value) {
  const digest = digestActionPacketV2(value);
  const [hi, lo] = sha256DigestLimbs(digest);
  return Object.freeze([
    hi.toString(16).padStart(64, '0'),
    lo.toString(16).padStart(64, '0'),
  ]);
}

export function packetFromNormalized(fields) {
  return encodeActionPacketV2({
    networkId: fields.networkId,
    kind: fields.kind,
    flags: 0,
    instanceId: fields.instanceId,
    preState: normalizePoolStateV2(fields.preState),
    postState: normalizePoolStateV2(fields.postState),
    publicNullifier: fields.publicNullifier,
    outputNoteLeaf: fields.outputNoteLeaf,
    encryptedRecord: fields.encryptedRecord,
    withdrawalLockingBytecodeHash: fields.withdrawalLockingBytecodeHash,
    transactionContextHash: fields.transactionContextHash,
  });
}

export { poolStatesEqual };
