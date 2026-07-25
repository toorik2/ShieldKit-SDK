// Browser-safe SCAR action-packet codec. It deliberately mirrors the wire
// format without importing the Node-only @shield.cash/action-packet package.
import { bytes, bytesToHex, hex32, hexToBytes, isBytes } from './portable-core.mjs';

export const ACTION_PACKET_BYTES = 752;
export const ACTION_STATE_BYTES = 192;
export const ACTION_PACKET_VERSION = 1;
export const CHIPNET_NETWORK_ID = 2;
export const DENOMINATION_SATS = 10_000_000n;
export const ACTION_PACKET_OFFSETS = Object.freeze({
  magic: 0, version: 4, network: 5, kind: 6, reserved: 7, preState: 8,
  postState: 200, inputCommitment: 392, inputNullifier: 424,
  outputCommitment: 456, outputRecord: 488, boundaryAmount: 680,
  withdrawalScriptHash: 688, transactionContextDigest: 720, end: 752,
});

const STATE_KEYS = Object.freeze(['profileId', 'instanceId', 'noteRoot', 'nullifierRoot', 'nextLeafIndex', 'actionSequence', 'liveNoteCount', 'reserveSats', 'maximumReserve', 'stateCommitment']);
const ACTION_KIND_CODES = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });
const ACTION_KINDS = Object.freeze(Object.fromEntries(Object.entries(ACTION_KIND_CODES).map(([kind, code]) => [code, kind])));
const ZERO_32 = '0'.repeat(64);
const DECIMAL = /^(0|[1-9][0-9]*)$/;

export class PortableActionPacketError extends Error {
  constructor(code, message) { super(message); this.name = 'PortableActionPacketError'; this.code = code; }
}
const fail = (code, message) => { throw new PortableActionPacketError(code, message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const uint = (value, maximum, label) => {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail('INVALID_INTEGER', `${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value); if (parsed > maximum) fail('INTEGER_RANGE', `${label} exceeds its range`); return parsed;
};
const u32le = (value) => Uint8Array.of(Number(value & 0xffn), Number((value >> 8n) & 0xffn), Number((value >> 16n) & 0xffn), Number((value >> 24n) & 0xffn));
const u64le = (value) => Uint8Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(index * 8)) & 0xffn));
const readU32le = (value, offset) => (BigInt(value[offset]) | (BigInt(value[offset + 1]) << 8n) | (BigInt(value[offset + 2]) << 16n) | (BigInt(value[offset + 3]) << 24n)).toString();
const readU64le = (value, offset) => Array.from(value.subarray(offset, offset + 8)).reduceRight((total, byte) => (total << 8n) | BigInt(byte), 0n).toString();
const zero = (value) => value.every((byte) => byte === 0);
const hex = (value, label) => { try { return hex32(value, label); } catch (error) { fail(error.code ?? 'INVALID_IDENTIFIER', error.message); } };

export function encodePortableActionState(value) {
  exactKeys(value, 'action state', STATE_KEYS);
  return bytes(
    hexToBytes(hex(value.profileId, 'state profileId')), hexToBytes(hex(value.instanceId, 'state instanceId')),
    hexToBytes(hex(value.noteRoot, 'state noteRoot')), hexToBytes(hex(value.nullifierRoot, 'state nullifierRoot')),
    u32le(uint(value.nextLeafIndex, 0xffff_ffffn, 'state nextLeafIndex')),
    u64le(uint(value.actionSequence, 0xffff_ffff_ffff_ffffn, 'state actionSequence')),
    u32le(uint(value.liveNoteCount, 0xffff_ffffn, 'state liveNoteCount')),
    u64le(uint(value.reserveSats, 0xffff_ffff_ffff_ffffn, 'state reserveSats')),
    u64le(uint(value.maximumReserve, 0xffff_ffff_ffff_ffffn, 'state maximumReserve')),
    hexToBytes(hex(value.stateCommitment, 'state stateCommitment')),
  );
}

export function decodePortableActionState(value) {
  if (!isBytes(value, ACTION_STATE_BYTES)) fail('INVALID_STATE_BYTES', 'action state must contain exactly 192 bytes');
  const readHex = (offset) => bytesToHex(value.subarray(offset, offset + 32));
  return Object.freeze({
    profileId: readHex(0), instanceId: readHex(32), noteRoot: readHex(64), nullifierRoot: readHex(96),
    nextLeafIndex: readU32le(value, 128), actionSequence: readU64le(value, 132), liveNoteCount: readU32le(value, 140),
    reserveSats: readU64le(value, 144), maximumReserve: readU64le(value, 152), stateCommitment: readHex(160),
  });
}

const stateBytes = (value, label) => {
  if (isBytes(value, ACTION_STATE_BYTES)) return decodePortableActionState(value);
  try { return decodePortableActionState(encodePortableActionState(value)); } catch (error) { if (error instanceof PortableActionPacketError) throw error; fail('INVALID_STATE', `${label} is invalid`); }
};
const sameState = (left, right) => STATE_KEYS.every((key) => left[key] === right[key]);
const canonicalActionFields = (decoded) => {
  const outputRecordIsZero = zero(decoded.outputRecord);
  if (decoded.kind === 'deposit') {
    if (decoded.inputCommitment !== ZERO_32 || decoded.inputNullifier !== ZERO_32 || decoded.outputCommitment === ZERO_32 || decoded.boundaryAmount !== DENOMINATION_SATS.toString() || decoded.withdrawalScriptHash !== ZERO_32) fail('NONCANONICAL_ACTION', 'deposit packet contains noncanonical action fields');
  } else if (decoded.kind === 'transfer') {
    if (decoded.inputCommitment === ZERO_32 || decoded.inputNullifier === ZERO_32 || decoded.outputCommitment === ZERO_32 || decoded.boundaryAmount !== '0' || decoded.withdrawalScriptHash !== ZERO_32) fail('NONCANONICAL_ACTION', 'transfer packet contains noncanonical action fields');
  } else if (decoded.inputCommitment === ZERO_32 || decoded.inputNullifier === ZERO_32 || decoded.outputCommitment !== ZERO_32 || decoded.boundaryAmount !== DENOMINATION_SATS.toString() || decoded.withdrawalScriptHash === ZERO_32 || !outputRecordIsZero) {
    fail('NONCANONICAL_ACTION', 'withdrawal packet contains noncanonical action fields');
  }
};
const immutableState = (decoded) => {
  if (decoded.preState.profileId !== decoded.postState.profileId || decoded.preState.instanceId !== decoded.postState.instanceId || decoded.preState.maximumReserve !== decoded.postState.maximumReserve) fail('STATE_IMMUTABILITY', 'packet changes an immutable state field');
};

export function decodePortableActionPacket(value) {
  if (!isBytes(value, ACTION_PACKET_BYTES)) fail('INVALID_PACKET_BYTES', 'action packet must contain exactly 752 bytes');
  const packet = new Uint8Array(value);
  if (bytesToHex(packet.subarray(0, 4)) !== '53434152') fail('PACKET_MAGIC', 'action packet magic is invalid');
  if (packet[4] !== ACTION_PACKET_VERSION) fail('PACKET_VERSION', 'action packet version is unsupported');
  if (packet[5] !== CHIPNET_NETWORK_ID) fail('PACKET_NETWORK', 'action packet network is unsupported');
  if (packet[7] !== 0) fail('PACKET_RESERVED', 'action packet reserved byte must be zero');
  const kind = ACTION_KINDS[packet[6]]; if (kind === undefined) fail('PACKET_KIND', 'action packet kind is unsupported');
  const decoded = Object.freeze({
    kind, networkId: packet[5], preState: decodePortableActionState(packet.subarray(8, 200)), postState: decodePortableActionState(packet.subarray(200, 392)),
    inputCommitment: bytesToHex(packet.subarray(392, 424)), inputNullifier: bytesToHex(packet.subarray(424, 456)),
    outputCommitment: bytesToHex(packet.subarray(456, 488)), outputRecord: new Uint8Array(packet.subarray(488, 680)),
    boundaryAmount: readU64le(packet, 680), withdrawalScriptHash: bytesToHex(packet.subarray(688, 720)), transactionContextDigest: bytesToHex(packet.subarray(720, 752)),
  });
  canonicalActionFields(decoded); immutableState(decoded); return decoded;
}

export function encodePortableActionPacket(value) {
  exactKeys(value, 'action packet', ['kind', 'networkId', 'preState', 'postState', 'inputCommitment', 'inputNullifier', 'outputCommitment', 'outputRecord', 'boundaryAmount', 'withdrawalScriptHash', 'transactionContextDigest']);
  const kindCode = ACTION_KIND_CODES[value.kind]; if (kindCode === undefined) fail('PACKET_KIND', 'action packet kind is unsupported');
  if (value.networkId !== CHIPNET_NETWORK_ID) fail('PACKET_NETWORK', 'action packet network is unsupported');
  const outputRecord = value.outputRecord;
  if (!isBytes(outputRecord, 192)) fail('INVALID_OUTPUT_RECORD', 'output record must contain exactly 192 bytes');
  const packet = bytes(
    Uint8Array.of(0x53, 0x43, 0x41, 0x52, ACTION_PACKET_VERSION, CHIPNET_NETWORK_ID, kindCode, 0),
    encodePortableActionState(stateBytes(value.preState, 'pre-state')), encodePortableActionState(stateBytes(value.postState, 'post-state')),
    hexToBytes(hex(value.inputCommitment, 'input commitment')), hexToBytes(hex(value.inputNullifier, 'input nullifier')),
    hexToBytes(hex(value.outputCommitment, 'output commitment')), new Uint8Array(outputRecord),
    u64le(uint(value.boundaryAmount, 0xffff_ffff_ffff_ffffn, 'boundary amount')),
    hexToBytes(hex(value.withdrawalScriptHash, 'withdrawal script hash')), hexToBytes(hex(value.transactionContextDigest, 'transaction context digest')),
  );
  if (packet.length !== ACTION_PACKET_BYTES) fail('INTERNAL_SIZE', 'internal action-packet size mismatch');
  decodePortableActionPacket(packet); return packet;
}

export const portableActionStatesEqual = sameState;
