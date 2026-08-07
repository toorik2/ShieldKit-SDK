/**
 * SFP1 — 424-byte action packet.
 * Normative: FRI_STARK_REPLACEMENT_PLAN.md
 */
import { createHash } from 'node:crypto';
import { digest4FromHex, ZERO_DIGEST4_HEX } from '../crypto/h4.mjs';
import { decodeState, encodeState, STATE_BYTES } from './state.mjs';

export const PACKET_BYTES = 424;
export const PACKET_MAGIC = Buffer.from('SFP1');
export const KIND = Object.freeze({ DEPOSIT: 1, TRANSFER: 2, WITHDRAWAL: 3 });

function hex32(h, label) {
  if (typeof h !== 'string' || !/^[0-9a-f]{64}$/i.test(h)) {
    throw new Error(`bad 32-byte hex ${label}`);
  }
  return Buffer.from(h.toLowerCase(), 'hex');
}

export function validatePacket(packet) {
  if (![1, 2].includes(packet.networkId)) throw new Error('bad networkId');
  if (![1, 2, 3].includes(packet.kind)) throw new Error('bad kind');
  if ((packet.flags ?? 0) !== 0) throw new Error('flags must be 0');
  if (!/^[0-9a-f]{64}$/i.test(packet.instanceId)) throw new Error('bad instanceId');
  digest4FromHex(packet.publicNullifier);
  digest4FromHex(packet.outputNoteLeaf);
  if (!/^[0-9a-f]{64}$/i.test(packet.withdrawalLockingBytecodeHash)) {
    throw new Error('bad withdrawal hash');
  }
  if (!/^[0-9a-f]{64}$/i.test(packet.transactionContextHash)) {
    throw new Error('bad tx context hash');
  }
  // encode states to enforce invariants
  encodeState(packet.preState);
  encodeState(packet.postState);
  const zero = ZERO_DIGEST4_HEX;
  if (packet.kind === KIND.DEPOSIT) {
    if (packet.publicNullifier !== zero) throw new Error('deposit nullifier must be zero');
    if (packet.withdrawalLockingBytecodeHash !== '0'.repeat(64)) {
      throw new Error('deposit withdrawal hash zero');
    }
  }
  if (packet.kind === KIND.TRANSFER) {
    if (packet.withdrawalLockingBytecodeHash !== '0'.repeat(64)) {
      throw new Error('transfer withdrawal hash zero');
    }
  }
  if (packet.kind === KIND.WITHDRAWAL) {
    if (packet.outputNoteLeaf !== zero) throw new Error('withdrawal leaf zero');
  }
}

export function encodePacket(packet) {
  validatePacket(packet);
  const buf = Buffer.concat([
    PACKET_MAGIC,
    Buffer.from([packet.networkId]),
    Buffer.from([packet.kind]),
    Buffer.alloc(2),
    hex32(packet.instanceId, 'instanceId'),
    encodeState(packet.preState),
    encodeState(packet.postState),
    hex32(packet.publicNullifier, 'publicNullifier'),
    hex32(packet.outputNoteLeaf, 'outputNoteLeaf'),
    hex32(packet.withdrawalLockingBytecodeHash, 'withdrawal'),
    hex32(packet.transactionContextHash, 'txContext'),
  ]);
  if (buf.length !== PACKET_BYTES) throw new Error(`SFP1 length ${buf.length}`);
  return buf;
}

export function decodePacket(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length !== PACKET_BYTES) throw new Error(`SFP1 must be ${PACKET_BYTES} bytes`);
  if (!buf.subarray(0, 4).equals(PACKET_MAGIC)) throw new Error('bad SFP1 magic');
  const packet = {
    networkId: buf[4],
    kind: buf[5],
    flags: buf.readUInt16LE(6),
    instanceId: buf.subarray(8, 40).toString('hex'),
    preState: decodeState(buf.subarray(40, 168)),
    postState: decodeState(buf.subarray(168, 296)),
    publicNullifier: buf.subarray(296, 328).toString('hex'),
    outputNoteLeaf: buf.subarray(328, 360).toString('hex'),
    withdrawalLockingBytecodeHash: buf.subarray(360, 392).toString('hex'),
    transactionContextHash: buf.subarray(392, 424).toString('hex'),
  };
  validatePacket(packet);
  return packet;
}

/**
 * statementDigest = SHA256(SFP1_bytes) — public AIR statement (8× U32LE limbs).
 */
export function statementDigest(packetOrBytes) {
  const buf = Buffer.isBuffer(packetOrBytes) ? packetOrBytes : encodePacket(packetOrBytes);
  if (buf.length !== PACKET_BYTES) throw new Error('statementDigest expects 424-byte SFP1');
  return createHash('sha256').update(buf).digest();
}

export function statementDigestHex(packetOrBytes) {
  return statementDigest(packetOrBytes).toString('hex');
}

/** Eight strict U32LE limbs of the 32-byte digest. */
export function statementDigestU32le8(packetOrBytes) {
  const d = statementDigest(packetOrBytes);
  const limbs = [];
  for (let i = 0; i < 8; i += 1) limbs.push(d.readUInt32LE(i * 4));
  return limbs;
}

export { STATE_BYTES, PACKET_BYTES as SFP1_BYTES };
