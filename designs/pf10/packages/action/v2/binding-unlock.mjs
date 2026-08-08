import {
  decodeAuthenticationInstructions,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  ACTION_PACKET_BYTES,
} from './packet.mjs';

export const DIRECT_V2_BINDING_PACKET_PREFIX_BYTES =
  ACTION_PACKET_BYTES + 3;
export const DIRECT_V2_BINDING_P2SH32_LOCK_BYTES = 35;
export const DIRECT_V2_MAX_UNLOCKING_BYTECODE_BYTES = 10_000;

const PACKET_MAGIC = Buffer.from('SDA2', 'ascii');
const PACKET_PUSH_PREFIX = Buffer.from([0x4d, 0x28, 0x02]);

export class DirectV2BindingUnlockError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2BindingUnlockError';
  }
}

const fail = (message) => {
  throw new DirectV2BindingUnlockError(message);
};

function exactKeys(value, label, required, optional = []) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const actual = Object.keys(value);
  if (
    required.some((key) => !actual.includes(key))
    || actual.some((key) => !allowed.has(key))
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function bytes(value, label, { nonempty = false } = {}) {
  if (
    !(value instanceof Uint8Array)
    || (nonempty && value.length === 0)
  ) {
    fail(`${label} must be ${nonempty ? 'nonempty ' : ''}bytes`);
  }
  return Buffer.from(value);
}

function packetBytes(value, label) {
  const packet = bytes(value, label);
  if (
    packet.length !== ACTION_PACKET_BYTES
    || !packet.subarray(0, PACKET_MAGIC.length).equals(PACKET_MAGIC)
  ) {
    fail(
      `${label} must be an exact ${ACTION_PACKET_BYTES}-byte SDA2 packet`,
    );
  }
  return packet;
}

function redeemFromMinimalPush(value) {
  const push = bytes(value, 'binding redeem push', { nonempty: true });
  const instructions = decodeAuthenticationInstructions(push);
  if (instructions.length !== 1) {
    fail(
      'binding packet prefix must be followed by exactly one redeem push with no extra bytes',
    );
  }
  const [instruction] = instructions;
  let redeem;
  if (
    'data' in instruction
    && !('malformed' in instruction)
  ) {
    redeem = Buffer.from(instruction.data);
  } else if (instruction.opcode === 0x4f) {
    redeem = Buffer.from([0x81]);
  } else if (
    instruction.opcode >= 0x51
    && instruction.opcode <= 0x60
  ) {
    redeem = Buffer.from([instruction.opcode - 0x50]);
  } else {
    fail('binding redeem must use a well-formed push instruction');
  }
  if (
    redeem.length === 0
    || !Buffer.from(encodeDataPush(redeem)).equals(push)
  ) {
    fail('binding redeem must be nonempty and minimally pushed');
  }
  return redeem;
}

export function deriveDirectV2BindingP2sh32Lock(redeemScript) {
  const redeem = bytes(
    redeemScript,
    'binding redeem script',
    { nonempty: true },
  );
  return Buffer.from(
    encodeLockingBytecodeP2sh32(hash256(redeem)),
  );
}

export function verifyDirectV2BindingP2sh32Lock(value) {
  exactKeys(
    value,
    'binding P2SH32 verification',
    ['redeemScript', 'sourceLockingBytecode'],
  );
  const redeem = bytes(
    value.redeemScript,
    'binding redeem script',
    { nonempty: true },
  );
  const sourceLock = bytes(
    value.sourceLockingBytecode,
    'binding source locking bytecode',
  );
  const expected = deriveDirectV2BindingP2sh32Lock(redeem);
  if (
    sourceLock.length !== DIRECT_V2_BINDING_P2SH32_LOCK_BYTES
    || sourceLock[0] !== 0xaa
    || sourceLock[1] !== 0x20
    || sourceLock[34] !== 0x87
    || !sourceLock.equals(expected)
  ) {
    fail(
      'binding redeem hash256 does not match the exact source P2SH32 locking bytecode',
    );
  }
  return Buffer.from(sourceLock);
}

export function encodeDirectV2BindingUnlock(value) {
  exactKeys(
    value,
    'binding unlock',
    ['packet', 'redeemScript', 'sourceLockingBytecode'],
  );
  const packet = packetBytes(value.packet, 'binding action packet');
  const redeem = bytes(
    value.redeemScript,
    'binding redeem script',
    { nonempty: true },
  );
  verifyDirectV2BindingP2sh32Lock({
    redeemScript: redeem,
    sourceLockingBytecode: value.sourceLockingBytecode,
  });
  const unlock = Buffer.concat([
    PACKET_PUSH_PREFIX,
    packet,
    Buffer.from(encodeDataPush(redeem)),
  ]);
  if (unlock.length > DIRECT_V2_MAX_UNLOCKING_BYTECODE_BYTES) {
    fail(
      `binding unlock exceeds ${DIRECT_V2_MAX_UNLOCKING_BYTECODE_BYTES} bytes`,
    );
  }
  return unlock;
}

export function decodeDirectV2BindingUnlock(value) {
  exactKeys(
    value,
    'binding unlock inspection',
    ['sourceLockingBytecode', 'unlockingBytecode'],
    ['expectedPacket'],
  );
  const unlock = bytes(
    value.unlockingBytecode,
    'binding unlocking bytecode',
    { nonempty: true },
  );
  if (unlock.length > DIRECT_V2_MAX_UNLOCKING_BYTECODE_BYTES) {
    fail(
      `binding unlock exceeds ${DIRECT_V2_MAX_UNLOCKING_BYTECODE_BYTES} bytes`,
    );
  }
  if (
    unlock.length <= DIRECT_V2_BINDING_PACKET_PREFIX_BYTES
    || !unlock.subarray(0, 3).equals(PACKET_PUSH_PREFIX)
  ) {
    fail(
      `binding unlock must begin with canonical PUSHDATA2(${ACTION_PACKET_BYTES})`,
    );
  }
  const packet = packetBytes(
    unlock.subarray(3, DIRECT_V2_BINDING_PACKET_PREFIX_BYTES),
    'binding action packet',
  );
  if (
    value.expectedPacket !== undefined
    && !packet.equals(
      packetBytes(value.expectedPacket, 'expected action packet'),
    )
  ) {
    fail('binding action packet differs from the expected packet');
  }
  const redeemScript = redeemFromMinimalPush(
    unlock.subarray(DIRECT_V2_BINDING_PACKET_PREFIX_BYTES),
  );
  const sourceLockingBytecode = verifyDirectV2BindingP2sh32Lock({
    redeemScript,
    sourceLockingBytecode: value.sourceLockingBytecode,
  });
  return Object.freeze({
    packet,
    redeemScript,
    sourceLockingBytecode,
  });
}
