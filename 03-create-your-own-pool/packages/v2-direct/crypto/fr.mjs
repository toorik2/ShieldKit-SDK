import { FR_MODULUS } from '../constants.mjs';

export class FrError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FrError';
  }
}

const fail = (message) => {
  throw new FrError(message);
};

const HEX_32 = /^[0-9a-f]{64}$/;

export function assertFr(value, label = 'Fr') {
  if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) {
    fail(`${label} is not a canonical BN254 scalar`);
  }
  return value;
}

export function frFromBytes(bytes, label = 'Fr') {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    fail(`${label} encoding must contain exactly 32 bytes`);
  }
  const value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  if (value >= FR_MODULUS) fail(`${label} is noncanonical ( ≥ r )`);
  return value;
}

export function frToBytes(value) {
  assertFr(value);
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

export function frFromHex(value, label = 'Fr') {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hex bytes`);
  }
  return frFromBytes(Buffer.from(value, 'hex'), label);
}

export function frToHex(value) {
  return frToBytes(value).toString('hex');
}

/** OS2IP big-endian of 16 bytes → Fr (always < 2^128 < r). */
export function os2ipBe16(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    fail('OS2IP limb requires exactly 16 bytes');
  }
  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

/** Split a 32-byte SHA-256 digest into two 128-bit public-input limbs (big-endian each half). */
export function sha256DigestLimbs(digest) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    fail('SHA-256 digest must contain exactly 32 bytes');
  }
  const buf = Buffer.from(digest);
  return Object.freeze([os2ipBe16(buf.subarray(0, 16)), os2ipBe16(buf.subarray(16, 32))]);
}

export function identifierLimbs(hex32, label = 'identifier') {
  if (typeof hex32 !== 'string' || !HEX_32.test(hex32)) {
    fail(`${label} must be 32 lowercase hex bytes`);
  }
  return sha256DigestLimbs(Buffer.from(hex32, 'hex'));
}
