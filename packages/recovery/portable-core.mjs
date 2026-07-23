// Runtime-neutral V1 byte primitives. This file intentionally has no Node or
// WebCrypto imports: it runs in browsers, workers, and JavaScript Android hosts.
import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { poseidon6, poseidon7, poseidon9 } from 'poseidon-lite';

export const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const OUTPUT_RECORD_BYTES = 192;
export const RECOVERY_RECORD_CIPHERTEXT_BYTES = 128;
export const RECOVERY_RECORD_PADDING_BYTES = 2;
export const ADDRESS_SCHEMA = 'shield.cash/recipient-address/v1';
export const RECORD_VERSION = 1;

const encoder = new TextEncoder();
const HEX_32 = /^[0-9a-f]{64}$/;

export class PortableCoreError extends Error {
  constructor(code, message) { super(message); this.name = 'PortableCoreError'; this.code = code; }
}

export const failCore = (code, message) => { throw new PortableCoreError(code, message); };
export const utf8 = (value) => encoder.encode(value);
export const bytes = (...parts) => {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length); let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
export const equalBytes = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);
export const isBytes = (value, length) => value instanceof Uint8Array && (length === undefined || value.length === length);
export const hexToBytes = (value, label = 'hexadecimal bytes') => {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) failCore('INVALID_ENCODING', `${label} must be lowercase hexadecimal`);
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return output;
};
export const bytesToHex = (value) => Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
export const hex32 = (value, label) => {
  if (typeof value !== 'string' || !HEX_32.test(value)) failCore('INVALID_IDENTIFIER', `${label} must be 32 lowercase hexadecimal bytes`);
  return value;
};
export const frFromHex = (value, label = 'Fr') => {
  if (typeof value !== 'string' || !HEX_32.test(value)) failCore('INVALID_FIELD', `${label} must be a 32-byte lowercase hex Fr encoding`);
  const parsed = BigInt(`0x${value}`);
  if (parsed >= FR_MODULUS) failCore('NONCANONICAL_FIELD', `${label} is noncanonical`);
  return parsed;
};
export const frToHex = (value) => {
  if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) failCore('INVALID_FIELD', 'Fr value is not canonical');
  return value.toString(16).padStart(64, '0');
};
export const nonzeroFr = (value, label) => {
  const parsed = frFromHex(value, label);
  if (parsed === 0n) failCore('ZERO_FIELD', `${label} must be nonzero`);
  return frToHex(parsed);
};
const hash = (...parts) => sha256(bytes(...parts));

/** A complete synchronous backend contract; all byte outputs are fresh Uint8Array values. */
export function assertCryptoBackend(backend) {
  if (backend === null || typeof backend !== 'object') failCore('INVALID_BACKEND', 'crypto backend must be an object');
  for (const method of ['getPublicKey', 'getSharedSecret', 'hkdfSha256', 'seal', 'open']) {
    if (typeof backend[method] !== 'function') failCore('INVALID_BACKEND', `crypto backend lacks ${method}`);
  }
  return backend;
}

/** Pure-JS audited primitives, usable in Node, browsers, workers, and Android JS hosts. */
export const NOBLE_CRYPTO_BACKEND = Object.freeze({
  getPublicKey(secret) { return new Uint8Array(x25519.getPublicKey(secret)); },
  getSharedSecret(secret, publicKey) { return new Uint8Array(x25519.getSharedSecret(secret, publicKey)); },
  hkdfSha256(shared, salt, info, length) { return new Uint8Array(hkdf(sha256, shared, salt, info, length)); },
  seal(key, nonce, aad, plaintext) { return new Uint8Array(chacha20poly1305(key, nonce, aad).encrypt(plaintext)); },
  open(key, nonce, aad, sealed) { return new Uint8Array(chacha20poly1305(key, nonce, aad).decrypt(sealed)); },
});

export const deriveScalar = (seed, label, profileId, instanceId) => {
  const digest = hash(utf8(label), seed, hexToBytes(profileId), hexToBytes(instanceId));
  return frToHex((BigInt(`0x${bytesToHex(digest)}`) % (FR_MODULUS - 1n)) + 1n);
};

function poseidonHash(tag, ...values) {
  for (const value of [tag, ...values]) if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) failCore('INVALID_FIELD', 'Poseidon input is not canonical Fr');
  const inputs = [tag, ...values];
  if (inputs.length === 6) return poseidon6(inputs);
  if (inputs.length === 7) return poseidon7(inputs);
  if (inputs.length === 9) return poseidon9(inputs);
  failCore('INTERNAL_POSEIDON_ARITY', 'unsupported V1 Poseidon input arity');
}

const identifierLimbs = (identifier, label) => {
  const value = hexToBytes(hex32(identifier, label));
  return [BigInt(`0x${bytesToHex(value.subarray(0, 16))}`), BigInt(`0x${bytesToHex(value.subarray(16, 32))}`)];
};

export async function deriveRecipientAuthority({ profileId, instanceId, spendSecret }) {
  const profile = identifierLimbs(profileId, 'recipient profileId');
  const instance = identifierLimbs(instanceId, 'recipient instanceId');
  const secret = nonzeroFr(spendSecret, 'recipient spend secret');
  return frToHex(poseidonHash(1001n, ...profile, ...instance, BigInt(`0x${secret}`)));
}

/** Exact V1 recipient output commitment, independent of the Node reference module. */
export async function deriveOutputNote({ profileId, instanceId, ak, rho, r }) {
  const profile = identifierLimbs(profileId, 'output note profileId');
  const instance = identifierLimbs(instanceId, 'output note instanceId');
  const authority = nonzeroFr(ak, 'output note ak'); const nonce = nonzeroFr(rho, 'output note rho'); const randomness = nonzeroFr(r, 'output note r');
  const cm = frToHex(poseidonHash(1002n, ...profile, ...instance, 10_000_000n, BigInt(`0x${authority}`), BigInt(`0x${nonce}`), BigInt(`0x${randomness}`)));
  if (cm === '0'.repeat(64)) failCore('ZERO_COMMITMENT', 'derived output note commitment is zero');
  return Object.freeze({ ak: authority, cm, rho: nonce, r: randomness });
}

/** Exact V1 spendable note fields after a recipient record is authenticated. */
export async function deriveRecipientNote({ profileId, instanceId, spendSecret, rho, r }) {
  const ak = await deriveRecipientAuthority({ profileId, instanceId, spendSecret });
  const output = await deriveOutputNote({ profileId, instanceId, ak, rho, r });
  const profile = identifierLimbs(profileId, 'note profileId');
  const instance = identifierLimbs(instanceId, 'note instanceId');
  const secret = nonzeroFr(spendSecret, 'note spend secret'); const nonce = nonzeroFr(rho, 'note rho');
  const nf = frToHex(poseidonHash(1003n, ...profile, ...instance, BigInt(`0x${secret}`), BigInt(`0x${nonce}`)));
  if (nf === '0'.repeat(64)) failCore('ZERO_NULLIFIER', 'derived nullifier is zero');
  return Object.freeze({ ...output, nf, sk: secret });
}

export const recoveryPrivateKey = (seed, profileId, instanceId) => hash(utf8('shield.cash/wallet-recovery-x25519/v1\0'), seed, hexToBytes(profileId), hexToBytes(instanceId));

export function recoveryAad({ kindCode, slot, profileId, instanceId, outputCm }) {
  return bytes(utf8('shield.cash/recovery-record/v1\0SCAR'), Uint8Array.of(RECORD_VERSION, 2, kindCode, 0, slot), hexToBytes(profileId), hexToBytes(instanceId), hexToBytes(outputCm));
}
