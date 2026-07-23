// Typed public-address note construction and chain-recovery primitive.
// This module is local wallet code; it does not prove, broadcast, or make a
// qualification/privacy claim. Its 192-byte record is only byte-bound by G1.
import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  diffieHellman, hkdfSync, randomBytes,
} from 'node:crypto';
import {
  FR_MODULUS, OUTPUT_RECORD_BYTES, createShieldedTransitionReference, frFromHex, frToHex,
} from '../core/shielded-transition.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const KIND_CODE = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const RECORD_VERSION = 1;
const RECORD_CIPHERTEXT_BYTES = 128;
const RECORD_PADDING_BYTES = 2;
const ADDRESS_SCHEMA = 'shield.cash/recipient-address/v1';

export class RecoveryError extends Error {
  constructor(message) { super(message); this.name = 'RecoveryError'; }
}

const fail = (message) => { throw new RecoveryError(message); };
const sha256 = (...parts) => {
  const hash = createHash('sha256'); for (const part of parts) hash.update(part); return hash.digest();
};
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) fail(`${label} has missing or unknown properties`);
};
const oneOfKeys = (value, label, alternatives) => {
  for (const expected of alternatives) {
    const actual = value !== null && !Array.isArray(value) && typeof value === 'object' ? Object.keys(value).sort() : [];
    const wanted = [...expected].sort();
    if (actual.length === wanted.length && actual.every((key, i) => key === wanted[i])) return;
  }
  fail(`${label} has missing or unknown properties`);
};
const hex32 = (value, label) => {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`);
  return value;
};
const field = (value, label, nonzero = true) => {
  try {
    const parsed = frFromHex(value, label);
    if (nonzero && parsed === 0n) fail(`${label} must be nonzero`);
    return frToHex(parsed);
  } catch (error) {
    if (error instanceof RecoveryError) throw error;
    fail(error.message);
  }
};
const index = (value) => {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) fail('addressIndex must be a u32');
  return value;
};
const seed32 = (value) => {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail('wallet seed must contain exactly 32 bytes');
  return value;
};
const kind = (value) => {
  if (!KINDS.includes(value)) fail('record kind is unsupported');
  return value;
};
const slot = (value) => {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) fail('record slot must be a byte');
  return value;
};
const u32be = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const rawPrivateKey = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('X25519 private material must contain exactly 32 bytes');
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, bytes]), format: 'der', type: 'pkcs8' });
};
const rawPublicKey = (bytes) => {
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) fail('X25519 public material must contain exactly 32 bytes');
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, bytes]), format: 'der', type: 'spki' });
};
const publicRaw = (privateKey) => Buffer.from(createPublicKey(privateKey).export({ format: 'der', type: 'spki' })).subarray(-32);
const random = (rng, length) => {
  let bytes;
  try { bytes = rng === undefined ? randomBytes(length) : rng.bytes(length); }
  catch { fail('CSPRNG failed'); }
  if (!Buffer.isBuffer(bytes) || bytes.length !== length) fail('CSPRNG returned an invalid byte string');
  return Buffer.from(bytes);
};
const randomField = (rng, label) => {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const bytes = random(rng, 32); const value = BigInt(`0x${bytes.toString('hex')}`);
    if (value > 0n && value < FR_MODULUS) return frToHex(value);
  }
  fail(`CSPRNG did not produce a canonical nonzero ${label}`);
};

function assertAddress(address) {
  exactKeys(address, 'recipient address', ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema']);
  if (address.schema !== ADDRESS_SCHEMA) fail('recipient address schema is unsupported');
  const profileId = hex32(address.profileId, 'recipient address profileId');
  const instanceId = hex32(address.instanceId, 'recipient address instanceId');
  const ak = field(address.ak, 'recipient address ak');
  hex32(address.recoveryPublicKey, 'recipient address recovery public key');
  return Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak, recoveryPublicKey: address.recoveryPublicKey });
}

function aad({ kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm }) {
  return Buffer.concat([
    Buffer.from('shield.cash/recovery-record/v1\0SCAR', 'utf8'), Buffer.of(RECORD_VERSION, 2, KIND_CODE[recordKind], 0, recordSlot),
    Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'), Buffer.from(outputCm, 'hex'),
  ]);
}

function deriveScalar(seed, label, profileId, instanceId, addressIndex) {
  const digest = sha256(Buffer.from(label, 'utf8'), seed, Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'), u32be(addressIndex));
  return frToHex((BigInt(`0x${digest.toString('hex')}`) % (FR_MODULUS - 1n)) + 1n);
}

/** Derive profile- and instance-separated private wallet material from a seed. */
export async function deriveRecipientWallet(input) {
  exactKeys(input, 'wallet derivation input', ['addressIndex', 'instanceId', 'profileId', 'seed']);
  const profileId = hex32(input.profileId, 'wallet profileId'); const instanceId = hex32(input.instanceId, 'wallet instanceId');
  const addressIndex = index(input.addressIndex); const seed = seed32(input.seed);
  const spendSecret = deriveScalar(seed, 'shield.cash/wallet-spend/v1\0', profileId, instanceId, addressIndex);
  const recoveryPrivateKey = sha256(Buffer.from('shield.cash/wallet-recovery-x25519/v1\0', 'utf8'), seed, Buffer.from(profileId, 'hex'), Buffer.from(instanceId, 'hex'), u32be(addressIndex));
  const reference = await createShieldedTransitionReference();
  const authority = reference.deriveNote({ profileId, instanceId, sk: spendSecret, rho: frToHex(1n), r: frToHex(1n) }).ak;
  field(authority, 'derived recipient authority key');
  const address = Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak: authority, recoveryPublicKey: publicRaw(rawPrivateKey(recoveryPrivateKey)).toString('hex') });
  return Object.freeze({ address, spendSecret, recoveryPrivateKey: Buffer.from(recoveryPrivateKey) });
}

/** Derive the public recipient address without exposing spend or scan material. */
export async function deriveRecipientAddress(input) {
  exactKeys(input, 'address derivation input', ['addressIndex', 'instanceId', 'profileId', 'seed']);
  return (await deriveRecipientWallet(input)).address;
}

/** Construct a recipient-bound public output and its exact 192-byte recovery record. */
export async function constructRecipientOutput(input) {
  oneOfKeys(input, 'output construction input', [
    ['address', 'kind', 'slot'], ['address', 'kind', 'rng', 'slot'],
  ]);
  const address = assertAddress(input.address); const recordKind = kind(input.kind); const recordSlot = slot(input.slot);
  if (recordKind === 'withdrawal') fail('withdrawal has no active recipient output');
  if (input.rng !== undefined && (input.rng === null || Array.isArray(input.rng) || typeof input.rng !== 'object' || typeof input.rng.bytes !== 'function')) fail('rng must expose bytes(length)');
  const rho = randomField(input.rng, 'rho'); const r = randomField(input.rng, 'r');
  const reference = await createShieldedTransitionReference();
  const output = reference.deriveOutputNote({ profileId: address.profileId, instanceId: address.instanceId, ak: address.ak, rho, r });
  const ephemeralPrivate = rawPrivateKey(random(input.rng, 32)); const nonce = random(input.rng, 12);
  let shared;
  try { shared = diffieHellman({ privateKey: ephemeralPrivate, publicKey: rawPublicKey(Buffer.from(address.recoveryPublicKey, 'hex')) }); }
  catch { fail('recipient recovery public key is invalid'); }
  const associatedData = aad({ kind: recordKind, slot: recordSlot, profileId: address.profileId, instanceId: address.instanceId, outputCm: output.cm });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from(address.profileId, 'hex'), associatedData, 32));
  const plaintext = Buffer.concat([Buffer.from(address.profileId, 'hex'), Buffer.from(address.instanceId, 'hex'), Buffer.from(rho, 'hex'), Buffer.from(r, 'hex')]);
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(associatedData, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  if (ciphertext.length !== RECORD_CIPHERTEXT_BYTES) fail('internal recovery ciphertext size mismatch');
  const record = Buffer.concat([Buffer.of(RECORD_VERSION, recordSlot), publicRaw(ephemeralPrivate), nonce, cipher.getAuthTag(), ciphertext, Buffer.alloc(RECORD_PADDING_BYTES)]);
  if (record.length !== OUTPUT_RECORD_BYTES) fail('internal recovery record size mismatch');
  return Object.freeze({ output: Object.freeze(output), record });
}

function decryptRecord({ recoveryPrivateKey, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm, record }) {
  if (!Buffer.isBuffer(record) || record.length !== OUTPUT_RECORD_BYTES) fail('record must contain exactly 192 bytes');
  if (record[0] !== RECORD_VERSION || record[1] !== recordSlot) fail('record version or output slot mismatch');
  if (!record.subarray(OUTPUT_RECORD_BYTES - RECORD_PADDING_BYTES).equals(Buffer.alloc(RECORD_PADDING_BYTES))) fail('record padding must be zero');
  const ephemeral = record.subarray(2, 34); const nonce = record.subarray(34, 46); const tag = record.subarray(46, 62); const ciphertext = record.subarray(62, 190);
  let shared;
  try { shared = diffieHellman({ privateKey: rawPrivateKey(recoveryPrivateKey), publicKey: rawPublicKey(ephemeral) }); }
  catch { fail('record authentication failed'); }
  const associatedData = aad({ kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.from(profileId, 'hex'), associatedData, 32));
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(associatedData, { plaintextLength: ciphertext.length }); decipher.setAuthTag(tag);
  let plaintext;
  try { plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]); } catch { fail('record authentication failed'); }
  if (plaintext.length !== RECORD_CIPHERTEXT_BYTES) fail('record plaintext length is invalid');
  const decoded = { profileId: plaintext.subarray(0, 32).toString('hex'), instanceId: plaintext.subarray(32, 64).toString('hex'), rho: plaintext.subarray(64, 96).toString('hex'), r: plaintext.subarray(96, 128).toString('hex') };
  if (decoded.profileId !== profileId || decoded.instanceId !== instanceId) fail('record plaintext identity mismatch');
  return decoded;
}

/** Decrypt, recompute, and validate a record using only local seed/index material. */
export async function recoverRecipientOutput(input) {
  exactKeys(input, 'recovery input', ['addressIndex', 'instanceId', 'kind', 'output', 'profileId', 'record', 'seed', 'slot']);
  const profileId = hex32(input.profileId, 'recovery profileId'); const instanceId = hex32(input.instanceId, 'recovery instanceId');
  const recordKind = kind(input.kind); const recordSlot = slot(input.slot); const addressIndex = index(input.addressIndex); const seed = seed32(input.seed);
  exactKeys(input.output, 'recovery output', ['ak', 'cm', 'r', 'rho']);
  const supplied = Object.freeze({ ak: field(input.output.ak, 'recovery output ak'), cm: field(input.output.cm, 'recovery output cm'), rho: field(input.output.rho, 'recovery output rho'), r: field(input.output.r, 'recovery output r') });
  const wallet = await deriveRecipientWallet({ seed, addressIndex, profileId, instanceId });
  if (wallet.address.ak !== supplied.ak) fail('output authority key does not match recipient address');
  const decoded = decryptRecord({ recoveryPrivateKey: wallet.recoveryPrivateKey, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm: supplied.cm, record: input.record });
  field(decoded.rho, 'record rho'); field(decoded.r, 'record r');
  const reference = await createShieldedTransitionReference();
  const output = reference.deriveOutputNote({ profileId, instanceId, ak: wallet.address.ak, rho: decoded.rho, r: decoded.r });
  if (output.cm !== supplied.cm || output.rho !== supplied.rho || output.r !== supplied.r) fail('record plaintext does not match public output');
  const note = reference.deriveNote({ profileId, instanceId, sk: wallet.spendSecret, rho: decoded.rho, r: decoded.r });
  if (note.ak !== supplied.ak || note.cm !== supplied.cm) fail('recomputed spendable note does not match public output');
  return Object.freeze(note);
}

export const RECOVERY_RECORD_LAYOUT = Object.freeze({ bytes: OUTPUT_RECORD_BYTES, version: RECORD_VERSION, ciphertextBytes: RECORD_CIPHERTEXT_BYTES, paddingBytes: RECORD_PADDING_BYTES });
export const RECIPIENT_ADDRESS_SCHEMA = ADDRESS_SCHEMA;
