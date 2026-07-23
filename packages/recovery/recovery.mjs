// Portable recipient address and chain-recovery V1 API. No Node built-ins,
// Buffer, network access, or storage are required by this entrypoint.
import {
  ADDRESS_SCHEMA, FR_MODULUS, NOBLE_CRYPTO_BACKEND, OUTPUT_RECORD_BYTES, PortableCoreError,
  RECOVERY_RECORD_CIPHERTEXT_BYTES, RECOVERY_RECORD_PADDING_BYTES, RECORD_VERSION, assertCryptoBackend,
  bytes, bytesToHex, deriveOutputNote, deriveRecipientAuthority, deriveRecipientNote, deriveScalar, equalBytes, hex32,
  hexToBytes, isBytes, nonzeroFr, recoveryAad, recoveryPrivateKey,
} from './portable-core.mjs';

const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const KIND_CODE = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 });

export class RecoveryError extends Error {
  constructor(code, message) { super(message); this.name = 'RecoveryError'; this.code = code; }
}

const fail = (code, message) => { throw new RecoveryError(code, message); };
const translate = (error) => {
  if (error instanceof RecoveryError) throw error;
  if (error instanceof PortableCoreError) fail(error.code, error.message);
  fail('CRYPTOGRAPHIC_FAILURE', 'cryptographic operation failed');
};
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const oneOfKeys = (value, label, alternatives) => {
  for (const expected of alternatives) {
    const actual = value !== null && !Array.isArray(value) && typeof value === 'object' ? Object.keys(value).sort() : [];
    const wanted = [...expected].sort();
    if (actual.length === wanted.length && actual.every((key, index) => key === wanted[index])) return;
  }
  fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const optionalBackend = (value) => {
  try { return value === undefined ? NOBLE_CRYPTO_BACKEND : assertCryptoBackend(value); } catch (error) { translate(error); }
};
const seed32 = (value) => {
  if (!isBytes(value, 32)) fail('INVALID_SEED', 'wallet seed must contain exactly 32 bytes');
  return new Uint8Array(value);
};
const kind = (value) => {
  if (!KINDS.includes(value)) fail('UNSUPPORTED_KIND', 'record kind is unsupported');
  return value;
};
const slot = (value) => {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) fail('INVALID_SLOT', 'record slot must be a byte');
  return value;
};
const identifier = (value, label) => { try { return hex32(value, label); } catch (error) { translate(error); } };
const field = (value, label) => { try { return nonzeroFr(value, label); } catch (error) { translate(error); } };
const validBytes = (value, length, label) => {
  if (!isBytes(value, length)) fail('INVALID_BYTES', `${label} must contain exactly ${length} bytes`);
  return new Uint8Array(value);
};
const random = (rng, length) => {
  let output;
  try { output = rng.bytes(length); } catch { fail('CSPRNG_FAILURE', 'CSPRNG failed'); }
  if (!isBytes(output, length)) fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
  return new Uint8Array(output);
};
const randomField = (rng, label) => {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const candidate = BigInt(`0x${bytesToHex(random(rng, 32))}`);
    if (candidate > 0n && candidate < FR_MODULUS) return candidate.toString(16).padStart(64, '0');
  }
  fail('CSPRNG_FAILURE', `CSPRNG did not produce a canonical nonzero ${label}`);
};

/** Wrap a genuine WebCrypto CSPRNG; it fails closed on absent or malformed APIs. */
export function createWebCryptoRandomSource(crypto = globalThis.crypto) {
  if (crypto === null || typeof crypto !== 'object' || typeof crypto.getRandomValues !== 'function') fail('CSPRNG_UNAVAILABLE', 'WebCrypto getRandomValues is unavailable');
  return Object.freeze({ bytes(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > 65_536) fail('CSPRNG_FAILURE', 'invalid WebCrypto random-byte request');
    try { return crypto.getRandomValues(new Uint8Array(length)); } catch { fail('CSPRNG_FAILURE', 'WebCrypto getRandomValues failed'); }
  } });
}

function assertAddress(address) {
  exactKeys(address, 'recipient address', ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema']);
  if (address.schema !== ADDRESS_SCHEMA) fail('UNSUPPORTED_ADDRESS_SCHEMA', 'recipient address schema is unsupported');
  const profileId = identifier(address.profileId, 'recipient address profileId'); const instanceId = identifier(address.instanceId, 'recipient address instanceId');
  const ak = field(address.ak, 'recipient address ak'); const recoveryPublicKey = identifier(address.recoveryPublicKey, 'recipient address recovery public key');
  return Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak, recoveryPublicKey });
}

function normalizeDerivationInput(input, label) {
  oneOfKeys(input, label, [['instanceId', 'profileId', 'seed'], ['cryptoBackend', 'instanceId', 'profileId', 'seed']]);
  return { seed: seed32(input.seed), profileId: identifier(input.profileId, 'wallet profileId'), instanceId: identifier(input.instanceId, 'wallet instanceId'), backend: optionalBackend(input.cryptoBackend) };
}

/** Derive profile- and instance-separated private wallet material from a seed. */
export async function deriveRecipientWallet(input) {
  const { seed, profileId, instanceId, backend } = normalizeDerivationInput(input, 'wallet derivation input');
  try {
    const spendSecret = deriveScalar(seed, 'shield.cash/wallet-spend/v1\0', profileId, instanceId);
    const recoverySecret = recoveryPrivateKey(seed, profileId, instanceId);
    const authority = await deriveRecipientAuthority({ profileId, instanceId, spendSecret });
    const recoveryPublicKey = bytesToHex(validBytes(backend.getPublicKey(recoverySecret), 32, 'X25519 public key'));
    const address = Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak: authority, recoveryPublicKey });
    return Object.freeze({ address, spendSecret, recoveryPrivateKey: new Uint8Array(recoverySecret) });
  } catch (error) { translate(error); }
}

/** Derive the public recipient address without exposing spend or scan material. */
export async function deriveRecipientAddress(input) { return (await deriveRecipientWallet(input)).address; }

/** Construct a public recipient output and its exact 192-byte recovery record. */
export async function constructRecipientOutput(input) {
  oneOfKeys(input, 'output construction input', [
    ['address', 'kind', 'slot'], ['address', 'kind', 'rng', 'slot'],
    ['address', 'cryptoBackend', 'kind', 'slot'], ['address', 'cryptoBackend', 'kind', 'rng', 'slot'],
  ]);
  const address = assertAddress(input.address); const recordKind = kind(input.kind); const recordSlot = slot(input.slot);
  if (recordKind === 'withdrawal') fail('UNSUPPORTED_KIND', 'withdrawal has no active recipient output');
  const rng = input.rng === undefined ? createWebCryptoRandomSource() : input.rng;
  if (rng === null || typeof rng !== 'object' || typeof rng.bytes !== 'function') fail('INVALID_RNG', 'rng must expose bytes(length)');
  const backend = optionalBackend(input.cryptoBackend);
  try {
    const rho = randomField(rng, 'rho'); const r = randomField(rng, 'r');
    const output = await deriveOutputNote({ profileId: address.profileId, instanceId: address.instanceId, ak: address.ak, rho, r });
    const ephemeralPrivate = random(rng, 32); const nonce = random(rng, 12);
    const peer = hexToBytes(address.recoveryPublicKey); const ephemeralPublic = validBytes(backend.getPublicKey(ephemeralPrivate), 32, 'ephemeral X25519 public key');
    let shared;
    try { shared = validBytes(backend.getSharedSecret(ephemeralPrivate, peer), 32, 'X25519 shared secret'); } catch { fail('RECORD_AUTHENTICATION_FAILED', 'recipient recovery public key is invalid'); }
    const associatedData = recoveryAad({ kindCode: KIND_CODE[recordKind], slot: recordSlot, profileId: address.profileId, instanceId: address.instanceId, outputCm: output.cm });
    const key = validBytes(backend.hkdfSha256(shared, hexToBytes(address.profileId), associatedData, 32), 32, 'HKDF output');
    const plaintext = bytes(hexToBytes(address.profileId), hexToBytes(address.instanceId), hexToBytes(rho), hexToBytes(r));
    const sealed = validBytes(backend.seal(key, nonce, associatedData, plaintext), 144, 'ChaCha20-Poly1305 output');
    const record = bytes(Uint8Array.of(RECORD_VERSION, recordSlot), ephemeralPublic, nonce, sealed, new Uint8Array(RECOVERY_RECORD_PADDING_BYTES));
    if (record.length !== OUTPUT_RECORD_BYTES) fail('INTERNAL_SIZE', 'internal recovery record size mismatch');
    return Object.freeze({ output: Object.freeze(output), record });
  } catch (error) { translate(error); }
}

function decryptRecord({ recoveryPrivateKey, backend, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm, record }) {
  const bytesRecord = validBytes(record, OUTPUT_RECORD_BYTES, 'record');
  if (bytesRecord[0] !== RECORD_VERSION || bytesRecord[1] !== recordSlot) fail('RECORD_HEADER', 'record version or output slot mismatch');
  if (!equalBytes(bytesRecord.subarray(OUTPUT_RECORD_BYTES - RECOVERY_RECORD_PADDING_BYTES), new Uint8Array(RECOVERY_RECORD_PADDING_BYTES))) fail('RECORD_PADDING', 'record padding must be zero');
  const ephemeral = bytesRecord.subarray(2, 34); const nonce = bytesRecord.subarray(34, 46); const sealed = bytesRecord.subarray(46, 190);
  let shared;
  try { shared = validBytes(backend.getSharedSecret(recoveryPrivateKey, ephemeral), 32, 'X25519 shared secret'); } catch { fail('RECORD_AUTHENTICATION_FAILED', 'record authentication failed'); }
  const associatedData = recoveryAad({ kindCode: KIND_CODE[recordKind], slot: recordSlot, profileId, instanceId, outputCm });
  const key = validBytes(backend.hkdfSha256(shared, hexToBytes(profileId), associatedData, 32), 32, 'HKDF output');
  let plaintext;
  try { plaintext = validBytes(backend.open(key, nonce, associatedData, sealed), RECOVERY_RECORD_CIPHERTEXT_BYTES, 'record plaintext'); } catch { fail('RECORD_AUTHENTICATION_FAILED', 'record authentication failed'); }
  const decoded = { profileId: bytesToHex(plaintext.subarray(0, 32)), instanceId: bytesToHex(plaintext.subarray(32, 64)), rho: bytesToHex(plaintext.subarray(64, 96)), r: bytesToHex(plaintext.subarray(96, 128)) };
  if (decoded.profileId !== profileId || decoded.instanceId !== instanceId) fail('RECORD_IDENTITY', 'record plaintext identity mismatch');
  return decoded;
}

/** Decrypt, recompute, and validate a record from local seed and serialized chain fields. */
export async function recoverRecipientOutput(input) {
  oneOfKeys(input, 'recovery input', [
    ['instanceId', 'kind', 'outputCommitment', 'profileId', 'record', 'seed', 'slot'],
    ['cryptoBackend', 'instanceId', 'kind', 'outputCommitment', 'profileId', 'record', 'seed', 'slot'],
  ]);
  const profileId = identifier(input.profileId, 'recovery profileId'); const instanceId = identifier(input.instanceId, 'recovery instanceId');
  const recordKind = kind(input.kind); const recordSlot = slot(input.slot); const seed = seed32(input.seed); const outputCommitment = field(input.outputCommitment, 'recovery output commitment');
  const backend = optionalBackend(input.cryptoBackend);
  try {
    const wallet = await deriveRecipientWallet({ seed, profileId, instanceId, cryptoBackend: backend });
    const decoded = decryptRecord({ recoveryPrivateKey: wallet.recoveryPrivateKey, backend, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm: outputCommitment, record: input.record });
    const note = await deriveRecipientNote({ profileId, instanceId, spendSecret: wallet.spendSecret, rho: decoded.rho, r: decoded.r });
    if (note.cm !== outputCommitment) fail('COMMITMENT_MISMATCH', 'record plaintext does not match output commitment');
    return note;
  } catch (error) { translate(error); }
}

export const RECOVERY_RECORD_LAYOUT = Object.freeze({ bytes: OUTPUT_RECORD_BYTES, version: RECORD_VERSION, ciphertextBytes: RECOVERY_RECORD_CIPHERTEXT_BYTES, paddingBytes: RECOVERY_RECORD_PADDING_BYTES });

// Kept as a separate module so the packet codec can remain browser-safe while
// history recovery reuses the exact V1 record-opening primitive above.
export { CHAIN_HISTORY_LAYOUT, ChainHistoryRecoveryError, recoverAuthenticatedChainHistory, serializeChainHistoryActions } from './chain-history.mjs';
export { decodePortableActionPacket, decodePortableActionState, encodePortableActionPacket, encodePortableActionState } from './portable-action-packet.mjs';
export const RECIPIENT_ADDRESS_SCHEMA = ADDRESS_SCHEMA;
