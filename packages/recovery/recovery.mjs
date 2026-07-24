// Portable recipient address and chain-recovery V2 API. No Node built-ins,
// Buffer, network access, or storage are required by this entrypoint.
import {
  ADDRESS_SCHEMA, BABYJUB_BASE8, BABYJUB_SUBGROUP_ORDER, FR_MODULUS, OUTPUT_RECORD_BYTES, PortableCoreError,
  RECOVERY_RECORD_CIPHERTEXT_BYTES, RECOVERY_RECORD_PADDING_BYTES, RECORD_VERSION,
  babyJubMul, bytes, bytesToHex, deriveBabyJubScalar, deriveOutputNote, deriveRecipientAuthority, deriveRecipientNote, equalBytes, hex32,
  hexToBytes, isBytes, nonzeroFr, packBabyJubPoint, recoveryMasks, unpackBabyJubPoint,
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
const randomScalar = (rng) => {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const candidate = BigInt(`0x${bytesToHex(random(rng, 32))}`);
    if (candidate > 0n && candidate < BABYJUB_SUBGROUP_ORDER) return candidate;
  }
  fail('CSPRNG_FAILURE', 'CSPRNG did not produce a canonical nonzero BabyJubJub scalar');
};

/** Wrap a genuine WebCrypto CSPRNG; it fails closed on absent or malformed APIs. */
export function createWebCryptoRandomSource(crypto = globalThis.crypto) {
  if (crypto === null || typeof crypto !== 'object' || typeof crypto.getRandomValues !== 'function') fail('CSPRNG_UNAVAILABLE', 'WebCrypto getRandomValues is unavailable');
  return Object.freeze({ bytes(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > 65_536) fail('CSPRNG_FAILURE', 'invalid WebCrypto random-byte request');
    try { return crypto.getRandomValues(new Uint8Array(length)); } catch { fail('CSPRNG_FAILURE', 'WebCrypto getRandomValues failed'); }
  } });
}

async function assertAddress(address) {
  exactKeys(address, 'recipient address', ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema', 'spendPublicKey']);
  if (address.schema !== ADDRESS_SCHEMA) fail('UNSUPPORTED_ADDRESS_SCHEMA', 'recipient address schema is unsupported');
  const profileId = identifier(address.profileId, 'recipient address profileId'); const instanceId = identifier(address.instanceId, 'recipient address instanceId');
  const ak = field(address.ak, 'recipient address ak'); const spendPublicKey = identifier(address.spendPublicKey, 'recipient address spend public key'); const recoveryPublicKey = identifier(address.recoveryPublicKey, 'recipient address recovery public key');
  try {
    unpackBabyJubPoint(hexToBytes(spendPublicKey)); unpackBabyJubPoint(hexToBytes(recoveryPublicKey));
  } catch (error) { translate(error); }
  const expectedAk = await deriveRecipientAuthority({ profileId, instanceId, spendPublicKey, recoveryPublicKey });
  if (ak !== expectedAk) fail('ADDRESS_AUTHORITY_MISMATCH', 'recipient address authority does not bind its spend and recovery public keys');
  return Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak, spendPublicKey, recoveryPublicKey });
}

function normalizeDerivationInput(input, label) {
  oneOfKeys(input, label, [['instanceId', 'profileId', 'seed']]);
  return { seed: seed32(input.seed), profileId: identifier(input.profileId, 'wallet profileId'), instanceId: identifier(input.instanceId, 'wallet instanceId') };
}

/** Derive profile- and instance-separated private wallet material from a seed. */
export async function deriveRecipientWallet(input) {
  const { seed, profileId, instanceId } = normalizeDerivationInput(input, 'wallet derivation input');
  try {
    const spendSecret = deriveBabyJubScalar(seed, 'shield.cash/wallet-spend/v2\0', profileId, instanceId).toString(16).padStart(64, '0');
    const recoverySecret = deriveBabyJubScalar(seed, 'shield.cash/wallet-recovery/v2\0', profileId, instanceId).toString(16).padStart(64, '0');
    const spendPublicKey = bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(`0x${spendSecret}`))));
    const recoveryPublicKey = bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(`0x${recoverySecret}`))));
    const authority = await deriveRecipientAuthority({ profileId, instanceId, spendPublicKey, recoveryPublicKey });
    const address = Object.freeze({ schema: ADDRESS_SCHEMA, profileId, instanceId, ak: authority, spendPublicKey, recoveryPublicKey });
    return Object.freeze({ address, spendSecret, recoverySecret });
  } catch (error) { translate(error); }
}

/** Derive the public recipient address without exposing spend or scan material. */
export async function deriveRecipientAddress(input) { return (await deriveRecipientWallet(input)).address; }

/** Construct a public recipient output and its exact 192-byte recovery record.
 * The recipient point remains private witness material: serializing a stable
 * address key would link all notes received by that address. */
export async function constructRecipientOutput(input) {
  oneOfKeys(input, 'output construction input', [
    ['address', 'kind', 'slot'], ['address', 'kind', 'rng', 'slot'],
  ]);
  const address = await assertAddress(input.address); const recordKind = kind(input.kind); const recordSlot = slot(input.slot);
  if (recordKind === 'withdrawal') fail('UNSUPPORTED_KIND', 'withdrawal has no active recipient output');
  const rng = input.rng === undefined ? createWebCryptoRandomSource() : input.rng;
  if (rng === null || typeof rng !== 'object' || typeof rng.bytes !== 'function') fail('INVALID_RNG', 'rng must expose bytes(length)');
  try {
    const rho = randomField(rng, 'rho'); const r = randomField(rng, 'r');
    const output = await deriveOutputNote({ profileId: address.profileId, instanceId: address.instanceId, ak: address.ak, rho, r });
    if (recordSlot !== 0) fail('UNSUPPORTED_SLOT', 'the one-output G1 relation fixes the recovery record slot to zero');
    const recipientPoint = unpackBabyJubPoint(hexToBytes(address.recoveryPublicKey));
    const ephemeralScalar = randomScalar(rng); const ephemeralPoint = babyJubMul(BABYJUB_BASE8, ephemeralScalar); const sharedPoint = babyJubMul(recipientPoint, ephemeralScalar);
    const masks = recoveryMasks({ profileId: address.profileId, instanceId: address.instanceId, outputCm: output.cm, outputAk: output.ak, recoveryPoint: recipientPoint, ephemeralPoint, sharedPoint, kindCode: KIND_CODE[recordKind] });
    const ciphertextRho = (BigInt(`0x${rho}`) + masks.rhoMask) % FR_MODULUS; const ciphertextR = (BigInt(`0x${r}`) + masks.rMask) % FR_MODULUS;
    const authentication = masks.authentication(ciphertextRho, ciphertextR);
    const record = bytes(Uint8Array.of(RECORD_VERSION, recordSlot), packBabyJubPoint(ephemeralPoint), hexToBytes(ciphertextRho.toString(16).padStart(64, '0')), hexToBytes(ciphertextR.toString(16).padStart(64, '0')), hexToBytes(authentication), new Uint8Array(RECOVERY_RECORD_PADDING_BYTES));
    if (record.length !== OUTPUT_RECORD_BYTES) fail('INTERNAL_SIZE', 'internal recovery record size mismatch');
    const spendPoint = unpackBabyJubPoint(hexToBytes(address.spendPublicKey));
    return Object.freeze({ output: Object.freeze(output), record, recoveryWitness: Object.freeze({
      ephemeralScalar: ephemeralScalar.toString(10),
      spendPoint: Object.freeze({ x: spendPoint[0].toString(10), y: spendPoint[1].toString(10) }),
      recoveryPoint: Object.freeze({ x: recipientPoint[0].toString(10), y: recipientPoint[1].toString(10) }),
    }) });
  } catch (error) { translate(error); }
}

function decryptRecord({ recoverySecret, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm, outputAk, record }) {
  const bytesRecord = validBytes(record, OUTPUT_RECORD_BYTES, 'record');
  if (bytesRecord[0] !== RECORD_VERSION || bytesRecord[1] !== recordSlot) fail('RECORD_HEADER', 'record version or output slot mismatch');
  if (recordSlot !== 0) fail('RECORD_HEADER', 'record slot is unsupported by the one-output relation');
  if (!equalBytes(bytesRecord.subarray(OUTPUT_RECORD_BYTES - RECOVERY_RECORD_PADDING_BYTES), new Uint8Array(RECOVERY_RECORD_PADDING_BYTES))) fail('RECORD_PADDING', 'record padding must be zero');
  const recoveryPoint = babyJubMul(BABYJUB_BASE8, BigInt(`0x${recoverySecret}`));
  const ephemeralPoint = unpackBabyJubPoint(bytesRecord.subarray(2, 34)); const sharedPoint = babyJubMul(ephemeralPoint, BigInt(`0x${recoverySecret}`));
  const ciphertextRho = BigInt(`0x${bytesToHex(bytesRecord.subarray(34, 66))}`); const ciphertextR = BigInt(`0x${bytesToHex(bytesRecord.subarray(66, 98))}`); const authentication = bytesToHex(bytesRecord.subarray(98, 130));
  if (ciphertextRho >= FR_MODULUS || ciphertextR >= FR_MODULUS) fail('RECORD_AUTHENTICATION_FAILED', 'record authentication failed');
  const masks = recoveryMasks({ profileId, instanceId, outputCm, outputAk, recoveryPoint, ephemeralPoint, sharedPoint, kindCode: KIND_CODE[recordKind] });
  if (authentication !== masks.authentication(ciphertextRho, ciphertextR)) fail('RECORD_AUTHENTICATION_FAILED', 'record authentication failed');
  return { rho: ((ciphertextRho - masks.rhoMask + FR_MODULUS) % FR_MODULUS).toString(16).padStart(64, '0'), r: ((ciphertextR - masks.rMask + FR_MODULUS) % FR_MODULUS).toString(16).padStart(64, '0') };
}

/** Decrypt, recompute, and validate a record from local seed and serialized chain fields. */
export async function recoverRecipientOutput(input) {
  oneOfKeys(input, 'recovery input', [['instanceId', 'kind', 'outputCommitment', 'profileId', 'record', 'seed', 'slot']]);
  const profileId = identifier(input.profileId, 'recovery profileId'); const instanceId = identifier(input.instanceId, 'recovery instanceId');
  const recordKind = kind(input.kind); const recordSlot = slot(input.slot); const seed = seed32(input.seed); const outputCommitment = field(input.outputCommitment, 'recovery output commitment');
  try {
    const wallet = await deriveRecipientWallet({ seed, profileId, instanceId });
    const decoded = decryptRecord({ recoverySecret: wallet.recoverySecret, kind: recordKind, slot: recordSlot, profileId, instanceId, outputCm: outputCommitment, outputAk: wallet.address.ak, record: input.record });
    const note = await deriveRecipientNote({ profileId, instanceId, spendSecret: wallet.spendSecret, recoveryPublicKey: wallet.address.recoveryPublicKey, rho: decoded.rho, r: decoded.r });
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
