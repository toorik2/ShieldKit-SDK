// Runtime-neutral V2 recovery primitives. This file intentionally has no Node or
// WebCrypto imports: it runs in browsers, workers, and JavaScript Android hosts.
import { sha256 } from '@noble/hashes/sha2.js';
import { poseidon6, poseidon7, poseidon9 } from 'poseidon-lite';

export const FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const OUTPUT_RECORD_BYTES = 192;
export const RECOVERY_RECORD_CIPHERTEXT_BYTES = 64;
// The recipient public point is deliberately not serialized. An address is
// stable for a seed/profile/instance, so publishing it on every output would
// make receipts to that address trivially linkable. The fixed record leaves
// its former 32-byte slot as mandatory zero padding instead.
export const RECOVERY_RECORD_PADDING_BYTES = 62;
export const ADDRESS_SCHEMA = 'shield.cash/recipient-address/v2';
export const RECORD_VERSION = 2;
export const BABYJUB_SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
export const BABYJUB_BASE8 = Object.freeze([
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]);

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

const mod = (value) => ((value % FR_MODULUS) + FR_MODULUS) % FR_MODULUS;
const pow = (base, exponent) => { let result = 1n; let value = mod(base); let power = exponent; while (power > 0n) { if (power & 1n) result = mod(result * value); value = mod(value * value); power >>= 1n; } return result; };
const inverse = (value) => { if (mod(value) === 0n) failCore('INVALID_POINT', 'BabyJubJub point has a zero addition denominator'); return pow(value, FR_MODULUS - 2n); };
const sqrt = (value) => {
  const target = mod(value); if (target === 0n) return 0n;
  if (pow(target, (FR_MODULUS - 1n) / 2n) !== 1n) return null;
  let q = FR_MODULUS - 1n; let s = 0n; while ((q & 1n) === 0n) { q >>= 1n; s += 1n; }
  let z = 2n; while (pow(z, (FR_MODULUS - 1n) / 2n) !== FR_MODULUS - 1n) z += 1n;
  let c = pow(z, q); let x = pow(target, (q + 1n) / 2n); let t = pow(target, q); let m = s;
  while (t !== 1n) { let i = 1n; let probe = mod(t * t); while (probe !== 1n) { probe = mod(probe * probe); i += 1n; if (i >= m) return null; } const b = pow(c, 1n << (m - i - 1n)); x = mod(x * b); c = mod(b * b); t = mod(t * c); m = i; }
  return x;
};

/** BabyJubJub arithmetic over the Circom/BN254 scalar field. These values and
 * encodings are deliberately identical to circomlib's BabyPbk/PointBits.
 *
 * Affine addition needs two exponentiation-based inversions. Recovery scans
 * multiply every valid ephemeral point by the account scan scalar, so doing
 * that inside a double-and-add loop makes normal history recovery need many
 * thousands of inversions. The internal representation below is the standard
 * unified projective formula for a twisted Edwards curve. It performs only one
 * inversion when the public affine result is requested. Inputs and outputs of
 * the public API remain exact affine field elements; this is an implementation
 * change only. This public-address/recovery code makes no constant-time claim.
 */
const BABYJUB_A = 168700n;
const BABYJUB_D = 168696n;
const extendedIdentity = () => [0n, 1n, 1n];
const extendedFromAffine = (point) => [mod(point[0]), mod(point[1]), 1n];
const extendedAdd = ([x1, y1, z1], [x2, y2, z2]) => {
  // Hisil et al. unified projective addition, specialized to a=168700,
  // d=168696. It agrees with circomlib's affine addPoint for every valid
  // BabyJubJub subgroup point while avoiding per-addition inversions.
  const z = mod(z1 * z2); const zz = mod(z * z);
  const xx = mod(x1 * x2); const yy = mod(y1 * y2);
  const dxy = mod(BABYJUB_D * xx * yy);
  const minus = mod(zz - dxy); const plus = mod(zz + dxy);
  const sum = mod((x1 + y1) * (x2 + y2) - xx - yy);
  return [mod(z * minus * sum), mod(z * plus * (yy - BABYJUB_A * xx)), mod(minus * plus)];
};
const affineFromExtended = ([x, y, z]) => {
  if (z === 0n) failCore('INVALID_POINT', 'BabyJubJub point has a zero projective denominator');
  const zInverse = inverse(z);
  return Object.freeze([mod(x * zInverse), mod(y * zInverse)]);
};
export const babyJubAdd = (left, right) => affineFromExtended(extendedAdd(extendedFromAffine(left), extendedFromAffine(right)));
export const babyJubMul = (point, scalar) => {
  if (!Array.isArray(point) || point.length !== 2 || typeof scalar !== 'bigint' || scalar < 0n) failCore('INVALID_POINT', 'invalid BabyJubJub multiplication input');
  let result = extendedIdentity(); let base = extendedFromAffine(point); let remaining = scalar;
  while (remaining > 0n) { if (remaining & 1n) result = extendedAdd(result, base); base = extendedAdd(base, base); remaining >>= 1n; }
  return affineFromExtended(result);
};
export const babyJubInSubgroup = (point) => {
  if (!Array.isArray(point) || point.length !== 2 || point.some((coordinate) => typeof coordinate !== 'bigint' || coordinate < 0n || coordinate >= FR_MODULUS)) return false;
  const [x, y] = point; if (mod(168700n * x * x + y * y) !== mod(1n + 168696n * x * x * y * y)) return false;
  const result = babyJubMul(point, BABYJUB_SUBGROUP_ORDER); return result[0] === 0n && result[1] === 1n && x !== 0n;
};
export const packBabyJubPoint = (point) => {
  if (!babyJubInSubgroup(point)) failCore('INVALID_POINT', 'BabyJubJub public point is not a nonidentity prime-subgroup point');
  const output = new Uint8Array(32); let y = point[1]; for (let index = 0; index < 32; index += 1) { output[index] = Number(y & 0xffn); y >>= 8n; }
  if (point[0] > (FR_MODULUS - 1n) / 2n) output[31] |= 0x80;
  return output;
};
export const unpackBabyJubPoint = (encoded) => {
  if (!isBytes(encoded, 32)) failCore('INVALID_POINT', 'BabyJubJub point encoding must contain 32 bytes');
  const bytesCopy = new Uint8Array(encoded); const negative = (bytesCopy[31] & 0x80) !== 0; bytesCopy[31] &= 0x7f;
  let y = 0n; for (let index = 31; index >= 0; index -= 1) y = (y << 8n) | BigInt(bytesCopy[index]);
  if (y >= FR_MODULUS) failCore('INVALID_POINT', 'BabyJubJub point encoding is noncanonical');
  const x2 = mod((1n - y * y) * inverse(168700n - 168696n * y * y)); const root = sqrt(x2);
  if (root === null) failCore('INVALID_POINT', 'BabyJubJub point encoding is off-curve');
  let x = root; if ((x > (FR_MODULUS - 1n) / 2n) !== negative) x = mod(-x);
  const point = Object.freeze([x, y]); if (!babyJubInSubgroup(point)) failCore('INVALID_POINT', 'BabyJubJub point is not a nonidentity prime-subgroup point'); return point;
};

export const deriveScalar = (seed, label, profileId, instanceId) => {
  const digest = hash(utf8(label), seed, hexToBytes(profileId), hexToBytes(instanceId));
  return frToHex((BigInt(`0x${bytesToHex(digest)}`) % (FR_MODULUS - 1n)) + 1n);
};
export const deriveBabyJubScalar = (seed, label, profileId, instanceId) => {
  const digest = hash(utf8(label), seed, hexToBytes(profileId), hexToBytes(instanceId));
  return (BigInt(`0x${bytesToHex(digest)}`) % (BABYJUB_SUBGROUP_ORDER - 1n)) + 1n;
};

function poseidonHash(tag, ...values) {
  for (const value of [tag, ...values]) if (typeof value !== 'bigint' || value < 0n || value >= FR_MODULUS) failCore('INVALID_FIELD', 'Poseidon input is not canonical Fr');
  const inputs = [tag, ...values];
  if (inputs.length === 6) return poseidon6(inputs);
  if (inputs.length === 7) return poseidon7(inputs);
  if (inputs.length === 9) return poseidon9(inputs);
  failCore('INTERNAL_POSEIDON_ARITY', 'unsupported V2 Poseidon input arity');
}

const identifierLimbs = (identifier, label) => {
  const value = hexToBytes(hex32(identifier, label));
  return [BigInt(`0x${bytesToHex(value.subarray(0, 16))}`), BigInt(`0x${bytesToHex(value.subarray(16, 32))}`)];
};

export async function deriveRecipientAuthority({ profileId, instanceId, spendPublicKey, recoveryPublicKey }) {
  const profile = identifierLimbs(profileId, 'recipient profileId');
  const instance = identifierLimbs(instanceId, 'recipient instanceId');
  const spendPoint = unpackBabyJubPoint(hexToBytes(hex32(spendPublicKey, 'recipient spend public key')));
  const recoveryPoint = unpackBabyJubPoint(hexToBytes(hex32(recoveryPublicKey, 'recipient recovery public key')));
  return frToHex(poseidonHash(1004n, ...profile, ...instance, spendPoint[0], spendPoint[1], recoveryPoint[0], recoveryPoint[1]));
}

/** Exact V2 recipient output commitment, independent of the Node reference module. */
export async function deriveOutputNote({ profileId, instanceId, ak, rho, r }) {
  const profile = identifierLimbs(profileId, 'output note profileId');
  const instance = identifierLimbs(instanceId, 'output note instanceId');
  const authority = nonzeroFr(ak, 'output note ak'); const nonce = nonzeroFr(rho, 'output note rho'); const randomness = nonzeroFr(r, 'output note r');
  const cm = frToHex(poseidonHash(1002n, ...profile, ...instance, 10_000_000n, BigInt(`0x${authority}`), BigInt(`0x${nonce}`), BigInt(`0x${randomness}`)));
  if (cm === '0'.repeat(64)) failCore('ZERO_COMMITMENT', 'derived output note commitment is zero');
  return Object.freeze({ ak: authority, cm, rho: nonce, r: randomness });
}

/** Exact V2 spendable note fields after a recipient record is authenticated. */
export async function deriveRecipientNote({ profileId, instanceId, spendSecret, recoveryPublicKey, rho, r }) {
  const secret = nonzeroFr(spendSecret, 'note spend secret');
  if (BigInt(`0x${secret}`) >= BABYJUB_SUBGROUP_ORDER) failCore('INVALID_SCALAR', 'note spend secret is outside the BabyJubJub subgroup order');
  const spendPublicKey = bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, BigInt(`0x${secret}`))));
  const ak = await deriveRecipientAuthority({ profileId, instanceId, spendPublicKey, recoveryPublicKey });
  return derivePreparedRecipientNote({ profileId, instanceId, spendSecret: secret, ak, rho, r });
}

/**
 * Derive a note after a prepared account has already authenticated the spend
 * and recovery public keys into `ak`. This deliberately checks all dynamic
 * scalar and field inputs, but does not repeat the static key-to-authority
 * relation for every record in one contiguous history scan.
 */
export async function derivePreparedRecipientNote({ profileId, instanceId, spendSecret, ak, rho, r }) {
  const secret = nonzeroFr(spendSecret, 'note spend secret');
  if (BigInt(`0x${secret}`) >= BABYJUB_SUBGROUP_ORDER) failCore('INVALID_SCALAR', 'note spend secret is outside the BabyJubJub subgroup order');
  const authority = nonzeroFr(ak, 'prepared note ak');
  const output = await deriveOutputNote({ profileId, instanceId, ak: authority, rho, r });
  const profile = identifierLimbs(profileId, 'note profileId');
  const instance = identifierLimbs(instanceId, 'note instanceId');
  const nonce = nonzeroFr(rho, 'note rho');
  const nf = frToHex(poseidonHash(1003n, ...profile, ...instance, BigInt(`0x${secret}`), BigInt(`0x${nonce}`)));
  if (nf === '0'.repeat(64)) failCore('ZERO_NULLIFIER', 'derived nullifier is zero');
  return Object.freeze({ ...output, nf, sk: secret });
}

const recoveryMasksCore = ({ profileId, instanceId, outputCm, recoveryPoint, ephemeralPoint, sharedPoint, outputAk, kindCode }) => {
  const profile = identifierLimbs(profileId, 'recovery profileId'); const instance = identifierLimbs(instanceId, 'recovery instanceId');
  const commitment = BigInt(`0x${nonzeroFr(outputCm, 'recovery output commitment')}`); const authority = BigInt(`0x${nonzeroFr(outputAk, 'recovery output ak')}`);
  if (!Number.isInteger(kindCode) || kindCode < 1 || kindCode > 3) failCore('INVALID_KIND', 'recovery action kind code is invalid');
  const shared = poseidonHash(1101n, recoveryPoint[0], recoveryPoint[1], ephemeralPoint[0], ephemeralPoint[1], sharedPoint[0], sharedPoint[1], commitment, BigInt(kindCode));
  const rhoMask = poseidonHash(1102n, shared, profile[0], profile[1], instance[0], instance[1]);
  const rMask = poseidonHash(1103n, shared, profile[0], profile[1], instance[0], instance[1]);
  return Object.freeze({ shared, rhoMask, rMask, authentication: (ciphertextRho, ciphertextR) => frToHex(poseidonHash(1104n, shared, ciphertextRho, ciphertextR, authority, profile[0], profile[1], instance[0], instance[1])) });
};
export function recoveryMasks({ profileId, instanceId, outputCm, recoveryPoint, ephemeralPoint, sharedPoint, outputAk, kindCode }) {
  for (const point of [recoveryPoint, ephemeralPoint, sharedPoint]) if (!babyJubInSubgroup(point)) failCore('INVALID_POINT', 'recovery point is not a nonidentity prime-subgroup point');
  return recoveryMasksCore({ profileId, instanceId, outputCm, recoveryPoint, ephemeralPoint, sharedPoint, outputAk, kindCode });
}

/** Internal scan helper. Its point arguments must have passed canonical
 * decoding/subgroup checks, or be scalar products of those checked points. */
export const recoveryMasksFromValidatedPoints = recoveryMasksCore;
