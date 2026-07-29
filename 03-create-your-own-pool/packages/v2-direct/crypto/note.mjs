/**
 * Note, nullifier, address, and encrypted-record derivation (V2 Direct).
 */
import { randomBytes } from 'node:crypto';
import {
  DENOMINATION_SATS,
  DOMAIN,
  ENCRYPTED_RECORD_BYTES,
  FR_MODULUS,
} from '../constants.mjs';
import {
  assertFr, frFromHex, frToBytes, frToHex, identifierLimbs, sha256DigestLimbs,
} from './fr.mjs';
import { poseidon, poseidonSponge } from './poseidon.mjs';

// BabyJubJub base8 and subgroup order (circomlib / portable-core compatible).
export const BABYJUB_SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// Compressed point helpers: use affine x with sign bit in MSB of first byte (circomlib style).
// For the reference model we treat spend/view public keys as field x-coordinates with a sign flag
// and derive authority from (Sx, Sy, Vx, Vy) after scalar mul when sk is known.

export class NoteCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NoteCryptoError';
  }
}

const fail = (m) => {
  throw new NoteCryptoError(m);
};

const HEX_32 = /^[0-9a-f]{64}$/;

function randomFr() {
  // Rejection sampling into Fr \ {0}
  for (;;) {
    const buf = randomBytes(32);
    const v = BigInt(`0x${buf.toString('hex')}`) % FR_MODULUS;
    if (v !== 0n) return v;
  }
}

function randomScalar() {
  for (;;) {
    const buf = randomBytes(32);
    const v = BigInt(`0x${buf.toString('hex')}`) % BABYJUB_SUBGROUP_ORDER;
    if (v !== 0n) return v;
  }
}

/**
 * Simplified BabyJub scalar-mul using only x-coordinate placeholder for KATs.
 * Full subgroup checks are enforced in circuit; here we use Poseidon-based
 * deterministic "point" derivation so authority is binding without shipping a
 * full EC implementation dependency beyond what the monorepo already uses.
 *
 * For production correctness we import babyJub from recover/portable-core when available.
 */
import {
  BABYJUB_BASE8,
  babyJubMul,
  unpackBabyJubPoint,
  packBabyJubPoint,
} from '../../recover/portable-core.mjs';

export { BABYJUB_BASE8 };

export function deriveSpendPoint(sk) {
  const secret = typeof sk === 'bigint' ? sk : frFromHex(sk, 'sk');
  if (secret === 0n || secret >= BABYJUB_SUBGROUP_ORDER) {
    fail('sk must be a canonical nonzero BabyJub scalar');
  }
  return babyJubMul(BABYJUB_BASE8, secret);
}

export function deriveViewPoint(ivk) {
  const secret = typeof ivk === 'bigint' ? ivk : frFromHex(ivk, 'ivk');
  if (secret === 0n || secret >= BABYJUB_SUBGROUP_ORDER) {
    fail('ivk must be a canonical nonzero BabyJub scalar');
  }
  return babyJubMul(BABYJUB_BASE8, secret);
}

export function computeAuthority({ profileId, instanceId, S, V }) {
  const profile = identifierLimbs(profileId, 'profileId');
  const instance = identifierLimbs(instanceId, 'instanceId');
  return poseidon(
    DOMAIN.ADDRESS,
    ...profile,
    ...instance,
    assertFr(S[0], 'S.x'),
    assertFr(S[1], 'S.y'),
    assertFr(V[0], 'V.x'),
    assertFr(V[1], 'V.y'),
  );
}

export function computeRho({ profileId, instanceId, postActionSequence, rhoBlind }) {
  const profile = identifierLimbs(profileId, 'profileId');
  const instance = identifierLimbs(instanceId, 'instanceId');
  const seq = typeof postActionSequence === 'bigint'
    ? postActionSequence
    : BigInt(postActionSequence);
  const blind = typeof rhoBlind === 'bigint' ? rhoBlind : frFromHex(rhoBlind, 'rhoBlind');
  if (blind === 0n) fail('rhoBlind must be nonzero');
  return poseidon(DOMAIN.RHO, ...profile, ...instance, seq, blind);
}

export function computeNoteCommitment({
  profileId, instanceId, authority, rho, r,
}) {
  const profile = identifierLimbs(profileId, 'profileId');
  const instance = identifierLimbs(instanceId, 'instanceId');
  const ak = typeof authority === 'bigint' ? authority : frFromHex(authority, 'authority');
  const nonce = typeof rho === 'bigint' ? rho : frFromHex(rho, 'rho');
  const randomness = typeof r === 'bigint' ? r : frFromHex(r, 'r');
  if (nonce === 0n || randomness === 0n) fail('rho and r must be nonzero');
  return poseidon(
    DOMAIN.NOTE,
    ...profile,
    ...instance,
    DENOMINATION_SATS,
    ak,
    nonce,
    randomness,
  );
}

export function computeNullifier({
  profileId, instanceId, sk, rho, cm,
}) {
  const profile = identifierLimbs(profileId, 'profileId');
  const instance = identifierLimbs(instanceId, 'instanceId');
  const secret = typeof sk === 'bigint' ? sk : frFromHex(sk, 'sk');
  const nonce = typeof rho === 'bigint' ? rho : frFromHex(rho, 'rho');
  const commitment = typeof cm === 'bigint' ? cm : frFromHex(cm, 'cm');
  return poseidon(
    DOMAIN.NULLIFIER,
    ...profile,
    ...instance,
    secret,
    nonce,
    commitment,
  );
}

/**
 * Encrypt rho/r into 128-byte record:
 *   compressed E (32) || enc_rho (32) || enc_r (32) || tag (32)
 */
export function encryptNoteRecord({
  profileId, instanceId, cm, viewPoint, rho, r, esk,
}) {
  const ephemeral = typeof esk === 'bigint' ? esk : frFromHex(esk, 'esk');
  if (ephemeral === 0n || ephemeral >= BABYJUB_SUBGROUP_ORDER) fail('esk invalid');
  const E = babyJubMul(BABYJUB_BASE8, ephemeral);
  const V = viewPoint;
  // Shared secret = [esk]V  (or [ivk]E when decrypting)
  const shared = babyJubMul(V, ephemeral);
  const ss = poseidon(DOMAIN.RECORD, shared[0], shared[1]);
  const rhoFr = typeof rho === 'bigint' ? rho : frFromHex(rho, 'rho');
  const rFr = typeof r === 'bigint' ? r : frFromHex(r, 'r');
  const maskRho = poseidon(DOMAIN.RECORD, ss, 1n);
  const maskR = poseidon(DOMAIN.RECORD, ss, 2n);
  const encRho = (rhoFr + maskRho) % FR_MODULUS;
  const encR = (rFr + maskR) % FR_MODULUS;
  const profile = identifierLimbs(profileId, 'profileId');
  const instance = identifierLimbs(instanceId, 'instanceId');
  const cmFr = typeof cm === 'bigint' ? cm : frFromHex(cm, 'cm');
  const tag = poseidon(
    DOMAIN.RECORD,
    ss,
    ...profile,
    ...instance,
    cmFr,
    E[0],
    E[1],
    encRho,
    encR,
  );

  const packedE = Buffer.from(packBabyJubPoint(E));
  if (packedE.length !== 32) fail('compressed E must be 32 bytes');
  const record = Buffer.alloc(ENCRYPTED_RECORD_BYTES);
  packedE.copy(record, 0);
  frToBytes(encRho).copy(record, 32);
  frToBytes(encR).copy(record, 64);
  frToBytes(tag).copy(record, 96);
  return record;
}

export function recordCommitment(recordBytes) {
  if (!(recordBytes instanceof Uint8Array) || recordBytes.length !== ENCRYPTED_RECORD_BYTES) {
    fail('encrypted record must be 128 bytes');
  }
  const buf = Buffer.from(recordBytes);
  const limbs = [];
  for (let i = 0; i < 8; i += 1) {
    limbs.push(BigInt(`0x${buf.subarray(i * 16, i * 16 + 16).toString('hex')}`));
  }
  return poseidonSponge(DOMAIN.RECORD, limbs);
}

export function computeOutputNoteLeaf(cm, record) {
  const cmFr = typeof cm === 'bigint' ? cm : frFromHex(cm, 'cm');
  const rc = typeof record === 'bigint' ? record : recordCommitment(record);
  return poseidon(DOMAIN.NOTE_LEAF, cmFr, rc);
}

export function createAccountKeys() {
  const sk = randomScalar();
  const ivk = randomScalar();
  const S = deriveSpendPoint(sk);
  const V = deriveViewPoint(ivk);
  return Object.freeze({
    sk: frToHex(sk),
    ivk: frToHex(ivk),
    S: Object.freeze([frToHex(S[0]), frToHex(S[1])]),
    V: Object.freeze([frToHex(V[0]), frToHex(V[1])]),
    Sx: S[0],
    Sy: S[1],
    Vx: V[0],
    Vy: V[1],
  });
}

export function shieldAddress({ networkId, profileId, instanceId, account }) {
  const S = [frFromHex(account.S[0]), frFromHex(account.S[1])];
  const V = [frFromHex(account.V[0]), frFromHex(account.V[1])];
  const authority = computeAuthority({ profileId, instanceId, S, V });
  return Object.freeze({
    networkId,
    profileId,
    instanceId,
    S: account.S,
    V: account.V,
    authority: frToHex(authority),
  });
}

export function freshOutputNote({
  profileId, instanceId, authority, postActionSequence, viewPoint,
}) {
  const rhoBlind = randomFr();
  const r = randomFr();
  const esk = randomScalar();
  const rho = computeRho({
    profileId, instanceId, postActionSequence, rhoBlind,
  });
  const cm = computeNoteCommitment({
    profileId, instanceId, authority, rho, r,
  });
  const record = encryptNoteRecord({
    profileId, instanceId, cm, viewPoint, rho, r, esk,
  });
  const leaf = computeOutputNoteLeaf(cm, record);
  return Object.freeze({
    rhoBlind: frToHex(rhoBlind),
    rho: frToHex(rho),
    r: frToHex(r),
    esk: frToHex(esk),
    cm: frToHex(cm),
    outputNoteLeaf: frToHex(leaf),
    encryptedRecord: record,
    recordCommitment: frToHex(recordCommitment(record)),
  });
}

export {
  randomFr, randomScalar, frToHex, frFromHex, packBabyJubPoint, unpackBabyJubPoint,
};
