/**
 * Fixed-arity H4 digests per FRI_STARK_REPLACEMENT_PLAN.md §2.
 * H4_D(x0..x7): state = [x0..x7, IV_D[0..3]]; Poseidon2; return state[0..3]
 */
import { createHash } from 'node:crypto';
import { GOLDILOCKS_P, fe } from './field.mjs';
import { permutation } from './poseidon2.mjs';

const P = GOLDILOCKS_P;

/** Domain labels → frozen IVs (derived deterministically). */
const DOMAIN_LABELS = Object.freeze([
  'PROFILE_ID',
  'INSTANCE_ID',
  'IDS',
  'PARAMS',
  'POOL',
  'OWNER',
  'NULLIFIER_KEY',
  'RHO',
  'NOTE',
  'NOTE_LEAF',
  'EMPTY_NOTE_LEAF',
  'NULLIFIER',
  'NULLIFIER_META',
  'NULLIFIER_KEYS',
  'NULLIFIER_LEAF',
  ...Array.from({ length: 33 }, (_, i) => `NOTE_MERKLE_L${i}`),
  ...Array.from({ length: 33 }, (_, i) => `NF_MERKLE_L${i}`),
]);

function deriveIv(label) {
  let counter = 0;
  for (;;) {
    const h = createHash('sha256')
      .update(`ShieldKit/FRI-Poseidon2-IV/v1/${label}`)
      .update(Buffer.from([0]))
      .update(Buffer.from([(counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]))
      .digest();
    const limbs = [];
    let ok = true;
    for (let i = 0; i < 4; i += 1) {
      const limb = h.readBigUInt64LE(i * 8);
      if (limb === 0n || limb >= P) {
        ok = false;
        break;
      }
      limbs.push(limb);
    }
    if (ok) return Object.freeze(limbs);
    counter += 1;
    if (counter > 10_000) throw new Error(`IV derive failed for ${label}`);
  }
}

export const DOMAIN_IVS = Object.freeze(
  Object.fromEntries(DOMAIN_LABELS.map((l) => [l, deriveIv(l)])),
);

/** Split 32 bytes into eight U32LE field elements (injective). */
export function u32le8FromBytes32(bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (b.length !== 32) throw new Error('u32le8 expects 32 bytes');
  const out = [];
  for (let i = 0; i < 8; i += 1) {
    out.push(BigInt(b.readUInt32LE(i * 4)));
  }
  return out;
}

export function digest4ToBytes(fes) {
  if (fes.length !== 4) throw new Error('Digest4 needs 4 FE');
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i += 1) {
    const v = fe(fes[i]);
    if (v >= P) throw new Error('non-canonical Digest4 limb');
    out.writeBigUInt64LE(v, i * 8);
  }
  return out;
}

export function digest4FromBytes(bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (b.length !== 32) throw new Error('Digest4 is 32 bytes');
  const fes = [];
  for (let i = 0; i < 4; i += 1) {
    const v = b.readBigUInt64LE(i * 8);
    if (v >= P) throw new Error('non-canonical Digest4 limb');
    fes.push(v);
  }
  return fes;
}

export function digest4ToHex(fes) {
  return digest4ToBytes(fes).toString('hex');
}

export function digest4FromHex(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('bad Digest4 hex');
  return digest4FromBytes(Buffer.from(hex, 'hex'));
}

/**
 * H4_D over exactly eight field elements.
 */
export function h4(domainLabel, x0to7) {
  if (!DOMAIN_IVS[domainLabel]) throw new Error(`unknown domain ${domainLabel}`);
  if (!Array.isArray(x0to7) || x0to7.length !== 8) {
    throw new Error('H4 requires exactly 8 field elements');
  }
  const iv = DOMAIN_IVS[domainLabel];
  const state = [...x0to7.map(fe), ...iv.map(fe)];
  const out = permutation(state);
  return [fe(out[0]), fe(out[1]), fe(out[2]), fe(out[3])];
}

export function h4Bytes32(domainLabel, bytes32) {
  return h4(domainLabel, u32le8FromBytes32(bytes32));
}

export function h4Concat4(domainLabel, a4, b4) {
  if (a4.length !== 4 || b4.length !== 4) throw new Error('concat4 needs two Digest4');
  return h4(domainLabel, [...a4.map(fe), ...b4.map(fe)]);
}

export const ZERO_DIGEST4_HEX = digest4ToHex([0n, 0n, 0n, 0n]);
