/**
 * Poseidon2 over Goldilocks (t=12) matching vendor native_poseidon2.py KATs.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { GOLDILOCKS_P, fe, feAdd, feMul } from './field.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONST = JSON.parse(
  readFileSync(
    path.join(__dirname, './poseidon2-constants.json'),
    'utf8',
  ),
);

const WIDTH = CONST.WIDTH;
const RATE = CONST.RATE;
const ROUNDS_F = CONST.ROUNDS_F;
const ROUNDS_P = CONST.ROUNDS_P;
const RF_HALF = ROUNDS_F / 2;
const ROUNDS = ROUNDS_F + ROUNDS_P;
// Constants are decimal strings — JSON numbers are not safe above 2^53.
const MAT_DIAG12 = CONST.MAT_DIAG12.map((x) => BigInt(x));
const RC = CONST.RC.map((row) => row.map((x) => BigInt(x)));
const KAT_EXPECTED = CONST.KAT_EXPECTED.map((x) => BigInt(x));
const HASH_1_2_3_4 = BigInt(CONST.HASH_1_2_3_4);

function sbox(x) {
  const x2 = feMul(x, x);
  const x4 = feMul(x2, x2);
  const x6 = feMul(x4, x2);
  return feMul(x6, x);
}

function matmulM4(s) {
  for (let i = 0; i < WIDTH; i += 4) {
    const t0 = feAdd(s[i], s[i + 1]);
    const t1 = feAdd(s[i + 2], s[i + 3]);
    const t2 = feAdd(feMul(2n, s[i + 1]), t1);
    const t3 = feAdd(feMul(2n, s[i + 3]), t0);
    const t4 = feAdd(feMul(4n, t1), t3);
    const t5 = feAdd(feMul(4n, t0), t2);
    const t6 = feAdd(t3, t5);
    const t7 = feAdd(t2, t4);
    s[i] = t6;
    s[i + 1] = t5;
    s[i + 2] = t7;
    s[i + 3] = t4;
  }
}

function matmulExternal(s) {
  matmulM4(s);
  const stored = [0n, 0n, 0n, 0n];
  const t4 = WIDTH / 4;
  for (let l = 0; l < 4; l += 1) {
    let acc = s[l];
    for (let j = 1; j < t4; j += 1) acc = feAdd(acc, s[4 * j + l]);
    stored[l] = acc;
  }
  for (let i = 0; i < WIDTH; i += 1) s[i] = feAdd(s[i], stored[i % 4]);
}

function matmulInternal(s) {
  let total = 0n;
  for (const v of s) total = feAdd(total, v);
  for (let i = 0; i < WIDTH; i += 1) {
    s[i] = feAdd(feMul(s[i], MAT_DIAG12[i]), total);
  }
}

export function permutation(stateIn) {
  if (!Array.isArray(stateIn) || stateIn.length !== WIDTH) {
    throw new Error('Poseidon2 state must have width 12');
  }
  const s = stateIn.map((v) => fe(v));
  matmulExternal(s);
  const pEnd = RF_HALF + ROUNDS_P;
  for (let r = 0; r < ROUNDS; r += 1) {
    const full = r < RF_HALF || r >= pEnd;
    if (full) {
      for (let i = 0; i < WIDTH; i += 1) s[i] = sbox(feAdd(s[i], RC[r][i]));
      matmulExternal(s);
    } else {
      s[0] = sbox(feAdd(s[0], RC[r][0]));
      matmulInternal(s);
    }
  }
  return s;
}

export function hashTo1(inputs) {
  let state = Array(WIDTH).fill(0n);
  let items = (inputs?.length ? inputs : [0n]).map((v) => fe(v));
  const pad = (RATE - (items.length % RATE)) % RATE;
  items = items.concat(Array(pad).fill(0n));
  for (let off = 0; off < items.length; off += RATE) {
    for (let i = 0; i < RATE; i += 1) {
      state[i] = feAdd(state[i], items[off + i]);
    }
    state = permutation(state);
  }
  return state[0];
}

/** Squeeze 4 field elements (GDig32 payload). */
export function hashTo4(inputs) {
  let state = Array(WIDTH).fill(0n);
  let items = (inputs?.length ? inputs : [0n]).map((v) => fe(v));
  const pad = (RATE - (items.length % RATE)) % RATE;
  items = items.concat(Array(pad).fill(0n));
  for (let off = 0; off < items.length; off += RATE) {
    for (let i = 0; i < RATE; i += 1) {
      state[i] = feAdd(state[i], items[off + i]);
    }
    state = permutation(state);
  }
  const out = [];
  while (out.length < 4) {
    for (let i = 0; i < RATE && out.length < 4; i += 1) out.push(state[i]);
    if (out.length < 4) state = permutation(state);
  }
  return out;
}

export function merkleCompress(a, b) {
  return hashTo1([a, b]);
}

export function assertPoseidon2Kat() {
  const out = permutation([...Array(WIDTH).keys()].map((i) => BigInt(i)));
  for (let i = 0; i < WIDTH; i += 1) {
    if (out[i] !== KAT_EXPECTED[i]) {
      throw new Error(`Poseidon2 KAT mismatch at ${i}`);
    }
  }
  const h = hashTo1([1n, 2n, 3n, 4n]);
  if (h !== HASH_1_2_3_4) {
    throw new Error('hash_to_1 KAT mismatch');
  }
  return true;
}

export { GOLDILOCKS_P, WIDTH, RATE, ROUNDS };
