// Strict, local-only adapter from a caller-hash-pinned snarkjs BN254 Groth16
// tuple into the fixture field names consumed by verifier.cash PF7. It does
// not run setup, verify a pairing, write a profile, or authorize deployment.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254 } from '@noble/curves/bn254.js';

const BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;

export class SnarkjsAdapterError extends Error {
  constructor(message) { super(message); this.name = 'SnarkjsAdapterError'; }
}
const fail = (message) => { throw new SnarkjsAdapterError(message); };
const object = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
};
const exactKeys = (value, label, keys) => {
  object(value, label);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
};

/** Duplicate-key-safe JSON parser. JSON.parse alone silently overwrites keys. */
export function parseStrictJson(bytes, label = 'JSON') {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail(`${label} is not valid UTF-8`); }
  if (text.charCodeAt(0) === 0xfeff) fail(`${label} must not contain a UTF-8 BOM`);
  let index = 0;
  const whitespace = () => { while (/^[\u0009\u000a\u000d\u0020]$/.test(text[index] ?? '')) index += 1; };
  const quoted = () => {
    const start = index++;
    let escaped = false;
    while (index < text.length) {
      const character = text[index++];
      if (!escaped && character === '"') {
        try { return JSON.parse(text.slice(start, index)); } catch { fail(`${label}: invalid JSON string at byte ${start}`); }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) fail(`${label}: control character at byte ${index - 1}`);
      escaped = !escaped && character === '\\';
      if (escaped && character !== '\\') escaped = false;
    }
    fail(`${label}: unterminated JSON string at byte ${start}`);
  };
  const number = () => {
    const match = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail(`${label}: invalid JSON number at byte ${index}`);
    index += match[0].length;
    const parsed = Number(match[0]); if (!Number.isFinite(parsed)) fail(`${label}: non-finite JSON number`);
    return parsed;
  };
  const value = () => {
    whitespace(); const current = text[index];
    if (current === '{') return dictionary();
    if (current === '[') return array();
    if (current === '"') return quoted();
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, index)) { index += token.length; return result; }
    }
    if (current === '-' || /[0-9]/.test(current ?? '')) return number();
    fail(`${label}: invalid JSON value at byte ${index}`);
  };
  const array = () => {
    index += 1; whitespace(); const result = [];
    if (text[index] === ']') { index += 1; return result; }
    while (true) {
      result.push(value()); whitespace();
      if (text[index] === ']') { index += 1; return result; }
      if (text[index] !== ',') fail(`${label}: expected comma at byte ${index}`); index += 1;
    }
  };
  const dictionary = () => {
    index += 1; whitespace(); const result = Object.create(null); const names = new Set();
    if (text[index] === '}') { index += 1; return result; }
    while (true) {
      whitespace(); if (text[index] !== '"') fail(`${label}: expected object key at byte ${index}`);
      const key = quoted(); if (names.has(key)) fail(`${label}: duplicate JSON object name: ${key}`); names.add(key);
      whitespace(); if (text[index] !== ':') fail(`${label}: expected colon at byte ${index}`); index += 1;
      result[key] = value(); whitespace();
      if (text[index] === '}') { index += 1; return result; }
      if (text[index] !== ',') fail(`${label}: expected comma at byte ${index}`); index += 1;
    }
  };
  const result = value(); whitespace(); if (index !== text.length) fail(`${label}: trailing JSON data at byte ${index}`); return result;
}

export async function sha256File(filename) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest('hex');
}
export const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function pinnedRegularFile(record, label) {
  exactKeys(record, label, ['path', 'sha256']);
  if (typeof record.path !== 'string' || record.path.length === 0) fail(`${label}.path must be a nonempty string`);
  if (typeof record.sha256 !== 'string' || !SHA256.test(record.sha256)) fail(`${label}.sha256 must be lowercase SHA-256`);
  const filename = path.resolve(record.path);
  const before = await lstat(filename).catch(() => fail(`${label} is missing: ${record.path}`));
  if (!before.isFile() || before.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (await realpath(filename) !== filename) fail(`${label} resolves through a symlink`);
  const hash = await sha256File(filename);
  const after = await lstat(filename);
  if (!after.isFile() || after.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) fail(`${label} changed while hashing`);
  if (hash !== record.sha256) fail(`${label} SHA-256 mismatch: expected ${record.sha256}, got ${hash}`);
  const artifact = { path: filename, sha256: hash, bytes: before.size };
  Object.defineProperties(artifact, {
    dev: { value: before.dev, enumerable: false },
    ino: { value: before.ino, enumerable: false },
  });
  return Object.freeze(artifact);
}
async function pinnedJson(record, label) {
  const artifact = await pinnedRegularFile(record, label);
  const bytes = await readFile(artifact.path);
  // Bind the exact buffer parsed below, not merely a later pathname read. The
  // following pathname checks remain required to detect replacement/mutation.
  const bytesHash = sha256Bytes(bytes);
  if (bytesHash !== artifact.sha256) fail(`${label} read bytes SHA-256 mismatch: expected ${artifact.sha256}, got ${bytesHash}`);
  const afterRead = await lstat(artifact.path);
  if (!afterRead.isFile() || afterRead.isSymbolicLink() || afterRead.dev !== artifact.dev || afterRead.ino !== artifact.ino || afterRead.size !== artifact.bytes) fail(`${label} changed while reading`);
  const postReadHash = await sha256File(artifact.path);
  const afterPostRead = await lstat(artifact.path);
  if (!afterPostRead.isFile() || afterPostRead.isSymbolicLink() || afterPostRead.dev !== artifact.dev || afterPostRead.ino !== artifact.ino || afterPostRead.size !== artifact.bytes) fail(`${label} changed during post-read hash`);
  if (postReadHash !== artifact.sha256) fail(`${label} hash drift after read`);
  return { artifact, value: parseStrictJson(bytes, label) };
}
const canonicalField = (value, label, modulus) => {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical nonnegative decimal string`);
  const integer = BigInt(value); if (integer >= modulus) fail(`${label} is outside the canonical field range`);
  return integer;
};
const fieldString = (value, label) => canonicalField(value, label, BASE_FIELD).toString();
const scalarString = (value, label) => canonicalField(value, label, SCALAR_FIELD).toString();
const nonInfinity = (point, group, label) => {
  if (point.equals(group.ZERO)) fail(`${label} must not be infinity`);
  if (!point.isTorsionFree()) fail(`${label} is not in the prime-order subgroup`);
  return point;
};
function g1(raw, label, { allowInfinity = false } = {}) {
  if (!Array.isArray(raw) || raw.length !== 3) fail(`${label} must be [x,y,1]`);
  if (raw[2] === '0') {
    if (!allowInfinity) fail(`${label} must not be infinity`);
    if (raw[0] !== '0' || raw[1] !== '1') fail(`${label} has a noncanonical infinity encoding`);
    return Object.freeze({ x: '0', y: '1', infinity: true });
  }
  const x = fieldString(raw[0], `${label}[0]`); const y = fieldString(raw[1], `${label}[1]`);
  if (raw[2] !== '1') fail(`${label}[2] must be canonical affine 1`);
  try {
    const point = bn254.G1.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });
    point.assertValidity(); nonInfinity(point, bn254.G1.Point, label);
  }
  catch (error) { if (error instanceof SnarkjsAdapterError) throw error; fail(`${label} is not a valid BN254 G1 point`); }
  return Object.freeze({ x, y });
}
function g2(raw, label) {
  if (!Array.isArray(raw) || raw.length !== 3 || !Array.isArray(raw[0]) || !Array.isArray(raw[1]) || !Array.isArray(raw[2]) || raw[0].length !== 2 || raw[1].length !== 2 || raw[2].length !== 2) fail(`${label} must be [[x.c0,x.c1],[y.c0,y.c1],[1,0]]`);
  const x0 = fieldString(raw[0][0], `${label}[0][0]`); const x1 = fieldString(raw[0][1], `${label}[0][1]`);
  const y0 = fieldString(raw[1][0], `${label}[1][0]`); const y1 = fieldString(raw[1][1], `${label}[1][1]`);
  if (raw[2][0] !== '1' || raw[2][1] !== '0') fail(`${label}[2] must be canonical affine [1,0]`);
  try {
    const point = bn254.G2.Point.fromAffine({ x: { c0: BigInt(x0), c1: BigInt(x1) }, y: { c0: BigInt(y0), c1: BigInt(y1) } });
    point.assertValidity(); nonInfinity(point, bn254.G2.Point, label);
  } catch (error) { if (error instanceof SnarkjsAdapterError) throw error; fail(`${label} is not a valid BN254 G2 point`); }
  return Object.freeze({ x0, x1, y0, y1 });
}
function fq12(raw, label) {
  if (!Array.isArray(raw) || raw.length !== 2 || raw.some((a) => !Array.isArray(a) || a.length !== 3 || a.some((b) => !Array.isArray(b) || b.length !== 2))) fail(`${label} must be 2x3x2 Fq coefficients`);
  return raw.map((a, i) => a.map((b, j) => b.map((value, k) => fieldString(value, `${label}[${i}][${j}][${k}]`))));
}
function verificationKey(raw) {
  exactKeys(raw, 'verification_key.json', ['IC', 'curve', 'nPublic', 'protocol', 'vk_alpha_1', 'vk_alphabeta_12', 'vk_beta_2', 'vk_delta_2', 'vk_gamma_2']);
  if (raw.protocol !== 'groth16') fail('verification_key.json.protocol must be groth16');
  if (raw.curve !== 'bn128') fail('verification_key.json.curve must be bn128');
  if (raw.nPublic !== 2) fail('verification_key.json.nPublic must be exactly 2');
  if (!Array.isArray(raw.IC) || raw.IC.length !== 3) fail('verification_key.json.IC must contain nPublic + 1 G1 points');
  return Object.freeze({
    alpha: g1(raw.vk_alpha_1, 'verification_key.json.vk_alpha_1'),
    beta: g2(raw.vk_beta_2, 'verification_key.json.vk_beta_2'),
    gamma: g2(raw.vk_gamma_2, 'verification_key.json.vk_gamma_2'),
    delta: g2(raw.vk_delta_2, 'verification_key.json.vk_delta_2'),
    alphaBeta: fq12(raw.vk_alphabeta_12, 'verification_key.json.vk_alphabeta_12'),
    // IC[0] is the constant term and may legitimately be the canonical G1
    // infinity (the zero contribution). Proof points and nonconstant IC terms
    // may not. PF7 may impose a stricter finite-IC import gate downstream.
    ic: raw.IC.map((point, index) => g1(point, `verification_key.json.IC[${index}]`, { allowInfinity: index === 0 })),
  });
}
function proof(raw) {
  exactKeys(raw, 'proof.json', ['curve', 'pi_a', 'pi_b', 'pi_c', 'protocol']);
  if (raw.protocol !== 'groth16') fail('proof.json.protocol must be groth16');
  if (raw.curve !== 'bn128') fail('proof.json.curve must be bn128');
  return Object.freeze({ a: g1(raw.pi_a, 'proof.json.pi_a'), b: g2(raw.pi_b, 'proof.json.pi_b'), c: g1(raw.pi_c, 'proof.json.pi_c') });
}
function publicSignals(raw) {
  if (!Array.isArray(raw) || raw.length !== 2) fail('public.json must contain exactly two public signals');
  return Object.freeze(raw.map((value, index) => scalarString(value, `public.json[${index}]`)));
}

/**
 * Convert an immutable snarkjs tuple to the fields consumed by PF7's
 * `ELIG_INSTANCE=file` parser. G2 byte/component convention: snarkjs
 * `pi_b=[[x.c0,x.c1],[y.c0,y.c1],[1,0]]`; Bxa/Bxb/Bya/Byb preserve that order.
 */
export async function adaptSnarkjsGroth16(records) {
  exactKeys(records, 'adapter input', ['proof', 'publicSignals', 'verificationKey']);
  const [vkInput, proofInput, publicInput] = await Promise.all([
    pinnedJson(records.verificationKey, 'verification_key.json'),
    pinnedJson(records.proof, 'proof.json'),
    pinnedJson(records.publicSignals, 'public.json'),
  ]);
  const vk = verificationKey(vkInput.value); const parsedProof = proof(proofInput.value); const inputs = publicSignals(publicInput.value);
  const fixture = Object.freeze({
    Ax: parsedProof.a.x, Ay: parsedProof.a.y,
    Bxa: parsedProof.b.x0, Bxb: parsedProof.b.x1,
    Bya: parsedProof.b.y0, Byb: parsedProof.b.y1,
    Cx: parsedProof.c.x, Cy: parsedProof.c.y,
    in0: inputs[0], in1: inputs[1],
  });
  return Object.freeze({
    schema: 'shield.cash/snarkjs-groth16-pf7-adapter/v1',
    qualification: 'local conversion only; not a verifier bundle, profile, setup, standardness, or deployment result; canonical infinity IC0 is valid source material but PF7-incompatible and rejected downstream without substitution; current PF7 builder rejects all adapter input because its gb3/SZ/FIXED_G2 trajectories are static',
    source: Object.freeze({ verificationKey: vkInput.artifact, proof: proofInput.artifact, publicSignals: publicInput.artifact }),
    byteOrder: Object.freeze({
      scalars: 'canonical unsigned base-10 JSON strings; PF7 converts to its existing VM-number representation',
      g1: 'snarkjs affine [x,y,1] maps directly to Ax/Ay and Cx/Cy',
      g2: 'snarkjs affine [[x.c0,x.c1],[y.c0,y.c1],[1,0]] maps directly to Bxa/Bxb/Bya/Byb; no component reversal',
    }),
    verificationKey: Object.freeze({ publicArity: vk.ic.length - 1, ic: vk.ic.length }),
    // verifier.cash derives every Miller trajectory directly from these affine
    // points. It does not consume snarkjs's vk_alphabeta_12 precomputation, so
    // that value is intentionally validated above but not exported as material.
    verifierCashVk: Object.freeze({
      alpha: vk.alpha,
      beta: vk.beta,
      gamma: vk.gamma,
      delta: vk.delta,
      ic: vk.ic,
    }),
    verifierCashFixture: fixture,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = process.argv[2];
  if (!manifest) { console.error('usage: groth16.mjs MANIFEST.json'); process.exitCode = 2; }
  else pinnedJson({ path: manifest, sha256: process.argv[3] ?? '' }, 'adapter manifest')
    .then(({ value }) => adaptSnarkjsGroth16(value))
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => { console.error(error.message); process.exitCode = 1; });
}
