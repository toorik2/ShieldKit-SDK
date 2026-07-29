// Pinned import boundary for ShieldKit's V2 Direct local snarkjs adapter result. This
// intentionally accepts a complete, immutable conversion result, not separate
// caller-selected VK/proof/public files: one SHA-256 pin binds their relation.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

const BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const fail = (message) => { throw new Error(`V2 Direct Groth16 adapter input: ${message}`); };

const object = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
};
const exactKeys = (value, label, keys) => {
  object(value, label);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
};

/** Duplicate-key-safe parser: a pin protects bytes, but must not hide schema ambiguity. */
export function parseStrictJson(bytes, label = 'JSON') {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail(`${label} is not valid UTF-8`); }
  if (text.charCodeAt(0) === 0xfeff) fail(`${label} must not contain a UTF-8 BOM`);
  let index = 0;
  const whitespace = () => { while (/^[\u0009\u000a\u000d\u0020]$/.test(text[index] ?? '')) index += 1; };
  const quoted = () => {
    const start = index++; let escaped = false;
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
    index += match[0].length; const parsed = Number(match[0]);
    if (!Number.isFinite(parsed)) fail(`${label}: non-finite JSON number`);
    return parsed;
  };
  const value = () => {
    whitespace(); const current = text[index];
    if (current === '{') return dictionary(); if (current === '[') return array(); if (current === '"') return quoted();
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) if (text.startsWith(token, index)) { index += token.length; return result; }
    if (current === '-' || /[0-9]/.test(current ?? '')) return number();
    fail(`${label}: invalid JSON value at byte ${index}`);
  };
  const array = () => {
    index += 1; whitespace(); const result = [];
    if (text[index] === ']') { index += 1; return result; }
    while (true) { result.push(value()); whitespace(); if (text[index] === ']') { index += 1; return result; } if (text[index] !== ',') fail(`${label}: expected comma at byte ${index}`); index += 1; }
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

const decimal = (value, label, modulus) => {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical nonnegative decimal string`);
  if (BigInt(value) >= modulus) fail(`${label} is outside canonical field range`);
  return value;
};
const g1 = (value, label) => {
  if (value !== null && !Array.isArray(value) && typeof value === 'object' && Object.hasOwn(value, 'infinity')) {
    exactKeys(value, label, ['infinity', 'x', 'y']);
    if (value.infinity === true && value.x === '0' && value.y === '1') fail(`${label} is canonical infinity; V2 Direct requires finite IC points`);
  }
  exactKeys(value, label, ['x', 'y']);
  return Object.freeze({ x: decimal(value.x, `${label}.x`, BASE_FIELD), y: decimal(value.y, `${label}.y`, BASE_FIELD) });
};
const g2 = (value, label) => {
  exactKeys(value, label, ['x0', 'x1', 'y0', 'y1']);
  return Object.freeze({
    x0: decimal(value.x0, `${label}.x0`, BASE_FIELD), x1: decimal(value.x1, `${label}.x1`, BASE_FIELD),
    y0: decimal(value.y0, `${label}.y0`, BASE_FIELD), y1: decimal(value.y1, `${label}.y1`, BASE_FIELD),
  });
};
const artifact = (value, label) => {
  exactKeys(value, label, ['bytes', 'path', 'sha256']);
  if (typeof value.path !== 'string' || value.path.length === 0 || typeof value.sha256 !== 'string' || !SHA256.test(value.sha256)
    || !Number.isSafeInteger(value.bytes) || value.bytes < 0) fail(`${label} is not a canonical adapter artifact record`);
};

export function validateV2DirectGroth16AdapterResult(raw) {
  exactKeys(raw, 'adapter result', ['byteOrder', 'qualification', 'schema', 'source', 'verificationKey', 'verifierCashFixture', 'verifierCashVk']);
  if (raw.schema !== 'shieldkit-v2-direct-groth16-adapter-v1') fail('unsupported schema');
  if (typeof raw.qualification !== 'string') fail('qualification must be a string');
  exactKeys(raw.source, 'source', ['proof', 'publicSignals', 'verificationKey']);
  artifact(raw.source.verificationKey, 'source.verificationKey'); artifact(raw.source.proof, 'source.proof'); artifact(raw.source.publicSignals, 'source.publicSignals');
  exactKeys(raw.byteOrder, 'byteOrder', ['g1', 'g2', 'scalars']);
  for (const name of ['g1', 'g2', 'scalars']) if (typeof raw.byteOrder[name] !== 'string' || raw.byteOrder[name].length === 0) fail(`byteOrder.${name} must be a nonempty string`);
  exactKeys(raw.verificationKey, 'verificationKey', ['ic', 'publicArity']);
  if (raw.verificationKey.publicArity !== 2 || raw.verificationKey.ic !== 3) fail('V2 Direct requires exactly two public signals and three IC points');
  exactKeys(raw.verifierCashVk, 'verifierCashVk', ['alpha', 'beta', 'delta', 'gamma', 'ic']);
  if (!Array.isArray(raw.verifierCashVk.ic) || raw.verifierCashVk.ic.length !== 3) fail('verifierCashVk.ic must contain exactly three points');
  const vk = Object.freeze({
    alpha: g1(raw.verifierCashVk.alpha, 'verifierCashVk.alpha'), beta: g2(raw.verifierCashVk.beta, 'verifierCashVk.beta'),
    gamma: g2(raw.verifierCashVk.gamma, 'verifierCashVk.gamma'), delta: g2(raw.verifierCashVk.delta, 'verifierCashVk.delta'),
    // V2 Direct's ECIP/MSM input requires finite affine IC points. The adapter may
    // represent an infinity IC0, but this generator rejects it rather than
    // substituting an identity encoding.
    ic: Object.freeze(raw.verifierCashVk.ic.map((value, index) => g1(value, `verifierCashVk.ic[${index}]`))),
  });
  exactKeys(raw.verifierCashFixture, 'verifierCashFixture', ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'in0', 'in1']);
  const fixture = Object.freeze({
    Ax: decimal(raw.verifierCashFixture.Ax, 'verifierCashFixture.Ax', BASE_FIELD), Ay: decimal(raw.verifierCashFixture.Ay, 'verifierCashFixture.Ay', BASE_FIELD),
    Bxa: decimal(raw.verifierCashFixture.Bxa, 'verifierCashFixture.Bxa', BASE_FIELD), Bxb: decimal(raw.verifierCashFixture.Bxb, 'verifierCashFixture.Bxb', BASE_FIELD),
    Bya: decimal(raw.verifierCashFixture.Bya, 'verifierCashFixture.Bya', BASE_FIELD), Byb: decimal(raw.verifierCashFixture.Byb, 'verifierCashFixture.Byb', BASE_FIELD),
    Cx: decimal(raw.verifierCashFixture.Cx, 'verifierCashFixture.Cx', BASE_FIELD), Cy: decimal(raw.verifierCashFixture.Cy, 'verifierCashFixture.Cy', BASE_FIELD),
    in0: decimal(raw.verifierCashFixture.in0, 'verifierCashFixture.in0', SCALAR_FIELD), in1: decimal(raw.verifierCashFixture.in1, 'verifierCashFixture.in1', SCALAR_FIELD),
  });
  return Object.freeze({ vk, fixture });
}

export async function loadPinnedV2DirectGroth16AdapterResult(record) {
  exactKeys(record, 'adapter pin', ['path', 'sha256']);
  if (typeof record.path !== 'string' || record.path.length === 0 || typeof record.sha256 !== 'string' || !SHA256.test(record.sha256)) fail('adapter pin must contain a path and lowercase SHA-256');
  const filename = path.resolve(record.path);
  const before = await lstat(filename).catch(() => fail(`missing: ${record.path}`));
  if (!before.isFile() || before.isSymbolicLink()) fail('must be a regular non-symlink file');
  if (await realpath(filename) !== filename) fail('resolves through a symlink');
  const hash = await sha256File(filename);
  const after = await lstat(filename);
  if (!after.isFile() || after.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) fail('changed while hashing');
  if (hash !== record.sha256) fail(`SHA-256 mismatch: expected ${record.sha256}, got ${hash}`);
  const bytes = await readFile(filename);
  // Bind the exact bytes that strict JSON parsing consumes. A subsequent
  // pathname hash and identity check still catch concurrent replacement.
  const bytesHash = sha256Bytes(bytes);
  if (bytesHash !== record.sha256) fail(`read bytes SHA-256 mismatch: expected ${record.sha256}, got ${bytesHash}`);
  const afterRead = await lstat(filename);
  if (!afterRead.isFile() || afterRead.isSymbolicLink() || afterRead.dev !== before.dev || afterRead.ino !== before.ino || afterRead.size !== before.size) fail('changed while reading');
  const postReadHash = await sha256File(filename);
  const afterPostRead = await lstat(filename);
  if (!afterPostRead.isFile() || afterPostRead.isSymbolicLink() || afterPostRead.dev !== before.dev || afterPostRead.ino !== before.ino || afterPostRead.size !== before.size) fail('changed during post-read hash');
  if (postReadHash !== record.sha256) fail('hash drift after read');
  return Object.freeze({ artifact: Object.freeze({ path: filename, sha256: hash, bytes: before.size }), ...validateV2DirectGroth16AdapterResult(parseStrictJson(bytes, 'adapter result')) });
}
