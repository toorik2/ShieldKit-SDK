import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { bn254 } from '@noble/curves/bn254.js';
import { loadPinnedShieldAdapterResult, sha256Bytes } from '../src/c7/shield-adapter-input.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const vectorsPath = path.join(repoRoot, 'harness/src/checkpoints/pairing-vectors.json');
const digest = async (filename) => createHash('sha256').update(await readFile(filename)).digest('hex');

const adapterResultFor = (vec) => ({
  schema: 'shield.cash/snarkjs-groth16-pf7-adapter/v1',
  qualification: 'test-only static-vector equivalence; not a profile or deployment result',
  source: {
    verificationKey: { path: '/pinned/vk.json', sha256: '1'.repeat(64), bytes: 1 },
    proof: { path: '/pinned/proof.json', sha256: '2'.repeat(64), bytes: 1 },
    publicSignals: { path: '/pinned/public.json', sha256: '3'.repeat(64), bytes: 1 },
  },
  byteOrder: { scalars: 'canonical decimal', g1: 'x,y', g2: 'x0,x1,y0,y1' },
  verificationKey: { publicArity: 2, ic: 3 },
  verifierCashVk: {
    alpha: vec.vk.alpha,
    beta: { x0: vec.vk.beta.x.c0, x1: vec.vk.beta.x.c1, y0: vec.vk.beta.y.c0, y1: vec.vk.beta.y.c1 },
    gamma: { x0: vec.vk.gamma.x.c0, x1: vec.vk.gamma.x.c1, y0: vec.vk.gamma.y.c0, y1: vec.vk.gamma.y.c1 },
    delta: { x0: vec.vk.delta.x.c0, x1: vec.vk.delta.x.c1, y0: vec.vk.delta.y.c0, y1: vec.vk.delta.y.c1 },
    ic: vec.vk.ic,
  },
  verifierCashFixture: {
    Ax: vec.proof.a.x, Ay: vec.proof.a.y,
    Bxa: vec.proof.b.x.c0, Bxb: vec.proof.b.x.c1, Bya: vec.proof.b.y.c0, Byb: vec.proof.b.y.c1,
    Cx: vec.proof.c.x, Cy: vec.proof.c.y, in0: vec.publicInputs[0], in1: vec.publicInputs[1],
  },
});
const g1 = (point) => bn254.G1.Point.fromAffine({ x: BigInt(point.x), y: BigInt(point.y) });
const g2 = (point) => bn254.G2.Point.fromAffine({ x: { c0: BigInt(point.x0), c1: BigInt(point.x1) }, y: { c0: BigInt(point.y0), c1: BigInt(point.y1) } });

test('pinned complete material is coordinate-equivalent to verifier.cash static vector and verifies its real Groth16 equation', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-adapter-'));
  try {
    const vec = JSON.parse(await readFile(vectorsPath, 'utf8'));
    const filename = path.join(directory, 'adapter-result.json'); await writeFile(filename, `${JSON.stringify(adapterResultFor(vec))}\n`);
    const loaded = await loadPinnedShieldAdapterResult({ path: filename, sha256: await digest(filename) });
    assert.deepEqual(loaded.vk.alpha, vec.vk.alpha);
    assert.deepEqual(loaded.vk.ic, vec.vk.ic);
    assert.deepEqual(loaded.fixture.in0, vec.publicInputs[0]); assert.deepEqual(loaded.fixture.in1, vec.publicInputs[1]);
    const proof = loaded.fixture; let vkx = g1(loaded.vk.ic[0]);
    vkx = vkx.add(g1(loaded.vk.ic[1]).multiply(BigInt(proof.in0))).add(g1(loaded.vk.ic[2]).multiply(BigInt(proof.in1)));
    const product = bn254.pairingBatch([
      { g1: g1({ x: proof.Ax, y: proof.Ay }).negate(), g2: g2({ x0: proof.Bxa, x1: proof.Bxb, y0: proof.Bya, y1: proof.Byb }) },
      { g1: g1(loaded.vk.alpha), g2: g2(loaded.vk.beta) },
      { g1: vkx, g2: g2(loaded.vk.gamma) },
      { g1: g1({ x: proof.Cx, y: proof.Cy }), g2: g2(loaded.vk.delta) },
    ], true);
    assert.equal(bn254.fields.Fp12.eql(product, bn254.fields.Fp12.ONE), true);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('pinned import rejects hash drift, duplicate keys, and unsupported PF7 arity', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-adapter-'));
  try {
    const vec = JSON.parse(await readFile(vectorsPath, 'utf8')); const filename = path.join(directory, 'adapter-result.json');
    await writeFile(filename, `${JSON.stringify(adapterResultFor(vec))}\n`);
    await assert.rejects(() => loadPinnedShieldAdapterResult({ path: filename, sha256: '0'.repeat(64) }), /SHA-256 mismatch/);
    await writeFile(filename, '{"schema":"x","schema":"x"}');
    const duplicateHash = await digest(filename);
    await assert.rejects(() => loadPinnedShieldAdapterResult({ path: filename, sha256: duplicateHash }), /duplicate JSON object name/);
    const malformed = adapterResultFor(vec); malformed.verificationKey.publicArity = 3;
    await writeFile(filename, `${JSON.stringify(malformed)}\n`);
    const malformedHash = await digest(filename);
    await assert.rejects(() => loadPinnedShieldAdapterResult({ path: filename, sha256: malformedHash }), /requires exactly two public signals/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('PF7 rejects canonical snarkjs IC0 infinity without identity substitution', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-adapter-'));
  try {
    const vec = JSON.parse(await readFile(vectorsPath, 'utf8')); const filename = path.join(directory, 'adapter-result.json');
    const result = adapterResultFor(vec); result.verifierCashVk.ic[0] = { x: '0', y: '1', infinity: true };
    await writeFile(filename, `${JSON.stringify(result)}\n`);
    const infinityHash = await digest(filename);
    await assert.rejects(() => loadPinnedShieldAdapterResult({ path: filename, sha256: infinityHash }), /canonical infinity; PF7 currently requires finite IC points/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('pinned import hashes the exact adapter bytes before parsing', async () => {
  assert.equal(sha256Bytes(Buffer.from('{"a":1}')), createHash('sha256').update('{"a":1}').digest('hex'));
  const implementation = await readFile(new URL('../src/c7/shield-adapter-input.mjs', import.meta.url), 'utf8');
  assert.match(implementation, /const bytesHash = sha256Bytes\(bytes\);/);
  assert.match(implementation, /bytesHash !== record\.sha256/);
  assert.match(implementation, /postReadHash !== record\.sha256/);
});
