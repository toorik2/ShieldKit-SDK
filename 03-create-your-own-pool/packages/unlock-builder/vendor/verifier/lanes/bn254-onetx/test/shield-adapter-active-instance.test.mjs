import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { hexToBin, vmNumberToBigInt } from '@bitauth/libauth';

const execFile = promisify(execFileCallback);
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const vectorsPath = path.join(repoRoot, 'harness/src/checkpoints/pairing-vectors.json');
const multiproofPath = path.join(repoRoot, 'harness/src/bch/groth16-singleton-multiproof-vectors.json');

const adapterResultFor = (vec, fixture = undefined) => ({
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
  verifierCashFixture: fixture ?? {
    Ax: vec.proof.a.x, Ay: vec.proof.a.y,
    Bxa: vec.proof.b.x.c0, Bxb: vec.proof.b.x.c1, Bya: vec.proof.b.y.c0, Byb: vec.proof.b.y.c1,
    Cx: vec.proof.c.x, Cy: vec.proof.c.y, in0: vec.publicInputs[0], in1: vec.publicInputs[1],
  },
});

const parseUnlocking = (hex) => {
  const bytes = hexToBin(hex); const values = []; let offset = 0;
  while (offset < bytes.length) {
    const opcode = bytes[offset++];
    if (opcode === 0x00) values.push(0n);
    else if (opcode === 0x4f) values.push(-1n);
    else if (opcode >= 0x51 && opcode <= 0x60) values.push(BigInt(opcode - 0x50));
    else {
      let length;
      if (opcode <= 75) length = opcode;
      else if (opcode === 0x4c) length = bytes[offset++];
      else if (opcode === 0x4d) { length = bytes[offset] | (bytes[offset + 1] << 8); offset += 2; }
      else throw new Error(`unsupported push opcode ${opcode}`);
      values.push(vmNumberToBigInt(bytes.slice(offset, offset + length), { requireMinimalEncoding: false }));
      offset += length;
    }
  }
  const d = values.reverse();
  return Object.fromEntries(['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'in0', 'in1'].map((key, index) => [key, d[index].toString()]));
};

const cleanEnvironment = (overrides = {}) => {
  const env = { ...process.env, ...overrides };
  for (const name of ['C7_SHIELD_ADAPTER_FILE', 'C7_SHIELD_ADAPTER_SHA256', 'ELIG_INSTANCE', 'ELIG_FILE', 'ELIG_IDX', 'T7']) {
    if (!(name in overrides)) delete env[name];
  }
  return env;
};

const snapshotProgram = `
  import * as mm from './build/chunked/pairing/_millermath.mjs';
  import * as sz from './build/chunked/pairing/_szmath.mjs';
  import * as residue from './build/chunked/pairing/_residuemath.mjs';
  import * as gb3 from './build/chunked/pairing/gen_miller_gb3_9k7.mjs';
  import * as fixed from './lanes/bn254-onetx/src/c7/fixed-g2-lines.mjs';
  const strings = (values) => values.map(String);
  const pairs = mm.pairsFor(mm.publicInputs);
  const boundary = mm.millerBatchOps(pairs).boundary;
  const witness = residue.residueWitness(boundary);
  const trace = sz.trajectory();
  console.log(JSON.stringify({
    source: mm.activeInstance.source,
    publicInputs: strings(mm.publicInputs),
    vk: { alpha: mm.vk.alpha.toAffine(), beta: mm.vk.beta.toAffine(), gamma: mm.vk.gamma.toAffine(), delta: mm.vk.delta.toAffine(), ic: mm.vk.ic.map((point) => point.toAffine()) },
    proof: { a: mm.proof.a.toAffine(), b: mm.proof.b.toAffine(), c: mm.proof.c.toAffine() },
    pairs: pairs.map((pair) => pair.name),
    boundary: strings(mm.f12limbs(boundary)),
    residue: { c: strings(residue.fp12limbsOf(witness.c)), cInv: strings(residue.fp12limbsOf(witness.cInv)), w: strings(residue.fp12limbsOf(witness.w)) },
    trajectory: { gamma: trace.gamma.toString(), z: trace.z.toString(), fAB: strings(mm.f12limbs(trace.fAB)), statement: strings(trace.stmtLimbs), state1: strings(gb3.stateVal(1)) },
    fixedG2: fixed.fixedLineWindow(1, 14).digestHex,
  }, (_key, value) => typeof value === 'bigint' ? value.toString() : value));
`;

const snapshot = async (env = {}) => {
  const { stdout } = await execFile('node', ['--input-type=module', '--eval', snapshotProgram], {
    // GB3 serializes the fixed-pair affine slopes. This probe intentionally
    // exercises that active-instance-aware representation, not a CashC build.
    cwd: repoRoot, env: cleanEnvironment({ SZ_ALLAFF: '1', ...env }), maxBuffer: 8 * 1024 * 1024,
  });
  return JSON.parse(stdout);
};

const withAdapter = async (record, run) => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-active-'));
  try {
    const filename = path.join(directory, 'adapter-result.json');
    await writeFile(filename, `${JSON.stringify(record)}\n`);
    const sha256 = createHash('sha256').update(await readFile(filename)).digest('hex');
    return await run({ C7_SHIELD_ADAPTER_FILE: filename, C7_SHIELD_ADAPTER_SHA256: sha256 });
  } finally { await rm(directory, { recursive: true, force: true }); }
};

test('adapter is the sole active source and exactly reproduces the static PF7 trajectory without CashC', async () => {
  const vec = JSON.parse(await readFile(vectorsPath, 'utf8'));
  const baseline = await snapshot();
  const adapted = await withAdapter(adapterResultFor(vec), snapshot);
  assert.equal(baseline.source, 'committed-pairing-vectors');
  assert.equal(adapted.source, 'shield-adapter');
  delete baseline.source; delete adapted.source;
  assert.deepEqual(adapted, baseline);
});

test('a different valid same-VK fixture changes the live Miller and SZ trajectory', async () => {
  const vec = JSON.parse(await readFile(vectorsPath, 'utf8'));
  const multiproof = JSON.parse(await readFile(multiproofPath, 'utf8'));
  const baseline = await snapshot();
  const adapted = await withAdapter(adapterResultFor(vec, parseUnlocking(multiproof.proofs[1].unlocking)), snapshot);
  assert.equal(adapted.source, 'shield-adapter');
  assert.deepEqual(adapted.vk, baseline.vk);
  assert.notDeepEqual(adapted.publicInputs, baseline.publicInputs);
  assert.notDeepEqual(adapted.proof, baseline.proof);
  assert.notDeepEqual(adapted.boundary, baseline.boundary);
  assert.notEqual(adapted.trajectory.gamma, baseline.trajectory.gamma);
  assert.notEqual(adapted.trajectory.z, baseline.trajectory.z);
  assert.notDeepEqual(adapted.trajectory.statement, baseline.trajectory.statement);
  assert.notDeepEqual(adapted.trajectory.state1, baseline.trajectory.state1);
  assert.equal(adapted.fixedG2, baseline.fixedG2);
});

test('adapter mode forbids static-vector selectors and no longer permits a second build authority', async () => {
  const vec = JSON.parse(await readFile(vectorsPath, 'utf8'));
  await withAdapter(adapterResultFor(vec), async (env) => {
    await assert.rejects(
      () => execFile('node', ['--input-type=module', '--eval', "import * as m from './build/chunked/pairing/_millermath.mjs'; void m.vec.scalars;"], { cwd: repoRoot, env: cleanEnvironment(env) }),
      /C7_SHIELD_ADAPTER_\* forbids static vec\.scalars/,
    );
    await assert.rejects(() => snapshot({ ...env, T7: '1' }), /T7 requires committed synthetic toxic-waste scalars/);
    await assert.rejects(() => snapshot({ ...env, ELIG_IDX: '1' }), /cannot be combined with ELIG selectors/);
  });
  const [build, sz] = await Promise.all([
    readFile(path.join(repoRoot, 'lanes/bn254-onetx/src/c7/build.ts'), 'utf8'),
    readFile(path.join(repoRoot, 'build/chunked/pairing/_szmath.mjs'), 'utf8'),
  ]);
  assert.doesNotMatch(build, /\bACTIVE_VK\b|\bactivePairsFor\b|loadPinnedShieldAdapterResult/);
  assert.doesNotMatch(sz, /\bvec\b/);
});
