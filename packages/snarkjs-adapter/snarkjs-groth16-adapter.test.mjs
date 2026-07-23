import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { SnarkjsAdapterError, adaptSnarkjsGroth16 } from './snarkjs-groth16-adapter.mjs';

const execFile = promisify(execFileCallback);
const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, 'test-fixtures', 'two-public');
const cli = path.join(here, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const adapterCli = path.join(here, 'snarkjs-groth16-adapter.mjs');
const digest = async (filename) => createHash('sha256').update(await readFile(filename)).digest('hex');
const record = async (filename) => ({ path: filename, sha256: await digest(filename) });
const records = async (directory = fixture) => ({
  verificationKey: await record(path.join(directory, 'verification_key.json')),
  proof: await record(path.join(directory, 'proof.json')),
  publicSignals: await record(path.join(directory, 'public.json')),
});
async function copyFixture(directory) {
  for (const name of ['verification_key.json', 'proof.json', 'public.json']) await writeFile(path.join(directory, name), await readFile(path.join(fixture, name)));
}
async function changed(directory, name, mutate) {
  const filename = path.join(directory, name); const value = JSON.parse(await readFile(filename, 'utf8'));
  mutate(value); await writeFile(filename, `${JSON.stringify(value)}\n`); return filename;
}

test('adapts a real snarkjs-verified two-public BN254 Groth16 fixture into PF7 fields', async () => {
  const key = path.join(fixture, 'verification_key.json'); const proof = path.join(fixture, 'proof.json'); const publicSignals = path.join(fixture, 'public.json');
  const { stdout } = await execFile(process.execPath, [cli, 'groth16', 'verify', key, publicSignals, proof]);
  assert.match(stdout, /OK!/);
  const result = await adaptSnarkjsGroth16(await records());
  const rawProof = JSON.parse(await readFile(proof, 'utf8'));
  assert.equal(result.verificationKey.publicArity, 2);
  assert.deepEqual(result.verifierCashFixture, {
    Ax: rawProof.pi_a[0], Ay: rawProof.pi_a[1],
    Bxa: rawProof.pi_b[0][0], Bxb: rawProof.pi_b[0][1],
    Bya: rawProof.pi_b[1][0], Byb: rawProof.pi_b[1][1],
    Cx: rawProof.pi_c[0], Cy: rawProof.pi_c[1], in0: '3', in1: '5',
  });
  assert.match(result.byteOrder.g2, /no component reversal/);
});

test('rejects duplicate JSON keys before Groth16 interpretation', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
  try {
    await copyFixture(directory);
    const filename = path.join(directory, 'proof.json');
    await writeFile(filename, '{"protocol":"groth16","protocol":"groth16","curve":"bn128","pi_a":[],"pi_b":[],"pi_c":[]}');
    const input = await records(directory);
    await assert.rejects(() => adaptSnarkjsGroth16(input), /duplicate JSON object name/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('rejects caller hash drift and symlinked artifacts', async () => {
  const input = await records(); input.proof.sha256 = '0'.repeat(64);
  await assert.rejects(() => adaptSnarkjsGroth16(input), /SHA-256 mismatch/);
  const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
  try {
    const linked = path.join(directory, 'linked-proof.json'); await symlink(path.join(fixture, 'proof.json'), linked);
    const linkedInput = await records(); linkedInput.proof = { path: linked, sha256: await digest(path.join(fixture, 'proof.json')) };
    await assert.rejects(() => adaptSnarkjsGroth16(linkedInput), /non-symlink/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('rejects wrong protocol, curve, public arity, scalar encoding, and malformed G1', async () => {
  const cases = [
    ['wrong proof protocol', 'proof.json', (v) => { v.protocol = 'plonk'; }, /protocol/],
    ['wrong verification-key curve', 'verification_key.json', (v) => { v.curve = 'bls12381'; }, /curve/],
    ['wrong verification-key public arity', 'verification_key.json', (v) => { v.nPublic = 3; }, /nPublic/],
    ['noncanonical public scalar', 'public.json', (v) => { v[0] = '03'; }, /canonical nonnegative decimal/],
    ['malformed proof G1', 'proof.json', (v) => { v.pi_a = ['2', '1', '1']; }, /valid BN254 G1/],
  ];
  for (const [name, filename, mutate, error] of cases) {
    const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
    try {
      await copyFixture(directory); await changed(directory, filename, mutate);
      await assert.rejects(async () => adaptSnarkjsGroth16(await records(directory)), error, name);
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
});

test('rejects infinity-shaped and out-of-field BN254 G2 values', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
  try {
    await copyFixture(directory);
    await changed(directory, 'proof.json', (v) => { v.pi_b[2] = ['0', '0']; });
    await assert.rejects(async () => adaptSnarkjsGroth16(await records(directory)), /canonical affine/);
    await copyFixture(directory);
    await changed(directory, 'proof.json', (v) => { v.pi_b[0][0] = '21888242871839275222246405745257275088696311157297823662689037894645226208583'; });
    await assert.rejects(async () => adaptSnarkjsGroth16(await records(directory)), /canonical field range/);
    await copyFixture(directory);
    await changed(directory, 'verification_key.json', (v) => { v.vk_beta_2[0][0] = '1'; });
    await assert.rejects(async () => adaptSnarkjsGroth16(await records(directory)), /valid BN254 G2/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('rejects incorrect public-signal count', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
  try {
    await copyFixture(directory); await writeFile(path.join(directory, 'public.json'), '["3","5","7"]\n');
    await assert.rejects(async () => adaptSnarkjsGroth16(await records(directory)), /exactly two public signals/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('exports only the explicit PF7 fixture field names', async () => {
  const result = await adaptSnarkjsGroth16(await records());
  assert.deepEqual(Object.keys(result.verifierCashFixture).sort(), ['Ax', 'Ay', 'Bxa', 'Bxb', 'Bya', 'Byb', 'Cx', 'Cy', 'in0', 'in1'].sort());
  assert.throws(() => Object.assign(result.verifierCashFixture, { extra: 'forbidden' }), TypeError);
  assert.ok(result instanceof Object);
  assert.equal(result.qualification.includes('not a verifier bundle'), true);
  assert.equal(SnarkjsAdapterError.prototype instanceof Error, true);
});

test('CLI requires a caller-pinned manifest and emits the same PF7 fixture', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-adapter-'));
  try {
    const manifest = path.join(directory, 'manifest.json'); const input = await records();
    await writeFile(manifest, `${JSON.stringify(input)}\n`);
    const { stdout } = await execFile(process.execPath, [adapterCli, manifest, await digest(manifest)]);
    assert.deepEqual(JSON.parse(stdout).verifierCashFixture, (await adaptSnarkjsGroth16(input)).verifierCashFixture);
    await assert.rejects(() => execFile(process.execPath, [adapterCli, manifest, '0'.repeat(64)]), /SHA-256 mismatch/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
