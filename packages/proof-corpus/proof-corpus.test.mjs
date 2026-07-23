import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, mkdir, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { ProofCorpusError, parseStrictJson, runProofCorpus, sha256File } from './proof-corpus.mjs';

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(packageDirectory, 'node_modules', 'circom_runtime', 'test', 'circuit');
const snarkjsCli = path.join(packageDirectory, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const digest = async (filename) => createHash('sha256').update(await readFile(filename)).digest('hex');
const artifact = async (filename) => ({ path: filename, sha256: await digest(filename) });

async function manifestAt(directory, changes = {}) {
  const wasm = path.join(fixture, 'circuit_js', 'circuit.wasm');
  const input = path.join(fixture, 'input.json');
  const manifest = {
    schema: 'shield.cash/proof-corpus/v1',
    snarkjs: { path: snarkjsCli, sha256: await digest(snarkjsCli), version: '0.7.6' },
    artifacts: {
      r1cs: await artifact(path.join(fixture, 'circuit.r1cs')),
      wasm: await artifact(wasm),
      zkey: await artifact(path.join(fixture, 'circuit.zkey')),
      verificationKey: await artifact(path.join(fixture, 'verification_key.json')),
    },
    actions: await Promise.all(['deposit', 'transfer', 'withdrawal'].map(async (kind) => ({
      kind, input: await artifact(input), packetDigest: ['1', '2'],
    }))),
    outputDirectory: path.join(directory, 'output'),
    ...changes,
  };
  const filename = path.join(directory, 'manifest.json');
  await writeFile(filename, `${JSON.stringify(manifest)}\n`);
  return { filename, manifest };
}
async function assertNoStage(directory, outputDirectory) {
  const prefix = `.${path.basename(outputDirectory)}.staging-`;
  assert.equal((await readdir(directory)).some((name) => name.startsWith(prefix)), false);
}

test('tiny real circuit verifies then leaves no published or staged output on incompatible public arity', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    await assert.rejects(() => runProofCorpus(filename), /public signals must contain exactly two packet-digest limbs/);
    await assert.rejects(() => lstat(manifest.outputDirectory));
    await assertNoStage(directory, manifest.outputDirectory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a symlinked caller artifact before creating output', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    const linked = path.join(directory, 'linked.r1cs');
    await symlink(manifest.artifacts.r1cs.path, linked);
    manifest.artifacts.r1cs = { path: linked, sha256: await digest(manifest.artifacts.r1cs.path) };
    await writeFile(filename, `${JSON.stringify(manifest)}\n`);
    await assert.rejects(() => runProofCorpus(filename), ProofCorpusError);
    await assert.rejects(() => lstat(manifest.outputDirectory));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a duplicate manifest key before artifact execution', () => {
  assert.throws(() => parseStrictJson('{"schema":"shield.cash/proof-corpus/v1","schema":"drift"}', 'manifest'), /duplicate key/);
});

test('rejects caller-pinned snarkjs hash drift', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    manifest.snarkjs.sha256 = '0'.repeat(64);
    await writeFile(filename, `${JSON.stringify(manifest)}\n`);
    await assert.rejects(() => runProofCorpus(filename), /snarkjs SHA-256 mismatch/);
    await assert.rejects(() => lstat(manifest.outputDirectory));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects caller-pinned snarkjs version drift', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    manifest.snarkjs.version = '0.0.0';
    await writeFile(filename, `${JSON.stringify(manifest)}\n`);
    await assert.rejects(() => runProofCorpus(filename), /pinned snarkjs version mismatch/);
    await assert.rejects(() => lstat(manifest.outputDirectory));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a destination with a symlinked parent', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    const actualParent = path.join(directory, 'actual'); const linkedParent = path.join(directory, 'linked');
    await mkdir(actualParent); await symlink(actualParent, linkedParent);
    manifest.outputDirectory = path.join(linkedParent, 'output');
    await writeFile(filename, `${JSON.stringify(manifest)}\n`);
    await assert.rejects(() => runProofCorpus(filename), /output parent must be a direct non-symlink directory/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('streams SHA-256 rather than buffering a large artifact', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const filename = path.join(directory, 'large.r1cs'); const bytes = Buffer.alloc(8 * 1024 * 1024, 0xa5);
    await writeFile(filename, bytes);
    assert.equal(await sha256File(filename), createHash('sha256').update(bytes).digest('hex'));
    const source = await readFile(path.join(packageDirectory, 'proof-corpus.mjs'), 'utf8');
    assert.match(source, /for await \(const chunk of createReadStream\(filename\)\)/);
    assert.doesNotMatch(source.match(/export async function sha256File[\s\S]*?\n}\n/)?.[0] ?? '', /readFile\(/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
