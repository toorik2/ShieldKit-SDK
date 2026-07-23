import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { ProofCorpusError, runProofCorpus } from './proof-corpus.mjs';

const fixture = path.join(path.dirname(fileURLToPath(import.meta.url)), 'node_modules', 'circom_runtime', 'test', 'circuit');
const digest = async (filename) => createHash('sha256').update(await (await import('node:fs/promises')).readFile(filename)).digest('hex');
const artifact = async (filename) => ({ path: filename, sha256: await digest(filename) });

async function manifestAt(directory, changes = {}) {
  const wasm = path.join(fixture, 'circuit_js', 'circuit.wasm');
  const input = path.join(fixture, 'input.json');
  const manifest = {
    schema: 'shield.cash/proof-corpus/v1',
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

test('tiny real circuit is rejected after proof verification when public arity is not two', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    await assert.rejects(() => runProofCorpus(filename), /public signals must contain exactly two packet-digest limbs/);
    await lstat(path.join(manifest.outputDirectory, 'deposit.wtns'));
    await lstat(path.join(manifest.outputDirectory, 'deposit.proof.json'));
    await lstat(path.join(manifest.outputDirectory, 'deposit.public.json'));
    await assert.rejects(() => lstat(path.join(manifest.outputDirectory, 'result.json')));
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

test('refuses a pre-existing output directory without touching supplied artifacts', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-proof-corpus-'));
  try {
    const { filename, manifest } = await manifestAt(directory);
    await mkdir(manifest.outputDirectory);
    await assert.rejects(() => runProofCorpus(filename), /refusing to overwrite output directory/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
