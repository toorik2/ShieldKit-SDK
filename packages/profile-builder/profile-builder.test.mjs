// These fixtures are deliberately non-cryptographic temporary bytes. They
// exercise packaging and loader boundaries only; no setup, proof, verifier, or
// BCH artifact is created or represented as valid by these tests.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import {
  ProfileBuildError, assertVerifierSetIsPreGenesis, buildVerifierProfileBundle,
} from './profile-builder.mjs';

const execFileAsync = promisify(execFile);
const digest = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const bytes = (name, seed) => Buffer.from(`NON-CRYPTOGRAPHIC PROFILE-BUILDER TEST BYTES: ${name}: ${seed}\n`);

async function makeInput(root, seed, destination, options = {}) {
  const sourceRoot = path.join(root, `source-${seed}`);
  const artifacts = {
    'bch-verifier-set': ['bch-verifier-set', 'artifacts/verifier-set.json', bytes('bch-verifier-set', seed)],
    'constraint-system': ['constraint-system', 'artifacts/constraints.r1cs', bytes('constraint-system', 'shared')],
    'proving-key': ['proving-key', 'artifacts/pk.bin', bytes('proving-key', seed)],
    'public-input-abi': ['public-input-abi', 'artifacts/public-input-abi.json', bytes('public-input-abi', 'shared')],
    'relation-definition': ['relation-definition', 'artifacts/relation.json', bytes('relation-definition', 'shared')],
    'verification-key': ['verification-key', 'artifacts/vk.bin', bytes('verification-key', seed)],
    'witness-generator': ['witness-generator', 'artifacts/witness-generator.bin', bytes('witness-generator', seed)],
  };
  for (const [, relative, content] of Object.values(artifacts)) {
    const file = path.join(sourceRoot, relative); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, content);
  }
  const compiler = path.join(sourceRoot, 'toolchain/compiler'); const generator = path.join(sourceRoot, 'toolchain/generator');
  await mkdir(path.dirname(compiler), { recursive: true }); await writeFile(compiler, bytes('compiler', 'shared')); await writeFile(generator, bytes('generator', 'shared'));
  const artifactInputs = Object.entries(artifacts).map(([id, [kind, relative]]) => ({
    id, kind, path: relative, source: { sourcePath: path.join(sourceRoot, relative) },
  }));
  return {
    destination,
    profile: { proofSystem: 'groth16', curve: 'bn254', relation: { id: 'shielded-action-v1' }, publicInputAbi: { id: 'shielded-action-public-input-v1' } },
    setup: {
      mode: 'development-only', provenance: { method: 'local-initialization', initializerCommitment: digest(`initializer-${seed}`) },
      material: {
        phase1: { ptauSource: 'noncryptographic-test-ptau', ptauSha256: digest(`ptau-${seed}`) },
        phase2: {
          initializationCommand: { argv: ['fixture-zkey', 'new', 'circuit.r1cs', 'ptau'] },
          contributionCommand: { argv: ['fixture-zkey', 'contribute', 'initial.zkey', 'final.zkey'] },
          randomnessCommitment: digest(`randomness-${seed}`), finalZkeySha256: digest(artifacts['proving-key'][2]),
        },
      },
    },
    toolchain: {
      compiler: { name: 'fixture-compiler', version: '0.0.0-noncryptographic', source: { sourcePath: compiler } },
      generator: { name: 'fixture-generator', version: '0.0.0-noncryptographic', source: { sourcePath: generator } },
    },
    network: { name: 'chipnet' },
    artifacts: artifactInputs,
    genesis: {
      categoryInputOutpoint: { txid: options.categoryTxid ?? digest('shared-category-input').slice('sha256:'.length), vout: '0' },
      reserveCapSatoshis: '10000000',
    },
  };
}

async function testRoot(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-profile-builder-test-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
  return root;
}

test('identical caller material is reproducible and distinct setup/key material gets distinct identities', async (t) => {
  const root = await testRoot(t);
  const firstInput = await makeInput(root, 'same', path.join(root, 'bundle-a'));
  const secondInput = { ...firstInput, destination: path.join(root, 'bundle-b') };
  const first = await buildVerifierProfileBundle(firstInput);
  const second = await buildVerifierProfileBundle(secondInput);
  assert.equal(first.profileId, second.profileId);
  assert.equal(first.instanceId, second.instanceId);
  assert.deepEqual(
    await readFile(path.join(first.directory, 'manifest.json')),
    await readFile(path.join(second.directory, 'manifest.json')),
  );

  const changedInput = await makeInput(root, 'changed', path.join(root, 'bundle-changed'));
  const changed = await buildVerifierProfileBundle(changedInput);
  assert.equal(first.manifest.profile.relation.sha256, changed.manifest.profile.relation.sha256);
  assert.equal(first.manifest.profile.publicInputAbi.sha256, changed.manifest.profile.publicInputAbi.sha256);
  assert.notEqual(first.manifest.profile.bchVerifierSetHash, changed.manifest.profile.bchVerifierSetHash);
  assert.notEqual(first.profileId, changed.profileId);
  assert.notEqual(first.instanceId, changed.instanceId);
  assert.equal(changed.manifest.setup.mode, 'development-only');
});

test('builder fails closed for traversal, symlink source, supplied hash mismatch, and existing destination', async (t) => {
  const root = await testRoot(t);
  const traversal = await makeInput(root, 'traversal', path.join(root, 'traversal-output'));
  traversal.artifacts[0].path = '../escape';
  await assert.rejects(() => buildVerifierProfileBundle(traversal), /safe relative POSIX path|traversal/);

  const symlinked = await makeInput(root, 'symlink', path.join(root, 'symlink-output'));
  const linked = path.join(root, 'linked-relation');
  await symlink(symlinked.artifacts.find((artifact) => artifact.kind === 'relation-definition').source.sourcePath, linked);
  symlinked.artifacts.find((artifact) => artifact.kind === 'relation-definition').source.sourcePath = linked;
  await assert.rejects(() => buildVerifierProfileBundle(symlinked), /regular non-symlink file|must not use symlinks/);

  const hashMismatch = await makeInput(root, 'hash-mismatch', path.join(root, 'hash-output'));
  hashMismatch.artifacts[0].expectedSha256 = `sha256:${'0'.repeat(64)}`;
  await assert.rejects(() => buildVerifierProfileBundle(hashMismatch), /artifact expected hash mismatch/);

  const wrongFinalZkey = await makeInput(root, 'wrong-final-zkey', path.join(root, 'wrong-final-zkey-output'));
  wrongFinalZkey.setup.material.phase2.finalZkeySha256 = digest('different-final-zkey');
  await assert.rejects(() => buildVerifierProfileBundle(wrongFinalZkey), /setup material final zkey hash does not bind proving-key artifact/);

  const existing = path.join(root, 'existing'); await mkdir(existing); await writeFile(path.join(existing, 'sentinel'), 'preserve');
  const overwrite = await makeInput(root, 'overwrite', existing);
  await assert.rejects(() => buildVerifierProfileBundle(overwrite), /destination already exists; refusing overwrite/);
  assert.equal(await readFile(path.join(existing, 'sentinel'), 'utf8'), 'preserve');
});

test('expected binding rejection happens during staging and does not create a destination', async (t) => {
  const root = await testRoot(t);
  const destination = path.join(root, 'rejected-binding');
  const input = await makeInput(root, 'expected-binding', destination);
  input.expected = { profileId: digest('unrelated-profile') };
  await assert.rejects(() => buildVerifierProfileBundle(input), /expected profile binding mismatch: refusing hot swap/);
  await assert.rejects(() => lstat(destination));
});

test('CLI resolves caller paths from metadata and emits only built identities', async (t) => {
  const root = await testRoot(t);
  const input = await makeInput(root, 'cli', path.join(root, 'cli-output'));
  const metadata = path.join(root, 'input.json'); await writeFile(metadata, JSON.stringify(input));
  const { stdout, stderr } = await execFileAsync(process.execPath, ['cli.mjs', '--input', metadata], { cwd: path.dirname(new URL(import.meta.url).pathname) });
  assert.equal(stderr, '');
  const result = JSON.parse(stdout);
  assert.match(result.profileId, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.instanceId, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.directory, path.join(root, 'cli-output'));
});

test('public errors are typed', () => {
  assert.equal(new ProfileBuildError('x').name, 'ProfileBuildError');
});

test('pre-genesis verifier-set guard rejects direct final profile or instance identifiers', () => {
  const profileId = digest('profile-id'); const instanceId = digest('instance-id');
  assert.doesNotThrow(() => assertVerifierSetIsPreGenesis(bytes('verifier-set', 'no-identities'), { profileId, instanceId }));
  assert.throws(
    () => assertVerifierSetIsPreGenesis(Buffer.from(`lock ${profileId}`), { profileId, instanceId }),
    /bch-verifier-set must not embed final profileId/,
  );
  assert.throws(
    () => assertVerifierSetIsPreGenesis(Buffer.from(instanceId.slice('sha256:'.length), 'hex'), { profileId, instanceId }),
    /bch-verifier-set must not embed final instanceId/,
  );
});
