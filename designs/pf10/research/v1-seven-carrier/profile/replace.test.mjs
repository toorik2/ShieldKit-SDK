// The fixtures below are hash-authenticated bundle inputs with canonical
// P2SH32 carrier authority. They deliberately do not execute a proof or PF7
// verifier VM and are not production, ceremony, or deployment evidence.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { buildVerifierProfileBundle } from './build.mjs';
import {
  derivePf7SettlementKernelAuthority,
  encodeCanonicalPf7CarrierSourceSet,
} from '../prove/authority.mjs';
import { runProfileReplacementDrill } from './replace.mjs';

const execFileAsync = promisify(execFile);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const digest = (value) => `sha256:${sha256(value)}`;

function verifierSet(seed) {
  const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];
  const scripts = names.map((name, index) => {
    const redeem = Buffer.from([0x51, index + 1, seed.charCodeAt(0)]);
    return {
      name,
      redeemBytecodeHex: redeem.toString('hex'),
      lockingBytecodeHex: `aa20${sha256(createHash('sha256').update(redeem).digest())}87`,
      sourceValueSatoshis: String(1_000 + index),
    };
  });
  const carriers = scripts.map((script) => ({
    role: script.name,
    lockingBytecode: Buffer.from(script.lockingBytecodeHex, 'hex'),
    valueSatoshis: BigInt(script.sourceValueSatoshis),
  }));
  return Buffer.from(JSON.stringify({
    schema: 'shield.cash/bch-verifier-set/v1', scripts,
    sourceSet: {
      encoding: 'libauth-transaction-outputs-v1', carrierCount: 7,
      sha256: digest(encodeCanonicalPf7CarrierSourceSet(scripts)),
    },
    settlementKernel: derivePf7SettlementKernelAuthority(carriers).artifact,
  }));
}

async function makeBundle(root, seed, categoryTxid) {
  const source = path.join(root, `source-${seed}`);
  const artifactBytes = {
    'bch-verifier-set': verifierSet(seed),
    'constraint-system': Buffer.from('STRUCTURAL DRILL R1CS; no proof claim\n'),
    'proving-key': Buffer.from(`STRUCTURAL DRILL proving key ${seed}; no proof claim\n`),
    'public-input-abi': Buffer.from('{"publicInputs":2,"structuralDrill":true}\n'),
    'relation-definition': Buffer.from('STRUCTURAL DRILL relation; no proof claim\n'),
    'verification-key': Buffer.from(`STRUCTURAL DRILL verification key ${seed}; no proof claim\n`),
    'witness-generator': Buffer.from('STRUCTURAL DRILL witness generator; no proof claim\n'),
  };
  const filenames = {
    'bch-verifier-set': 'artifacts/bch-verifier-set.json',
    'constraint-system': 'artifacts/constraints.r1cs',
    'proving-key': 'artifacts/proving.zkey',
    'public-input-abi': 'artifacts/abi.json',
    'relation-definition': 'artifacts/relation.txt',
    'verification-key': 'artifacts/verification-key.json',
    'witness-generator': 'artifacts/witness.bin',
  };
  for (const [kind, bytes] of Object.entries(artifactBytes)) {
    const filename = path.join(source, filenames[kind]);
    await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, bytes);
  }
  const compiler = path.join(source, 'toolchain/compiler'); const generator = path.join(source, 'toolchain/generator');
  await mkdir(path.dirname(compiler), { recursive: true });
  await writeFile(compiler, 'structural-drill compiler\n'); await writeFile(generator, 'structural-drill generator\n');
  return buildVerifierProfileBundle({
    destination: path.join(root, `bundle-${seed}`),
    profile: { proofSystem: 'groth16', curve: 'bn254', relation: { id: 'shielded-action-v2' }, publicInputAbi: { id: 'shielded-action-public-input-v1' } },
    setup: {
      mode: 'development-only',
      provenance: { method: 'local-initialization', initializerCommitment: digest(`initializer-${seed}`) },
      material: {
        phase1: { ptauSource: 'structural-drill-ptau', ptauSha256: digest('structural-drill-ptau') },
        phase2: {
          initializationCommand: { argv: ['structural-drill', 'init'] },
          contributionCommand: { argv: ['structural-drill', 'contribute'] },
          randomnessCommitment: digest(`randomness-${seed}`),
          finalZkeySha256: digest(artifactBytes['proving-key']),
        },
      },
    },
    toolchain: {
      compiler: { name: 'structural-drill-compiler', version: '1', source: { sourcePath: compiler } },
      generator: { name: 'structural-drill-generator', version: '1', source: { sourcePath: generator } },
    },
    network: { name: 'chipnet' },
    artifacts: Object.entries(filenames).map(([kind, filename]) => ({ id: kind, kind, path: filename, source: { sourcePath: path.join(source, filename) } })),
    genesis: { categoryInputOutpoint: { txid: categoryTxid, vout: '0' }, reserveCapSatoshis: '10000000' },
  });
}

const pin = (bundle) => ({ network: 'chipnet', profileId: bundle.profileId, instanceId: bundle.instanceId });

test('distinct authenticated PF7 bundles preserve SDK shape and reject cross-profile loading', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-profile-replacement-drill-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const left = await makeBundle(root, 'a', '11'.repeat(32));
  const right = await makeBundle(root, 'b', '22'.repeat(32));
  const result = await runProfileReplacementDrill({
    left: { bundleDirectory: left.directory, expectedProfile: pin(left) },
    right: { bundleDirectory: right.directory, expectedProfile: pin(right) },
  });
  assert.equal(result.schema, 'shield.cash/profile-replacement-drill/v1');
  assert.equal(result.setupMode, 'development-only');
  assert.equal(result.sdk.schema, 'shield.cash/desktop-wallet-sdk/v2');
  assert.equal(result.sdk.methods.length, 11);
  assert.notEqual(result.replacements.left.profileId, result.replacements.right.profileId);
  assert.notEqual(result.replacements.left.instanceId, result.replacements.right.instanceId);
  assert.notEqual(result.replacements.left.stateNftCategory, result.replacements.right.stateNftCategory);
  assert.notEqual(result.replacements.left.pf7SourceSetSha256, result.replacements.right.pf7SourceSetSha256);
  assert.notEqual(result.replacements.left.stateHelperSha256, result.replacements.right.stateHelperSha256);

  const input = path.join(root, 'drill.json');
  await writeFile(input, JSON.stringify({
    left: { bundleDirectory: path.basename(left.directory), expectedProfile: pin(left) },
    right: { bundleDirectory: path.basename(right.directory), expectedProfile: pin(right) },
  }));
  const { stdout, stderr } = await execFileAsync(process.execPath, ['replace-cli.mjs', '--input', input], { cwd: path.dirname(new URL(import.meta.url).pathname) });
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout), result);
  const output = path.join(root, 'drill-result.json');
  const published = await execFileAsync(process.execPath, ['replace-cli.mjs', '--input', input, '--output', output], { cwd: path.dirname(new URL(import.meta.url).pathname) });
  assert.equal(published.stderr, '');
  assert.equal(await readFile(output, 'utf8'), published.stdout);
  await assert.rejects(
    () => execFileAsync(process.execPath, ['replace-cli.mjs', '--input', input, '--output', output], { cwd: path.dirname(new URL(import.meta.url).pathname) }),
    /profile-replacement-drill:/,
  );
});

test('drill rejects a post-authentication verifier-set mutation before SDK loading', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-profile-replacement-drill-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const left = await makeBundle(root, 'a', '11'.repeat(32));
  const right = await makeBundle(root, 'b', '22'.repeat(32));
  await writeFile(path.join(right.directory, 'artifacts/bch-verifier-set.json'), 'mutated after profile authentication\n');
  await assert.rejects(
    () => runProfileReplacementDrill({
      left: { bundleDirectory: left.directory, expectedProfile: pin(left) },
      right: { bundleDirectory: right.directory, expectedProfile: pin(right) },
    }),
    /authenticated bundle load failed: artifact hash mismatch: artifacts\/bch-verifier-set.json/,
  );
});
