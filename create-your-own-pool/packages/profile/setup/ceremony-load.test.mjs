/**
 * Offline: ceremony runner → build profile → loadVerifierProfileBundle (same loader as development).
 */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { SNARKJS_VERSION, getPinnedSnarkjsInfo } from './development.mjs';
import { init } from '../init.mjs';
import { loadVerifierProfileBundle } from '../load.mjs';

const execFileAsync = promisify(execFile);
const here = path.dirname(new URL(import.meta.url).pathname);
const snarkCli = path.join(here, '..', 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const circomCli = path.join(here, '..', 'node_modules', 'circom2', 'cli.js');
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const bytes = (name, seed) => Buffer.from(`NON-CRYPTOGRAPHIC INIT TEST: ${name}: ${seed}\n`);

async function run(args, { entropy } = {}) {
  const child = execFile(process.execPath, [snarkCli, ...args], { cwd: here, env: {}, windowsHide: true });
  let output = ''; let suppliedEntropy = false;
  child.stdout.on('data', (chunk) => {
    if (entropy === undefined || suppliedEntropy) return;
    output = `${output}${String(chunk)}`.slice(-512);
    if (output.includes('Enter a random text. (Entropy):')) {
      suppliedEntropy = true;
      child.stdin.end(Buffer.concat([entropy, Buffer.from('\n')]));
    }
  });
  child.stderr.resume();
  if (entropy === undefined) child.stdin.end();
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`snarkjs failed: ${args.join(' ')}`));
      else if (entropy !== undefined && !suppliedEntropy) reject(new Error('entropy not requested'));
      else resolve();
    });
  });
}

async function tinyCircuit(root) {
  const source = path.join(root, 'tiny.circom');
  const compiled = path.join(root, 'compiled');
  await mkdir(compiled);
  await writeFile(source, 'pragma circom 2.0.0;\ntemplate Tiny() { signal input a; signal input b; signal product; product <== a * b; }\ncomponent main {public [a, b]} = Tiny();\n');
  await execFileAsync(process.execPath, [circomCli, source, '--r1cs', '--O0', '-o', compiled], { cwd: root, env: {} });
  const r1cs = path.join(compiled, 'tiny.r1cs');
  const pot0 = path.join(root, 'pot0.ptau');
  const pot1 = path.join(root, 'pot1.ptau');
  const ptau = path.join(root, 'phase2.ptau');
  await run(['powersoftau', 'new', 'bn128', '4', pot0]);
  await run(['powersoftau', 'contribute', pot0, pot1], { entropy: Buffer.from(randomBytes(64).toString('hex')) });
  await run(['powersoftau', 'prepare', 'phase2', pot1, ptau]);
  return { r1cs, ptau };
}

test('ceremony init → build → loadVerifierProfileBundle (same loader)', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-ceremony-load-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
  const { r1cs, ptau } = await tinyCircuit(root);
  const tool = await getPinnedSnarkjsInfo();
  const snarkjsCli = path.join(here, '..', 'node_modules', 'snarkjs', 'build', 'cli.cjs');
  const sourceRoot = path.join(root, 'sources');
  await mkdir(path.join(sourceRoot, 'artifacts'), { recursive: true });
  await mkdir(path.join(sourceRoot, 'toolchain'), { recursive: true });
  // Non-key fixtures (relation/abi/wasm/verifier-set)
  const fixtureFiles = {
    'artifacts/relation.json': bytes('relation', 'shared'),
    'artifacts/constraints.r1cs': await readFile(r1cs), // real r1cs ok
    'artifacts/public-input-abi.json': bytes('abi', 'shared'),
    'artifacts/witness-generator.bin': bytes('wg', 'shared'),
    'artifacts/verifier-set.json': bytes('vs', 'ceremony-load'),
    'toolchain/compiler': bytes('compiler', 'shared'),
    'toolchain/generator': await readFile(snarkjsCli),
  };
  for (const [rel, content] of Object.entries(fixtureFiles)) {
    const f = path.join(sourceRoot, rel);
    await mkdir(path.dirname(f), { recursive: true });
    await writeFile(f, content);
  }

  const e1 = Buffer.from(randomBytes(64).toString('hex'));
  const e2 = Buffer.from(randomBytes(64).toString('hex'));
  const setupDest = path.join(root, 'ceremony-setup');
  const bundleDest = path.join(root, 'profile-bundle');

  const result = await init({
    mode: 'ceremony-production',
    setup: {
      destination: setupDest,
      r1csPath: r1cs,
      ptauPath: ptau,
      ptauSource: 'local-test-phase1-power-4',
      expectedR1csSha256: digest(await readFile(r1cs)),
      expectedPtauSha256: digest(await readFile(ptau)),
      expectedPtauPower: 4,
      expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: tool.cliSha256 },
      participants: [
        { entropySource: { kind: 'bytes', bytes: e1 } },
        { entropySource: { kind: 'bytes', bytes: e2 } },
      ],
    },
    bundle: {
      destination: bundleDest,
      profile: {
        proofSystem: 'groth16',
        curve: 'bn254',
        relation: { id: 'shielded-action-v2' },
        publicInputAbi: { id: 'shielded-action-public-input-v1' },
      },
      toolchain: {
        compiler: {
          name: 'fixture-compiler',
          version: '0.0.0-noncryptographic',
          source: { sourcePath: path.join(sourceRoot, 'toolchain/compiler') },
        },
        generator: {
          name: 'snarkjs',
          version: SNARKJS_VERSION,
          source: { sourcePath: snarkjsCli },
        },
      },
      network: { name: 'chipnet' },
      genesis: {
        categoryInputOutpoint: {
          txid: digest('ceremony-category').slice('sha256:'.length),
          vout: '0',
        },
        reserveCapSatoshis: '10000000',
      },
      // ids strictly sorted
      artifacts: [
        { id: 'abi', kind: 'public-input-abi', path: 'artifacts/public-input-abi.json', source: { sourcePath: path.join(sourceRoot, 'artifacts/public-input-abi.json') } },
        { id: 'pk', kind: 'proving-key', path: 'artifacts/final.zkey' },
        { id: 'relation', kind: 'relation-definition', path: 'artifacts/relation.json', source: { sourcePath: path.join(sourceRoot, 'artifacts/relation.json') } },
        { id: 'r1cs', kind: 'constraint-system', path: 'artifacts/constraints.r1cs', source: { sourcePath: path.join(sourceRoot, 'artifacts/constraints.r1cs') } },
        { id: 'transcript', kind: 'ceremony-transcript', path: 'artifacts/ceremony-transcript.json' },
        { id: 'vk', kind: 'verification-key', path: 'artifacts/verification_key.json' },
        { id: 'vs', kind: 'bch-verifier-set', path: 'artifacts/verifier-set.json', source: { sourcePath: path.join(sourceRoot, 'artifacts/verifier-set.json') } },
        { id: 'wg', kind: 'witness-generator', path: 'artifacts/witness-generator.bin', source: { sourcePath: path.join(sourceRoot, 'artifacts/witness-generator.bin') } },
      ],
    },
    load: true,
  });

  assert.equal(result.mode, 'ceremony-production');
  assert.equal(result.manifest.setup.mode, 'ceremony-production');
  assert.equal(result.manifest.setup.provenance.method, 'multi-party-randomness');
  assert.ok(result.manifest.setup.contributions.length >= 2);
  assert.equal(result.manifest.setup.transcript.status, 'complete');
  assert.ok(result.loaded);
  assert.equal(result.loaded.profileId, result.profileId);
  assert.equal(result.loaded.instanceId, result.instanceId);
  assert.equal(result.loaded.manifest.setup.mode, 'ceremony-production');

  // Same loader entry as development path
  const again = await loadVerifierProfileBundle(result.bundleDirectory, {
    network: 'chipnet',
    profileId: result.profileId,
    instanceId: result.instanceId,
  });
  assert.equal(again.profileId, result.profileId);
  assert.equal(again.manifest.setup.mode, 'ceremony-production');
});
