// These are integration tests: every proving/verifying key comes from a tiny
// real Circom/snarkjs local setup. Supporting relation/BCH bytes are marked
// test-only packaging inputs and make no verifier, proof, or release claim.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { SNARKJS_VERSION, getPinnedSnarkjsInfo, initializeDevelopmentGroth16 } from '../local-setup/local-setup.mjs';
import { compareDevelopmentVerifierProfileBundles } from '../core/verifier-profile.mjs';
import { SetupProfileBridgeError, bridgeLocalSetupToProfile } from './setup-profile-bridge.mjs';

const execFileAsync = promisify(execFile);
const here = path.dirname(new URL(import.meta.url).pathname);
const localSetup = path.resolve(here, '../local-setup');
const snarkCli = path.join(localSetup, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const circomCli = path.join(localSetup, 'node_modules', 'circom2', 'cli.js');
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

async function runSnark(args, { entropy } = {}) {
  const child = execFile(process.execPath, [snarkCli, ...args], { cwd: localSetup, env: {}, windowsHide: true });
  let output = ''; let sent = false;
  child.stdout.on('data', (chunk) => {
    if (entropy === undefined || sent) return;
    output = `${output}${String(chunk)}`.slice(-512);
    if (output.includes('Enter a random text. (Entropy):')) { sent = true; child.stdin.end(Buffer.concat([entropy, Buffer.from('\n')])); }
  });
  child.stderr.resume(); if (entropy === undefined) child.stdin.end();
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`snarkjs integration command failed: ${args.join(' ')}`));
      else if (entropy !== undefined && !sent) reject(new Error('snarkjs integration contribution did not request entropy'));
      else resolve();
    });
  });
}

async function realFixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-setup-profile-bridge-test-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
  const source = path.join(root, 'tiny.circom'); const compiled = path.join(root, 'compiled'); await mkdir(compiled);
  await writeFile(source, 'pragma circom 2.0.0;\ntemplate Tiny() { signal input a; signal input b; signal product; product <== a * b; }\ncomponent main {public [a, b]} = Tiny();\n');
  await execFileAsync(process.execPath, [circomCli, source, '--r1cs', '--O0', '-o', compiled], { cwd: root, env: {} });
  const r1cs = path.join(compiled, 'tiny.r1cs'); const pot0 = path.join(root, 'pot0.ptau'); const pot1 = path.join(root, 'pot1.ptau'); const ptau = path.join(root, 'phase2.ptau');
  await runSnark(['powersoftau', 'new', 'bn128', '4', pot0]);
  const phaseOneEntropy = Buffer.from(randomBytes(64).toString('hex'));
  try { await runSnark(['powersoftau', 'contribute', pot0, pot1], { entropy: phaseOneEntropy }); } finally { phaseOneEntropy.fill(0); }
  await runSnark(['powersoftau', 'prepare', 'phase2', pot1, ptau]);
  const pinned = await getPinnedSnarkjsInfo();
  async function setup(name) {
    const entropyPath = path.join(root, `${name}-entropy.txt`); await writeFile(entropyPath, randomBytes(64).toString('hex'), { mode: 0o600 }); await chmod(entropyPath, 0o600);
    const entropy = await open(entropyPath, 'r'); t.after(async () => entropy.close());
    return initializeDevelopmentGroth16({
      destination: path.join(root, name), r1csPath: r1cs, ptauPath: ptau, ptauSource: 'tiny-real-test-ptau-power-4',
      expectedR1csSha256: digest(await readFile(r1cs)), expectedPtauSha256: digest(await readFile(ptau)), expectedPtauPower: 4,
      expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: pinned.cliSha256 }, entropySource: { kind: 'fd', fd: entropy.fd },
    });
  }
  return { root, r1cs, setup, generatorPath: path.join(localSetup, 'node_modules', 'snarkjs', 'build', 'cli.cjs') };
}

async function bridgeInput(fixture, setupDirectory, destination) {
  const setupMetadata = path.join(setupDirectory, 'setup-metadata.json'); const source = path.join(fixture.root, 'profile-inputs'); await mkdir(source, { recursive: true });
  const supporting = {
    'bch-verifier-set': ['bch-verifier-set', 'artifacts/verifier-set.bin', Buffer.from('TEST-ONLY verifier-set bytes; no BCH execution claim\n')],
    'public-input-abi': ['public-input-abi', 'artifacts/public-input-abi.json', Buffer.from('{"testOnly":true,"publicInputs":2,"outputs":0}\n')],
    'relation-definition': ['relation-definition', 'artifacts/relation.json', Buffer.from('{"testOnly":true,"relation":"tiny-real-setup-bridge"}\n')],
    'witness-generator': ['witness-generator', 'artifacts/witness.bin', Buffer.from('TEST-ONLY witness generator descriptor\n')],
  };
  const artifacts = [
    { id: 'bch-verifier-set', kind: 'bch-verifier-set', path: 'artifacts/verifier-set.bin', source: { sourcePath: path.join(source, supporting['bch-verifier-set'][1]) } },
    { id: 'constraint-system', kind: 'constraint-system', path: 'artifacts/tiny.r1cs', source: { sourcePath: fixture.r1cs } },
    { id: 'proving-key', kind: 'proving-key', path: 'artifacts/final.zkey' },
    { id: 'public-input-abi', kind: 'public-input-abi', path: 'artifacts/public-input-abi.json', source: { sourcePath: path.join(source, supporting['public-input-abi'][1]) } },
    { id: 'relation-definition', kind: 'relation-definition', path: 'artifacts/relation.json', source: { sourcePath: path.join(source, supporting['relation-definition'][1]) } },
    { id: 'verification-key', kind: 'verification-key', path: 'artifacts/verification_key.json' },
    { id: 'witness-generator', kind: 'witness-generator', path: 'artifacts/witness.bin', source: { sourcePath: path.join(source, supporting['witness-generator'][1]) } },
  ];
  for (const [, relative, bytes] of Object.values(supporting)) { const target = path.join(source, relative); await mkdir(path.dirname(target), { recursive: true }); await writeFile(target, bytes); }
  const compiler = path.join(source, 'toolchain/compiler'); await mkdir(path.dirname(compiler), { recursive: true }); await writeFile(compiler, 'test-only compiler provenance\n');
  return {
    destination, setupMetadata: { sourcePath: setupMetadata, expectedSha256: digest(await readFile(setupMetadata)) },
    profile: { proofSystem: 'groth16', curve: 'bn254', relation: { id: 'shielded-action-v1' }, publicInputAbi: { id: 'shielded-action-public-input-v1' } },
    toolchain: {
      compiler: { name: 'test-compiler', version: 'test-only', source: { sourcePath: compiler } },
      generator: { name: 'snarkjs', version: SNARKJS_VERSION, source: { sourcePath: fixture.generatorPath } },
    },
    network: { name: 'chipnet' }, artifacts,
    genesis: { categoryInputOutpoint: { txid: '11'.repeat(32), vout: '0' }, reserveCapSatoshis: '10000000' },
  };
}

test('two tiny real local setups bridge as distinct immutable development profiles', async (t) => {
  const fixture = await realFixture(t); const firstSetup = await fixture.setup('setup-a'); const secondSetup = await fixture.setup('setup-b');
  const firstInput = await bridgeInput(fixture, firstSetup.directory, path.join(fixture.root, 'profile-a'));
  const secondInput = await bridgeInput(fixture, secondSetup.directory, path.join(fixture.root, 'profile-b'));
  const first = await bridgeLocalSetupToProfile(firstInput);
  secondInput.genesis.categoryInputOutpoint.txid = '22'.repeat(32);
  const secondVerifierSet = secondInput.artifacts.find((artifact) => artifact.kind === 'bch-verifier-set').source.sourcePath;
  await writeFile(secondVerifierSet, 'TEST-ONLY replacement verifier-set bytes; no BCH execution claim\n');
  const second = await bridgeLocalSetupToProfile(secondInput);
  assert.equal(first.manifest.setup.mode, 'development-only');
  assert.equal(first.manifest.artifacts.find((artifact) => artifact.kind === 'proving-key').sha256, first.manifest.setup.material.phase2.finalZkeySha256);
  assert.deepEqual(await readFile(path.join(first.directory, 'artifacts/final.zkey')), await readFile(path.join(firstSetup.directory, 'final.zkey')));
  assert.notEqual(first.profileId, second.profileId);
  assert.notEqual(first.instanceId, second.instanceId);

  const comparison = await compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory });
  const parsed = JSON.parse(comparison);
  assert.equal(parsed.scope, 'interface-replacement-only');
  assert.equal(parsed.replacementProperty, 'satisfied');
  assert.equal(parsed.shared.genesis.reserveCapSatoshis, '10000000');
  assert.notEqual(parsed.replacements.left.bchVerifierSetSha256, parsed.replacements.right.bchVerifierSetSha256);
  assert.notDeepEqual(parsed.replacements.left.categoryInputOutpoint, parsed.replacements.right.categoryInputOutpoint);

  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [path.join(here, '../core/compare-development-profiles.mjs'), '--left', first.directory, '--right', second.directory],
    { cwd: here, env: {} },
  );
  assert.equal(stderr, ''); assert.equal(stdout, `${comparison}\n`);

  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory, instanceId: first.instanceId }),
    /replacement comparison input has missing or unknown properties/,
  );
  const alias = path.join(fixture.root, 'profile-a-alias'); await symlink(first.directory, alias, 'dir');
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: alias, rightDirectory: second.directory }),
    /bundle directory must be a real non-symlink directory/,
  );
  await writeFile(path.join(second.directory, 'artifacts/verification_key.json'), 'post-build hash drift\n');
  await assert.rejects(
    () => compareDevelopmentVerifierProfileBundles({ leftDirectory: first.directory, rightDirectory: second.directory }),
    /artifact hash mismatch: artifacts\/verification_key.json/,
  );
});

test('bridge rejects relabeling, metadata drift, key-source override, and existing profile destination', async (t) => {
  const fixture = await realFixture(t); const setup = await fixture.setup('setup'); const input = await bridgeInput(fixture, setup.directory, path.join(fixture.root, 'profile'));
  const hashMismatch = structuredClone(input); hashMismatch.setupMetadata.expectedSha256 = `sha256:${'0'.repeat(64)}`;
  await assert.rejects(() => bridgeLocalSetupToProfile(hashMismatch), /setup metadata hash mismatch/);

  const relabeledPath = path.join(fixture.root, 'relabeled.json'); const relabeled = JSON.parse(await readFile(input.setupMetadata.sourcePath, 'utf8'));
  relabeled.mode = 'ceremony-production'; await writeFile(relabeledPath, JSON.stringify(relabeled));
  const relabeledInput = structuredClone(input); relabeledInput.setupMetadata = { sourcePath: relabeledPath, expectedSha256: digest(await readFile(relabeledPath)) };
  await assert.rejects(() => bridgeLocalSetupToProfile(relabeledInput), /must remain development-only/);

  const wrongAbiPath = path.join(fixture.root, 'wrong-abi.json'); const wrongAbi = JSON.parse(await readFile(input.setupMetadata.sourcePath, 'utf8'));
  wrongAbi.inputs.r1cs.nPublicInputs = 1; await writeFile(wrongAbiPath, JSON.stringify(wrongAbi));
  const wrongAbiInput = structuredClone(input); wrongAbiInput.setupMetadata = { sourcePath: wrongAbiPath, expectedSha256: digest(await readFile(wrongAbiPath)) };
  await assert.rejects(() => bridgeLocalSetupToProfile(wrongAbiInput), /does not use the current shield.cash ABI/);

  const keyOverride = structuredClone(input); keyOverride.artifacts.find((artifact) => artifact.kind === 'proving-key').source = { sourcePath: fixture.r1cs };
  await assert.rejects(() => bridgeLocalSetupToProfile(keyOverride), /bridge key artifact has missing or unknown properties/);

  const existing = path.join(fixture.root, 'existing'); await mkdir(existing); await writeFile(path.join(existing, 'sentinel'), 'preserve');
  const overwrite = structuredClone(input); overwrite.destination = existing;
  await assert.rejects(() => bridgeLocalSetupToProfile(overwrite), /destination already exists; refusing overwrite/);
  assert.equal(await readFile(path.join(existing, 'sentinel'), 'utf8'), 'preserve');
});

test('CLI resolves bridge paths and emits a development-only immutable bundle identity', async (t) => {
  const fixture = await realFixture(t); const setup = await fixture.setup('setup'); const input = await bridgeInput(fixture, setup.directory, path.join(fixture.root, 'cli-profile'));
  const metadataPath = path.join(fixture.root, 'bridge.json'); await writeFile(metadataPath, JSON.stringify(input));
  const { stdout, stderr } = await execFileAsync(process.execPath, ['cli.mjs', '--input', metadataPath], { cwd: here });
  assert.equal(stderr, ''); const result = JSON.parse(stdout);
  assert.equal(result.mode, 'development-only'); assert.match(result.profileId, /^sha256:[0-9a-f]{64}$/); assert.match(result.instanceId, /^sha256:[0-9a-f]{64}$/);
});

test('public bridge errors are typed', () => {
  assert.equal(new SetupProfileBridgeError('x').name, 'SetupProfileBridgeError');
});
