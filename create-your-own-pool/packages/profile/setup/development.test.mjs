// This test creates a tiny real Circom circuit and a tiny local development
// ptau solely to exercise the pinned snarkjs setup path. It is not a ceremony,
// proof corpus, BCH artifact, or production/setup qualification claim.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { open } from 'node:fs/promises';
import { chmod, lstat, mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { createHash } from 'node:crypto';
import {
  LocalSetupError, SNARKJS_VERSION, assertUnchangedSetupInputs, getPinnedSnarkjsInfo, hashFileStreaming, initializeDevelopmentGroth16,
} from './development.mjs';

const execFileAsync = promisify(execFile);
const here = path.dirname(new URL(import.meta.url).pathname);
const snarkCli = path.join(here, '..', 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const circomCli = path.join(here, '..', 'node_modules', 'circom2', 'cli.js');
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

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
      if (code !== 0) reject(new Error(`snarkjs test command failed: ${args.join(' ')}`));
      else if (entropy !== undefined && !suppliedEntropy) reject(new Error(`snarkjs test command did not request entropy: ${args.join(' ')}`));
      else resolve();
    });
  });
}

async function fixture(t, { verifiedPtau = true } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-local-setup-test-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
  const source = path.join(root, 'tiny.circom'); const compiled = path.join(root, 'compiled'); await mkdir(compiled);
  await writeFile(source, 'pragma circom 2.0.0;\ntemplate Tiny() { signal input a; signal input b; signal product; product <== a * b; }\ncomponent main {public [a, b]} = Tiny();\n');
  await execFileAsync(process.execPath, [circomCli, source, '--r1cs', '--O0', '-o', compiled], { cwd: root, env: {} });
  const r1cs = path.join(compiled, 'tiny.r1cs'); const pot0 = path.join(root, 'pot0.ptau'); const pot1 = path.join(root, 'pot1.ptau'); const ptau = path.join(root, 'phase2.ptau');
  await run(['powersoftau', 'new', 'bn128', '4', pot0]);
  if (verifiedPtau) {
    await run(['powersoftau', 'contribute', pot0, pot1], { entropy: Buffer.from(randomBytes(64).toString('hex')) });
    await run(['powersoftau', 'prepare', 'phase2', pot1, ptau]);
  } else {
    await run(['powersoftau', 'prepare', 'phase2', pot0, ptau]);
  }
  const entropyPath = path.join(root, 'entropy.txt'); await writeFile(entropyPath, randomBytes(64).toString('hex'), { mode: 0o600 }); await chmod(entropyPath, 0o600);
  const entropy = await open(entropyPath, 'r'); t.after(async () => entropy.close());
  const tool = await getPinnedSnarkjsInfo();
  return {
    root, r1cs, ptau, entropyFd: entropy.fd, entropyHandle: entropy, tool,
    expectedR1csSha256: digest(await readFile(r1cs)), expectedPtauSha256: digest(await readFile(ptau)),
  };
}

function inputFor(data, destination) {
  return {
    destination, r1csPath: data.r1cs, ptauPath: data.ptau, ptauSource: 'local-test-phase1-power-4',
    expectedR1csSha256: data.expectedR1csSha256, expectedPtauSha256: data.expectedPtauSha256,
    expectedPtauPower: 4, expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: data.tool.cliSha256 },
    entropySource: { kind: 'fd', fd: data.entropyFd },
  };
}

test('real pinned snarkjs development setup creates one verified local contribution', async (t) => {
  const data = await fixture(t); const destination = path.join(data.root, 'development-bundle');
  const result = await initializeDevelopmentGroth16(inputFor(data, destination));
  assert.equal(result.metadata.mode, 'development-only');
  assert.equal(result.metadata.setup.mode, 'development-only');
  assert.equal(result.metadata.setup.provenance.method, 'local-initialization');
  assert.match(result.metadata.setup.material.phase2.randomnessCommitment, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.metadata.setup.material.phase2.finalZkeySha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.metadata.outputs.provingKey.path, 'final.zkey');
  assert.equal(result.metadata.outputs.verificationKey.path, 'verification_key.json');
  assert.equal(result.metadata.inputs.r1cs.nPublicInputs, 2);
  assert.equal(result.metadata.inputs.r1cs.nOutputs, 0);
  assert.equal(Number.isInteger(result.metadata.inputs.r1cs.nConstraints), true);
  await lstat(path.join(destination, 'final.zkey')); await lstat(path.join(destination, 'verification_key.json'));
  await assert.rejects(() => lstat(path.join(destination, 'initial.zkey')));
  const serialized = JSON.parse(await readFile(path.join(destination, 'setup-metadata.json'), 'utf8'));
  assert.equal(serialized.setup.mode, 'development-only');
  assert.equal(JSON.stringify(serialized).includes('entropy.txt'), false);
  await data.entropyHandle.stat();

  const shortEntropyPath = path.join(data.root, 'short-entropy.txt');
  await writeFile(shortEntropyPath, 'too-short', { mode: 0o600 }); await chmod(shortEntropyPath, 0o600);
  const shortEntropy = await open(shortEntropyPath, 'r'); t.after(async () => shortEntropy.close());
  const cleanupDestination = path.join(data.root, 'must-be-removed'); const cleanupInput = inputFor(data, cleanupDestination);
  cleanupInput.entropySource = { kind: 'fd', fd: shortEntropy.fd };
  await assert.rejects(() => initializeDevelopmentGroth16(cleanupInput), /entropy must contain at least 32 bytes/);
  await shortEntropy.stat();
  await assert.rejects(() => lstat(cleanupDestination));
});

test('runner rejects drift, symlinks, insufficient declared capacity, and overwrite before setup', async (t) => {
  const data = await fixture(t, { verifiedPtau: false });
  const hashMismatch = inputFor(data, path.join(data.root, 'hash-mismatch')); hashMismatch.expectedR1csSha256 = `sha256:${'0'.repeat(64)}`;
  await assert.rejects(() => initializeDevelopmentGroth16(hashMismatch), /r1cs hash mismatch/);

  const link = path.join(data.root, 'r1cs-link'); await symlink(data.r1cs, link);
  const symlinkInput = inputFor(data, path.join(data.root, 'symlink')); symlinkInput.r1csPath = link;
  await assert.rejects(() => initializeDevelopmentGroth16(symlinkInput), /regular non-symlink file|must not use symlinks/);

  const realParent = path.join(data.root, 'real-parent'); const parentLink = path.join(data.root, 'parent-link');
  await mkdir(realParent); await symlink(realParent, parentLink);
  await assert.rejects(() => initializeDevelopmentGroth16(inputFor(data, path.join(parentLink, 'bundle'))), /destination parent directory must not use symlinks/);

  const powerMismatch = inputFor(data, path.join(data.root, 'power')); powerMismatch.expectedPtauPower = 3;
  await assert.rejects(() => initializeDevelopmentGroth16(powerMismatch), /ptau power mismatch/);

  const versionMismatch = inputFor(data, path.join(data.root, 'version')); versionMismatch.expectedSnarkjs.version = '0.0.0';
  await assert.rejects(() => initializeDevelopmentGroth16(versionMismatch), /expected snarkjs version/);

  const existing = path.join(data.root, 'existing'); await mkdir(existing); await writeFile(path.join(existing, 'sentinel'), 'preserve');
  await assert.rejects(() => initializeDevelopmentGroth16(inputFor(data, existing)), /destination already exists; refusing overwrite/);
  assert.equal(await readFile(path.join(existing, 'sentinel'), 'utf8'), 'preserve');
});

test('runner rejects an empty Phase-1 source and a non-shield.cash R1CS ABI before setup', async (t) => {
  const early = {
    destination: path.join(tmpdir(), 'unused-development-bundle'), r1csPath: '/does/not/matter', ptauPath: '/does/not/matter',
    ptauSource: '', expectedR1csSha256: `sha256:${'0'.repeat(64)}`, expectedPtauSha256: `sha256:${'0'.repeat(64)}`,
    expectedPtauPower: 4, expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: `sha256:${'0'.repeat(64)}` }, entropySource: { kind: 'stdin' },
  };
  await assert.rejects(() => initializeDevelopmentGroth16(early), /ptau source must be a non-empty string/);

  const data = await fixture(t, { verifiedPtau: false }); const source = path.join(data.root, 'wrong-abi.circom'); const compiled = path.join(data.root, 'wrong-abi');
  await mkdir(compiled);
  await writeFile(source, 'pragma circom 2.0.0;\ntemplate Wrong() { signal input a; signal output b; b <== a * a; }\ncomponent main {public [a]} = Wrong();\n');
  await execFileAsync(process.execPath, [circomCli, source, '--r1cs', '--O0', '-o', compiled], { cwd: data.root, env: {} });
  const wrongR1cs = path.join(compiled, 'wrong-abi.r1cs'); const invalidAbi = inputFor(data, path.join(data.root, 'wrong-abi-bundle'));
  invalidAbi.r1csPath = wrongR1cs; invalidAbi.expectedR1csSha256 = digest(await readFile(wrongR1cs));
  await assert.rejects(() => initializeDevelopmentGroth16(invalidAbi), /exactly 2 public inputs and 0 outputs/);
});

test('post-execution input revalidation rejects direct-file hash drift', async (t) => {
  const data = await fixture(t, { verifiedPtau: false });
  await writeFile(data.r1cs, 'drift');
  await assert.rejects(() => assertUnchangedSetupInputs({
    r1csPath: data.r1cs, ptauPath: data.ptau,
    r1csSha256: data.expectedR1csSha256, ptauSha256: data.expectedPtauSha256,
  }), /r1cs changed during setup/);
});

test('public setup errors are typed', () => {
  assert.equal(new LocalSetupError('x').name, 'LocalSetupError');
});

test('artifact hashing is streaming and returns the real SHA-256', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-streaming-hash-test-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
  const artifact = path.join(root, 'large-artifact.bin');
  const block = Buffer.alloc(1024 * 1024, 0xa5);
  await writeFile(artifact, Buffer.concat(Array.from({ length: 8 }, () => block)));
  assert.equal(await hashFileStreaming(artifact), digest(await readFile(artifact)));
  const moduleSource = await readFile(path.join(here, 'development.mjs'), 'utf8');
  const implementation = moduleSource.slice(moduleSource.indexOf('export async function hashFileStreaming'), moduleSource.indexOf('const digestFile'));
  assert.match(implementation, /createReadStream/);
  assert.doesNotMatch(implementation, /readFile/);
});
