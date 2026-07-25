import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { SNARKJS_VERSION, getPinnedSnarkjsInfo } from './development.mjs';
import { assertCeremonyMetadata, initializeCeremonyGroth16, CeremonyError } from './ceremony.mjs';
import { loadVerifierProfileBundle } from '../load.mjs';

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
      else if (entropy !== undefined && !suppliedEntropy) reject(new Error('entropy not requested'));
      else resolve();
    });
  });
}

async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-ceremony-'));
  t.after(async () => { await (await import('node:fs/promises')).rm(root, { recursive: true, force: true }); });
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
  const tool = await getPinnedSnarkjsInfo();
  return {
    root, r1cs, ptau, tool,
    expectedR1csSha256: digest(await readFile(r1cs)),
    expectedPtauSha256: digest(await readFile(ptau)),
  };
}

test('ceremony runner produces ≥2 contributions + transcript (ceremony-production)', async (t) => {
  const data = await fixture(t);
  const destination = path.join(data.root, 'ceremony-bundle');
  const e1 = Buffer.from(randomBytes(64).toString('hex'));
  const e2 = Buffer.from(randomBytes(64).toString('hex'));
  const result = await initializeCeremonyGroth16({
    destination,
    r1csPath: data.r1cs,
    ptauPath: data.ptau,
    ptauSource: 'local-test-phase1-power-4',
    expectedR1csSha256: data.expectedR1csSha256,
    expectedPtauSha256: data.expectedPtauSha256,
    expectedPtauPower: 4,
    expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: data.tool.cliSha256 },
    participants: [
      { entropySource: { kind: 'bytes', bytes: e1 } },
      { entropySource: { kind: 'bytes', bytes: e2 } },
    ],
  });
  assert.equal(result.metadata.mode, 'ceremony-production');
  assert.equal(result.metadata.setup.mode, 'ceremony-production');
  assert.equal(result.metadata.setup.provenance.method, 'multi-party-randomness');
  assert.equal(result.metadata.setup.contributions.length, 2);
  assert.equal(result.metadata.setup.transcript.status, 'complete');
  await lstat(path.join(destination, 'final.zkey'));
  await lstat(path.join(destination, 'ceremony-transcript.json'));
  assertCeremonyMetadata(result.metadata);
});

test('mode laundering development→ceremony refused', () => {
  assert.throws(
    () => assertCeremonyMetadata({ mode: 'development-only', setup: { mode: 'development-only' } }),
    /mode laundering refused/,
  );
});

test('ceremony requires ≥2 participants', async (t) => {
  const data = await fixture(t);
  const e1 = Buffer.from(randomBytes(64).toString('hex'));
  await assert.rejects(
    () => initializeCeremonyGroth16({
      destination: path.join(data.root, 'one-party'),
      r1csPath: data.r1cs,
      ptauPath: data.ptau,
      ptauSource: 'local-test-phase1-power-4',
      expectedR1csSha256: data.expectedR1csSha256,
      expectedPtauSha256: data.expectedPtauSha256,
      expectedPtauPower: 4,
      expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: data.tool.cliSha256 },
      participants: [{ entropySource: { kind: 'bytes', bytes: e1 } }],
    }),
    /at least two participants/,
  );
});
