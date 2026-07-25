import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { parseStrictJson } from '../profile/load.mjs';

export const PROVER_ARTIFACT_BUDGET_BYTES = 512 * 1024 * 1024;
const HASH = /^sha256:[0-9a-f]{64}$/;
const STDERR_LIMIT = 64 * 1024;

export class ProverArtifactBudgetError extends Error {
  constructor(message) { super(message); this.name = 'ProverArtifactBudgetError'; }
}
const fail = (message) => { throw new ProverArtifactBudgetError(message); };
const object = (value, label) => { if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`); return value; };
const string = (value, label) => { if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`); return value; };
const hash = (value, label) => { string(value, label); if (!HASH.test(value)) fail(`${label} must be a lowercase sha256 pin`); return value; };
const exactKeys = (value, label, keys) => { object(value, label); const actual = Object.keys(value).sort(), expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail(`${label} has missing or unknown properties`); };
export const canonicalJson = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  object(value, 'canonical JSON value'); return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
};

function validatePackageInput(input) {
  exactKeys(input, 'package input', ['destination', 'zstd', 'finalZkey', 'witnessGeneratorWasm']);
  string(input.destination, 'destination');
  exactKeys(input.zstd, 'zstd', ['path', 'sha256', 'version']); string(input.zstd.path, 'zstd.path'); hash(input.zstd.sha256, 'zstd.sha256'); string(input.zstd.version, 'zstd.version');
  for (const [label, record] of [['finalZkey', input.finalZkey], ['witnessGeneratorWasm', input.witnessGeneratorWasm]]) {
    exactKeys(record, label, ['path', 'sha256']); string(record.path, `${label}.path`); hash(record.sha256, `${label}.sha256`);
  }
}

/** Parse the CLI manifest before any path is resolved or dereferenced. */
export function parsePackageManifest(bytes, manifestFilename) {
  let manifest;
  try { manifest = parseStrictJson(bytes); } catch (error) { fail(`input manifest is invalid: ${error.message}`); }
  exactKeys(manifest, 'input manifest', ['schema', 'destination', 'zstd', 'finalZkey', 'witnessGeneratorWasm']);
  if (manifest.schema !== 'shield.cash/prover-artifact-budget-input/v1') fail('unsupported input manifest schema');
  const base = path.dirname(path.resolve(string(manifestFilename, 'input manifest filename')));
  const resolveRecord = (record, label) => {
    exactKeys(record, label, ['path', 'sha256']); return { path: path.resolve(base, string(record.path, `${label}.path`)), sha256: hash(record.sha256, `${label}.sha256`) };
  };
  exactKeys(manifest.zstd, 'input manifest zstd', ['path', 'sha256', 'version']);
  const parsed = {
    destination: path.resolve(base, string(manifest.destination, 'input manifest destination')),
    zstd: { path: path.resolve(base, string(manifest.zstd.path, 'input manifest zstd.path')), sha256: hash(manifest.zstd.sha256, 'input manifest zstd.sha256'), version: string(manifest.zstd.version, 'input manifest zstd.version') },
    finalZkey: resolveRecord(manifest.finalZkey, 'input manifest finalZkey'), witnessGeneratorWasm: resolveRecord(manifest.witnessGeneratorWasm, 'input manifest witnessGeneratorWasm'),
  };
  validatePackageInput(parsed); return parsed;
}

async function directRegularFile(filename, label) {
  const requested = path.resolve(string(filename, label));
  const stats = await lstat(requested).catch(() => fail(`${label} does not exist`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not use symlinks`);
  return { path: requested, stats };
}

async function sha256File(filename) {
  return new Promise((resolve, reject) => {
    const digest = createHash('sha256'); const stream = createReadStream(filename, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => digest.update(chunk)); stream.on('error', reject);
    stream.on('end', () => resolve(`sha256:${digest.digest('hex')}`));
  });
}

async function snapshotPinnedFile(record, label) {
  exactKeys(record, label, ['path', 'sha256']); const file = await directRegularFile(record.path, `${label}.path`); const actual = await sha256File(file.path);
  if (actual !== hash(record.sha256, `${label}.sha256`)) fail(`${label} hash mismatch`);
  const stats = await lstat(file.path); return { path: file.path, sha256: actual, bytes: stats.size, ino: stats.ino, mtimeMs: stats.mtimeMs };
}

async function assertStable(snapshot, label) {
  const file = await directRegularFile(snapshot.path, label); const stats = await lstat(file.path); const actual = await sha256File(file.path);
  if (stats.size !== snapshot.bytes || stats.ino !== snapshot.ino || stats.mtimeMs !== snapshot.mtimeMs || actual !== snapshot.sha256) fail(`${label} changed during packaging`);
}

function boundedChild(command, args, { stdoutMode = 'capture' } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stderr = Buffer.alloc(0), stdout = Buffer.alloc(0), overflow = false;
    const append = (current, chunk) => {
      if (current.length + chunk.length > STDERR_LIMIT) { overflow = true; child.kill('SIGKILL'); return current; }
      return Buffer.concat([current, chunk]);
    };
    child.stdout.on('data', (chunk) => { if (stdoutMode === 'capture') stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.on('error', (error) => reject(new ProverArtifactBudgetError(`zstd execution failed: ${error.message}`)));
    child.on('close', (code) => {
      if (overflow) return reject(new ProverArtifactBudgetError('zstd output exceeded bounded capture limit'));
      if (code !== 0) return reject(new ProverArtifactBudgetError(`zstd exited ${code}: ${stderr.toString('utf8').trim()}`));
      resolve({ stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8') });
    });
  });
}

async function zstdIdentity(record) {
  exactKeys(record, 'zstd', ['path', 'sha256', 'version']); const binary = await snapshotPinnedFile({ path: record.path, sha256: record.sha256 }, 'zstd');
  const observed = (await boundedChild(binary.path, ['--version'])).stdout.trim();
  if (observed !== string(record.version, 'zstd.version')) fail('zstd version mismatch');
  await assertStable(binary, 'zstd binary');
  return { identity: { path: binary.path, sha256: binary.sha256, version: observed }, snapshot: binary };
}

async function decompressAndHash(tool, compressed, expected, label) {
  return new Promise((resolve, reject) => {
    const args = ['-d', '-q', '--no-progress', '-c', compressed]; const child = spawn(tool.path, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const digest = createHash('sha256'); let bytes = 0, stderr = Buffer.alloc(0), overflow = false;
    child.stdout.on('data', (chunk) => { digest.update(chunk); bytes += chunk.length; });
    child.stderr.on('data', (chunk) => { if (stderr.length + chunk.length > STDERR_LIMIT) { overflow = true; child.kill('SIGKILL'); } else stderr = Buffer.concat([stderr, chunk]); });
    child.on('error', (error) => reject(new ProverArtifactBudgetError(`zstd decompression failed: ${error.message}`)));
    child.on('close', (code) => {
      if (overflow) return reject(new ProverArtifactBudgetError('zstd decompression stderr exceeded bounded capture limit'));
      if (code !== 0) return reject(new ProverArtifactBudgetError(`zstd decompression exited ${code}: ${stderr.toString('utf8').trim()}`));
      const sha256 = `sha256:${digest.digest('hex')}`; if (sha256 !== expected.sha256 || bytes !== expected.bytes) return reject(new ProverArtifactBudgetError(`${label} streaming decompression verification failed`));
      resolve({ argv: args, sha256, bytes });
    });
  });
}

async function privateDestination(destination) {
  const requested = path.resolve(string(destination, 'destination')); const parent = path.dirname(requested);
  const stats = await lstat(parent).catch(() => fail('destination parent does not exist'));
  if (!stats.isDirectory() || stats.isSymbolicLink() || await realpath(parent) !== parent) fail('destination parent must be a direct non-symlink directory');
  if (await lstat(requested).catch(() => undefined)) fail('destination already exists; refusing overwrite');
  return { destination: requested, staging: path.join(parent, `.${path.basename(requested)}.staging-${randomUUID()}`) };
}

export function budgetVerdict(totalCompressedBytes) {
  if (!Number.isSafeInteger(totalCompressedBytes) || totalCompressedBytes < 0) fail('compressed total must be a non-negative safe integer');
  return totalCompressedBytes <= PROVER_ARTIFACT_BUDGET_BYTES ? 'PASS' : 'FAIL';
}

export async function packageProverArtifacts(input) {
  validatePackageInput(input);
  if (input.finalZkey.path === input.witnessGeneratorWasm.path) fail('final zkey and witness generator inputs must be distinct');
  const destination = await privateDestination(input.destination);
  const tool = await zstdIdentity(input.zstd);
  const sources = [
    ['finalZkey', input.finalZkey, 'final.zkey.zst'],
    ['witnessGeneratorWasm', input.witnessGeneratorWasm, 'witness-generator.wasm.zst'],
  ];
  const snapshots = [];
  for (const [name, record, output] of sources) snapshots.push([name, await snapshotPinnedFile(record, name), output]);
  let published = false;
  try {
    await mkdir(destination.staging, { mode: 0o700 });
    const artifacts = {};
    for (const [name, source, outputName] of snapshots) {
      await assertStable(source, name); const compressed = path.join(destination.staging, outputName);
      const argv = ['-q', '--no-progress', '-T1', '-19', '--no-check', '-o', compressed, source.path];
      await boundedChild(tool.identity.path, argv); await assertStable(tool.snapshot, 'zstd binary'); const compressedFile = await directRegularFile(compressed, `${name} compressed output`);
      const compressedSha256 = await sha256File(compressedFile.path); const compressedStats = await lstat(compressedFile.path);
      const decompressed = await decompressAndHash(tool.identity, compressedFile.path, source, name); await assertStable(tool.snapshot, 'zstd binary'); await assertStable(source, name);
      artifacts[name] = { source: { path: source.path, sha256: source.sha256, bytes: source.bytes }, compressed: { path: path.join(destination.destination, outputName), sha256: compressedSha256, bytes: compressedStats.size }, compressionArgv: argv, decompressionArgv: decompressed.argv };
    }
    await assertStable(tool.snapshot, 'zstd binary');
    const totalCompressedBytes = Object.values(artifacts).reduce((sum, artifact) => sum + artifact.compressed.bytes, 0);
    const result = { schema: 'shield.cash/prover-artifact-budget/v1', scope: 'artifact compression measurement only; not G1 qualification', node: { version: process.version }, zstd: tool.identity, artifacts, budget: { compressedLimitBytes: PROVER_ARTIFACT_BUDGET_BYTES, totalCompressedBytes, verdict: budgetVerdict(totalCompressedBytes) } };
    await writeFile(path.join(destination.staging, 'result.json'), `${canonicalJson(result)}\n`, { flag: 'wx', mode: 0o600 });
    if (await lstat(destination.destination).catch(() => undefined)) fail('destination already exists; refusing overwrite');
    await rename(destination.staging, destination.destination); published = true; return result;
  } finally { if (!published) await rm(destination.staging, { recursive: true, force: true }); }
}
