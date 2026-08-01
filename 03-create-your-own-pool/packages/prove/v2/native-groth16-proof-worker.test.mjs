import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os, { availableParallelism } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { GMP_SHA256, GMP_VERSION, RAPIDSNARK_COMMIT, RAPIDSNARK_REPOSITORY, RAPIDSNARK_SUBMODULES, V2_NATIVE_PROVER_MANIFEST_SCHEMA } from '../../../scripts/setup-v2-native-prover.mjs';
import { loadV2NativeGroth16ProverInstallationForTest } from './native-groth16-prover-installation.mjs';
import { proveV2DirectNativeGroth16, reapV2NativeGroth16ProofWorkspaces } from './native-groth16-proof-worker.mjs';

const hash = (v) => createHash('sha256').update(v).digest('hex');
async function receipt(filename, bytes) {
  const stat = await lstat(filename, { bigint: true });
  return Object.freeze({ path: filename, sha256: hash(bytes), identity: Object.freeze({ dev: stat.dev.toString(), ino: stat.ino.toString(), mode: stat.mode.toString(), uid: stat.uid.toString(), gid: stat.gid.toString(), size: stat.size.toString(), nlink: stat.nlink.toString(), mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString(), birthtimeNs: stat.birthtimeNs.toString() }) });
}
const proofOwner = (workspaceDirectory, pid, processStartTicks) => ({ schema: 'shieldkit-v2-native-groth16-proof-owner-v1', workspaceDirectory, pid, processStartTicks, operationNonce: 'ab'.repeat(32) });
const containment = (mutate = undefined) => { const value = { backend: 'linux-systemd-cgroup-v2', command: process.execPath, arguments: [], containment: { cgroup: '/private', memoryMax: '4294967296', memorySwapMax: '0', memoryPeak: '1', memoryEvents: { oom: 0, oomKill: 0 } }, termination: { exitCode: 0, signal: null, memoryPeak: '1', memoryEvents: { oom: 0, oomKill: 0 } } }; mutate?.(value); return value; };
async function selfStartTicks() { const raw = await readFile('/proc/self/stat', 'utf8'); return raw.slice(raw.lastIndexOf(')') + 1).trim().split(/\s+/u)[19]; }
async function orphan(workspace, name, owner) { const directory = path.join(workspace, name); await mkdir(directory, { mode: 0o700 }); await chmod(directory, 0o700); await writeFile(path.join(directory, 'owner.json'), canonicalizeJcs(owner), { mode: 0o600 }); await chmod(path.join(directory, 'owner.json'), 0o600); await writeFile(path.join(directory, 'witness.wtns'), 'secret witness', { mode: 0o600 }); return directory; }
async function nativeInstallation(root) {
  const installationDirectory = path.join(root, 'native'); const binaryDirectory = path.join(installationDirectory, 'bin'); await mkdir(binaryDirectory, { recursive: true, mode: 0o700 }); await chmod(installationDirectory, 0o700); await chmod(binaryDirectory, 0o700);
  const binaryPath = path.join(binaryDirectory, 'prover'); const binary = Buffer.from('native worker test binary\n'); await writeFile(binaryPath, binary, { mode: 0o700 }); await chmod(binaryPath, 0o700);
  const binarySha256 = hash(binary); const manifest = { schema: V2_NATIVE_PROVER_MANIFEST_SCHEMA, source: { repository: RAPIDSNARK_REPOSITORY, commit: RAPIDSNARK_COMMIT, submodules: [...RAPIDSNARK_SUBMODULES] }, gmp: { version: GMP_VERSION, archiveSha256: GMP_SHA256, staticLibrarySha256: '11'.repeat(32) }, build: { useAsm: false, useOpenmp: true, sourceTreeUnchanged: true, cxxFlagsRelease: '-O3 -DNDEBUG -include cstdint', nproc: availableParallelism(), wallMs: 1 }, toolchain: { compiler: 'unit-test', cmake: 'unit-test', node: process.version, platform: `${process.platform}/${process.arch}` }, binary: { path: 'bin/prover', bytes: binary.length, sha256: binarySha256 } };
  const manifestPath = path.join(installationDirectory, 'manifest.json'); await writeFile(manifestPath, canonicalizeJcs(manifest), { mode: 0o600 }); await chmod(manifestPath, 0o600);
  return loadV2NativeGroth16ProverInstallationForTest({ installationDirectory, policy: { binarySha256, nproc: availableParallelism() } });
}
async function artifactsFor(root) { const entries = {}; for (const name of ['r1cs', 'wasm', 'provingKey', 'verificationKey']) { const filename = path.join(root, name); const bytes = Buffer.from(name); await writeFile(filename, bytes, { mode: 0o600 }); await chmod(filename, 0o600); entries[name] = await receipt(filename, bytes); } return Object.freeze({ schema: 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1', installationReceiptSha256: 'a'.repeat(64), artifacts: Object.freeze(entries) }); }
async function writeAcceptedResult(requestFilename, mutate = undefined) { const request = JSON.parse(await readFile(requestFilename, 'utf8')); const cores = availableParallelism(); const result = { schema: 'shieldkit-v2-direct-native-groth16-proof-result-v1', claims: { proofVerified: true, witnessCalculated: true, witnessR1csChecked: false }, sourceHashes: Object.fromEntries(Object.entries(request.artifacts.artifacts).map(([name, entry]) => [name, entry.sha256])), nativeProver: { backend: 'rapidsnark', sha256: request.nativeProver.sha256, ompThreads: cores, threads: cores, activeCpuThreads: cores, peakRssKiB: 1, userTicks: 1, systemTicks: 0 }, inputSha256: request.input.sha256, proof: { protocol: 'groth16' }, publicInputs: request.expectedPublicInputs, timingsMs: { witnessCalculation: 0, proofGeneration: 1, proofVerification: 0, total: 1 } }; mutate?.(result); await writeFile(request.outputPath, canonicalizeJcs(result), { mode: 0o600 }); }
test('native worker rejects an unbranded native installation before child execution', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-native-worker-')); await chmod(root, 0o700); t.after(async () => { const { rm } = await import('node:fs/promises'); await rm(root, { recursive: true, force: true }); });
  const entries = {}; for (const n of ['r1cs', 'wasm', 'provingKey', 'verificationKey']) { const file = path.join(root, n); const bytes = Buffer.from(n); await writeFile(file, bytes, { mode: 0o600 }); entries[n] = await receipt(file, bytes); }
  const artifacts = Object.freeze({ schema: 'shieldkit-v2-beta-receipt-bound-proof-artifacts-v1', installationReceiptSha256: 'a'.repeat(64), artifacts: Object.freeze(entries) });
  await assert.rejects(() => proveV2DirectNativeGroth16({ artifacts, nativeProverInstallation: Object.freeze({}), circuitInput: { alpha: '1' }, expectedPublicInputs: ['1', '2'], workspaceDirectory: root }, { runContainedWorker: async () => { throw new Error('must not execute'); } }), { code: 'NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED' });
  await writeFile(entries.wasm.path, 'mutated', { mode: 0o600 });
  let childRan = false;
  await assert.rejects(() => proveV2DirectNativeGroth16({ artifacts, nativeProverInstallation: Object.freeze({}), circuitInput: { alpha: '1' }, expectedPublicInputs: ['1', '2'], workspaceDirectory: root }, { runContainedWorker: async () => { childRan = true; } }), { code: 'NATIVE_PROVER_ARTIFACT_CHANGED' });
  assert.equal(childRan, false);
  assert.deepEqual((await readdir(root)).sort(), ['provingKey', 'r1cs', 'verificationKey', 'wasm'].sort());
});

test('warm parent and child stat proof receipts instead of rehashing large proof files', async () => {
  const worker = await readFile(new URL('./native-groth16-proof-worker.mjs', import.meta.url), 'utf8');
  const child = await readFile(new URL('./native-groth16-proof-child.mjs', import.meta.url), 'utf8');
  assert.match(worker, /await receipt\(artifactReceipt\.artifacts\[n\]/u);
  assert.match(child, /await receipt\(r\.artifacts\.artifacts\[name\]/u);
  assert.doesNotMatch(worker, /await pin\(artifactReceipt\.artifacts\[n\]/u);
  assert.doesNotMatch(child, /await pin\(r\.artifacts\.artifacts\[name\]/u);
  assert.match(worker, /ARTIFACTS\.map\(\(n\) => unchanged\(artifacts\[n\]/u);
  assert.match(child, /ARTIFACTS\.map\(\(name\) => unchanged\(artifacts\[name\]/u);
});

test('warm parent and child stat the install-verified native binary rather than rehash it', async () => {
  const worker = await readFile(new URL('./native-groth16-proof-worker.mjs', import.meta.url), 'utf8');
  const child = await readFile(new URL('./native-groth16-proof-child.mjs', import.meta.url), 'utf8');
  assert.match(worker, /await receipt\(await consumeV2NativeGroth16ProverInstallation/u);
  assert.match(child, /const binary = await receipt\(r\.nativeProver/u);
  assert.doesNotMatch(worker, /await pin\(await consumeV2NativeGroth16ProverInstallation/u);
  assert.doesNotMatch(child, /const binary = await pin\(r\.nativeProver/u);
});

test('worker removes private temporary workspaces after both success and failure', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-native-worker-cleanup-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const installation = await nativeInstallation(root); const artifacts = await artifactsFor(root);
  const value = { artifacts, nativeProverInstallation: installation, circuitInput: { alpha: '1' }, expectedPublicInputs: ['1', '2'], workspaceDirectory: root };
  const proven = await proveV2DirectNativeGroth16(value, { runContainedWorker: async ({ arguments: [, request] }) => { await writeAcceptedResult(request); return containment(); } });
  assert.deepEqual(proven.containment, { backend: 'linux-systemd-cgroup-v2', memoryMaxBytes: '4294967296', memorySwapMaxBytes: '0', memoryPeakBytes: '1', oomDelta: 0, oomKillDelta: 0, terminatedSuccessfully: true });
  assert.equal((await readdir(root)).some((name) => name.startsWith('.shieldkit-v2-native-proof-')), false);
  await assert.rejects(() => proveV2DirectNativeGroth16(value, { runContainedWorker: async () => { throw Object.assign(new Error('contained failure'), { code: 'CONTAINED_FAILURE' }); } }), { code: 'CONTAINED_FAILURE' });
  assert.equal((await readdir(root)).some((name) => name.startsWith('.shieldkit-v2-native-proof-')), false);
});

test('worker rejects every strict native-result and containment telemetry violation', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-native-worker-negative-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const installation = await nativeInstallation(root); const artifacts = await artifactsFor(root); const value = { artifacts, nativeProverInstallation: installation, circuitInput: { alpha: '1' }, expectedPublicInputs: ['1', '2'], workspaceDirectory: root }; const cores = availableParallelism();
  const cases = [
    ['ompThreads', result => { result.nativeProver.ompThreads = cores + 1; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['threads', result => { result.nativeProver.threads = Math.max(0, cores - 1); }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['activeCpuThreads-too-few', result => { result.nativeProver.activeCpuThreads = Math.max(0, cores - 1); }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['activeCpuThreads-too-many', result => { result.nativeProver.activeCpuThreads = cores + 1; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['peakRssKiB', result => { result.nativeProver.peakRssKiB = 0; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['cpuTicks', result => { result.nativeProver.userTicks = 0; result.nativeProver.systemTicks = 0; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['witnessCalculation', result => { result.timingsMs.witnessCalculation = -1; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['proofGeneration', result => { result.timingsMs.proofGeneration = 0; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['proofVerification', result => { result.timingsMs.proofVerification = -1; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['total', result => { result.timingsMs.total = -1; }, undefined, 'NATIVE_PROVER_RESULT_INVALID'],
    ['backend', undefined, result => { result.backend = 'uncontained'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['cgroup', undefined, result => { result.containment.cgroup = 'not-a-cgroup'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['memoryMax', undefined, result => { result.containment.memoryMax = '4294967295'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['memorySwapMax', undefined, result => { result.containment.memorySwapMax = '1'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['initialPeakZero', undefined, result => { result.containment.memoryPeak = '0'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['initialOomMalformed', undefined, result => { result.containment.memoryEvents.oom = -1; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['terminationPeakZero', undefined, result => { result.termination.memoryPeak = '0'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['terminationPeakOverCap', undefined, result => { result.termination.memoryPeak = '4294967297'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['exitCode', undefined, result => { result.termination.exitCode = 1; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['signal', undefined, result => { result.termination.signal = 'SIGTERM'; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['oomDelta', undefined, result => { result.termination.memoryEvents.oom = 1; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
    ['oomKillDelta', undefined, result => { result.termination.memoryEvents.oomKill = 1; }, 'NATIVE_PROVER_CONTAINMENT_INVALID'],
  ];
  for (const [, mutateResult, mutateContainment, code] of cases) {
    await assert.rejects(
      () => proveV2DirectNativeGroth16(value, { runContainedWorker: async ({ arguments: [, request] }) => { await writeAcceptedResult(request, mutateResult); return containment(mutateContainment); } }),
      error => error?.code === code,
    );
  }
});

test('startup reaper removes only dead-owner SIGKILL-style workspaces and refuses unsafe entries', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-native-worker-reaper-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  await orphan(root, '.shieldkit-v2-native-proof-deadowner', proofOwner(root, '999999999', '1'));
  await reapV2NativeGroth16ProofWorkspaces(root);
  assert.equal((await readdir(root)).some((name) => name.startsWith('.shieldkit-v2-native-proof-')), false);
  const live = await orphan(root, '.shieldkit-v2-native-proof-liveowner', proofOwner(root, String(process.pid), await selfStartTicks()));
  await reapV2NativeGroth16ProofWorkspaces(root);
  assert.equal((await lstat(live)).isDirectory(), true);
  await rm(live, { recursive: true, force: true });
  await writeFile(path.join(root, '.shieldkit-v2-native-proof-unsafe'), 'not a directory', { mode: 0o600 });
  await assert.rejects(() => reapV2NativeGroth16ProofWorkspaces(root), { code: 'NATIVE_PROVER_WORKSPACE_UNTRUSTED' });
});
