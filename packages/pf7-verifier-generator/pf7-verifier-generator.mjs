import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, parseStrictJson } from '../core/verifier-profile.mjs';

const BASE = '26468ae29004d2401619032de2a6ec8de269a4d6';
const TERMINAL = '17c6b9552c48b0fc5271be626a1578fb0065df09';
const TREE = 'd9673df5a3f5358df6aaff9c4042a029bc26a521';
const CANDIDATE = 'bn254-onetx-pf7-sub62-r1';
const CANDIDATE_SHA256 = 'c03e8ae157998f513f058433e58e3252e05a2d2c39f5577a992d39c9daf3ff19';
const ROOT_PACKAGE_SHA256 = 'eb77c00095f5ebba72ffb4e35e8287134f063b0afca4d6d7e5bc1279dc647892';
const ROOT_LOCK_SHA256 = '1b0a9c2b198cb0bfaf9661368fc65445e4c11c6ba549804ee3d6574daf6fe5d7';
const ROOT_RUNTIME_PACKAGES = Object.freeze({ '@bitauth/libauth': '3.1.0-next.8', '@noble/curves': '1.9.7', '@noble/hashes': '1.8.0' });
const LEAN_OPTIMIZER_PACKAGE_SHA256 = '85466c817d79d430baa023f2799017cfb366b454a3f7af0e484878a0aa8581db';
const LEAN_OPTIMIZER_LOCK_SHA256 = 'b9b1935da7df52b4e34649353231c77a8a1f20c11d07a03e4d17c02a10277dd5';
const LEAN_OPTIMIZER_RUNTIME_PACKAGES = Object.freeze({ '@bitauth/libauth': '3.1.0-next.8' });
const HARNESS_PACKAGE_SHA256 = '31244146be6aabb1983b78f49149a98cdcbb0f2979e406e343836e3c03b13ea2';
const HARNESS_LOCK_SHA256 = '123bfd3aa1497c01c40c71367a188efc7d435125d4d3539d5f7175d1e09eed01';
const HARNESS_RUNTIME_PACKAGES = Object.freeze({ '@bitauth/libauth': '3.1.0-next.8', '@noble/curves': '2.2.0', tsx: '4.22.4', typescript: '6.0.3' });
const HASH = /^[0-9a-f]{64}$/;
const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(packageDirectory, '../..');
const provenanceFile = path.join(repositoryRoot, 'provenance/verifier.cash-pf7-sub62/series.json');
const referenceMatrixFile = path.join(repositoryRoot, 'evidence/G1/pf7-verifier-generator/reference-matrix.json');

export class Pf7VerifierGeneratorError extends Error {
  constructor(message) { super(message); this.name = 'Pf7VerifierGeneratorError'; }
}
const fail = (message) => { throw new Pf7VerifierGeneratorError(message); };
const object = (value, label) => { if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`); return value; };
const exactKeys = (value, label, keys) => { object(value, label); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`); };
const string = (value, label) => { if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail(`${label} must be a nonempty string without NUL`); return value; };
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha256d = (bytes) => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();

async function regularAbsolute(filename, label, { directory = false } = {}) {
  string(filename, label); if (!path.isAbsolute(filename)) fail(`${label} must be absolute`);
  const requested = path.resolve(filename); const stat = await lstat(requested).catch(() => fail(`${label} does not exist`));
  if ((directory && !stat.isDirectory()) || (!directory && (!stat.isFile() || stat.isSymbolicLink()))) fail(`${label} has the wrong filesystem type`);
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not resolve through a symlink`);
  return { path: resolved, stat };
}
async function pinnedFile(record, label) {
  exactKeys(record, label, ['path', 'sha256']); if (!HASH.test(record.sha256)) fail(`${label}.sha256 must be lowercase SHA-256`);
  const before = await regularAbsolute(record.path, `${label}.path`); const bytes = await readFile(before.path);
  if (digest(bytes) !== record.sha256) fail(`${label} SHA-256 mismatch`);
  const after = await lstat(before.path); if (after.dev !== before.stat.dev || after.ino !== before.stat.ino || after.size !== before.stat.size) fail(`${label} changed while reading`);
  if (digest(await readFile(before.path)) !== record.sha256) fail(`${label} changed after reading`);
  return { path: before.path, bytes, sha256: record.sha256 };
}
export function validateAdapter(bytes) {
  const adapter = parseStrictJson(bytes, 'PF7 adapter');
  exactKeys(adapter, 'PF7 adapter', ['byteOrder', 'qualification', 'schema', 'source', 'verificationKey', 'verifierCashFixture', 'verifierCashVk']);
  if (adapter.schema !== 'shield.cash/snarkjs-groth16-pf7-adapter/v1') fail('unsupported adapter schema');
  exactKeys(adapter.source, 'PF7 adapter source', ['proof', 'publicSignals', 'verificationKey']);
  for (const name of ['proof', 'publicSignals', 'verificationKey']) { exactKeys(adapter.source[name], `PF7 adapter source.${name}`, ['bytes', 'path', 'sha256']); if (!HASH.test(adapter.source[name].sha256) || !Number.isSafeInteger(adapter.source[name].bytes)) fail(`PF7 adapter source.${name} is malformed`); }
  return adapter;
}
async function validateAdapterSources(adapter) {
  for (const name of ['proof', 'publicSignals', 'verificationKey']) {
    const source = adapter.source[name];
    if (source.bytes < 0) fail(`PF7 adapter source.${name}.bytes must be nonnegative`);
    const pinned = await pinnedFile({ path: source.path, sha256: source.sha256 }, `PF7 adapter source.${name}`);
    if (pinned.bytes.length !== source.bytes) fail(`PF7 adapter source.${name} byte length mismatch`);
  }
}
function run(executable, args, { cwd, env }) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8'); child.stdout.on('data', (data) => { stdout += data; }); child.stderr.on('data', (data) => { stderr += data; });
    child.once('error', () => reject(new Pf7VerifierGeneratorError(`cannot execute ${path.basename(executable)}`)));
    child.once('close', (code, signal) => { if (code === 0 && signal === null) resolve({ stdout, stderr }); else reject(new Pf7VerifierGeneratorError(`${path.basename(executable)} failed (${code ?? signal}): ${stderr.slice(-4000)}`)); });
  });
}
async function git(checkout, args) { return (await run('git', ['-C', checkout, ...args], { cwd: checkout, env: { PATH: process.env.PATH ?? '' } })).stdout.trim(); }
export async function assertCleanGitRepository(checkout, label) {
  const topLevel = await git(checkout, ['rev-parse', '--show-toplevel']);
  if (await git(topLevel, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') fail(`${label} repository has tracked or untracked changes`);
  return topLevel;
}
export async function validateRuntimePackageVersions(nodeModulesPath, expectedPackages, label) {
  const nodeModules = await regularAbsolute(nodeModulesPath, `${label} node_modules`, { directory: true });
  const versions = {};
  for (const [name, expected] of Object.entries(expectedPackages)) {
    const packageJson = parseStrictJson(await readFile(path.join(nodeModules.path, name, 'package.json')), `${label} runtime package ${name}`);
    if (packageJson?.version !== expected) fail(`${label} runtime package version mismatch: ${name}`);
    versions[name] = packageJson.version;
  }
  return versions;
}
async function validateRootRuntime(checkout) {
  // The PF7 build resolves these packages from the verifier checkout root.
  // node_modules is ignored by Git, so bind its declared closure to terminal
  // metadata and refuse an indirection at the dependency-root boundary.
  const packageManifest = await pinnedFile({ path: path.join(checkout, 'package.json'), sha256: ROOT_PACKAGE_SHA256 }, 'verifier root package manifest');
  const lock = await pinnedFile({ path: path.join(checkout, 'package-lock.json'), sha256: ROOT_LOCK_SHA256 }, 'verifier root lockfile');
  void packageManifest; void lock;
  const packages = await validateRuntimePackageVersions(path.join(checkout, 'node_modules'), ROOT_RUNTIME_PACKAGES, 'verifier root');
  return { packageManifestSha256: ROOT_PACKAGE_SHA256, lockfileSha256: ROOT_LOCK_SHA256, packages };
}
async function validateLeanOptimizerRuntime(leanBchRoot) {
  const optimizer = await regularAbsolute(path.join(leanBchRoot, 'optimizer'), 'LeanBCH optimizer', { directory: true });
  const packageManifest = await pinnedFile({ path: path.join(optimizer.path, 'package.json'), sha256: LEAN_OPTIMIZER_PACKAGE_SHA256 }, 'LeanBCH optimizer package manifest');
  const lock = await pinnedFile({ path: path.join(optimizer.path, 'package-lock.json'), sha256: LEAN_OPTIMIZER_LOCK_SHA256 }, 'LeanBCH optimizer lockfile');
  void packageManifest; void lock;
  const packages = await validateRuntimePackageVersions(path.join(optimizer.path, 'node_modules'), LEAN_OPTIMIZER_RUNTIME_PACKAGES, 'LeanBCH optimizer');
  return { packageManifestSha256: LEAN_OPTIMIZER_PACKAGE_SHA256, lockfileSha256: LEAN_OPTIMIZER_LOCK_SHA256, packages };
}
async function validateHarnessRuntime(checkout) {
  const harness = await regularAbsolute(path.join(checkout, 'harness'), 'verifier harness', { directory: true });
  // node_modules is ignored by Git. Require it to be a direct directory and
  // bind its declared package closure to the terminal checkout's lockfile.
  const packageManifest = await pinnedFile({ path: path.join(harness.path, 'package.json'), sha256: HARNESS_PACKAGE_SHA256 }, 'verifier harness package manifest');
  const lock = await pinnedFile({ path: path.join(harness.path, 'pnpm-lock.yaml'), sha256: HARNESS_LOCK_SHA256 }, 'verifier harness lockfile');
  void packageManifest; void lock;
  const packages = await validateRuntimePackageVersions(path.join(harness.path, 'node_modules'), HARNESS_RUNTIME_PACKAGES, 'verifier harness');
  return { packageManifestSha256: HARNESS_PACKAGE_SHA256, lockfileSha256: HARNESS_LOCK_SHA256, packages };
}
export async function validateProvenance() {
  const bytes = await readFile(provenanceFile); const source = parseStrictJson(bytes, 'PF7 provenance');
  exactKeys(source, 'PF7 provenance', ['base', 'patches', 'schema', 'terminal']);
  exactKeys(source.base, 'PF7 provenance base', ['commit']);
  exactKeys(source.terminal, 'PF7 provenance terminal', ['commit', 'tree']);
  if (source.schema !== 'shield.cash/verifier.cash-pf7-provenance/v1' || source.base.commit !== BASE || source.terminal.commit !== TERMINAL || source.terminal.tree !== TREE || !Array.isArray(source.patches) || source.patches.length !== 7) fail('retained PF7 provenance is not the approved chain');
  for (const patch of source.patches) { exactKeys(patch, 'PF7 provenance patch', ['commit', 'path', 'sha256', 'tree']); if (!HASH.test(patch.sha256) || !/^[0-9a-f]{40}$/.test(patch.commit) || !/^[0-9a-f]{40}$/.test(patch.tree)) fail('PF7 provenance patch is malformed'); const file = await regularAbsolute(path.join(path.dirname(provenanceFile), patch.path), 'PF7 provenance patch'); if (digest(await readFile(file.path)) !== patch.sha256) fail(`retained patch hash mismatch: ${patch.path}`); }
  return source;
}
async function expectedSourceSetForAdapter(adapterSha256) {
  const matrix = parseStrictJson(await readFile(referenceMatrixFile), 'PF7 reference matrix');
  exactKeys(matrix, 'PF7 reference matrix', ['candidate', 'generatorReplay', 'invariants', 'qualification', 'runs', 'schema']);
  if (matrix.schema !== 'shield.cash/pf7-reference-matrix/v1' || !Array.isArray(matrix.runs)) fail('PF7 reference matrix is unsupported');
  const rows = matrix.runs.filter((row) => row?.adapterSha256 === adapterSha256);
  if (rows.length !== 1 || !HASH.test(rows[0].sourceSetSha256)) fail('adapter is not a bounded action-corpus member');
  const setupSet = matrix.invariants?.actionIndependentLocks?.[rows[0].setup];
  if (setupSet !== rows[0].sourceSetSha256) fail('reference matrix action-lock invariant is inconsistent');
  return setupSet;
}
function parseLastPush(hex) {
  const bytes = Buffer.from(hex, 'hex'); let offset = 0; let last;
  while (offset < bytes.length) { const opcode = bytes[offset++]; let length; if (opcode <= 75) length = opcode; else if (opcode === 0x4c) length = bytes[offset++]; else if (opcode === 0x4d) { length = bytes[offset] | (bytes[offset + 1] << 8); offset += 2; } else if (opcode === 0x4e) { length = bytes.readUInt32LE(offset); offset += 4; } else fail('unlocking bytecode is not push-only'); if (!Number.isSafeInteger(length) || offset + length > bytes.length) fail('unlocking bytecode has a truncated push'); last = bytes.subarray(offset, offset + length); offset += length; }
  if (last === undefined || last.length === 0) fail('unlocking bytecode lacks a redeem script'); return Buffer.from(last);
}
export function extractVerifierSet(inputs) {
  if (!Array.isArray(inputs) || inputs.length !== 7) fail('exact PF7 requires seven input records');
  const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];
  return inputs.map((input, index) => { exactKeys(input, `input ${index}`, ['lock', 'name', 'unlock']); if (input.name !== names[index] || !/^[0-9a-f]+$/.test(input.lock) || !/^[0-9a-f]+$/.test(input.unlock)) fail('unexpected PF7 input record'); const lock = Buffer.from(input.lock, 'hex'); const redeem = parseLastPush(input.unlock); if (lock.length !== 35 || lock[0] !== 0xaa || lock[1] !== 0x20 || lock[34] !== 0x87 || !sha256d(redeem).equals(lock.subarray(2, 34))) fail(`input ${input.name} is not an exact P2SH32 source/redeem pair`); return { name: input.name, lockingBytecodeHex: input.lock, redeemBytecodeHex: redeem.toString('hex') }; });
}
function exactEnvironment({ adapter, stage, verifier }) {
  return {
    PATH: `${path.join(verifier.checkout, 'harness/node_modules/.bin')}:${process.env.PATH ?? ''}`,
    CASHC_ROOT: verifier.cashcRoot, LEANBCH_ROOT: verifier.leanBchRoot,
    C7_SHIELD_ADAPTER_FILE: adapter.path, C7_SHIELD_ADAPTER_SHA256: adapter.sha256,
    C7_TMP: path.join(stage, 'build'), C7_GEN: path.join(stage, 'generated'),
    KWIN: '13', STRIPED_FRAGS: '5', SW: '32', CDNW: '1', CDWIDTH: '34', UNW: '16', WDWIDTH: '32', WIDE_POS: '', FIN_PAD: '', C7_MAXTRY: '2', NITS: '1', RESCHEDULE: 'on',
    SZ_ALLAFF: '1', L17SEL: '1', SEAMNARROW: '1', KSPEC: '1', SIBLING_READ: '1', FIXED_WDAT: '1', DYN_PACK: '1', DERIVE_MODE: '1', DP: '1', STRIPED: '1', STRIPE_BOUNDARY: '1', DIRECT_FINALIZE_STATE: '1', STRICT_DEPLOYMENT: '1', PUBLIC_BENCH_CONTEXT: '1', DRIVER_PACK_DERIVED: '1', DRIVER_WINDOW_DERIVED: '1',
    C7_PROJECTED_BQ_7: '1', C7_FIXED_G2_TABLE: '1', C7_FIXED_G2_COMPACT: '1', C7_FIXED_G2_NORMALIZED_ADDS: '1', C7_VK_DIGEST: '1', C7_WSEL_U8: '1', C7_COMPOSED_P2SH: '1', C7_COMPOSED_DIRECT_TERMINAL: '1', C7_PAIRFOLD_TOPOLOGY: '7', C7_SCALAR_ENDPOINT: '1', C7_ZBITS_GB3: './normalized-gb3.mjs', C7_SZ_MODULE: './mixed-sz.mjs', C7_FIXED_G2_UNLOCK_TABLE: '1', C7_FIXED_G2_WITNESS_TABLE_BYTES: '0,1536,2460,2427,2304', C7_SELF_CARRIED_TERMINAL: '1', TERMINAL_FUSION9: '1', TERMINAL_REUSE_ZPOWERS: '1', TERMINAL_CANON_ZPROLOGUE: '1', TERMINAL_FULL_OPT: '1',
  };
}
async function oneBuild(adapter, verifier, stage) {
  const environment = exactEnvironment({ adapter, verifier, stage }); await mkdir(environment.C7_TMP, { recursive: true }); await mkdir(environment.C7_GEN, { recursive: true });
  await run(path.join(verifier.checkout, 'harness/node_modules/.bin/tsx'), ['lanes/bn254-onetx/src/c7/build.ts'], { cwd: verifier.checkout, env: environment });
  const build = environment.C7_TMP; const standardness = path.join(build, 'standardness.json'); const attacks = path.join(build, 'raw-attacks.json');
  const result = parseStrictJson(await readFile(path.join(build, 'result.json')), 'PF7 result');
  assertBuildComplete(result);
  await run(path.join(verifier.checkout, 'harness/node_modules/.bin/tsx'), ['lanes/bn254-onetx/src/c7/check-standardness.ts', build, standardness], { cwd: verifier.checkout, env: environment });
  await run(path.join(verifier.checkout, 'harness/node_modules/.bin/tsx'), ['lanes/bn254-onetx/src/c7/measure-terminal-raw-attacks.ts', build, attacks], { cwd: verifier.checkout, env: environment });
  const files = Object.fromEntries(await Promise.all(['result.json', 'inputs_dump.json', 'c7_candidate_srcouts.hex', 'c7_candidate_tx.hex', 'standardness.json', 'raw-attacks.json'].map(async (name) => { const value = await readFile(path.join(build, name)); return [name, { bytes: value, sha256: digest(value) }]; })));
  return { files, result, inputs: parseStrictJson(files['inputs_dump.json'].bytes, 'PF7 inputs'), standardness: parseStrictJson(files['standardness.json'].bytes, 'PF7 standardness'), attacks: parseStrictJson(files['raw-attacks.json'].bytes, 'PF7 attacks') };
}
export function assertBuildComplete(result) {
  if (result?.built !== true) {
    const cause = JSON.stringify(result?.errors ?? null);
    fail(`PF7 build reported incomplete boundary: ${cause.slice(0, 4000)}`);
  }
}
function assertMeasured(runResult, expectedSourceSetSha256) {
  const { result, standardness, attacks } = runResult;
  if (result.gateOk !== true || result.verifierInputCount !== 7 || result.structuralRoleCount !== 0 || result.wire > 59000 || !Array.isArray(result.manual) || result.manual.length !== 7 || result.manual.some((row) => row.accepts !== true || row.unlockLen > 10000)) fail('PF7 normal-VM/topology/byte gate failed');
  if (standardness.standardVm !== 'createVirtualMachineBch2026(true)' || standardness.allAccept !== true || !Array.isArray(standardness.rows) || standardness.rows.length !== 7 || standardness.rows.some((row) => row.accepts !== true || row.unlockingBytes > 10000)) fail('PF7 standard-VM gate failed');
  if (attacks.honest?.allAccept !== true || attacks.rejected !== 18 || attacks.falseAccepts !== 0 || attacks.setupErrors !== 0) fail('PF7 raw tamper gate failed');
  if (runResult.files['c7_candidate_srcouts.hex'].sha256 !== expectedSourceSetSha256) fail('PF7 source-lock set does not match the action-invariant expected set');
}
function inputValidation(input) {
  exactKeys(input, 'PF7 generator input', ['adapter', 'destination', 'expectedSourceSetSha256', 'verifier']);
  if (!HASH.test(input.expectedSourceSetSha256)) fail('expectedSourceSetSha256 must be lowercase SHA-256'); string(input.destination, 'destination'); if (!path.isAbsolute(input.destination)) fail('destination must be absolute');
  exactKeys(input.verifier, 'verifier input', ['cashcCommit', 'cashcRoot', 'checkout', 'leanBchCommit', 'leanBchRoot']);
  for (const key of ['cashcCommit', 'leanBchCommit']) if (!/^[0-9a-f]{40}$/.test(input.verifier[key])) fail(`${key} must be a full commit hash`);
  return input;
}
export async function generatePf7VerifierSet(input) {
  inputValidation(input); const adapter = await pinnedFile(input.adapter, 'adapter'); const adapterValue = validateAdapter(adapter.bytes); await validateAdapterSources(adapterValue); const verifierRoot = await regularAbsolute(input.verifier.checkout, 'verifier.checkout', { directory: true }); const cashcRoot = await regularAbsolute(input.verifier.cashcRoot, 'verifier.cashcRoot', { directory: true }); const leanRoot = await regularAbsolute(input.verifier.leanBchRoot, 'verifier.leanBchRoot', { directory: true });
  await assertCleanGitRepository(verifierRoot.path, 'verifier checkout');
  await assertCleanGitRepository(cashcRoot.path, 'CashC checkout');
  await assertCleanGitRepository(leanRoot.path, 'LeanBCH checkout');
  const rootRuntime = await validateRootRuntime(verifierRoot.path);
  const harnessRuntime = await validateHarnessRuntime(verifierRoot.path);
  const leanOptimizerRuntime = await validateLeanOptimizerRuntime(leanRoot.path);
  const expectedForAdapter = await expectedSourceSetForAdapter(adapter.sha256);
  if (input.expectedSourceSetSha256 !== expectedForAdapter) fail('caller source-lock set is not the adapter action-invariant set');
  const verifier = { ...input.verifier, checkout: verifierRoot.path, cashcRoot: cashcRoot.path, leanBchRoot: leanRoot.path };
  await validateProvenance(); if (await git(verifier.checkout, ['rev-parse', 'HEAD']) !== TERMINAL || await git(verifier.checkout, ['rev-parse', 'HEAD^{tree}']) !== TREE || await git(verifier.checkout, ['merge-base', '--is-ancestor', BASE, 'HEAD']).catch(() => 'no') !== '') fail('verifier checkout does not exactly match the retained PF7 chain');
  if (await git(verifier.cashcRoot, ['rev-parse', 'HEAD']) !== verifier.cashcCommit || await git(verifier.leanBchRoot, ['rev-parse', 'HEAD']) !== verifier.leanBchCommit) fail('toolchain checkout commit mismatch');
  const candidate = await pinnedFile({ path: path.join(verifier.checkout, 'agent-work/pf7-sub55/candidates/bn254-onetx-pf7-sub62-r1.json'), sha256: CANDIDATE_SHA256 }, 'candidate manifest'); void candidate;
  const destination = path.resolve(input.destination); const parent = await regularAbsolute(path.dirname(destination), 'destination parent', { directory: true }); try { await lstat(destination); fail('destination already exists; refusing clobber'); } catch (error) { if (!(error?.code === 'ENOENT')) throw error; }
  const stage = await mkdtemp(path.join(parent.path, '.pf7-generator-')); let reservation; let published = false;
  try {
    const first = await oneBuild(adapter, verifier, path.join(stage, 'first')); const second = await oneBuild(adapter, verifier, path.join(stage, 'second'));
    for (const name of ['result.json', 'inputs_dump.json', 'c7_candidate_srcouts.hex', 'c7_candidate_tx.hex']) if (first.files[name].sha256 !== second.files[name].sha256) fail(`PF7 build is not identity-stable: ${name}`);
    assertMeasured(second, input.expectedSourceSetSha256); const locks = extractVerifierSet(second.inputs);
    // The raw-attack report records its staging directory, so its byte hash is
    // intentionally excluded from the canonical profile artifact. Its parsed
    // 18/18 verdict is still a hard gate above; the bounded evidence matrix
    // records externally retained raw-report hashes.
    const stableDependencies = Object.fromEntries(Object.entries(second.files)
      .filter(([name]) => name !== 'raw-attacks.json')
      .map(([name, value]) => [name, { sha256: value.sha256, bytes: value.bytes.length }]));
    const artifact = { schema: 'shield.cash/bch-verifier-set/v1', qualification: 'development-only verifier reference transaction; not complete shield.cash protocol settlement', candidate: { id: CANDIDATE, baseCommit: BASE, terminalCommit: TERMINAL, terminalTree: TREE, manifestSha256: CANDIDATE_SHA256, topologyInputs: 7, genericFallback: 'forbidden' }, adapter: { sha256: adapter.sha256, source: Object.fromEntries(Object.entries(adapterValue.source).map(([name, value]) => [name, { bytes: value.bytes, sha256: value.sha256 }])) }, toolchain: { cashcCommit: verifier.cashcCommit, leanBchCommit: verifier.leanBchCommit, rootRuntime, harnessRuntime, leanOptimizerRuntime }, measurements: { wireBytes: second.result.wire, scoreBytes: second.result.score, maxUnlockingBytes: Math.max(...second.result.manual.map((row) => row.unlockLen)), normalVm: '7/7', standardVm: '7/7', rawTamper: '18/18 reject', sourceSetSha256: second.files['c7_candidate_srcouts.hex'].sha256 }, scripts: locks, dependencies: stableDependencies };
    // mkdir is the no-clobber publication reservation. Consumers require the
    // manifest, written last with O_EXCL, as the completion marker; therefore
    // they never treat a partial crash directory as an emitted artifact.
    await mkdir(destination, { mode: 0o700 }); reservation = await lstat(destination);
    const serialized = `${canonicalJson(artifact)}\n`;
    await writeFile(path.join(destination, 'bch-verifier-set.json'), serialized, { flag: 'wx', mode: 0o600 });
    await writeFile(path.join(destination, 'manifest.json'), `${canonicalJson({ schema: 'shield.cash/pf7-verifier-generator-output/v1', bchVerifierSetSha256: digest(Buffer.from(serialized)), adapterSha256: adapter.sha256 })}\n`, { flag: 'wx', mode: 0o600 });
    published = true; return { destination, sha256: digest(Buffer.from(serialized)), artifact };
  } finally {
    await rm(stage, { recursive: true, force: true });
    if (!published && reservation !== undefined) {
      const current = await lstat(destination).catch(() => undefined);
      if (current?.isDirectory() && !current.isSymbolicLink() && current.dev === reservation.dev && current.ino === reservation.ino) await rm(destination, { recursive: true, force: true });
    }
  }
}
