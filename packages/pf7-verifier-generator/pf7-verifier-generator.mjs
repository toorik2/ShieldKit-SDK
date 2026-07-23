import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, loadVerifierProfileBundle, parseStrictJson } from '../core/verifier-profile.mjs';
import {
  ACTION_PACKET_BYTES,
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../action-packet/action-packet.mjs';
import { adaptSnarkjsGroth16 } from '../snarkjs-adapter/snarkjs-groth16-adapter.mjs';

const BASE = '26468ae29004d2401619032de2a6ec8de269a4d6';
const REFERENCE_TERMINAL = '17c6b9552c48b0fc5271be626a1578fb0065df09';
const REFERENCE_TREE = 'd9673df5a3f5358df6aaff9c4042a029bc26a521';
const SEAM_TERMINAL = '1d543756602edfd92081a0b58dba62d33d0aea34';
const SEAM_TREE = '1c1efb23e95bf51a715f8ab29f3cf698a359303d';
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
const seamProvenanceFile = path.join(repositoryRoot, 'provenance/verifier.cash-pf7-sub62/seam-series.json');
const referenceMatrixFile = path.join(repositoryRoot, 'evidence/G1/pf7-verifier-generator/reference-matrix.json');
const ACTION_KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

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
async function validatePatches(source, filename, expectedLength) {
  if (!Array.isArray(source.patches) || source.patches.length !== expectedLength) fail('retained PF7 provenance patch count mismatch');
  for (const patch of source.patches) { exactKeys(patch, 'PF7 provenance patch', ['commit', 'path', 'sha256', 'tree']); if (!HASH.test(patch.sha256) || !/^[0-9a-f]{40}$/.test(patch.commit) || !/^[0-9a-f]{40}$/.test(patch.tree) || !/^patches\/[0-9]{4}-[A-Za-z0-9._-]+\.patch$/.test(patch.path)) fail('PF7 provenance patch is malformed'); const file = await regularAbsolute(path.join(path.dirname(filename), patch.path), 'PF7 provenance patch'); if (digest(await readFile(file.path)) !== patch.sha256) fail(`retained patch hash mismatch: ${patch.path}`); }
}
export async function validateProvenance() {
  const source = parseStrictJson(await readFile(provenanceFile), 'PF7 reference provenance');
  exactKeys(source, 'PF7 reference provenance', ['base', 'patches', 'schema', 'terminal']);
  exactKeys(source.base, 'PF7 reference provenance base', ['commit']);
  exactKeys(source.terminal, 'PF7 reference provenance terminal', ['commit', 'tree']);
  if (!Array.isArray(source.patches)) fail('PF7 reference provenance patches must be an array');
  if (
    source.schema !== 'shield.cash/verifier.cash-pf7-provenance/v1'
    || source.base.commit !== BASE
    || source.terminal.commit !== REFERENCE_TERMINAL
    || source.terminal.tree !== REFERENCE_TREE
    || source.patches[6]?.commit !== REFERENCE_TERMINAL
    || source.patches[6]?.tree !== REFERENCE_TREE
  ) fail('retained PF7 reference provenance is not the approved historical chain');
  await validatePatches(source, provenanceFile, 7);
  return source;
}
export async function validateSeamProvenance() {
  const source = parseStrictJson(await readFile(seamProvenanceFile), 'PF7 seam provenance');
  exactKeys(source, 'PF7 seam provenance', ['base', 'patches', 'referenceTerminal', 'schema', 'terminal']);
  exactKeys(source.base, 'PF7 seam provenance base', ['commit']);
  exactKeys(source.referenceTerminal, 'PF7 seam provenance reference terminal', ['commit', 'tree']);
  exactKeys(source.terminal, 'PF7 seam provenance terminal', ['commit', 'tree']);
  if (!Array.isArray(source.patches)) fail('PF7 seam provenance patches must be an array');
  if (
    source.schema !== 'shield.cash/verifier.cash-pf7-seam-provenance/v1'
    || source.base.commit !== BASE
    || source.referenceTerminal.commit !== REFERENCE_TERMINAL
    || source.referenceTerminal.tree !== REFERENCE_TREE
    || source.terminal.commit !== SEAM_TERMINAL
    || source.terminal.tree !== SEAM_TREE
    || source.patches[6]?.commit !== REFERENCE_TERMINAL
    || source.patches[6]?.tree !== REFERENCE_TREE
    || source.patches[7]?.commit !== SEAM_TERMINAL
    || source.patches[7]?.tree !== SEAM_TREE
  ) fail('retained PF7 provenance is not the approved reference-plus-seam chain');
  await validatePatches(source, seamProvenanceFile, 8);
  return source;
}
async function referenceRowForAdapter(adapterSha256) {
  const matrix = parseStrictJson(await readFile(referenceMatrixFile), 'PF7 reference matrix');
  exactKeys(matrix, 'PF7 reference matrix', ['candidate', 'generatorReplay', 'invariants', 'qualification', 'runs', 'schema']);
  if (matrix.schema !== 'shield.cash/pf7-reference-matrix/v1' || !Array.isArray(matrix.runs)) fail('PF7 reference matrix is unsupported');
  const rows = matrix.runs.filter((row) => row?.adapterSha256 === adapterSha256);
  if (rows.length !== 1 || !HASH.test(rows[0].sourceSetSha256)) fail('adapter is not a bounded action-corpus member');
  const setupSet = matrix.invariants?.actionIndependentLocks?.[rows[0].setup];
  if (setupSet !== rows[0].sourceSetSha256) fail('reference matrix action-lock invariant is inconsistent');
  return { row: rows[0], sourceSetSha256: setupSet };
}
async function expectedSourceSetForAdapter(adapterSha256) {
  return (await referenceRowForAdapter(adapterSha256)).sourceSetSha256;
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
function exactEnvironment({ actionPacket, adapter, stage, verifier }) {
  return {
    PATH: `${path.join(verifier.checkout, 'harness/node_modules/.bin')}:${process.env.PATH ?? ''}`,
    TMPDIR: path.join(stage, 'tmp'),
    CASHC_ROOT: verifier.cashcRoot, LEANBCH_ROOT: verifier.leanBchRoot,
    C7_SHIELD_ADAPTER_FILE: adapter.path, C7_SHIELD_ADAPTER_SHA256: adapter.sha256,
    ...(actionPacket === undefined ? {} : {
      C7_STRUCTURAL_ROLE_COUNT: '3',
      C7_SHIELD_ACTION_PACKET_FILE: actionPacket.path,
      C7_SHIELD_ACTION_PACKET_SHA256: actionPacket.sha256,
    }),
    C7_TMP: path.join(stage, 'build'), C7_GEN: path.join(stage, 'generated'),
    KWIN: '13', STRIPED_FRAGS: '5', SW: '32', CDNW: '1', CDWIDTH: '34', UNW: '16', WDWIDTH: '32', WIDE_POS: '', FIN_PAD: '', C7_MAXTRY: '2', NITS: '1', RESCHEDULE: 'on',
    SZ_ALLAFF: '1', L17SEL: '1', SEAMNARROW: '1', KSPEC: '1', SIBLING_READ: '1', FIXED_WDAT: '1', DYN_PACK: '1', DERIVE_MODE: '1', DP: '1', STRIPED: '1', STRIPE_BOUNDARY: '1', DIRECT_FINALIZE_STATE: '1', STRICT_DEPLOYMENT: '1', PUBLIC_BENCH_CONTEXT: '1', DRIVER_PACK_DERIVED: '1', DRIVER_WINDOW_DERIVED: '1',
    C7_PROJECTED_BQ_7: '1', C7_FIXED_G2_TABLE: '1', C7_FIXED_G2_COMPACT: '1', C7_FIXED_G2_NORMALIZED_ADDS: '1', C7_VK_DIGEST: '1', C7_WSEL_U8: '1', C7_COMPOSED_P2SH: '1', C7_COMPOSED_DIRECT_TERMINAL: '1', C7_PAIRFOLD_TOPOLOGY: '7', C7_SCALAR_ENDPOINT: '1', C7_ZBITS_GB3: './normalized-gb3.mjs', C7_SZ_MODULE: './mixed-sz.mjs', C7_FIXED_G2_UNLOCK_TABLE: '1', C7_FIXED_G2_WITNESS_TABLE_BYTES: '0,1536,2460,2427,2304', C7_SELF_CARRIED_TERMINAL: '1', TERMINAL_FUSION9: '1', TERMINAL_REUSE_ZPOWERS: '1', TERMINAL_CANON_ZPROLOGUE: '1', TERMINAL_FULL_OPT: '1',
  };
}
async function oneBuild(adapter, verifier, stage, actionPacket) {
  const environment = exactEnvironment({ actionPacket, adapter, verifier, stage }); await mkdir(environment.TMPDIR, { recursive: true }); await mkdir(environment.C7_TMP, { recursive: true }); await mkdir(environment.C7_GEN, { recursive: true });
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
  validateVerifierShape(input.verifier);
  return input;
}
function validateVerifierShape(verifier) {
  object(verifier, 'verifier input');
  exactKeys(verifier, 'verifier input', ['cashcCommit', 'cashcRoot', 'checkout', 'leanBchCommit', 'leanBchRoot']);
  for (const key of ['cashcCommit', 'leanBchCommit']) if (!/^[0-9a-f]{40}$/.test(verifier[key])) fail(`${key} must be a full commit hash`);
  for (const key of ['cashcRoot', 'checkout', 'leanBchRoot']) if (!path.isAbsolute(string(verifier[key], `verifier.${key}`))) fail(`verifier.${key} must be absolute`);
  return verifier;
}
async function prepareVerifier(input, { commit, tree, label, provenance }) {
  const verifierRoot = await regularAbsolute(input.checkout, 'verifier.checkout', { directory: true });
  const cashcRoot = await regularAbsolute(input.cashcRoot, 'verifier.cashcRoot', { directory: true });
  const leanRoot = await regularAbsolute(input.leanBchRoot, 'verifier.leanBchRoot', { directory: true });
  await assertCleanGitRepository(verifierRoot.path, 'verifier checkout');
  await assertCleanGitRepository(cashcRoot.path, 'CashC checkout');
  await assertCleanGitRepository(leanRoot.path, 'LeanBCH checkout');
  const rootRuntime = await validateRootRuntime(verifierRoot.path);
  const harnessRuntime = await validateHarnessRuntime(verifierRoot.path);
  const leanOptimizerRuntime = await validateLeanOptimizerRuntime(leanRoot.path);
  const verifier = { ...input, checkout: verifierRoot.path, cashcRoot: cashcRoot.path, leanBchRoot: leanRoot.path };
  if (provenance === 'reference') await validateProvenance();
  else if (provenance === 'seam') await validateSeamProvenance();
  else fail('unknown PF7 provenance selection');
  if (
    await git(verifier.checkout, ['rev-parse', 'HEAD']) !== commit
    || await git(verifier.checkout, ['rev-parse', 'HEAD^{tree}']) !== tree
    || await git(verifier.checkout, ['merge-base', '--is-ancestor', BASE, 'HEAD']).catch(() => 'no') !== ''
  ) fail(`verifier checkout does not exactly match the retained PF7 ${label} chain`);
  if (await git(verifier.cashcRoot, ['rev-parse', 'HEAD']) !== verifier.cashcCommit || await git(verifier.leanBchRoot, ['rev-parse', 'HEAD']) !== verifier.leanBchCommit) fail('toolchain checkout commit mismatch');
  const candidate = await pinnedFile({ path: path.join(verifier.checkout, 'agent-work/pf7-sub55/candidates/bn254-onetx-pf7-sub62-r1.json'), sha256: CANDIDATE_SHA256 }, 'candidate manifest'); void candidate;
  return { verifier, toolchain: { cashcCommit: verifier.cashcCommit, leanBchCommit: verifier.leanBchCommit, rootRuntime, harnessRuntime, leanOptimizerRuntime } };
}
async function reserveDestination(destinationInput, label = 'destination') {
  string(destinationInput, label); if (!path.isAbsolute(destinationInput)) fail(`${label} must be absolute`);
  const destination = path.resolve(destinationInput);
  const parent = await regularAbsolute(path.dirname(destination), `${label} parent`, { directory: true });
  try { await lstat(destination); fail(`${label} already exists; refusing clobber`); } catch (error) { if (!(error?.code === 'ENOENT')) throw error; }
  return { destination, parent };
}
function normalizedRawAttackReport(attacks) {
  exactKeys(attacks, 'PF7 raw attack report', ['falseAccepts', 'honest', 'rejected', 'results', 'runDir', 'setupErrors', 'total']);
  return { total: attacks.total, rejected: attacks.rejected, falseAccepts: attacks.falseAccepts, setupErrors: attacks.setupErrors, honest: attacks.honest, results: attacks.results };
}
function normalizedSeamRedteamReport(report) {
  exactKeys(report, 'PF7 seam redteam report', ['attackCount', 'attacks', 'crossAction', 'fixture', 'honest', 'honestDir', 'schema', 'scope', 'verdict']);
  return { schema: report.schema, scope: report.scope, honest: report.honest, attacks: report.attacks, crossAction: report.crossAction, attackCount: report.attackCount, verdict: report.verdict };
}
function sha256Canonical(value) {
  return digest(Buffer.from(canonicalJson(value)));
}
function artifactDependencies(files) {
  return Object.fromEntries(Object.entries(files)
    .filter(([name]) => name !== 'raw-attacks.json')
    .map(([name, value]) => [name, { sha256: value.sha256, bytes: value.bytes.length }]));
}
function exactSourceLockHashes(inputs) {
  if (!Array.isArray(inputs) || inputs.length !== 10) fail('seam build must expose exactly ten input records');
  const expected = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal', 'packet', 'state', 'fee'];
  return inputs.map((input, index) => {
    exactKeys(input, `seam input ${index}`, ['lock', 'name', 'unlock']);
    if (input.name !== expected[index] || !/^[0-9a-f]+$/.test(input.lock) || (input.unlock !== '' && !/^[0-9a-f]+$/.test(input.unlock))) fail('unexpected seam input record');
    return { name: input.name, lockingBytecodeSha256: digest(Buffer.from(input.lock, 'hex')), lockingBytes: input.lock.length / 2 };
  });
}
export function assertSeamMeasured(runResult) {
  const { result, standardness, attacks } = runResult;
  const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal', 'packet', 'state', 'fee'];
  if (
    result?.built !== true || result.gateOk !== true
    || result.verifierInputCount !== 7
    || result.structuralRoleCount !== 3
    || result.structuralRolesUnevaluated !== true
    || result.wire > 59000
    || !Array.isArray(result.manual) || result.manual.length !== 10
    || result.manual.some((row, index) => row.i !== index || row.name !== names[index] || row.unlockLen > 10000)
    || result.manual.slice(0, 7).some((row) => row.accepts !== true)
    || result.packet?.index !== 7 || result.packet.bytes !== ACTION_PACKET_BYTES || result.packet.unlockBytes !== ACTION_PACKET_BYTES + 3 || !HASH.test(result.packet.sha256)
    || result.projectionSignalCarrier?.genesisIndex !== 5
    || result.projectionSignalCarrier?.pushHeader !== '4de001'
    || result.projectionSignalCarrier?.projectionOffset !== 3
    || result.projectionSignalCarrier?.projectionBytes !== 448
    || result.projectionSignalCarrier?.digestOffset !== 451
    || result.projectionSignalCarrier?.digestBytes !== 32
  ) fail('PF7 seam normal-VM/topology/byte gate failed');
  if (
    standardness?.standardVm !== 'createVirtualMachineBch2026(true)'
    || standardness.contextInputCount !== 10
    || standardness.evaluatedInputCount !== 7
    || standardness.scope !== 'verifier roles only; structural packet/state/fee roles explicitly unevaluated'
    || standardness.allAccept !== true
    || !Array.isArray(standardness.rows) || standardness.rows.length !== 7
    || standardness.rows.some((row, index) => row.index !== index || row.name !== names[index] || row.accepts !== true || row.unlockingBytes > 10000)
  ) fail('PF7 seam standard-VM gate failed');
  if (attacks?.honest?.allAccept !== true || attacks.total !== 18 || attacks.rejected !== 18 || attacks.falseAccepts !== 0 || attacks.setupErrors !== 0 || !Array.isArray(attacks.results) || attacks.results.length !== 18) fail('PF7 seam raw terminal tamper gate failed');
  return true;
}
export function assertSeamRedteam(report) {
  const attackNames = [
    'altered-in0', 'altered-in1', 'carrier-digest-byte', 'carrier-header',
    'carrier-high-bit', 'carrier-little-endian-halves', 'carrier-swapped-halves',
    'input5-input7-swap', 'packet-byte', 'packet-header',
    'packet-nonminimal-push', 'packet-short', 'packet-trailing',
  ];
  if (
    report?.schema !== 'verifier.cash/bn254-onetx-shield-action-seam-redteam/v1'
    || report.scope !== 'seven verifier roles evaluated in complete ten-input context; packet/state/fee structural roles unevaluated'
    || report.verdict !== 'pass' || report.attackCount !== 17
    || !Array.isArray(report.honest) || report.honest.length !== 7 || report.honest.some((row) => row.accepts !== true)
    || object(report.attacks, 'PF7 seam redteam attacks') === undefined
    || Object.keys(report.attacks).sort().join('\0') !== attackNames.sort().join('\0')
    || Object.values(report.attacks).some((rows) => !Array.isArray(rows) || rows.length !== 7 || rows.every((row) => row.accepts === true))
    || !Array.isArray(report.crossAction) || report.crossAction.length !== 2
    || report.crossAction.some((cross) => !Array.isArray(cross.packetSubstitution) || cross.packetSubstitution.length !== 7 || cross.packetSubstitution[6]?.accepts !== false || !Array.isArray(cross.genesisSubstitution) || cross.genesisSubstitution.length !== 7 || cross.genesisSubstitution.every((row) => row.accepts === true))
  ) fail('PF7 seam cross-action redteam gate failed');
  return true;
}
function seamInputValidation(input) {
  exactKeys(input, 'PF7 seam corpus input', ['actions', 'destination', 'scratchDirectory', 'verifier']);
  string(input.destination, 'destination'); if (!path.isAbsolute(input.destination)) fail('destination must be absolute');
  string(input.scratchDirectory, 'scratchDirectory'); if (!path.isAbsolute(input.scratchDirectory)) fail('scratchDirectory must be absolute');
  validateVerifierShape(input.verifier);
  if (!Array.isArray(input.actions) || input.actions.length !== ACTION_KINDS.length) fail('actions must contain exactly deposit, transfer, and withdrawal');
  input.actions.forEach((action, index) => {
    exactKeys(action, `actions[${index}]`, ['adapter', 'kind', 'packet']);
    if (action.kind !== ACTION_KINDS[index]) fail('actions must be ordered deposit, transfer, withdrawal');
    for (const field of ['adapter', 'packet']) {
      exactKeys(action[field], `actions[${index}].${field}`, ['path', 'sha256']);
      string(action[field].path, `actions[${index}].${field}.path`);
      if (!path.isAbsolute(action[field].path) || !HASH.test(action[field].sha256)) fail(`actions[${index}].${field} must be an absolute SHA-256-pinned file`);
    }
  });
  return input;
}
export async function generatePf7VerifierSet(input) {
  inputValidation(input); const adapter = await pinnedFile(input.adapter, 'adapter'); const adapterValue = validateAdapter(adapter.bytes); await validateAdapterSources(adapterValue);
  const expectedForAdapter = await expectedSourceSetForAdapter(adapter.sha256);
  if (input.expectedSourceSetSha256 !== expectedForAdapter) fail('caller source-lock set is not the adapter action-invariant set');
  const { verifier, toolchain } = await prepareVerifier(input.verifier, { commit: REFERENCE_TERMINAL, tree: REFERENCE_TREE, label: 'reference', provenance: 'reference' });
  const { destination, parent } = await reserveDestination(input.destination);
  const stage = await mkdtemp(path.join(parent.path, '.pf7-generator-')); let reservation; let published = false;
  try {
    const first = await oneBuild(adapter, verifier, path.join(stage, 'first')); const second = await oneBuild(adapter, verifier, path.join(stage, 'second'));
    for (const name of ['result.json', 'inputs_dump.json', 'c7_candidate_srcouts.hex', 'c7_candidate_tx.hex']) if (first.files[name].sha256 !== second.files[name].sha256) fail(`PF7 build is not identity-stable: ${name}`);
    assertMeasured(second, input.expectedSourceSetSha256); const locks = extractVerifierSet(second.inputs);
    // The raw-attack report records its staging directory, so its byte hash is
    // intentionally excluded from the canonical profile artifact. Its parsed
    // 18/18 verdict is still a hard gate above; the bounded evidence matrix
    // records externally retained raw-report hashes.
    const stableDependencies = artifactDependencies(second.files);
    const artifact = { schema: 'shield.cash/bch-verifier-set/v1', qualification: 'development-only verifier reference transaction; not complete shield.cash protocol settlement', candidate: { id: CANDIDATE, baseCommit: BASE, terminalCommit: REFERENCE_TERMINAL, terminalTree: REFERENCE_TREE, manifestSha256: CANDIDATE_SHA256, topologyInputs: 7, genericFallback: 'forbidden' }, adapter: { sha256: adapter.sha256, source: Object.fromEntries(Object.entries(adapterValue.source).map(([name, value]) => [name, { bytes: value.bytes, sha256: value.sha256 }])) }, toolchain, measurements: { wireBytes: second.result.wire, scoreBytes: second.result.score, maxUnlockingBytes: Math.max(...second.result.manual.map((row) => row.unlockLen)), normalVm: '7/7', standardVm: '7/7', rawTamper: '18/18 reject', sourceSetSha256: second.files['c7_candidate_srcouts.hex'].sha256 }, scripts: locks, dependencies: stableDependencies };
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

export async function generatePf7ActionSeamCorpus(input) {
  seamInputValidation(input);
  const actions = [];
  for (const actionInput of input.actions) {
    const adapter = await pinnedFile(actionInput.adapter, `${actionInput.kind} adapter`);
    const adapterValue = validateAdapter(adapter.bytes);
    await validateAdapterSources(adapterValue);
    const packet = await pinnedFile(actionInput.packet, `${actionInput.kind} action packet`);
    if (packet.bytes.length !== ACTION_PACKET_BYTES) fail(`${actionInput.kind} action packet must be exactly ${ACTION_PACKET_BYTES} bytes`);
    let decoded;
    try { decoded = decodeActionPacket(packet.bytes); } catch (error) { fail(`${actionInput.kind} action packet is not canonical: ${error.message}`); }
    if (decoded.kind !== actionInput.kind) fail(`${actionInput.kind} action packet kind mismatch`);
    const publicLimbs = actionPacketPublicLimbs(packet.bytes);
    if (
      adapterValue.verifierCashFixture?.in0 !== publicLimbs[0]
      || adapterValue.verifierCashFixture?.in1 !== publicLimbs[1]
    ) fail(`${actionInput.kind} packet digest limbs do not match adapter public inputs`);
    const reference = await referenceRowForAdapter(adapter.sha256);
    if (reference.row.action !== actionInput.kind) fail(`${actionInput.kind} adapter is assigned to the wrong action`);
    actions.push({ kind: actionInput.kind, adapter, adapterValue, packet, publicLimbs, reference });
  }
  if (new Set(actions.map((action) => action.reference.row.setup)).size !== 1) fail('all seam adapters must belong to one reference setup');
  if (new Set(actions.map((action) => action.reference.sourceSetSha256)).size !== 1) fail('reference adapters do not have action-invariant source locks');

  const { verifier, toolchain } = await prepareVerifier(input.verifier, { commit: SEAM_TERMINAL, tree: SEAM_TREE, label: 'seam', provenance: 'seam' });
  const { destination } = await reserveDestination(input.destination);
  const scratch = await regularAbsolute(input.scratchDirectory, 'scratchDirectory', { directory: true });
  const stage = await mkdtemp(path.join(scratch.path, '.pf7-seam-corpus-')); let reservation; let published = false;
  try {
    const builds = [];
    const identityStableFiles = ['result.json', 'inputs_dump.json', 'c7_candidate_srcouts.hex', 'c7_candidate_tx.hex', 'standardness.json'];
    for (const action of actions) {
      const first = await oneBuild(action.adapter, verifier, path.join(stage, action.kind, 'first'), action.packet);
      const second = await oneBuild(action.adapter, verifier, path.join(stage, action.kind, 'second'), action.packet);
      for (const name of identityStableFiles) if (first.files[name].sha256 !== second.files[name].sha256) fail(`${action.kind} PF7 seam build is not identity-stable: ${name}`);
      if (canonicalJson(normalizedRawAttackReport(first.attacks)) !== canonicalJson(normalizedRawAttackReport(second.attacks))) fail(`${action.kind} PF7 seam raw-attack report is not identity-stable`);
      assertSeamMeasured(first); assertSeamMeasured(second);
      if (second.result.packet.sha256 !== action.packet.sha256) fail(`${action.kind} PF7 seam result did not bind the pinned packet`);
      builds.push({ action, first, second, directory: path.join(stage, action.kind, 'second', 'build') });
    }

    const sourceSetSha256 = builds[0].second.files['c7_candidate_srcouts.hex'].sha256;
    if (builds.some((build) => build.second.files['c7_candidate_srcouts.hex'].sha256 !== sourceSetSha256)) fail('PF7 seam source-output set changes across actions');
    const sourceLocks = exactSourceLockHashes(builds[0].second.inputs);
    const sourceLockIdentity = canonicalJson(sourceLocks);
    for (const build of builds.slice(1)) if (canonicalJson(exactSourceLockHashes(build.second.inputs)) !== sourceLockIdentity) fail('PF7 seam source locking bytecode changes across actions');
    const scripts = extractVerifierSet(builds[0].second.inputs.slice(0, 7));

    const redteams = new Map();
    for (const build of builds) {
      const output = path.join(stage, `${build.action.kind}-seam-redteam.json`);
      const crosses = builds.filter((other) => other !== build);
      await run(path.join(verifier.checkout, 'harness/node_modules/.bin/tsx'), [
        'lanes/bn254-onetx/src/c7/run-shield-action-seam-redteam.ts',
        '--honest', build.directory,
        '--fixture', build.action.adapter.path,
        '--out', output,
        ...crosses.flatMap((other) => ['--cross', other.directory]),
      ], { cwd: verifier.checkout, env: exactEnvironment({ actionPacket: build.action.packet, adapter: build.action.adapter, stage: path.join(stage, 'redteam-environment'), verifier }) });
      const report = parseStrictJson(await readFile(output), `${build.action.kind} PF7 seam redteam`);
      assertSeamRedteam(report);
      redteams.set(build.action.kind, normalizedSeamRedteamReport(report));
    }

    const actionRows = builds.map((build) => {
      const rawTerminal = normalizedRawAttackReport(build.second.attacks);
      const seamRedteam = redteams.get(build.action.kind);
      return {
        kind: build.action.kind,
        adapter: {
          sha256: build.action.adapter.sha256,
          source: Object.fromEntries(Object.entries(build.action.adapterValue.source).map(([name, value]) => [name, { bytes: value.bytes, sha256: value.sha256 }])),
        },
        actionPacket: { sha256: build.action.packet.sha256, bytes: build.action.packet.bytes.length, publicLimbs: build.action.publicLimbs },
        measurements: {
          contextWireBytes: build.second.result.wire,
          allBytesScore: build.second.result.score,
          maxVerifierUnlockingBytes: Math.max(...build.second.result.manual.slice(0, 7).map((row) => row.unlockLen)),
          maxContextUnlockingBytes: Math.max(...build.second.result.manual.map((row) => row.unlockLen)),
          normalVerifierVm: '7/7',
          standardVerifierVm: '7/7',
          rawTerminalTamper: '18/18 reject',
          seamRedteam: '17/17 reject',
        },
        reports: {
          rawTerminalNormalizedSha256: sha256Canonical(rawTerminal),
          seamRedteamNormalizedSha256: sha256Canonical(seamRedteam),
        },
        dependencies: artifactDependencies(build.second.files),
      };
    });
    const artifact = {
      schema: 'shield.cash/pf7-action-seam-corpus/v1',
      qualification: 'development-only verifier-role evidence experiment; not a complete settlement, G2 artifact, node-relay result, Chipnet result, ceremony, profile, or release claim',
      candidate: {
        id: CANDIDATE,
        baseCommit: BASE,
        referenceTerminalCommit: REFERENCE_TERMINAL,
        referenceTerminalTree: REFERENCE_TREE,
        seamTerminalCommit: SEAM_TERMINAL,
        seamTerminalTree: SEAM_TREE,
        manifestSha256: CANDIDATE_SHA256,
        verifierInputs: 7,
        contextInputs: 10,
        genericFallback: 'forbidden',
      },
      limits: { contextWireTargetBytes: 59000, perInputUnlockingBytes: 10000, percentageHeadroomRequired: false },
      scope: {
        evaluatedRoles: ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'],
        unevaluatedStructuralRoles: ['packet', 'state', 'fee'],
        structuralRoleWarning: 'inputs 7 through 9 are present in transaction context but are not evaluated as settlement covenants',
        packetAbi: 'input7 exactly PUSHDATA2(752); terminal single-SHA256; genesis first push PUSHDATA2(480)=projection[448]||digest[32]',
      },
      reproducibility: { buildsPerAction: 2, identityStableFiles, sourceLocksIdenticalAcrossActions: true },
      setup: actions[0].reference.row.setup,
      sourceSetSha256,
      sourceLocks,
      scripts,
      toolchain,
      actions: actionRows,
    };

    await mkdir(destination, { mode: 0o700 }); reservation = await lstat(destination);
    const outputFiles = {};
    for (const build of builds) {
      const rawTerminal = `${canonicalJson(normalizedRawAttackReport(build.second.attacks))}\n`;
      const seamRedteam = `${canonicalJson(redteams.get(build.action.kind))}\n`;
      for (const [suffix, contents] of [['raw-terminal-attacks', rawTerminal], ['seam-redteam', seamRedteam]]) {
        const name = `${build.action.kind}-${suffix}.json`;
        await writeFile(path.join(destination, name), contents, { flag: 'wx', mode: 0o600 });
        outputFiles[name] = { sha256: digest(Buffer.from(contents)), bytes: Buffer.byteLength(contents) };
      }
    }
    const serialized = `${canonicalJson(artifact)}\n`;
    await writeFile(path.join(destination, 'pf7-action-seam-corpus.json'), serialized, { flag: 'wx', mode: 0o600 });
    outputFiles['pf7-action-seam-corpus.json'] = { sha256: digest(Buffer.from(serialized)), bytes: Buffer.byteLength(serialized) };
    const manifest = `${canonicalJson({ schema: 'shield.cash/pf7-action-seam-corpus-output/v1', corpusSha256: outputFiles['pf7-action-seam-corpus.json'].sha256, files: outputFiles })}\n`;
    await writeFile(path.join(destination, 'manifest.json'), manifest, { flag: 'wx', mode: 0o600 });
    published = true;
    return { destination, sha256: outputFiles['pf7-action-seam-corpus.json'].sha256, artifact };
  } finally {
    await rm(stage, { recursive: true, force: true });
    if (!published && reservation !== undefined) {
      const current = await lstat(destination).catch(() => undefined);
      if (current?.isDirectory() && !current.isSymbolicLink() && current.dev === reservation.dev && current.ino === reservation.ino) await rm(destination, { recursive: true, force: true });
    }
  }
}

// Fresh material deliberately has a separate entrypoint from the retained
// reference-matrix corpus above. The retained matrix is historical evidence;
// accepting a new setup through it would turn an evidence selector into an
// unreviewed profile authority.
const HASH_IDENTIFIER = /^sha256:[0-9a-f]{64}$/;
function hashIdentifier(value, label) {
  if (typeof value !== 'string' || !HASH_IDENTIFIER.test(value)) fail(`${label} must be a lowercase sha256 identifier`);
  return value;
}
function freshAbsolutePath(value, label) {
  string(value, label);
  if (!path.isAbsolute(value) || value.split(path.sep).includes('..')) fail(`${label} must be an absolute path without traversal`);
  return value;
}
function freshFileRecord(value, label) {
  exactKeys(value, label, ['path', 'sha256']);
  freshAbsolutePath(value.path, `${label}.path`);
  if (!HASH.test(value.sha256)) fail(`${label} must be an absolute SHA-256-pinned file`);
  return value;
}
function freshPreProfileValidation(value) {
  exactKeys(value, 'fresh pre-profile', ['r1cs', 'schema', 'setupMetadata', 'verificationKey']);
  if (value.schema !== 'shield.cash/pf7-fresh-development-preprofile/v1') fail('fresh pre-profile schema is unsupported');
  for (const key of ['setupMetadata', 'r1cs', 'verificationKey']) freshFileRecord(value[key], `fresh pre-profile.${key}`);
  return value;
}
function freshActionValidation(action, index) {
  exactKeys(action, `fresh actions[${index}]`, ['kind', 'packet', 'proof', 'publicSignals', 'verificationKey']);
  if (action.kind !== ACTION_KINDS[index]) fail('fresh actions must be ordered deposit, transfer, withdrawal');
  for (const key of ['packet', 'proof', 'publicSignals', 'verificationKey']) freshFileRecord(action[key], `fresh actions[${index}].${key}`);
  return action;
}
export function validatePf7FreshDevelopmentInput(input) {
  object(input, 'fresh PF7 input');
  const required = ['actions', 'destination', 'mode', 'preProfile', 'scratchDirectory', 'verifier'];
  const keys = input.mode === 'final-replay' ? [...required, 'expected', 'finalProfile'] : required;
  exactKeys(input, 'fresh PF7 input', keys);
  if (input.mode !== 'discovery' && input.mode !== 'final-replay') fail('fresh PF7 mode must be discovery or final-replay');
  freshAbsolutePath(input.destination, 'destination'); freshAbsolutePath(input.scratchDirectory, 'scratchDirectory');
  freshPreProfileValidation(input.preProfile); validateVerifierShape(input.verifier);
  if (!Array.isArray(input.actions) || input.actions.length !== ACTION_KINDS.length) fail('fresh actions must contain exactly deposit, transfer, and withdrawal');
  input.actions.forEach(freshActionValidation);
  if (input.actions.some((action) => action.verificationKey.sha256 !== input.preProfile.verificationKey.sha256)) fail('fresh actions must pin the pre-profile verification key');
  if (input.mode === 'final-replay') {
    exactKeys(input.expected, 'fresh final replay expected', ['sourceSetSha256', 'verifierSetSha256']);
    if (!HASH.test(input.expected.verifierSetSha256) || !HASH.test(input.expected.sourceSetSha256)) fail('fresh final replay expected hashes must be lowercase SHA-256');
    exactKeys(input.finalProfile, 'fresh final replay profile', ['bundleDirectory', 'instanceId', 'profileId']);
    freshAbsolutePath(input.finalProfile.bundleDirectory, 'fresh final replay bundleDirectory');
    hashIdentifier(input.finalProfile.profileId, 'fresh final replay profileId');
    hashIdentifier(input.finalProfile.instanceId, 'fresh final replay instanceId');
  }
  return input;
}
async function freshSetup(preProfile) {
  const [metadata, r1cs, verificationKey] = await Promise.all([
    pinnedFile(preProfile.setupMetadata, 'fresh setup metadata'),
    pinnedFile(preProfile.r1cs, 'fresh R1CS'),
    pinnedFile(preProfile.verificationKey, 'fresh verification key'),
  ]);
  const value = parseStrictJson(metadata.bytes, 'fresh setup metadata');
  exactKeys(value, 'fresh setup metadata', ['inputs', 'mode', 'outputs', 'schema', 'setup', 'toolchain']);
  if (value.schema !== 'shield.cash/local-development-setup/v1' || value.mode !== 'development-only') fail('fresh setup metadata must be a local development-only setup');
  exactKeys(value.inputs, 'fresh setup metadata inputs', ['ptau', 'r1cs']);
  exactKeys(value.inputs.r1cs, 'fresh setup metadata R1CS', ['nConstraints', 'nOutputs', 'nPublicInputs', 'requiredPower', 'sha256']);
  if (value.inputs.r1cs.nPublicInputs !== 2 || value.inputs.r1cs.nOutputs !== 0 || value.inputs.r1cs.sha256 !== `sha256:${r1cs.sha256}`) fail('fresh setup metadata does not bind the supplied two-public-input R1CS');
  exactKeys(value.outputs, 'fresh setup metadata outputs', ['provingKey', 'verificationKey']);
  exactKeys(value.outputs.verificationKey, 'fresh setup metadata verification key', ['path', 'sha256']);
  if (value.outputs.verificationKey.path !== 'verification_key.json' || value.outputs.verificationKey.sha256 !== `sha256:${verificationKey.sha256}`) fail('fresh setup metadata does not bind the supplied verification key');
  exactKeys(value.setup, 'fresh setup metadata setup', ['contributions', 'material', 'mode', 'provenance', 'transcript']);
  if (value.setup.mode !== 'development-only' || value.setup.provenance?.method !== 'local-initialization' || value.setup.transcript?.status !== 'not-applicable') fail('fresh setup metadata is not a local development-only setup');
  return { metadata, r1cs, verificationKey, value };
}
export async function deriveFreshDevelopmentActions(input, setup) {
  const actions = [];
  for (const [index, actionInput] of input.actions.entries()) {
    if (actionInput.verificationKey.sha256 !== setup.verificationKey.sha256) fail(`${actionInput.kind} action verification key does not match the pre-profile key`);
    const [packet, proof, publicSignals, verificationKey] = await Promise.all([
      pinnedFile(actionInput.packet, `${actionInput.kind} action packet`),
      pinnedFile(actionInput.proof, `${actionInput.kind} proof`),
      pinnedFile(actionInput.publicSignals, `${actionInput.kind} public signals`),
      pinnedFile(actionInput.verificationKey, `${actionInput.kind} verification key`),
    ]);
    if (packet.bytes.length !== ACTION_PACKET_BYTES) fail(`${actionInput.kind} action packet must be exactly ${ACTION_PACKET_BYTES} bytes`);
    let decoded;
    try { decoded = decodeActionPacket(packet.bytes); } catch (error) { fail(`${actionInput.kind} action packet is not canonical: ${error.message}`); }
    if (decoded.kind !== actionInput.kind) fail(`${actionInput.kind} action packet kind mismatch`);
    // This is the trusted raw snarkjs conversion, not caller-provided adapter
    // metadata. It rechecks canonical points, field elements, and source files.
    let adapterValue;
    try {
      adapterValue = await adaptSnarkjsGroth16({ proof: { path: proof.path, sha256: proof.sha256 }, publicSignals: { path: publicSignals.path, sha256: publicSignals.sha256 }, verificationKey: { path: verificationKey.path, sha256: verificationKey.sha256 } });
    } catch (error) { fail(`${actionInput.kind} trusted snarkjs adapter rejected input: ${error.message}`); }
    const limbs = actionPacketPublicLimbs(packet.bytes);
    if (adapterValue.verifierCashFixture.in0 !== limbs[0] || adapterValue.verifierCashFixture.in1 !== limbs[1]) fail(`${actionInput.kind} packet digest limbs do not match re-derived public inputs`);
    if (adapterValue.source.verificationKey.sha256 !== setup.verificationKey.sha256) fail(`${actionInput.kind} trusted adapter verification key drifted`);
    actions.push({ kind: ACTION_KINDS[index], packet, proof, publicSignals, verificationKey, adapterValue, publicLimbs: limbs });
  }
  if (new Set(actions.map((action) => action.verificationKey.sha256)).size !== 1) fail('fresh actions must use one exact verification key');
  return actions;
}
async function materializeFreshAdapters(actions, stage) {
  const directory = path.join(stage, 'derived-adapters'); await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const action of actions) {
    const bytes = Buffer.from(`${canonicalJson(action.adapterValue)}\n`);
    const filename = path.join(directory, `${action.kind}.json`);
    await writeFile(filename, bytes, { flag: 'wx', mode: 0o600 });
    action.adapter = { path: filename, bytes, sha256: digest(bytes) };
    validateAdapter(bytes); await validateAdapterSources(action.adapterValue);
  }
  return actions;
}
function freshActionRow(build) {
  return {
    kind: build.action.kind,
    rawInputs: {
      proofSha256: build.action.proof.sha256,
      publicSignalsSha256: build.action.publicSignals.sha256,
      verificationKeySha256: build.action.verificationKey.sha256,
      adapterSha256: build.action.adapter.sha256,
    },
    actionPacket: { sha256: build.action.packet.sha256, bytes: build.action.packet.bytes.length, publicLimbs: build.action.publicLimbs },
    contextSourceOutputsFile: {
      sha256: build.second.files['c7_candidate_srcouts.hex'].sha256,
      bytes: build.second.files['c7_candidate_srcouts.hex'].bytes.length,
      outputCount: 10,
      note: 'full verifier.cash context artifact; evidence dependency only, not seven-carrier authority',
    },
    measurements: {
      contextWireBytes: build.second.result.wire,
      allBytesScore: build.second.result.score,
      maxVerifierUnlockingBytes: Math.max(...build.second.result.manual.slice(0, 7).map((row) => row.unlockLen)),
      maxContextUnlockingBytes: Math.max(...build.second.result.manual.map((row) => row.unlockLen)),
      normalVerifierVm: '7/7', standardVerifierVm: '7/7', rawTerminalTamper: '18/18 reject', seamRedteam: '17/17 reject',
    },
    reports: { rawTerminalNormalizedSha256: sha256Canonical(normalizedRawAttackReport(build.second.attacks)), seamRedteamNormalizedSha256: sha256Canonical(build.seamRedteam) },
    dependencies: artifactDependencies(build.second.files),
  };
}
function freshVerifierScripts(scripts) {
  const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];
  if (!Array.isArray(scripts) || scripts.length !== names.length) fail('fresh verifier set must contain seven ordered scripts');
  return scripts.map((script, index) => {
    exactKeys(script, `fresh verifier set script ${index}`, ['lockingBytecodeHex', 'name', 'redeemBytecodeHex']);
    if (script.name !== names[index] || !/^[0-9a-f]+$/.test(script.lockingBytecodeHex) || !/^[0-9a-f]+$/.test(script.redeemBytecodeHex)) fail('fresh verifier set script is malformed');
    return { name: script.name, lockingBytecodeHex: script.lockingBytecodeHex, redeemBytecodeHex: script.redeemBytecodeHex };
  });
}

function readCanonicalCompactSize(encoded, offset, label) {
  if (offset >= encoded.length) fail(`${label} CompactSize is truncated`);
  const first = encoded[offset];
  if (first < 253) return { value: BigInt(first), next: offset + 1 };
  const width = first === 253 ? 2 : first === 254 ? 4 : 8;
  if (offset + 1 + width > encoded.length) fail(`${label} CompactSize is truncated`);
  let value;
  if (width === 2) value = BigInt(encoded.readUInt16LE(offset + 1));
  else if (width === 4) value = BigInt(encoded.readUInt32LE(offset + 1));
  else value = encoded.readBigUInt64LE(offset + 1);
  const minimum = width === 2 ? 253n : width === 4 ? 65536n : 4294967296n;
  if (value < minimum) fail(`${label} CompactSize is non-canonical`);
  return { value, next: offset + 1 + width };
}

function canonicalCompactSize(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('internal CompactSize value is invalid');
  if (value < 253) return Buffer.of(value);
  if (value <= 0xffff) { const bytes = Buffer.alloc(3); bytes[0] = 253; bytes.writeUInt16LE(value, 1); return bytes; }
  if (value <= 0xffffffff) { const bytes = Buffer.alloc(5); bytes[0] = 254; bytes.writeUInt32LE(value, 1); return bytes; }
  const bytes = Buffer.alloc(9); bytes[0] = 255; bytes.writeBigUInt64LE(BigInt(value), 1); return bytes;
}

/**
 * Decode the exact verifier.cash `c7_candidate_srcouts.hex` artifact without
 * importing a second transaction codec. Fresh seam builds have ten tokenless
 * context outputs: seven PF7 carriers followed by packet/state/fee context.
 * Only the first seven carrier output bytes are profile authority:
 *
 *   CompactSize(7) || rawOutput[0] || ... || rawOutput[6]
 *
 * The full ten-output file remains a separately pinned build dependency. This
 * prevents structural context from silently becoming verifier-carrier authority
 * while preserving exact build-artifact identity checks.
 */
export function bindPf7FreshCarrierSourcesFromContext(contextSourceOutputsHex, scripts) {
  const ordered = freshVerifierScripts(scripts);
  if (!(contextSourceOutputsHex instanceof Uint8Array)) fail('fresh verifier context source outputs must be the pinned hexadecimal file bytes');
  const fileBytes = Buffer.from(contextSourceOutputsHex);
  const text = fileBytes.toString('ascii');
  if (text.length === 0 || text.length % 2 !== 0 || !/^[0-9a-f]+$/.test(text)) {
    fail('fresh verifier context source outputs must be canonical lowercase hexadecimal without whitespace');
  }
  const encoded = Buffer.from(text, 'hex');
  const count = readCanonicalCompactSize(encoded, 0, 'fresh verifier context source-output count');
  if (count.value !== 10n) fail('fresh verifier context source outputs must contain exactly ten outputs');
  let offset = count.next;
  const rawOutputs = [];
  const outputs = [];
  for (let index = 0; index < 10; index += 1) {
    const start = offset;
    if (offset + 8 > encoded.length) fail(`fresh verifier context source output ${index} is truncated`);
    const valueSatoshis = encoded.readBigUInt64LE(offset);
    offset += 8;
    const payload = readCanonicalCompactSize(encoded, offset, `fresh verifier context source output ${index}`);
    if (payload.value > BigInt(encoded.length - payload.next)) fail(`fresh verifier context source output ${index} payload is truncated`);
    const payloadLength = Number(payload.value);
    const payloadBytes = encoded.subarray(payload.next, payload.next + payloadLength);
    if (payloadBytes[0] === 0xef) fail(`fresh verifier context source output ${index} must be tokenless`);
    offset = payload.next + payloadLength;
    rawOutputs.push(Buffer.from(encoded.subarray(start, offset)));
    outputs.push({ valueSatoshis, lockingBytecodeHex: payloadBytes.toString('hex') });
  }
  if (offset !== encoded.length) fail('fresh verifier context source outputs contain trailing bytes');
  const boundScripts = ordered.map((script, index) => {
    const output = outputs[index];
    if (output.valueSatoshis === 0n) fail(`fresh verifier carrier output ${index} value must be positive`);
    if (output.lockingBytecodeHex !== script.lockingBytecodeHex) fail(`fresh verifier carrier output ${index} does not match ordered verifier script`);
    return { ...script, sourceValueSatoshis: output.valueSatoshis.toString() };
  });
  const carrierSerialization = Buffer.concat([canonicalCompactSize(ordered.length), ...rawOutputs.slice(0, ordered.length)]);
  return Object.freeze({
    sourceSet: Object.freeze({
      encoding: 'libauth-transaction-outputs-v1',
      carrierCount: ordered.length,
      sha256: `sha256:${digest(carrierSerialization)}`,
    }),
    contextSourceOutputsFile: Object.freeze({
      encoding: 'verifier.cash-c7-candidate-srcouts-file-hex-v1',
      outputCount: 10,
      sha256: `sha256:${digest(fileBytes)}`,
      bytes: fileBytes.length,
    }),
    scripts: Object.freeze(boundScripts.map(Object.freeze)),
  });
}

/** Stable profile-import artifact. It deliberately excludes action proofs,
 * public signals, packets, full context source-output serializations, and replay metadata. */
export function derivePf7FreshVerifierSet({ verificationKeySha256, scripts, contextSourceOutputsHex }) {
  if (!HASH.test(verificationKeySha256)) fail('fresh verifier set verification key hash must be lowercase SHA-256');
  const carriers = bindPf7FreshCarrierSourcesFromContext(contextSourceOutputsHex, scripts);
  const artifact = {
    schema: 'shield.cash/bch-verifier-set/v1',
    qualification: 'development-only PF7 verifier material; not a complete shield.cash settlement, G2 artifact, node-relay result, Chipnet result, ceremony, profile, or release claim',
    candidate: { id: CANDIDATE, baseCommit: BASE, referenceTerminalCommit: REFERENCE_TERMINAL, referenceTerminalTree: REFERENCE_TREE, seamTerminalCommit: SEAM_TERMINAL, seamTerminalTree: SEAM_TREE, manifestSha256: CANDIDATE_SHA256, topologyInputs: 7, genericFallback: 'forbidden' },
    setup: { mode: 'development-only', verificationKeySha256: `sha256:${verificationKeySha256}` },
    sourceSet: carriers.sourceSet,
    scripts: carriers.scripts,
  };
  const serialized = `${canonicalJson(artifact)}\n`;
  return { artifact, serialized, sha256: digest(Buffer.from(serialized)), contextSourceOutputsFile: carriers.contextSourceOutputsFile };
}
export function validatePf7FreshFinalBundle(bundle, setup, expected) {
  object(bundle, 'fresh final replay bundle'); object(bundle.manifest, 'fresh final replay bundle manifest');
  if (bundle.manifest.setup?.mode !== 'development-only') fail('fresh final replay bundle setup mode does not match the local development pre-profile');
  if (bundle.manifest.profile?.constraintSystemHash !== `sha256:${setup.r1cs.sha256}`) fail('fresh final replay bundle R1CS does not match the pre-profile');
  if (!Array.isArray(bundle.manifest.artifacts)) fail('fresh final replay bundle artifacts are malformed');
  const verificationKeys = bundle.manifest.artifacts.filter((artifact) => artifact?.kind === 'verification-key');
  if (verificationKeys.length !== 1 || verificationKeys[0].sha256 !== `sha256:${setup.verificationKey.sha256}`) fail('fresh final replay bundle verification key does not match the pre-profile');
  const verifierSets = bundle.manifest.artifacts.filter((artifact) => artifact?.kind === 'bch-verifier-set');
  if (verifierSets.length !== 1 || verifierSets[0].sha256 !== `sha256:${expected.verifierSetSha256}` || bundle.manifest.profile?.bchVerifierSetHash !== `sha256:${expected.verifierSetSha256}`) fail('fresh final replay bundle verifier-set hash does not match expected stable verifier set');
  return verifierSets[0];
}
export function assertPf7FreshReplayAuthority(expected, observed) {
  exactKeys(expected, 'fresh replay expected authority', ['sourceSetSha256', 'verifierSetSha256']);
  exactKeys(observed, 'fresh replay observed authority', ['sourceSetSha256', 'verifierSetSha256']);
  if (expected.verifierSetSha256 !== observed.verifierSetSha256) fail('fresh final replay does not match caller-pinned stable verifier-set hash');
  if (expected.sourceSetSha256 !== observed.sourceSetSha256) fail('fresh final replay does not match caller-pinned source-set hash');
  return true;
}
export async function assertExactPf7FreshFinalVerifierSetArtifact(bundle, verifierSet, expected) {
  const artifact = validatePf7FreshFinalBundle(bundle, verifierSet.setup, expected);
  const filename = path.resolve(bundle.root, ...artifact.path.split('/'));
  const bytes = await readFile(filename);
  if (digest(bytes) !== expected.verifierSetSha256 || !bytes.equals(Buffer.from(verifierSet.serialized))) fail('fresh final replay bundle does not import the exact stable verifier-set artifact');
}

/**
 * Build a distinct, fresh local-development PF7 seam corpus. Discovery is
 * intentionally non-authoritative. Final replay only succeeds when a caller
 * pins the discovered seven-carrier source-set/verifier-set hashes and final bundle identity.
 */
export async function generatePf7FreshDevelopmentCorpus(input) {
  validatePf7FreshDevelopmentInput(input);
  const setup = await freshSetup(input.preProfile);
  const bundle = input.mode === 'final-replay'
    ? await loadVerifierProfileBundle(input.finalProfile.bundleDirectory, { network: 'chipnet', profileId: input.finalProfile.profileId, instanceId: input.finalProfile.instanceId })
    : undefined;
  if (bundle !== undefined) validatePf7FreshFinalBundle(bundle, setup, input.expected);
  const actions = await deriveFreshDevelopmentActions(input, setup);
  const { verifier, toolchain } = await prepareVerifier(input.verifier, { commit: SEAM_TERMINAL, tree: SEAM_TREE, label: 'seam', provenance: 'seam' });
  const { destination } = await reserveDestination(input.destination);
  const scratch = await regularAbsolute(input.scratchDirectory, 'fresh scratchDirectory', { directory: true });
  const stage = await mkdtemp(path.join(scratch.path, '.pf7-fresh-development-')); let reservation; let published = false;
  try {
    await materializeFreshAdapters(actions, stage);
    const builds = [];
    const identityStableFiles = ['result.json', 'inputs_dump.json', 'c7_candidate_srcouts.hex', 'c7_candidate_tx.hex', 'standardness.json'];
    for (const action of actions) {
      const first = await oneBuild(action.adapter, verifier, path.join(stage, action.kind, 'first'), action.packet);
      const second = await oneBuild(action.adapter, verifier, path.join(stage, action.kind, 'second'), action.packet);
      for (const name of identityStableFiles) if (first.files[name].sha256 !== second.files[name].sha256) fail(`${action.kind} fresh PF7 build is not identity-stable: ${name}`);
      if (canonicalJson(normalizedRawAttackReport(first.attacks)) !== canonicalJson(normalizedRawAttackReport(second.attacks))) fail(`${action.kind} fresh PF7 raw-attack report is not identity-stable`);
      assertSeamMeasured(first); assertSeamMeasured(second);
      if (second.result.packet.sha256 !== action.packet.sha256) fail(`${action.kind} fresh PF7 result did not bind the pinned packet`);
      builds.push({ action, first, second, directory: path.join(stage, action.kind, 'second', 'build') });
    }
    const scripts = extractVerifierSet(builds[0].second.inputs.slice(0, 7));
    const verifierSets = builds.map((build) => derivePf7FreshVerifierSet({
      verificationKeySha256: setup.verificationKey.sha256,
      scripts: extractVerifierSet(build.second.inputs.slice(0, 7)),
      contextSourceOutputsHex: build.second.files['c7_candidate_srcouts.hex'].bytes,
    }));
    const verifierSet = verifierSets[0];
    const sourceSetSha256 = verifierSet.artifact.sourceSet.sha256.slice('sha256:'.length);
    if (verifierSets.some((set) => set.artifact.sourceSet.sha256 !== verifierSet.artifact.sourceSet.sha256)) fail('fresh PF7 seven-carrier source set changes across actions');
    if (verifierSets.some((set) => set.sha256 !== verifierSet.sha256)) fail('fresh PF7 stable verifier set changes across actions');
    const sourceLocks = exactSourceLockHashes(builds[0].second.inputs).slice(0, 7); const sourceLockIdentity = canonicalJson(sourceLocks);
    for (const build of builds.slice(1)) if (canonicalJson(exactSourceLockHashes(build.second.inputs).slice(0, 7)) !== sourceLockIdentity) fail('fresh PF7 carrier locking bytecode changes across actions');
    if (input.mode === 'final-replay') assertPf7FreshReplayAuthority(input.expected, { sourceSetSha256, verifierSetSha256: verifierSet.sha256 });
    if (bundle !== undefined) await assertExactPf7FreshFinalVerifierSetArtifact(bundle, { ...verifierSet, setup }, input.expected);
    for (const build of builds) {
      const output = path.join(stage, `${build.action.kind}-seam-redteam.json`); const crosses = builds.filter((other) => other !== build);
      await run(path.join(verifier.checkout, 'harness/node_modules/.bin/tsx'), ['lanes/bn254-onetx/src/c7/run-shield-action-seam-redteam.ts', '--honest', build.directory, '--fixture', build.action.adapter.path, '--out', output, ...crosses.flatMap((other) => ['--cross', other.directory])], { cwd: verifier.checkout, env: exactEnvironment({ actionPacket: build.action.packet, adapter: build.action.adapter, stage: path.join(stage, 'redteam-environment'), verifier }) });
      const report = parseStrictJson(await readFile(output), `${build.action.kind} fresh PF7 seam redteam`); assertSeamRedteam(report); build.seamRedteam = normalizedSeamRedteamReport(report);
    }
    const artifact = {
      schema: 'shield.cash/pf7-fresh-development-corpus/v1',
      qualification: 'development-only verifier-role evidence; discovery is non-authoritative and is not a profile, G2 artifact, settlement, node-relay result, Chipnet result, ceremony, or release claim',
      candidate: { id: CANDIDATE, baseCommit: BASE, seamTerminalCommit: SEAM_TERMINAL, seamTerminalTree: SEAM_TREE, manifestSha256: CANDIDATE_SHA256, verifierInputs: 7, contextInputs: 10, genericFallback: 'forbidden' },
      limits: { contextWireTargetBytes: 59000, perInputUnlockingBytes: 10000, percentageHeadroomRequired: false },
      scope: { evaluatedRoles: ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'], unevaluatedStructuralRoles: ['packet', 'state', 'fee'], structuralRoleWarning: 'inputs 7 through 9 are present in transaction context but are not evaluated as settlement covenants', packetAbi: 'input7 exactly PUSHDATA2(752); terminal single-SHA256; genesis first push PUSHDATA2(480)=projection[448]||digest[32]' },
      reproducibility: { buildsPerAction: 2, identityStableFiles, fullContextSourceOutputFileIdentityCheckedPerAction: true, sevenCarrierAuthorityIdenticalAcrossActions: true, sourceLocksIdenticalAcrossActions: true },
      preProfile: { setupMetadataSha256: setup.metadata.sha256, r1csSha256: setup.r1cs.sha256, verificationKeySha256: setup.verificationKey.sha256, setupMode: 'development-only' },
      verifierSetSha256: verifierSet.sha256, sourceSetSha256, carrierSourceLocks: sourceLocks, scripts, toolchain, actions: builds.map(freshActionRow),
    };
    const serialized = `${canonicalJson(artifact)}\n`; const outputSha256 = digest(Buffer.from(serialized));
    await mkdir(destination, { mode: 0o700 }); reservation = await lstat(destination);
    const outputFiles = {};
    for (const build of builds) {
      for (const [suffix, body] of [['raw-terminal-attacks', normalizedRawAttackReport(build.second.attacks)], ['seam-redteam', build.seamRedteam]]) {
        const name = `${build.action.kind}-${suffix}.json`; const contents = `${canonicalJson(body)}\n`;
        await writeFile(path.join(destination, name), contents, { flag: 'wx', mode: 0o600 }); outputFiles[name] = { sha256: digest(Buffer.from(contents)), bytes: Buffer.byteLength(contents) };
      }
    }
    await writeFile(path.join(destination, 'bch-verifier-set.json'), verifierSet.serialized, { flag: 'wx', mode: 0o600 });
    outputFiles['bch-verifier-set.json'] = { sha256: verifierSet.sha256, bytes: Buffer.byteLength(verifierSet.serialized) };
    await writeFile(path.join(destination, 'pf7-fresh-development-corpus.json'), serialized, { flag: 'wx', mode: 0o600 });
    outputFiles['pf7-fresh-development-corpus.json'] = { sha256: outputSha256, bytes: Buffer.byteLength(serialized) };
    await writeFile(path.join(destination, 'manifest.json'), `${canonicalJson({ schema: 'shield.cash/pf7-fresh-development-output/v1', mode: input.mode, corpusSha256: outputSha256, verifierSetSha256: verifierSet.sha256, sourceSetSha256, ...(input.mode === 'final-replay' ? { finalProfile: input.finalProfile } : {}), files: outputFiles })}\n`, { flag: 'wx', mode: 0o600 });
    published = true; return { destination, sha256: outputSha256, verifierSetSha256: verifierSet.sha256, sourceSetSha256, artifact };
  } finally {
    await rm(stage, { recursive: true, force: true });
    if (!published && reservation !== undefined) {
      const current = await lstat(destination).catch(() => undefined);
      if (current?.isDirectory() && !current.isSymbolicLink() && current.dev === reservation.dev && current.ino === reservation.ino) await rm(destination, { recursive: true, force: true });
    }
  }
}
