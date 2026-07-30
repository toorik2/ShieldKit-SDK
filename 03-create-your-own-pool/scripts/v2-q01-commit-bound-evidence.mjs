#!/usr/bin/env node
/*
 * Q-01 is sealed local JavaScript codec-mutation evidence only. It has no BCH
 * VM, circuit, covenant, TypeScript, Rust, ceremony, signing, or final-release claim.
 */
import { createHash } from 'node:crypto';
import { chmodSync, closeSync, constants, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';

export const V2_Q01_COMMIT_BOUND_SCHEMA = 'shieldkit-v2-direct/q01-commit-bound-evidence/v1';
export const V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA = 'shieldkit-v2-direct/q01-commit-bound-bundle/v1';
const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
const SOURCE_PATHS = Object.freeze([
  '03-create-your-own-pool/packages/action/v2/packet.mjs',
  '03-create-your-own-pool/packages/action/v2/state.mjs',
  '03-create-your-own-pool/packages/action/v2/strict-codec-qualification.mjs',
  '03-create-your-own-pool/packages/action/v2/vectors/q01-state-packet-public-input.json',
  '03-create-your-own-pool/packages/profile/load.mjs',
  '03-create-your-own-pool/scripts/v2-q01-commit-bound-evidence.mjs',
]);
const LOCK_PATH = 'package-lock.json';
const INSTALL_COMMAND = Object.freeze(['npm', 'ci', '--include-workspace-root']);
// Node's child_process layer specially propagates ambient NODE_V8_COVERAGE
// unless the key is explicitly present. Pinning it empty prevents that bypass.
const NODE_ENVIRONMENT = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_V8_COVERAGE: '' });
const GIT_ENVIRONMENT = Object.freeze({
  LANG: 'C', LC_ALL: 'C', TZ: 'UTC', PATH: '/usr/bin:/bin', NODE_V8_COVERAGE: '',
  GIT_CONFIG_COUNT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
});
const ENVIRONMENT_POLICY = Object.freeze({
  schema: 'shieldkit-v2-direct/q01-sanitized-child-environment/v1',
  inheritAmbient: false,
  node: NODE_ENVIRONMENT,
  git: GIT_ENVIRONMENT,
  excludedControls: Object.freeze([
    'GIT_* ambient variables', 'NODE_OPTIONS', 'NODE_PATH', 'ambient NODE_V8_COVERAGE (pinned empty)',
    'npm_config_*', 'loaders', 'preloads',
  ]),
});
const TRUSTED_GIT_CANDIDATES = Object.freeze(['/usr/bin/git', '/bin/git']);
const RUNNER = [
  "import { canonicalJson } from './03-create-your-own-pool/packages/profile/load.mjs';",
  "import { runStrictCodecQualification } from './03-create-your-own-pool/packages/action/v2/strict-codec-qualification.mjs';",
  "import { actionPacketPublicLimbs, decodeActionPacket, digestActionPacket, encodeActionPacket } from './03-create-your-own-pool/packages/action/v2/packet.mjs';",
  "import { decodeStateNftCommitment, encodeStateNftCommitment } from './03-create-your-own-pool/packages/action/v2/state.mjs';",
  "const surface={name:'javascript',decodeState:decodeStateNftCommitment,encodeState:encodeStateNftCommitment,decodePacket:decodeActionPacket,encodePacket:encodeActionPacket,digestPacket:digestActionPacket,packetLimbs:actionPacketPublicLimbs};",
  'process.stdout.write(canonicalJson(runStrictCodecQualification(surface)));',
].join('');
const EXPECTED = Object.freeze({
  schema: 'shieldkit/v2-strict-codec-qualification/v1', surface: 'javascript',
  lengthsRejected: Object.freeze({ state: Object.freeze([127, 129]), packet: Object.freeze([551, 553]) }),
  categoryByteOrder: Object.freeze({ wireHex: '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f', explorerDisplayHex: '0ffeeddccbbaa9988776655443322110ffeeddccbbaa99887766554433221100' }),
  sha256BeU128: Object.freeze({ digestHex: 'ded42d09831ea2f39e521ce62b5faf474cf70946a76e934b6d6abe2280559a18', limbs: Object.freeze(['296190295460325907773963638825346379591', '102304013143187191688059162453337283096']) }),
  state: Object.freeze({ mutations: 32640, acceptedCanonicalDistinct: 24842, rejected: 7798 }),
  packet: Object.freeze({ mutations: 140760, acceptedCanonicalDistinct: 88727, rejected: 52033 }), publicInputVectors: 88727,
});
const QUALIFICATION = 'local-strict-codec-mutation-evidence-not-chain-or-final-qualification';
const BOUNDARIES = Object.freeze([
  'Q-01 is local JavaScript codec-mutation evidence only; it is not BCH VM or chain evidence.',
  'Q-01 does not establish circuit, covenant, TypeScript, Rust, proving, signing, ceremony, or cross-language equivalence.',
  'Q-01 is not a four-lane qualification: the circuit, covenant, TypeScript, and Rust lanes remain separately absent.',
  'Q-01 has no authenticated external signing authority and is not final qualification or a release authorization.',
]);
const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export class V2Q01CommitBoundEvidenceError extends Error { constructor(message) { super(message); this.name = 'V2Q01CommitBoundEvidenceError'; } }
const fail = (message) => { throw new V2Q01CommitBoundEvidenceError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sameJson = (left, right) => canonicalJson(left) === canonicalJson(right);
const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function exact(value, keys, label) { if (value === null || Array.isArray(value) || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(`${label} must be a plain object`); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`); return value; }
function directDirectory(path, label, create = false) { if (!isAbsolute(path) || resolve(path) !== path) fail(`${label} must be an absolute normalized path`); if (create) mkdirSync(path, { mode: 0o700 }); const stat = lstatSync(path); if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0700 directory`); return stat; }
function child(root, name, label) { if (typeof name !== 'string' || name.length === 0 || basename(name) !== name) fail(`${label} must be one direct filename`); const result = join(root, name); if (dirname(result) !== root) fail(`${label} escapes its bundle`); return result; }
function ownedFile(path, label) { const stat = lstatSync(path); if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0600 single-link file`); return stat; }
function writeFully(fd, bytes) { for (let offset = 0; offset < bytes.length;) { const count = writeSync(fd, bytes, offset, bytes.length - offset); if (count <= 0) fail('atomic write made no progress'); offset += count; } }
function writeAtomic(root, name, bytes) { const target = child(root, name, 'artifact'); if (existsSync(target)) fail(`refusing to overwrite ${target}`); const temporary = child(root, `.${name}.${process.pid}.${Date.now()}.tmp`, 'temporary artifact'); let fd; try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); chmodSync(temporary, 0o600); writeFully(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; ownedFile(temporary, 'temporary artifact'); renameSync(temporary, target); ownedFile(target, 'artifact'); return Object.freeze({ path: name, bytes: bytes.length, sha256: sha256(bytes) }); } finally { if (fd !== undefined) closeSync(fd); if (existsSync(temporary)) unlinkSync(temporary); } }
function fsyncDirectory(path) { const fd = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)); try { fsyncSync(fd); } finally { closeSync(fd); } }
function parseCanonical(bytes, label) { let value; try { value = parseStrictJson(bytes); } catch (error) { fail(`${label} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); } if (canonicalJson(value) !== text.decode(bytes)) fail(`${label} is not canonical JSON`); return value; }
function trustedGitExecutable() {
  for (const candidate of TRUSTED_GIT_CANDIDATES) {
    if (!existsSync(candidate)) continue;
    const executable = realpathSync(candidate); const stat = lstatSync(executable);
    if (!isAbsolute(executable) || resolve(executable) !== executable || stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o022) !== 0 || (typeof process.getuid === 'function' && stat.uid !== 0)) continue;
    return executable;
  }
  fail(`no trusted root-owned non-writable Git executable exists at: ${TRUSTED_GIT_CANDIDATES.join(', ')}`);
}
function runGit(root, args) {
  const executable = trustedGitExecutable();
  const result = spawnSync(executable, args, { cwd: root, env: GIT_ENVIRONMENT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0 || result.signal) fail(`${executable} ${args.join(' ')} failed: ${(result.stderr || result.error?.message || '').trim()}`);
  return result.stdout;
}
function gitToolRecord() {
  const executable = trustedGitExecutable();
  const version = runGit(moduleRoot, ['--version']).trim();
  if (!/^git version [0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[.A-Za-z0-9+-]*)$/u.test(version)) fail('trusted Git version output is invalid');
  return Object.freeze({ executable, executableSha256: sha256(readFileSync(executable)), version });
}
function git(root, args) { return runGit(root, args); }
function trackedFile(root, relative, label) { if (!SOURCE_PATHS.includes(relative) && ![LOCK_PATH, 'package.json'].includes(relative)) fail(`${label} is not an approved Q-01 source path`); git(root, ['ls-files', '--error-unmatch', '--', relative]); const path = resolve(root, relative); if (!path.startsWith(`${root}/`)) fail(`${label} escapes source root`); const stat = lstatSync(path); if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || realpathSync(path) !== path) fail(`${label} must be a direct single-link tracked file`); const bytes = readFileSync(path); return Object.freeze({ path: relative, bytes: bytes.length, sha256: sha256(bytes) }); }
function runtimeRecord(root) {
  const executable = realpathSync(process.execPath); const stat = lstatSync(executable);
  if (!isAbsolute(executable) || resolve(executable) !== executable || stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) fail('Node executable must be a direct absolute single-link file');
  const lock = trackedFile(root, LOCK_PATH, 'runtime lockfile'); const packageJson = trackedFile(root, 'package.json', 'package manifest');
  const manifest = parseStrictJson(readFileSync(resolve(root, 'package.json'))); const lockManifest = parseStrictJson(readFileSync(resolve(root, LOCK_PATH)));
  if (manifest?.scripts?.['install:deps'] !== 'npm ci --include-workspace-root' || typeof manifest.name !== 'string' || typeof manifest.version !== 'string' || !Number.isSafeInteger(lockManifest.lockfileVersion)) fail('package or lock metadata is invalid');
  return Object.freeze({
    schema: `${V2_Q01_COMMIT_BOUND_SCHEMA}/runtime`,
    node: Object.freeze({ executable, executableSha256: sha256(readFileSync(executable)), version: process.version, platform: process.platform, arch: process.arch }),
    git: gitToolRecord(),
    environmentPolicy: ENVIRONMENT_POLICY,
    packageMetadata: Object.freeze({
      packageJsonPath: 'package.json', packageJsonSha256: packageJson.sha256,
      lockfilePath: LOCK_PATH, lockfileSha256: lock.sha256, lockfileVersion: lockManifest.lockfileVersion,
      name: manifest.name, version: manifest.version, declaredInstallCommand: INSTALL_COMMAND,
      dependencyProvenance: 'package-and-lock-metadata-only; installed node_modules are not attested',
      installedNodeModulesAttested: false,
    }),
  });
}
function sourceSet(root = moduleRoot) { const sourceRoot = resolve(root); if (realpathSync(sourceRoot) !== sourceRoot) fail('source root must be a direct absolute checkout path'); if (git(sourceRoot, ['rev-parse', '--show-toplevel']).trim() !== sourceRoot) fail('source root must be the exact Git checkout root'); if (git(sourceRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') fail('real Q-01 evidence requires an exact clean committed source checkout'); const gitCommit = git(sourceRoot, ['rev-parse', 'HEAD']).trim(); const gitTree = git(sourceRoot, ['rev-parse', 'HEAD^{tree}']).trim(); if (!GIT.test(gitCommit) || !GIT.test(gitTree)) fail('Git commit/tree identity is invalid'); const files = SOURCE_PATHS.map((path) => trackedFile(sourceRoot, path, 'Q-01 source file')); const locks = [trackedFile(sourceRoot, LOCK_PATH, 'Q-01 lock file')]; const sourceSetSha256 = sha256(Buffer.from(canonicalJson({ files, locks }), 'utf8')); return Object.freeze({ schema: `${V2_Q01_COMMIT_BOUND_SCHEMA}/source-set`, sourceRoot, gitCommit, gitTree, runtime: runtimeRecord(sourceRoot), files, locks, sourceSetSha256 }); }
function recheckSource(source) { if (git(source.sourceRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== '' || git(source.sourceRoot, ['rev-parse', 'HEAD']).trim() !== source.gitCommit || git(source.sourceRoot, ['rev-parse', 'HEAD^{tree}']).trim() !== source.gitTree) fail('source checkout changed during Q-01 evidence generation or verification'); for (const entry of [...source.files, ...source.locks]) { const current = trackedFile(source.sourceRoot, entry.path, 'bound source file'); if (!sameJson(current, entry)) fail(`bound source file drifted: ${entry.path}`); } if (!sameJson(source.runtime, runtimeRecord(source.sourceRoot))) fail('bound runtime, lockfile, package-manager, or installation provenance drifted'); }
function expectedQualification(value, label) { exact(value, ['categoryByteOrder', 'lengthsRejected', 'packet', 'publicInputVectors', 'schema', 'sha256BeU128', 'state', 'surface'], label); if (!sameJson(value, EXPECTED)) fail(`${label} does not have the exact Q-01 mutation/count/vector coverage`); return value; }
function sourceRecord(value, label) { exact(value, ['files', 'gitCommit', 'gitTree', 'locks', 'runtime', 'schema', 'sourceRoot', 'sourceSetSha256'], label); if (value.schema !== `${V2_Q01_COMMIT_BOUND_SCHEMA}/source-set` || !isAbsolute(value.sourceRoot) || resolve(value.sourceRoot) !== value.sourceRoot || !GIT.test(value.gitCommit) || !GIT.test(value.gitTree)) fail(`${label} identity is invalid`); const check = (records, expectedPaths, recordLabel) => { if (!Array.isArray(records) || records.length !== expectedPaths.length) fail(`${recordLabel} count is invalid`); for (let index = 0; index < records.length; index += 1) { const entry = records[index]; exact(entry, ['bytes', 'path', 'sha256'], `${recordLabel}[${index}]`); if (entry.path !== expectedPaths[index] || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !HASH.test(entry.sha256)) fail(`${recordLabel}[${index}] is invalid`); } }; check(value.files, SOURCE_PATHS, `${label}.files`); check(value.locks, [LOCK_PATH], `${label}.locks`); runtime(value.runtime, `${label}.runtime`); if (!HASH.test(value.sourceSetSha256) || value.sourceSetSha256 !== sha256(Buffer.from(canonicalJson({ files: value.files, locks: value.locks }), 'utf8'))) fail(`${label} source-set digest is invalid`); return value; }
function runtime(value, label) {
  exact(value, ['environmentPolicy', 'git', 'node', 'packageMetadata', 'schema'], label);
  if (value.schema !== `${V2_Q01_COMMIT_BOUND_SCHEMA}/runtime` || !sameJson(value.environmentPolicy, ENVIRONMENT_POLICY)) fail(`${label} policy is invalid`);
  exact(value.node, ['arch', 'executable', 'executableSha256', 'platform', 'version'], `${label}.node`);
  if (!isAbsolute(value.node.executable) || resolve(value.node.executable) !== value.node.executable || !HASH.test(value.node.executableSha256) || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u.test(value.node.version) || typeof value.node.platform !== 'string' || typeof value.node.arch !== 'string') fail(`${label}.node is invalid`);
  exact(value.git, ['executable', 'executableSha256', 'version'], `${label}.git`);
  if (!isAbsolute(value.git.executable) || resolve(value.git.executable) !== value.git.executable || !HASH.test(value.git.executableSha256) || !/^git version /u.test(value.git.version)) fail(`${label}.git is invalid`);
  exact(value.packageMetadata, ['declaredInstallCommand', 'dependencyProvenance', 'installedNodeModulesAttested', 'lockfilePath', 'lockfileSha256', 'lockfileVersion', 'name', 'packageJsonPath', 'packageJsonSha256', 'version'], `${label}.packageMetadata`);
  if (value.packageMetadata.packageJsonPath !== 'package.json' || value.packageMetadata.lockfilePath !== LOCK_PATH || !HASH.test(value.packageMetadata.packageJsonSha256) || !HASH.test(value.packageMetadata.lockfileSha256) || !Number.isSafeInteger(value.packageMetadata.lockfileVersion) || value.packageMetadata.lockfileVersion < 1 || typeof value.packageMetadata.name !== 'string' || typeof value.packageMetadata.version !== 'string' || !sameJson(value.packageMetadata.declaredInstallCommand, INSTALL_COMMAND) || value.packageMetadata.dependencyProvenance !== 'package-and-lock-metadata-only; installed node_modules are not attested' || value.packageMetadata.installedNodeModulesAttested !== false) fail(`${label}.packageMetadata is invalid`);
  return value;
}
function artifactReference(root, entry, label) { exact(entry, ['bytes', 'path', 'role', 'sha256'], label); if (typeof entry.role !== 'string' || typeof entry.path !== 'string' || basename(entry.path) !== entry.path || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !HASH.test(entry.sha256)) fail(`${label} is invalid`); const path = child(root, entry.path, label); const stat = ownedFile(path, label); const bytes = readFileSync(path); if (stat.size !== entry.bytes || bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) fail(`${label} hash differs`); return Object.freeze({ ...entry, path, value: parseCanonical(bytes, label) }); }
function expectedCommand(source) { return Object.freeze({ executable: source.runtime.node.executable, argv: Object.freeze(['--input-type=module', '--eval', RUNNER]), cwd: source.sourceRoot, environment: NODE_ENVIRONMENT }); }
function runNode(executable, argv, cwd) { return spawnSync(executable, argv, { cwd, env: NODE_ENVIRONMENT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 }); }
function executeQualification(source) { const command = expectedCommand(source); const result = runNode(command.executable, command.argv, command.cwd); if (result.error || result.status !== 0 || result.signal) fail(`bound Q-01 qualification runner failed: ${(result.stderr || result.error?.message || '').trim()}`); const stdout = Buffer.from(result.stdout); const stderr = Buffer.from(result.stderr); const codec = parseCanonical(stdout, 'bound Q-01 qualification runner stdout'); expectedQualification(codec, 'bound Q-01 qualification runner'); return Object.freeze({ codec, command: Object.freeze({ ...command, exitStatus: 0, stdoutSha256: sha256(stdout), stderrSha256: sha256(stderr) }) }); }
function executionRecord(source, command, testOnly) { return Object.freeze({ schema: `${V2_Q01_COMMIT_BOUND_SCHEMA}/execution`, sourceSetSha256: source.sourceSetSha256, runtime: source.runtime, command, testOnly, boundaries: BOUNDARIES }); }
function qualificationRecord(source, codecEvidence, testOnly) { expectedQualification(codecEvidence, 'strict codec evidence'); return Object.freeze({ schema: V2_Q01_COMMIT_BOUND_SCHEMA, sourceSetSha256: source.sourceSetSha256, localOnly: true, chainAuthenticated: false, finalQualification: false, testOnly, qualification: testOnly ? 'test-only-local-codec-mutation-evidence' : QUALIFICATION, codec: codecEvidence }); }
function validateExecution(value, source, { publicVerification }) { exact(value, ['boundaries', 'command', 'runtime', 'schema', 'sourceSetSha256', 'testOnly'], 'execution evidence'); if (value.schema !== `${V2_Q01_COMMIT_BOUND_SCHEMA}/execution` || value.sourceSetSha256 !== source.sourceSetSha256 || typeof value.testOnly !== 'boolean' || !Array.isArray(value.boundaries) || !sameJson(value.boundaries, BOUNDARIES) || !sameJson(value.runtime, source.runtime)) fail('execution evidence boundary is invalid'); if (value.testOnly) { if (value.command !== null) fail('test-only execution evidence must not fabricate a command'); return value; } if (publicVerification && !sameJson(source.runtime, runtimeRecord(source.sourceRoot))) fail('runtime identity differs from this verifier runtime'); exact(value.command, ['argv', 'cwd', 'environment', 'executable', 'exitStatus', 'stderrSha256', 'stdoutSha256'], 'execution command'); const expected = expectedCommand(source); if (!sameJson({ executable: value.command.executable, argv: value.command.argv, cwd: value.command.cwd, environment: value.command.environment }, expected) || value.command.exitStatus !== 0 || !HASH.test(value.command.stdoutSha256) || !HASH.test(value.command.stderrSha256)) fail('execution command or controlled environment differs from the bound public Q-01 command'); return value; }
function verifyBundle(bundlePath, { verifySource = true, allowTestOnly = false, rerunQualification = true } = {}) { const root = resolve(bundlePath); directDirectory(root, 'bundle root'); const manifestPath = child(root, 'manifest.json', 'manifest'); ownedFile(manifestPath, 'manifest'); const manifest = parseCanonical(readFileSync(manifestPath), 'manifest'); exact(manifest, ['artifacts', 'chainAuthenticated', 'finalQualification', 'localOnly', 'schema'], 'manifest'); if (manifest.schema !== V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA || manifest.localOnly !== true || manifest.chainAuthenticated !== false || manifest.finalQualification !== false || !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 3) fail('manifest qualification boundary is invalid'); const names = new Set(['manifest.json']); const refs = new Map(); for (const entry of manifest.artifacts) { if (refs.has(entry.role) || names.has(entry.path)) fail('manifest has ambiguous artifact references'); refs.set(entry.role, artifactReference(root, entry, `artifact ${entry.role}`)); names.add(entry.path); } if (refs.size !== 3 || !refs.has('source-set') || !refs.has('qualification') || !refs.has('execution') || !sameJson(readdirSync(root).sort(), [...names].sort())) fail('bundle has missing or unreferenced artifacts'); const source = sourceRecord(refs.get('source-set').value, 'source set'); const evidence = refs.get('qualification').value; exact(evidence, ['chainAuthenticated', 'codec', 'finalQualification', 'localOnly', 'qualification', 'schema', 'sourceSetSha256', 'testOnly'], 'qualification evidence'); if (evidence.schema !== V2_Q01_COMMIT_BOUND_SCHEMA || evidence.sourceSetSha256 !== source.sourceSetSha256 || evidence.localOnly !== true || evidence.chainAuthenticated !== false || evidence.finalQualification !== false || typeof evidence.testOnly !== 'boolean' || evidence.qualification !== (evidence.testOnly ? 'test-only-local-codec-mutation-evidence' : QUALIFICATION)) fail('qualification evidence boundary is invalid'); if (evidence.testOnly && !allowTestOnly) fail('test-only Q-01 evidence is not accepted by the public verifier'); if (verifySource && !evidence.testOnly && source.sourceRoot !== moduleRoot) fail('public verifier only accepts evidence executed from this exact module source root'); const execution = validateExecution(refs.get('execution').value, source, { publicVerification: verifySource && !evidence.testOnly }); if (execution.testOnly !== evidence.testOnly) fail('execution and qualification test-only boundaries differ'); expectedQualification(evidence.codec, 'qualification codec evidence'); if (verifySource && !evidence.testOnly) { recheckSource(source); if (rerunQualification) { const rerun = executeQualification(source); if (!sameJson(rerun.codec, evidence.codec) || !sameJson(rerun.command, execution.command)) fail('bound Q-01 qualification execution does not reproduce the sealed evidence'); } } return Object.freeze({ schema: `${V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA}/verification`, bundlePath: root, status: evidence.testOnly ? 'verified-test-only-local' : 'verified-local-only', sourceSetSha256: source.sourceSetSha256, gitCommit: source.gitCommit, gitTree: source.gitTree, localOnly: true, chainAuthenticated: false, finalQualification: false, qualification: evidence.qualification, boundaries: BOUNDARIES }); }
function createBundle({ outputDirectory, source, codecEvidence, command, testOnly }) { const parent = resolve(outputDirectory); directDirectory(parent, 'output directory'); const root = join(parent, `q01-commit-bound-${Date.now()}-${process.pid}`); if (existsSync(root)) fail('refusing to overwrite Q-01 bundle'); directDirectory(root, 'bundle root', true); const sourceArtifact = writeAtomic(root, 'source-set.json', Buffer.from(canonicalJson(source), 'utf8')); const qualificationArtifact = writeAtomic(root, 'qualification.json', Buffer.from(canonicalJson(qualificationRecord(source, codecEvidence, testOnly)), 'utf8')); const executionArtifact = writeAtomic(root, 'execution.json', Buffer.from(canonicalJson(executionRecord(source, command, testOnly)), 'utf8')); const manifest = Object.freeze({ schema: V2_Q01_COMMIT_BOUND_MANIFEST_SCHEMA, localOnly: true, chainAuthenticated: false, finalQualification: false, artifacts: [Object.freeze({ role: 'source-set', ...sourceArtifact }), Object.freeze({ role: 'qualification', ...qualificationArtifact }), Object.freeze({ role: 'execution', ...executionArtifact })] }); writeAtomic(root, 'manifest.json', Buffer.from(canonicalJson(manifest), 'utf8')); fsyncDirectory(root); fsyncDirectory(parent); return verifyBundle(root, { verifySource: !testOnly, allowTestOnly: testOnly, rerunQualification: !testOnly }); }
export async function runV2Q01CommitBoundEvidence(options = {}) { if (options === null || Array.isArray(options) || typeof options !== 'object' || Object.keys(options).some((key) => key !== 'outputDirectory')) fail('public Q-01 generator accepts only outputDirectory and rejects injected source, runtime, or qualification seams'); const parent = resolve(options.outputDirectory); directDirectory(parent, 'output directory'); if (parent === moduleRoot || parent.startsWith(`${moduleRoot}/`)) fail('public Q-01 output directory must be outside the bound source checkout'); const source = sourceSet(moduleRoot); const execution = executeQualification(source); recheckSource(source); return createBundle({ outputDirectory: parent, source, codecEvidence: execution.codec, command: execution.command, testOnly: false }); }
/** TEST-ONLY: fixture source records never produce public Q-01 evidence. */
export async function runV2Q01CommitBoundEvidenceForTest({ outputDirectory, source, codecEvidence = EXPECTED } = {}) { const checked = sourceRecord(source, 'test source set'); expectedQualification(codecEvidence, 'test strict codec evidence'); return createBundle({ outputDirectory, source: checked, codecEvidence, command: null, testOnly: true }); }
/** TEST-ONLY: exercises the same absolute-tool and sanitized-child primitives without running the codec campaign. */
export function probeV2Q01SanitizedChildrenForTest() {
  const nodeExecutable = realpathSync(process.execPath);
  const probe = [
    'const controls=Object.keys(process.env).filter((key)=>',
    "/^(?:GIT_|NODE_|npm_config_)/u.test(key)&&process.env[key]!=='' ).sort();",
    'process.stdout.write(JSON.stringify({controls,environment:process.env}));',
  ].join('');
  const result = runNode(nodeExecutable, ['--input-type=module', '--eval', probe], moduleRoot);
  if (result.error || result.status !== 0 || result.signal) fail(`sanitized Node probe failed: ${(result.stderr || result.error?.message || '').trim()}`);
  const node = parseStrictJson(Buffer.from(result.stdout));
  if (!sameJson(node, { controls: [], environment: NODE_ENVIRONMENT })) fail('sanitized Node probe inherited an ambient control or unexpected environment variable');
  return Object.freeze({ git: gitToolRecord(), node, environmentPolicy: ENVIRONMENT_POLICY });
}
export function verifyV2Q01CommitBoundBundle(bundlePath) { return verifyBundle(bundlePath); }
/** TEST-ONLY: validates a visibly non-public fixture seal without a live checkout. */
export function verifyV2Q01CommitBoundBundleForTest(bundlePath) { return verifyBundle(bundlePath, { verifySource: false, allowTestOnly: true, rerunQualification: false }); }
export function parseV2Q01CommitBoundArguments(argv, cwd = process.cwd()) { if (!Array.isArray(argv) || argv.length !== 2 || !['--output-directory', '--verify'].includes(argv[0]) || typeof argv[1] !== 'string' || argv[1].startsWith('--')) fail('usage: v2-q01-commit-bound-evidence.mjs --output-directory <existing-mode-0700-directory> | --verify <bundle>'); return Object.freeze(argv[0] === '--verify' ? { mode: 'verify', bundlePath: resolve(cwd, argv[1]) } : { mode: 'run', outputDirectory: resolve(cwd, argv[1]) }); }
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) { try { const args = parseV2Q01CommitBoundArguments(process.argv.slice(2)); const result = args.mode === 'verify' ? verifyV2Q01CommitBoundBundle(args.bundlePath) : await runV2Q01CommitBoundEvidence(args); process.stdout.write(`${canonicalJson(result)}\n`); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; } }
