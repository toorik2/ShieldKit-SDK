/* TEST-ONLY: fixture bundles must never cross the public verification boundary. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { V2Q01CommitBoundEvidenceError, parseV2Q01CommitBoundArguments, probeV2Q01SanitizedChildrenForTest, runV2Q01CommitBoundEvidence, runV2Q01CommitBoundEvidenceForTest, verifyV2Q01CommitBoundBundle, verifyV2Q01CommitBoundBundleForTest } from './v2-q01-commit-bound-evidence.mjs';
import { canonicalJson } from '../packages/profile/load.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const root = () => mkdtempSync(join(tmpdir(), 'shieldkit-q01-'));
const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const nodeEnvironment = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', NODE_V8_COVERAGE: '' });
const gitEnvironment = Object.freeze({ LANG: 'C', LC_ALL: 'C', TZ: 'UTC', PATH: '/usr/bin:/bin', NODE_V8_COVERAGE: '', GIT_CONFIG_COUNT: '0', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' });
const environmentPolicy = Object.freeze({ schema: 'shieldkit-v2-direct/q01-sanitized-child-environment/v1', inheritAmbient: false, node: nodeEnvironment, git: gitEnvironment, excludedControls: ['GIT_* ambient variables', 'NODE_OPTIONS', 'NODE_PATH', 'ambient NODE_V8_COVERAGE (pinned empty)', 'npm_config_*', 'loaders', 'preloads'] });
const runtime = () => Object.freeze({
  schema: 'shieldkit-v2-direct/q01-commit-bound-evidence/v1/runtime',
  node: { executable: process.execPath, executableSha256: hash('node'), version: process.version, platform: process.platform, arch: process.arch },
  git: { executable: '/usr/bin/git', executableSha256: hash('git'), version: 'git version 2.0.0' },
  environmentPolicy,
  packageMetadata: {
    packageJsonPath: 'package.json', packageJsonSha256: hash('package'), lockfilePath: 'package-lock.json',
    lockfileSha256: hash('lock'), lockfileVersion: 3, name: 'shieldkit', version: '0.2.0',
    declaredInstallCommand: ['npm', 'ci', '--include-workspace-root'],
    dependencyProvenance: 'package-and-lock-metadata-only; installed node_modules are not attested',
    installedNodeModulesAttested: false,
  },
});
const source = () => Object.freeze({ schema: 'shieldkit-v2-direct/q01-commit-bound-evidence/v1/source-set', sourceRoot: '/test/q01-source', gitCommit: 'a'.repeat(40), gitTree: 'b'.repeat(40), runtime: runtime(), files: ['03-create-your-own-pool/packages/action/v2/packet.mjs', '03-create-your-own-pool/packages/action/v2/state.mjs', '03-create-your-own-pool/packages/action/v2/strict-codec-qualification.mjs', '03-create-your-own-pool/packages/action/v2/vectors/q01-state-packet-public-input.json', '03-create-your-own-pool/packages/profile/load.mjs', '03-create-your-own-pool/scripts/v2-q01-commit-bound-evidence.mjs'].map((path, index) => ({ path, bytes: index + 1, sha256: hash(path) })), locks: [{ path: 'package-lock.json', bytes: 7, sha256: hash('lock') }], sourceSetSha256: '' });
function fixtureSource() { const value = structuredClone(source()); value.sourceSetSha256 = hash(Buffer.from(canonicalJson({ files: value.files, locks: value.locks }))); return value; }
function reseal(bundle, mutate) { const sourcePath = join(bundle, 'source-set.json'); const qualificationPath = join(bundle, 'qualification.json'); const executionPath = join(bundle, 'execution.json'); const sourceValue = JSON.parse(readFileSync(sourcePath)); const qualification = JSON.parse(readFileSync(qualificationPath)); const execution = JSON.parse(readFileSync(executionPath)); mutate({ source: sourceValue, qualification, execution }); qualification.sourceSetSha256 = sourceValue.sourceSetSha256; execution.sourceSetSha256 = sourceValue.sourceSetSha256; writeFileSync(sourcePath, canonicalJson(sourceValue)); writeFileSync(qualificationPath, canonicalJson(qualification)); writeFileSync(executionPath, canonicalJson(execution)); for (const path of [sourcePath, qualificationPath, executionPath]) chmodSync(path, 0o600); const artifacts = [['source-set', sourcePath], ['qualification', qualificationPath], ['execution', executionPath]].map(([role, path]) => { const bytes = readFileSync(path); return { role, path: path.split('/').at(-1), bytes: bytes.length, sha256: hash(bytes) }; }); const manifestPath = join(bundle, 'manifest.json'); writeFileSync(manifestPath, canonicalJson({ schema: 'shieldkit-v2-direct/q01-commit-bound-bundle/v1', localOnly: true, chainAuthenticated: false, finalQualification: false, artifacts })); chmodSync(manifestPath, 0o600); }

test('Q-01 public generator refuses an uncommitted or dirty source before it can execute the mutation campaign', async () => { const parent = root(); try { await assert.rejects(() => runV2Q01CommitBoundEvidence({ outputDirectory: parent }), /clean committed source checkout/u); } finally { rmSync(parent, { recursive: true, force: true }); } });
test('Q-01 fixture bundle is sealed, private, and publicly nonqualifying', async () => { const parent = root(); try { const result = await runV2Q01CommitBoundEvidenceForTest({ outputDirectory: parent, source: fixtureSource() }); assert.equal(result.status, 'verified-test-only-local'); assert.equal(lstatSync(result.bundlePath).mode & 0o777, 0o700); assert.equal(lstatSync(join(result.bundlePath, 'execution.json')).mode & 0o777, 0o600); assert.throws(() => verifyV2Q01CommitBoundBundle(result.bundlePath), /test-only/u); assert.equal(verifyV2Q01CommitBoundBundleForTest(result.bundlePath).status, 'verified-test-only-local'); writeFileSync(join(result.bundlePath, 'manifest.json'), '{}'); chmodSync(join(result.bundlePath, 'manifest.json'), 0o600); assert.throws(() => verifyV2Q01CommitBoundBundleForTest(result.bundlePath), V2Q01CommitBoundEvidenceError); } finally { rmSync(parent, { recursive: true, force: true }); } });
test('Q-01 public verifier rejects a self-resealed source-root substitution before replay', async () => { const parent = root(); try { const result = await runV2Q01CommitBoundEvidenceForTest({ outputDirectory: parent, source: fixtureSource() }); reseal(result.bundlePath, ({ qualification, execution }) => { qualification.testOnly = false; qualification.qualification = 'local-strict-codec-mutation-evidence-not-chain-or-final-qualification'; execution.testOnly = false; execution.command = { executable: process.execPath, argv: ['--input-type=module', '--eval', 'x'], cwd: '/test/q01-source', exitStatus: 0, stdoutSha256: hash('stdout'), stderrSha256: hash('stderr') }; }); assert.throws(() => verifyV2Q01CommitBoundBundle(result.bundlePath), /exact module source root/u); } finally { rmSync(parent, { recursive: true, force: true }); } });
test('Q-01 public verifier rejects a self-resealed runtime substitution before replay', async () => { const parent = root(); try { const result = await runV2Q01CommitBoundEvidenceForTest({ outputDirectory: parent, source: fixtureSource() }); reseal(result.bundlePath, ({ source: value, qualification, execution }) => { value.sourceRoot = moduleRoot; value.runtime.node.executableSha256 = hash('forged-node'); qualification.testOnly = false; qualification.qualification = 'local-strict-codec-mutation-evidence-not-chain-or-final-qualification'; execution.testOnly = false; execution.runtime = value.runtime; execution.command = { executable: process.execPath, argv: ['--input-type=module', '--eval', 'x'], cwd: moduleRoot, environment: nodeEnvironment, exitStatus: 0, stdoutSha256: hash('stdout'), stderrSha256: hash('stderr') }; }); assert.throws(() => verifyV2Q01CommitBoundBundle(result.bundlePath), /runtime identity differs/u); } finally { rmSync(parent, { recursive: true, force: true }); } });
test('Q-01 Git wrapper ignores ambient fake Git and Git repository/config controls', async () => {
  const parent = root(); const fakeGit = join(parent, 'git'); const marker = join(parent, 'fake-git-ran');
  const keys = ['PATH', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_EXEC_PATH', 'GIT_OBJECT_DIRECTORY', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0'];
  const prior = new Map(keys.map((key) => [key, Object.hasOwn(process.env, key) ? process.env[key] : undefined]));
  try {
    writeFileSync(fakeGit, `#!/bin/sh\n: > '${marker}'\nexit 99\n`); chmodSync(fakeGit, 0o700);
    Object.assign(process.env, { PATH: parent, GIT_DIR: join(parent, 'forged.git'), GIT_WORK_TREE: parent, GIT_EXEC_PATH: parent, GIT_OBJECT_DIRECTORY: parent, GIT_CONFIG_GLOBAL: fakeGit, GIT_CONFIG_SYSTEM: fakeGit, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'alias.status', GIT_CONFIG_VALUE_0: '!false' });
    await assert.rejects(() => runV2Q01CommitBoundEvidence({ outputDirectory: parent }), /clean committed source checkout/u);
    assert.equal(existsSync(marker), false);
  } finally {
    for (const [key, value] of prior) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(parent, { recursive: true, force: true });
  }
});
test('Q-01 Node wrapper excludes ambient options, paths, preload, coverage, and npm controls', () => {
  const keys = ['NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'npm_config_node_options', 'npm_config_prefix'];
  const prior = new Map(keys.map((key) => [key, Object.hasOwn(process.env, key) ? process.env[key] : undefined]));
  try {
    Object.assign(process.env, {
      NODE_OPTIONS: '--require=/definitely/not/a/q01-preload.cjs',
      NODE_PATH: '/definitely/not/a/q01-node-path',
      NODE_V8_COVERAGE: '/definitely/not/a/q01-coverage-directory',
      npm_config_node_options: '--experimental-loader=/definitely/not/a/q01-loader.mjs',
      npm_config_prefix: '/definitely/not/a/q01-prefix',
    });
    const probe = probeV2Q01SanitizedChildrenForTest();
    assert.equal(canonicalJson(probe.node), canonicalJson({ controls: [], environment: nodeEnvironment }));
    assert.equal(probe.git.executable, '/usr/bin/git');
    assert.equal(probe.environmentPolicy.inheritAmbient, false);
  } finally {
    for (const [key, value] of prior) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});
test('Q-01 command parsing and public seam boundary are exact', async () => { assert.throws(() => parseV2Q01CommitBoundArguments([]), V2Q01CommitBoundEvidenceError); assert.deepEqual(parseV2Q01CommitBoundArguments(['--verify', '/bundle'], '/cwd'), { mode: 'verify', bundlePath: '/bundle' }); await assert.rejects(() => runV2Q01CommitBoundEvidence({ outputDirectory: '/tmp', source: {} }), /accepts only outputDirectory/u); });
