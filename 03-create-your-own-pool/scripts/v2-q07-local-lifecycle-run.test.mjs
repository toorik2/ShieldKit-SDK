import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';
import {
  V2Q07LocalLifecycleError, parseQ07LocalLifecycleArguments,
  runQ07LocalLifecycle, runQ07LocalLifecycleForTest, snapshotQ07BuiltBinaryForTest,
  verifyQ07LocalLifecycleBundle,
} from './v2-q07-local-lifecycle-run.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
function command(root, args) { const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' }); if (result.status !== 0) throw new Error(result.stderr); }
function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'q07-local-run-source-')); const output = mkdtempSync(join(tmpdir(), 'q07-local-run-output-')); chmodSync(root, 0o700); chmodSync(output, 0o700);
  writeFileSync(join(root, 'package-lock.json'), '{"lockfileVersion":3}\n'); writeFileSync(join(root, 'Cargo.lock'), '# test\n'); writeFileSync(join(root, 'tracked.mjs'), 'export const fixture = true;\n');
  command(root, ['init', '--quiet']); command(root, ['config', 'user.email', 'test@example.invalid']); command(root, ['config', 'user.name', 'test']); command(root, ['add', '.']); command(root, ['commit', '--quiet', '-m', 'fixture']); t.after(() => { rmSync(root, { recursive: true, force: true }); rmSync(output, { recursive: true, force: true }); }); return { root, output };
}
function fakeExecutor({ corpusPath, actionCount, testOnly }) {
  assert.equal(testOnly, true, 'fake executor is permitted only through the test seam'); assert.equal(actionCount, 3);
  const corpus = Buffer.from('test-only Q07 lifecycle corpus\n'); writeFileSync(corpusPath, corpus, { mode: 0o600 }); chmodSync(corpusPath, 0o600); const fileSha256 = hash(corpus);
  const generator = { schema: 'test-only-q07-lifecycle-result/v1', actionCount: '3', fileSha256, bodySha256: hash('body'), terminalStateHex: '00', chainAuthenticated: false, q07Qualified: false, qualification: 'test-only-nonqualifying' };
  const js = { ...generator, actionTranscriptSha256: hash('transcript') };
  const rust = { schema: 'test-only-rust-q07-lifecycle-result/v1', actionCount: '3', q07LifecycleCorpusVerified: true, bodySha256: generator.bodySha256, actionTranscriptSha256: js.actionTranscriptSha256, terminalStateHex: generator.terminalStateHex, chainAuthenticated: false, q07Qualified: false };
  return Promise.resolve({ generator: Buffer.from(canonicalJson(generator)), js: Buffer.from(canonicalJson(js)), rust: Buffer.from(canonicalJson(rust)), wallMs: { generator: 1, jsVerifier: 1, rustVerifier: 1 }, commands: [{ command: 'fake-test-only-executor', args: [] }] });
}
function resealRole(bundlePath, role, value) {
  const manifestPath = join(bundlePath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const entry = manifest.artifacts.find((candidate) => candidate.role === role);
  assert.ok(entry, `missing ${role}`);
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  writeFileSync(join(bundlePath, entry.path), bytes);
  entry.bytes = bytes.length;
  entry.sha256 = hash(bytes);
  writeFileSync(manifestPath, canonicalJson(manifest));
}
function manifestReference(bundlePath, role) {
  const manifest = JSON.parse(readFileSync(join(bundlePath, 'manifest.json'), 'utf8'));
  const { role: _ignored, ...reference } = manifest.artifacts.find((candidate) => candidate.role === role);
  return reference;
}

test('Q07 local lifecycle test seam seals a self-verifying local-only bundle', async (t) => {
  const { root, output } = fixture(t); const result = await runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor });
  assert.equal(result.status, 'verified-local-only'); assert.equal(result.actionCount, '3'); assert.equal(result.testOnly, true); assert.equal(result.qualification, 'test-only-non-chain-local-run'); assert.equal(result.chainAuthenticated, false); assert.equal(result.q07Qualified, false);
  const manifest = JSON.parse(readFileSync(join(result.bundlePath, 'manifest.json'), 'utf8')); assert.equal(manifest.artifacts.length, 7); for (const entry of manifest.artifacts) assert.equal((readFileSync(join(result.bundlePath, entry.path)).length), entry.bytes);
});

test('Q07 local lifecycle verifier rejects tampering, symlinks, hardlinks, and extras', async (t) => {
  for (const kind of ['tamper', 'symlink', 'hardlink', 'extra']) { const { root, output } = fixture(t); const result = await runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor }); const target = join(result.bundlePath, 'generator-result.json'); if (kind === 'tamper') writeFileSync(target, '{}'); if (kind === 'symlink') { writeFileSync(join(result.bundlePath, 'plain'), 'x'); symlinkSync(join(result.bundlePath, 'plain'), join(result.bundlePath, 'linked')); } if (kind === 'hardlink') linkSync(target, join(result.bundlePath, 'linked')); if (kind === 'extra') writeFileSync(join(result.bundlePath, 'unreferenced'), 'x'); assert.throws(() => verifyQ07LocalLifecycleBundle(result.bundlePath), V2Q07LocalLifecycleError); }
});

test('public lifecycle runner is exact-100k only and clean-checkout gated', async (t) => {
  const { root, output } = fixture(t); let fake100kCalled = false; const fake100k = async () => { fake100kCalled = true; throw new Error('must not execute'); }; await assert.rejects(() => runQ07LocalLifecycle({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor }), /rejects injected actionCount/); await assert.rejects(() => runQ07LocalLifecycle({ sourceRoot: root, outputDirectory: output, executor: fake100k }), /rejects injected executor/); await assert.rejects(() => runQ07LocalLifecycle({ sourceRoot: root, outputDirectory: output, testOnly: false }), /rejects injected testOnly/); assert.equal(fake100kCalled, false, 'public 100k mode never accepts an injected fake executor'); writeFileSync(join(root, 'dirty'), 'x'); await assert.rejects(() => runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor }), /clean committed source checkout/);
});

test('Q07 local lifecycle rechecks source identity after an executor and binds run references', async (t) => {
  const { root, output } = fixture(t); const mutating = async (args) => { const result = await fakeExecutor(args); writeFileSync(join(root, 'tracked.mjs'), 'export const fixture = false;\n'); return result; }; await assert.rejects(() => runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: mutating }), /changed during local lifecycle run/);
});

test('Q07 verifier rejects self-resealed semantic forgeries', async (t) => {
  {
    const { root, output } = fixture(t);
    const result = await runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor });
    const source = JSON.parse(readFileSync(join(result.bundlePath, 'source-set.json'), 'utf8'));
    source.locks = [];
    resealRole(result.bundlePath, 'source-set', source);
    const run = JSON.parse(readFileSync(join(result.bundlePath, 'run.json'), 'utf8'));
    run.sourceSet = manifestReference(result.bundlePath, 'source-set');
    resealRole(result.bundlePath, 'run', run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(result.bundlePath), /source locks/);
  }
  {
    const { root, output } = fixture(t);
    const result = await runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor });
    const run = JSON.parse(readFileSync(join(result.bundlePath, 'run.json'), 'utf8'));
    run.qualification = 'non-chain-local-run-not-final-or-published-machine-qualification';
    resealRole(result.bundlePath, 'run', run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(result.bundlePath), /local-only identity/);
  }
  {
    const { root, output } = fixture(t);
    const result = await runQ07LocalLifecycleForTest({ sourceRoot: root, outputDirectory: output, actionCount: 3, executor: fakeExecutor });
    const corpusReference = manifestReference(result.bundlePath, 'corpus');
    const profileId = '11'.repeat(32);
    const terminalNoteRoot = '22'.repeat(32);
    const terminalNullifierRoot = '33'.repeat(32);
    const terminalStateHex = `${profileId}${terminalNoteRoot}${terminalNullifierRoot}${'00'.repeat(32)}`;
    const bodySha256 = hash('forged-body');
    const actionTranscriptSha256 = hash('forged-transcript');
    const generator = { schema: 'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus/v1', path: join(result.bundlePath, corpusReference.path), actionCount: '100000', fileSha256: corpusReference.sha256, bodySha256, terminalStateHex, chainAuthenticated: false, q07Qualified: false, qualification: 'non-chain-corpus-generated-not-q07-qualified' };
    const js = { ...generator, actionTranscriptSha256, qualification: 'non-chain-corpus-verified-not-q07-qualified' };
    const rust = { schema: 'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus-result/v1', status: 'verified', authority: 'non-chain-lifecycle-corpus', actionCount: '100000', actionCounts: { deposit: '1', transfer: '99998', withdrawal: '1' }, actionTranscriptSha256, bodySha256, chainAuthenticated: false, instanceId: '44'.repeat(32), profileId, q07LifecycleCorpusVerified: true, q07Qualified: false, terminalNoteRoot, terminalNullifierRoot, terminalStateHex, terminalStateSha256: hash(Buffer.from(terminalStateHex, 'hex')) };
    resealRole(result.bundlePath, 'generator-result', generator);
    resealRole(result.bundlePath, 'js-verifier-result', js);
    resealRole(result.bundlePath, 'rust-verifier-result', rust);
    const run = JSON.parse(readFileSync(join(result.bundlePath, 'run.json'), 'utf8'));
    run.actionCount = '100000';
    run.testOnly = false;
    run.qualification = 'non-chain-local-run-not-final-or-published-machine-qualification';
    run.generator = manifestReference(result.bundlePath, 'generator-result');
    run.jsVerifier = manifestReference(result.bundlePath, 'js-verifier-result');
    run.rustVerifier = manifestReference(result.bundlePath, 'rust-verifier-result');
    run.build = { status: 'forged-missing-build-provenance' };
    run.childCgroup = { available: true, controlGroup: '/forged', memoryAccounting: true, memoryPeakBytes: '1', source: 'systemd --user transient service MemoryPeak property after SubState=exited', unit: 'shieldkit-q07-1-1' };
    run.wallMs = { build: 1, generator: 1, jsVerifier: 1, rustVerifier: 1, total: 4 };
    resealRole(result.bundlePath, 'run', run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(result.bundlePath), /build provenance/);
  }
});

test('Q07 local lifecycle CLI parser does not expose a reduced action count', () => {
  assert.deepEqual(parseQ07LocalLifecycleArguments(['--output-directory', 'out'], '/tmp'), { mode: 'run', outputDirectory: '/tmp/out', sourceRoot: '/tmp' }); assert.throws(() => parseQ07LocalLifecycleArguments(['--output-directory', 'out', '--actions', '3']), /usage/);
});

test('Q07 release-binary snapshot accepts only a single file or Cargo deps hardlink pair', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'q07-binary-topology-'));
  const release = join(root, 'target', 'release');
  const deps = join(release, 'deps');
  mkdirSync(deps, { recursive: true });
  const binary = join(release, 'q07-lifecycle-verify');
  const cargoBinary = join(deps, 'q07_lifecycle_verify-deadbeef');
  writeFileSync(binary, 'binary');
  chmodSync(binary, 0o755);
  let snapshot = snapshotQ07BuiltBinaryForTest(binary);
  assert.deepEqual(snapshot.linkTopology, { linkCount: 1, cargoDepsPath: null });
  linkSync(binary, cargoBinary);
  snapshot = snapshotQ07BuiltBinaryForTest(binary);
  assert.deepEqual(snapshot.linkTopology, { linkCount: 2, cargoDepsPath: cargoBinary });
  linkSync(binary, join(root, 'unexpected-third-link'));
  assert.throws(() => snapshotQ07BuiltBinaryForTest(binary), /optional deps hardlink/);
  t.after(() => rmSync(root, { recursive: true, force: true }));
});
