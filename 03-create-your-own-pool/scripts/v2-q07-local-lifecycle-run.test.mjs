import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';
import { encodeStateNftCommitment } from '../packages/action/v2/state.mjs';
import {
  V2_Q07_PRESERVED_ORIGIN_PINS,
  V2Q07LocalLifecycleError, inspectQ07UserSystemdForTest, parseQ07LocalLifecycleArguments,
  assertQ07ResumeRustSnapshotForTest, captureQ07BuiltBinaryForTest,
  q07ResumeBuildCommandForTest, q07ResumeRustSystemdArgsForTest,
  resumeQ07LocalLifecycle, resumeQ07LocalLifecycleForTest,
  runQ07LocalLifecycle, runQ07LocalLifecycleForTest, snapshotQ07BuiltBinaryForTest,
  runQ07SystemdSmokeForTest, snapshotQ07ExecutableForTest, verifyQ07LocalLifecycleBundle,
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

function resealResumeArtifact(bundlePath, path, value) {
  const manifestPath = join(bundlePath, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const entry = manifest.artifacts.find((candidate) => candidate.path === path);
  assert.ok(entry, `missing v2 resume artifact ${path}`);
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  writeFileSync(join(bundlePath, path), bytes, { mode: 0o600 });
  chmodSync(join(bundlePath, path), 0o600);
  entry.bytes = bytes.length;
  entry.sha256 = hash(bytes);
  writeFileSync(manifestPath, canonicalJson(manifest), { mode: 0o600 });
  chmodSync(manifestPath, 0o600);
}

const testRunnerPins = Object.freeze({
  gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40), runnerSha256: '3'.repeat(64),
});

test('Q07 preserved origin pins distinguish the source-set artifact from its tracked-files digest', () => {
  assert.equal(
    V2_Q07_PRESERVED_ORIGIN_PINS.source.sourceSetArtifactSha256,
    '70c2db593c0a46c56a6ec1181900840f25503f251f330a3b86910ac92a254cc8',
  );
  assert.equal(
    V2_Q07_PRESERVED_ORIGIN_PINS.source.sourceSetSha256,
    'd73b81c7769da928712ec721a90e085d602e171bce8fe427599c0894be4ad895',
  );
  assert.notEqual(
    V2_Q07_PRESERVED_ORIGIN_PINS.source.sourceSetArtifactSha256,
    V2_Q07_PRESERVED_ORIGIN_PINS.source.sourceSetSha256,
  );
});

async function interruptedPartial(t) {
  const { root, output } = fixture(t);
  const complete = await runQ07LocalLifecycleForTest({
    sourceRoot: root,
    outputDirectory: output,
    actionCount: 3,
    executor: fakeExecutor,
  });
  for (const name of [
    'manifest.json',
    'generator-result.json',
    'js-verifier-result.json',
    'rust-verifier-result.json',
    'run.json',
  ]) unlinkSync(join(complete.bundlePath, name));
  return Object.freeze({ root, output, bundlePath: complete.bundlePath });
}

const resumeTerminalStateHex = encodeStateNftCommitment({
  profileId: '11'.repeat(32),
  noteRoot: '01'.repeat(32),
  nullifierRoot: '02'.repeat(32),
  noteCount: '2',
  nullifierCount: '2',
  maximumLiveNotes: '32',
  reserveSats: '0',
  actionSequence: '3',
}, { denominationSats: '10000000' }).toString('hex');

function mockedSystemdEvidence() {
  const invocationId = 'ab'.repeat(16);
  const controlGroup = '/user.slice/user-1000.slice/mock-q07.service';
  return Object.freeze({
    available: true,
    unit: 'shieldkit-q07-resume-123-0123456789abcdef',
    running: Object.freeze({
      activeState: 'active',
      subState: 'running',
      controlGroup,
      invocationId,
    }),
    exited: Object.freeze({
      activeState: 'active',
      subState: 'exited',
      controlGroup: '',
      invocationId,
      result: 'success',
      execMainCode: 'exited',
      execMainCodeRaw: '1',
      execMainStatus: '0',
      memoryAccounting: true,
      memoryPeakBytes: '4096',
    }),
    launcherStdoutSha256: hash('mock systemd launcher stdout'),
    launcherStderrSha256: hash(''),
    source: 'systemd --user transient service observed while running and after successful exit',
  });
}

function resumeResults(corpusPath) {
  const corpusSha = hash(readFileSync(corpusPath));
  const js = Object.freeze({
    schema: 'test-only-q07-lifecycle-result/v1',
    actionCount: '3',
    fileSha256: corpusSha,
    bodySha256: hash('resume-body'),
    terminalStateHex: resumeTerminalStateHex,
    actionTranscriptSha256: hash('resume-transcript'),
    chainAuthenticated: false,
    q07Qualified: false,
    qualification: 'test-only-nonqualifying',
  });
  const rust = Object.freeze({
    schema: 'test-only-rust-q07-lifecycle-result/v1',
    actionCount: '3',
    q07LifecycleCorpusVerified: true,
    bodySha256: js.bodySha256,
    actionTranscriptSha256: js.actionTranscriptSha256,
    terminalStateHex: js.terminalStateHex,
    chainAuthenticated: false,
    q07Qualified: false,
  });
  return Object.freeze({ js, rust });
}

function mockedResumeExecutor(calls, { failRust = false } = {}) {
  const capture = (phase, stdout, overrides = {}) => {
    calls.push(phase);
    return Promise.resolve({
      stdout,
      stderr: Buffer.alloc(0),
      exitCode: 0,
      signal: null,
      wallMs: 2,
      command: { command: `mock-${phase}`, args: [] },
      binary: null,
      systemd: null,
      failure: null,
      ...overrides,
    });
  };
  return Object.freeze({
    build() {
      return capture('build', Buffer.from('mock pinned Rust build stdout\n'));
    },
    jsVerifier({ corpusPath }) {
      return capture('js-verifier', Buffer.from(`${canonicalJson(resumeResults(corpusPath).js)}\n`));
    },
    rustVerifier({ corpusPath }) {
      if (failRust) {
        return capture('rust-verifier', Buffer.alloc(0), {
          stderr: Buffer.from('injected Rust interruption\n'),
          exitCode: 1,
          failure: 'injected Rust interruption',
        });
      }
      return capture('rust-verifier', Buffer.from(`${canonicalJson(resumeResults(corpusPath).rust)}\n`), {
        systemd: mockedSystemdEvidence(),
      });
    },
  });
}

function corpusIdentity(path) {
  const stat = lstatSync(path, { bigint: true });
  return Object.freeze({
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    size: stat.size.toString(),
    mtimeNs: stat.mtimeNs.toString(),
    ctimeNs: stat.ctimeNs.toString(),
    sha256: hash(readFileSync(path)),
  });
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
  assert.deepEqual(parseQ07LocalLifecycleArguments(['--output-directory', 'out'], '/tmp'), { mode: 'run', outputDirectory: '/tmp/out', sourceRoot: '/tmp' });
  assert.deepEqual(parseQ07LocalLifecycleArguments([
    '--resume', 'partial', '--runner-git-commit', '1'.repeat(40), '--runner-git-tree', '2'.repeat(40), '--runner-file-sha256', '3'.repeat(64),
  ], '/tmp'), {
    mode: 'resume', bundlePath: '/tmp/partial',
    runnerGitCommit: testRunnerPins.gitCommit, runnerGitTree: testRunnerPins.gitTree,
    runnerSha256: testRunnerPins.runnerSha256,
  });
  assert.throws(() => parseQ07LocalLifecycleArguments(['--resume', 'partial'], '/tmp'), /usage/);
  assert.throws(() => parseQ07LocalLifecycleArguments(['--output-directory', 'out', '--actions', '3']), /usage/);
});

test('Q07 v2 resume preserves the corpus and reuses only validated completed phases', async (t) => {
  const partial = await interruptedPartial(t);
  const corpusPath = join(partial.bundlePath, 'q07-non-chain-lifecycle.ndjson');
  const before = corpusIdentity(corpusPath);
  const firstCalls = [];
  await assert.rejects(
    () => resumeQ07LocalLifecycleForTest({
      bundlePath: partial.bundlePath,
      actionCount: 3,
      executor: mockedResumeExecutor(firstCalls, { failRust: true }),
    }),
    /rust-verifier resume phase failed/,
  );
  assert.deepEqual(firstCalls, ['build', 'js-verifier', 'rust-verifier']);
  assert.deepEqual(corpusIdentity(corpusPath), before, 'failed resume preserves corpus inode, size, timestamps, and hash');
  const firstArtifacts = readdirSync(partial.bundlePath);
  assert.ok(firstArtifacts.some((name) => name.endsWith('-rust-verifier.stdout')));
  assert.ok(firstArtifacts.some((name) => name.endsWith('-rust-verifier.stderr')));
  assert.ok(firstArtifacts.some((name) => name.endsWith('-rust-verifier.receipt.json')));

  const secondCalls = [];
  const result = await resumeQ07LocalLifecycleForTest({
    bundlePath: partial.bundlePath,
    actionCount: 3,
    executor: mockedResumeExecutor(secondCalls),
  });
  assert.deepEqual(secondCalls, ['rust-verifier'], 'validated build and JS receipts are reused; failed Rust is rerun');
  assert.deepEqual(corpusIdentity(corpusPath), before, 'successful resume preserves corpus inode, size, timestamps, and hash');
  assert.equal(result.status, 'verified-resumed-local-only');
  assert.equal(result.chainAuthenticated, false);
  assert.equal(result.q07Qualified, false);
  assert.equal(result.testOnly, true);

  const manifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
  assert.equal(manifest.schema, 'shieldkit-v2-direct/q07-local-lifecycle-bundle/v2');
  const runEntry = manifest.artifacts.find((entry) => entry.role === 'run');
  const run = JSON.parse(readFileSync(join(partial.bundlePath, runEntry.path), 'utf8'));
  assert.equal(run.interruptedOrigin.generatorResult, null);
  assert.equal(run.interruptedOrigin.generatorWallMs, null);
  assert.equal(run.interruptedOrigin.originalJsVerifierWallMs, null);
  assert.equal(run.interruptedOrigin.originalRustVerifierWallMs, null);
  assert.equal(run.interruptedOrigin.originalTotalWallMs, null);
  assert.equal(run.wallMs.total, null);
  assert.equal(run.wallMs.generator, null);
  assert.notEqual(run.resumePhases.build.reusedFromAttemptId, null);
  assert.notEqual(run.resumePhases.jsVerifier.reusedFromAttemptId, null);
  assert.equal(run.resumePhases.rustVerifier.reusedFromAttemptId, null);

  const thirdCalls = [];
  const repeated = await resumeQ07LocalLifecycleForTest({
    bundlePath: partial.bundlePath,
    actionCount: 3,
    executor: mockedResumeExecutor(thirdCalls),
  });
  assert.equal(repeated.status, 'verified-resumed-local-only');
  assert.deepEqual(thirdCalls, [], 'a sealed valid v2 bundle is idempotently verified without rerunning phases');
  await assert.rejects(
    () => resumeQ07LocalLifecycle({ bundlePath: partial.bundlePath }),
    /incompatible with the requested resume mode/,
    'the public exact-100k path cannot accept a sealed test-only bundle',
  );
});

test('Q07 v2 resume fails closed on source drift and rejects sealed bundle drift or extras', async (t) => {
  {
    const partial = await interruptedPartial(t);
    writeFileSync(join(partial.root, 'tracked.mjs'), 'export const fixture = false;\n');
    const calls = [];
    await assert.rejects(
      () => resumeQ07LocalLifecycleForTest({
        bundlePath: partial.bundlePath,
        actionCount: 3,
        executor: mockedResumeExecutor(calls),
      }),
      /clean committed source checkout/,
    );
    assert.deepEqual(calls, []);
  }
  {
    const partial = await interruptedPartial(t);
    await resumeQ07LocalLifecycleForTest({
      bundlePath: partial.bundlePath,
      actionCount: 3,
      executor: mockedResumeExecutor([]),
    });
    const extra = join(partial.bundlePath, 'unreferenced');
    writeFileSync(extra, 'x', { mode: 0o600 });
    chmodSync(extra, 0o600);
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /unreferenced/);
    unlinkSync(extra);
    writeFileSync(join(partial.bundlePath, 'q07-non-chain-lifecycle.ndjson'), 'drift\n', { mode: 0o600 });
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /drifted|hash|corpus/);
  }
});

test('public Q07 v2 resume exposes no injected executor or reduced action count', async (t) => {
  const partial = await interruptedPartial(t);
  await assert.rejects(
    () => resumeQ07LocalLifecycle({ bundlePath: partial.bundlePath, actionCount: 3 }),
    /rejects injected actionCount/,
  );
  await assert.rejects(
    () => resumeQ07LocalLifecycle({ bundlePath: partial.bundlePath, executor: mockedResumeExecutor([]) }),
    /rejects injected executor/,
  );
});

test('Q07 v2 resume rejects self-resealed origin, runner, binary, lease, and label substitutions', async (t) => {
  const seal = async () => {
    const partial = await interruptedPartial(t);
    await resumeQ07LocalLifecycleForTest({
      bundlePath: partial.bundlePath, actionCount: 3, executor: mockedResumeExecutor([]), orchestrationPins: testRunnerPins,
    });
    return partial;
  };
  {
    const partial = await seal();
    const manifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const runPath = manifest.artifacts.find((entry) => entry.role === 'run').path;
    const run = JSON.parse(readFileSync(join(partial.bundlePath, runPath), 'utf8'));
    run.interruptedOrigin.originPins.corpus.sha256 = 'f'.repeat(64);
    resealResumeArtifact(partial.bundlePath, runPath, run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /origin pins/);
  }
  {
    const partial = await seal();
    const manifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const runPath = manifest.artifacts.find((entry) => entry.role === 'run').path;
    const run = JSON.parse(readFileSync(join(partial.bundlePath, runPath), 'utf8'));
    run.orchestrationPins.runnerSha256 = 'e'.repeat(64);
    resealResumeArtifact(partial.bundlePath, runPath, run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /runner pins/);
  }
  {
    const partial = await seal();
    const manifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const receiptPath = manifest.artifacts.find((entry) => entry.path.endsWith('-build.receipt.json')).path;
    const receipt = JSON.parse(readFileSync(join(partial.bundlePath, receiptPath), 'utf8'));
    receipt.binary = { path: '/substituted-binary', bytes: 1, sha256: 'd'.repeat(64) };
    resealResumeArtifact(partial.bundlePath, receiptPath, receipt);
    const refreshedManifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const runPath = refreshedManifest.artifacts.find((entry) => entry.role === 'run').path;
    const run = JSON.parse(readFileSync(join(partial.bundlePath, runPath), 'utf8'));
    const { role: _ignored, ...reference } = refreshedManifest.artifacts.find((entry) => entry.path === receiptPath);
    run.resumePhases.build.receipt = reference;
    resealResumeArtifact(partial.bundlePath, runPath, run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /test-only build receipt/);
  }
  {
    const partial = await seal();
    const manifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const receiptPath = manifest.artifacts.find((entry) => entry.path.endsWith('-js-verifier.receipt.json')).path;
    const receipt = JSON.parse(readFileSync(join(partial.bundlePath, receiptPath), 'utf8'));
    receipt.releaseQualified = true;
    resealResumeArtifact(partial.bundlePath, receiptPath, receipt);
    const refreshedManifest = JSON.parse(readFileSync(join(partial.bundlePath, 'manifest.json'), 'utf8'));
    const runPath = refreshedManifest.artifacts.find((entry) => entry.role === 'run').path;
    const run = JSON.parse(readFileSync(join(partial.bundlePath, runPath), 'utf8'));
    const { role: _ignored, ...reference } = refreshedManifest.artifacts.find((entry) => entry.path === receiptPath);
    run.resumePhases.jsVerifier.receipt = reference;
    resealResumeArtifact(partial.bundlePath, runPath, run);
    assert.throws(() => verifyQ07LocalLifecycleBundle(partial.bundlePath), /explicitly local-only/);
  }
  {
    const partial = await interruptedPartial(t);
    const calls = [];
    const nested = mockedResumeExecutor(calls);
    const executor = {
      ...nested,
      async build(args) {
        await assert.rejects(
          () => resumeQ07LocalLifecycleForTest({
            bundlePath: partial.bundlePath, actionCount: 3, executor: mockedResumeExecutor([]), orchestrationPins: testRunnerPins,
          }),
          /exclusive resume lease/,
        );
        return nested.build(args);
      },
    };
    await resumeQ07LocalLifecycleForTest({
      bundlePath: partial.bundlePath, actionCount: 3, executor, orchestrationPins: testRunnerPins,
    });
    assert.deepEqual(calls, ['build', 'js-verifier', 'rust-verifier']);
  }
});

test('Q07 mandatory user-systemd observer captures running and exited identity', async (t) => {
  const availability = await inspectQ07UserSystemdForTest();
  assert.equal(
    availability.available,
    true,
    `mandatory Q07 user-systemd observer is unavailable: ${availability.reason}`,
  );
  const root = mkdtempSync(join(tmpdir(), 'q07-systemd-smoke-'));
  chmodSync(root, 0o700);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const result = await runQ07SystemdSmokeForTest({ directory: root });
  assert.match(result.stdout, /q07-systemd-smoke/);
  assert.match(result.systemd.running.controlGroup, /^\//u);
  assert.match(result.systemd.running.invocationId, /^[0-9a-f]{32}$/u);
  assert.equal(result.systemd.exited.invocationId, result.systemd.running.invocationId);
  assert.equal(result.systemd.exited.result, 'success');
  assert.equal(result.systemd.exited.execMainCode, 'exited');
  assert.equal(result.systemd.exited.execMainStatus, '0');
  assert.match(result.systemd.exited.memoryPeakBytes, /^(?:0|[1-9][0-9]*)$/u);
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

test('Q07 resume snapshots a newly built binary and binds systemd to that immutable artifact', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'q07-resume-build-snapshot-'));
  const bundle = join(root, 'bundle');
  const target = join(root, '03-create-your-own-pool', 'crates', 'shieldkit-v2-recovery', 'target', 'release', 'q07-lifecycle-verify');
  mkdirSync(bundle, { mode: 0o700 });
  mkdirSync(join(root, '03-create-your-own-pool', 'crates', 'shieldkit-v2-recovery', 'target', 'release'), { recursive: true });
  chmodSync(bundle, 0o700);
  const attemptId = `1-${'c'.repeat(32)}`;
  assert.throws(
    () => captureQ07BuiltBinaryForTest({ sourceRoot: root, bundleRoot: bundle, attemptId }),
    /ENOENT/,
    'the snapshot is deliberately captured after a successful build, not before one',
  );
  const built = Buffer.from('newly-built-q07-verifier');
  writeFileSync(target, built, { mode: 0o755 });
  chmodSync(target, 0o755);
  const captured = captureQ07BuiltBinaryForTest({ sourceRoot: root, bundleRoot: bundle, attemptId });
  const snapshotPath = join(bundle, captured.snapshot.path);
  assert.equal(captured.sourceTarget.sha256, hash(built));
  assert.equal(captured.snapshot.sha256, hash(built));
  assert.equal(captured.snapshot.mode, '0700');
  assert.equal(readFileSync(snapshotPath).toString('utf8'), 'newly-built-q07-verifier');

  writeFileSync(target, 'substituted-target', { mode: 0o755 });
  chmodSync(target, 0o755);
  assert.equal(readFileSync(snapshotPath).toString('utf8'), 'newly-built-q07-verifier', 'a later mutable target substitution cannot change the sealed executable');
  const before = snapshotQ07ExecutableForTest(snapshotPath);
  const command = q07ResumeRustSystemdArgsForTest({
    sourceRoot: root,
    corpusPath: join(bundle, 'q07-non-chain-lifecycle.ndjson'),
    systemd: mockedSystemdEvidence(),
    buildSnapshot: captured.snapshot,
  });
  assert.equal(command.at(-1), snapshotPath, 'systemd must execute the sealed bundle snapshot');
  assert.notEqual(command.at(-1), target, 'systemd must never execute target/release directly');
  assertQ07ResumeRustSnapshotForTest({
    binary: { snapshot: captured.snapshot, before, after: before },
    bundleRoot: bundle,
    buildSnapshot: captured.snapshot,
  });
  writeFileSync(snapshotPath, 'tampered-snapshot', { mode: 0o700 });
  chmodSync(snapshotPath, 0o700);
  assert.throws(
    () => assertQ07ResumeRustSnapshotForTest({
      binary: { snapshot: captured.snapshot, before, after: before },
      bundleRoot: bundle,
      buildSnapshot: captured.snapshot,
    }),
    /changed|drifted/,
    'the sealed snapshot is part of the Rust receipt verification contract',
  );

  const build = q07ResumeBuildCommandForTest({
    sourceRoot: root,
    toolchain: {
      cargo: { path: '/opt/pinned/cargo', sha256: '1'.repeat(64), version: 'cargo 1.97.1 test' },
      rustc: { path: '/opt/pinned/rustc', sha256: '2'.repeat(64), version: 'rustc 1.97.1 test' },
    },
  });
  assert.equal(build.command, '/opt/pinned/cargo');
  assert.deepEqual(build.args.slice(0, 2), ['build', '--locked']);
  assert.equal(build.environment.RUSTC, '/opt/pinned/rustc');
  t.after(() => rmSync(root, { recursive: true, force: true }));
});
