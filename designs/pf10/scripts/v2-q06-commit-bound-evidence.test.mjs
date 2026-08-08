/* TEST-ONLY: nonqualifying fixtures must never cross the public verifier boundary. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../packages/profile/load.mjs';

import {
  assertV2Q06SafeHostEnvironment,
  V2Q06CommitBoundEvidenceError, parseV2Q06CommitBoundArguments, q06TestFixtures,
  installedDependencyInventoryForTest,
  publicV2Q06GeneratorOptions,
  runV2Q06CommitBoundEvidence, runV2Q06CommitBoundEvidenceForTest,
  validateV2Q06CrashCampaignForTest,
  verifyV2Q06CheckoutRootBindingForTest, verifyV2Q06CommitBoundBundle,
  verifyV2Q06CommitBoundBundleForTest,
} from './v2-q06-commit-bound-evidence.mjs';
import { runV2CrashQualification } from './v2-crash-qualification.mjs';

const root = () => mkdtempSync(join(tmpdir(), 'shieldkit-q06-'));
const publicOutputRoot = () => mkdtempSync('/tmp/shieldkit-q06-public-');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function resealArtifact(bundle, name, value) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  writeFileSync(join(bundle, name), bytes, { mode: 0o600 });
  const manifest = JSON.parse(readFileSync(join(bundle, 'manifest.json'), 'utf8'));
  const entry = manifest.artifacts.find((item) => item.path === name);
  entry.bytes = bytes.length; entry.sha256 = hash(bytes);
  writeFileSync(join(bundle, 'manifest.json'), canonicalJson(manifest), { mode: 0o600 });
}

test('Q-06 public generator refuses dirty/uncommitted source before it can run a campaign', async () => {
  // The portable runner deliberately points TMPDIR inside its clean checkout.
  // Public evidence output must remain outside that source tree so this test
  // reaches the intended dirty-checkout gate rather than the earlier output
  // containment gate.
  const parent = publicOutputRoot();
  const marker = join(repositoryRoot, `.q06-dirty-checkout-test-${process.pid}-${Date.now()}`);
  try {
    writeFileSync(marker, 'test-only dirty-checkout marker\n', { flag: 'wx', mode: 0o600 });
    await assert.rejects(
      () => runV2Q06CommitBoundEvidence({ outputDirectory: parent }),
      /clean committed source checkout/u,
    );
  } finally {
    rmSync(marker, { force: true });
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Q-06 rejects ambient loader, module-path, dynamic-loader, and HOME controls', () => {
  const home = process.env.HOME;
  assertV2Q06SafeHostEnvironment({ HOME: home }, ['--test']);
  for (const [environment, execArguments, expected] of [
    [{ HOME: home, NODE_OPTIONS: '--import=/tmp/attacker.mjs' }, [], /NODE_OPTIONS/u],
    [{ HOME: home, NODE_PATH: '/tmp/attacker-modules' }, [], /NODE_PATH/u],
    [{ HOME: home, LD_PRELOAD: '/tmp/attacker.so' }, [], /LD_PRELOAD/u],
    [{ HOME: home, DYLD_INSERT_LIBRARIES: '/tmp/attacker.dylib' }, [], /DYLD_INSERT_LIBRARIES/u],
    [{ HOME: '/tmp/attacker-home' }, [], /HOME/u],
    [{ HOME: home }, ['--import=/tmp/attacker.mjs'], /process\.execArgv/u],
  ]) {
    assert.throws(
      () => assertV2Q06SafeHostEnvironment(environment, execArguments),
      expected,
    );
  }
});

test('Q-06 fixture injection is sealed, canonical, and publicly nonqualifying', async () => {
  const parent = root();
  try {
    const result = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    assert.equal(result.status, 'verified-test-only-nonqualifying');
    assert.equal(result.schema, 'shieldkit-v2-direct/q06-commit-bound-verification/v2');
    assert.equal(result.replayedRecoveryCorpus, false);
    assert.equal(lstatSync(result.bundlePath).mode & 0o777, 0o700);
    assert.equal(lstatSync(join(result.bundlePath, 'manifest.json')).mode & 0o777, 0o600);
    assert.equal(lstatSync(join(result.bundlePath, 'replay-corpus.json')).mode & 0o777, 0o600);
    assert.match(readFileSync(join(result.bundlePath, 'execution.json'), 'utf8'), /"testOnly":true/u);
    assert.throws(() => verifyV2Q06CommitBoundBundle(result.bundlePath), /test-only Q-06 evidence/u);
    assert.equal(verifyV2Q06CommitBoundBundleForTest(result.bundlePath).status, 'verified-test-only-nonqualifying');
    writeFileSync(join(result.bundlePath, 'crash-campaign.json'), '{}'); chmodSync(join(result.bundlePath, 'crash-campaign.json'), 0o600);
    assert.throws(() => verifyV2Q06CommitBoundBundleForTest(result.bundlePath), V2Q06CommitBoundEvidenceError);

    const corpusResult = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    writeFileSync(join(corpusResult.bundlePath, 'replay-corpus.json'), '{}');
    chmodSync(join(corpusResult.bundlePath, 'replay-corpus.json'), 0o600);
    assert.throws(() => verifyV2Q06CommitBoundBundleForTest(corpusResult.bundlePath), V2Q06CommitBoundEvidenceError);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('Q-06 stage-derived crash contract accepts one real complete runner cycle', () => {
  const parent = root();
  try {
    const output = join(parent, 'crash-cycle.json');
    const evidence = runV2CrashQualification({ output, cases: 34 });
    assert.equal(
      validateV2Q06CrashCampaignForTest(evidence, 34),
      evidence,
    );
    assert.deepEqual(evidence.invariantCounts, {
      noCanonicalCommitBeforeAuthenticatedConfirmation: 28,
      authenticatedConfirmationCommitsCanonicalState: 1,
      noLostOrDuplicatedReservations: 16,
      noUnsignedBroadcastableState: 7,
      noDuplicateSend: 6,
      exactResumabilityOrAbandon: 34,
    });
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('installed dependency inventory rejects symlinks outside installed or tracked source closure', () => {
  const repository = root();
  const outside = root();
  try {
    mkdirSync(join(repository, 'node_modules'), { mode: 0o700 });
    mkdirSync(join(repository, 'packages'), { mode: 0o700 });
    mkdirSync(join(repository, 'packages', 'tracked'), { mode: 0o700 });
    writeFileSync(join(repository, 'packages', 'tracked', 'index.mjs'), 'export default true;\n');
    for (const args of [['init', '-q'], ['add', 'packages/tracked/index.mjs']]) {
      const result = spawnSync('git', args, { cwd: repository, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
    }
    symlinkSync('../packages/tracked', join(repository, 'node_modules', 'tracked'));
    assert.match(installedDependencyInventoryForTest(repository).inventorySha256, /^[0-9a-f]{64}$/u);
    const nested = join(repository, 'packages', 'tracked', 'nested.mjs');
    symlinkSync('index.mjs', nested);
    assert.throws(
      () => installedDependencyInventoryForTest(repository),
      /nested symlink outside node_modules/u,
    );
    rmSync(nested);
    writeFileSync(join(outside, 'unbound.mjs'), 'export default false;\n');
    symlinkSync(join(outside, 'unbound.mjs'), join(repository, 'node_modules', 'unbound'));
    assert.throws(
      () => installedDependencyInventoryForTest(repository),
      /escapes bound inventories/u,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test('Q-06 verifier rejects reduced crash coverage even when summary booleans remain true', async () => {
  const parent = root();
  try {
    const fixture = q06TestFixtures(); const crash = structuredClone(fixture.crash);
    crash.caseCountsByStage['operation.after_pending'] -= 1;
    await assert.rejects(() => runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, source: fixture.source, crash, reorg: fixture.reorg }), /stage coverage differs/u);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('Q-06 verifier rejects self-resealed source, runtime, and SIGKILL transcript tampering', async () => {
  const parent = root();
  try {
    const first = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    const source = JSON.parse(readFileSync(join(first.bundlePath, 'source-set.json'), 'utf8'));
    source.files[0].sha256 = '0'.repeat(64);
    source.sourceSetSha256 = hash(Buffer.from(canonicalJson({ files: source.files, locks: source.locks, dependencyClosure: source.dependencyClosure }), 'utf8'));
    resealArtifact(first.bundlePath, 'source-set.json', source);
    assert.throws(() => verifyV2Q06CommitBoundBundleForTest(first.bundlePath), /source binding differs/u);

    const second = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    const alteredSource = JSON.parse(readFileSync(join(second.bundlePath, 'source-set.json'), 'utf8'));
    alteredSource.runtime.nodeVersion = 'v0.0.0';
    resealArtifact(second.bundlePath, 'source-set.json', alteredSource);
    assert.throws(() => verifyV2Q06CommitBoundBundleForTest(second.bundlePath), /runtime differs/u);

    const third = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    const crash = JSON.parse(readFileSync(join(third.bundlePath, 'crash-campaign.json'), 'utf8'));
    crash.externalCrashCorpus.cases[0].crash.stdout = '{"event":"ready-to-kill","mode":"tampered"}\n';
    crash.externalCrashCorpus.cases[0].crash.stdoutSha256 = hash(crash.externalCrashCorpus.cases[0].crash.stdout);
    resealArtifact(third.bundlePath, 'crash-campaign.json', crash);
    const execution = JSON.parse(readFileSync(join(third.bundlePath, 'execution.json'), 'utf8'));
    execution.crashCampaignSha256 = hash(readFileSync(join(third.bundlePath, 'crash-campaign.json')));
    resealArtifact(third.bundlePath, 'execution.json', execution);
    assert.throws(() => verifyV2Q06CommitBoundBundleForTest(third.bundlePath), /transcript event differs/u);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('Q-06 checkout binding rejects a self-resealed alternate clean Git source', async () => {
  const parent = root();
  try {
    const alternate = join(parent, 'alternate-clean-checkout'); mkdirSync(alternate, { mode: 0o700 });
    writeFileSync(join(alternate, 'tracked.txt'), 'alternate\n');
    for (const args of [['init', '-q'], ['add', 'tracked.txt'], ['-c', 'user.name=Q06 Test', '-c', 'user.email=q06@example.invalid', 'commit', '-qm', 'alternate']]) {
      const result = spawnSync('git', args, { cwd: alternate, encoding: 'utf8' }); assert.equal(result.status, 0, result.stderr);
    }
    assert.equal(spawnSync('git', ['status', '--porcelain=v1'], { cwd: alternate, encoding: 'utf8' }).stdout, '');
    const result = await runV2Q06CommitBoundEvidenceForTest({ outputDirectory: parent, ...q06TestFixtures() });
    const source = JSON.parse(readFileSync(join(result.bundlePath, 'source-set.json'), 'utf8'));
    source.sourceRoot = alternate;
    source.gitCommit = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: alternate, encoding: 'utf8' }).stdout.trim();
    source.gitTree = spawnSync('git', ['rev-parse', 'HEAD^{tree}'], { cwd: alternate, encoding: 'utf8' }).stdout.trim();
    resealArtifact(result.bundlePath, 'source-set.json', source);
    assert.throws(() => verifyV2Q06CheckoutRootBindingForTest(result.bundlePath), /differs from this verifier module exact checkout/u);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('Q-06 CLI accepts only a public output directory or bundle verification target', () => {
  assert.deepEqual(parseV2Q06CommitBoundArguments(['--verify', '/bundle'], '/cwd'), { mode: 'verify', bundlePath: '/bundle' });
  assert.deepEqual(
    publicV2Q06GeneratorOptions(
      parseV2Q06CommitBoundArguments(['--output-directory', '/output'], '/cwd'),
    ),
    { outputDirectory: '/output' },
  );
  assert.throws(() => parseV2Q06CommitBoundArguments(['--cases', '1']), V2Q06CommitBoundEvidenceError);
  assert.throws(() => parseV2Q06CommitBoundArguments([]), V2Q06CommitBoundEvidenceError);
});

test('Q-06 public generator rejects CLI mode and every injected campaign seam', async () => {
  const parent = root();
  try {
    await assert.rejects(
      () => runV2Q06CommitBoundEvidence({ mode: 'run', outputDirectory: parent }),
      /accepts only outputDirectory/u,
    );
    await assert.rejects(
      () => runV2Q06CommitBoundEvidence({ outputDirectory: parent, cases: 1 }),
      /accepts only outputDirectory/u,
    );
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
