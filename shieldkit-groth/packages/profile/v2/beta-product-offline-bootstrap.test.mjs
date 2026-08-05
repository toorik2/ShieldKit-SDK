import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  installV2BetaProductOfflineBundleForTest,
  loadV2BetaProductTrackedReleasePin,
  V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY,
  V2_BETA_OFFLINE_RELEASE_MANIFEST,
  V2BetaOfflineBootstrapError,
} from './beta-product-offline-bootstrap.mjs';

const rejects = (code) => (error) => error instanceof V2BetaOfflineBootstrapError && error.code === code;

function directory(parent, name) {
  const result = path.join(parent, name);
  mkdirSync(result, { mode: 0o700 }); chmodSync(result, 0o700);
  return result;
}

async function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-offline-bundle-'));
  chmodSync(root, 0o700); t.after(() => rmSync(root, { recursive: true, force: true }));
  const product = directory(root, 'product'); const bundle = directory(root, 'bundle');
  const files = [
    ['runtime', 'proof/runtime.bin', 'runtime\n', 0o600],
    ['ceremony', 'result/ceremony.bin', 'ceremony\n', 0o600],
    ['native', 'manifest.json', 'manifest\n', 0o600],
    ['native', 'bin/prover', 'prover\n', 0o700],
  ];
  const artifacts = { runtime: [], ceremony: [], native: [] };
  for (const [section, relative, content, mode] of files) {
    const base = path.join(bundle, section, ...relative.split('/').slice(0, -1));
    mkdirSync(base, { recursive: true, mode: 0o700 }); chmodSync(base, 0o700);
    const filename = path.join(bundle, section, ...relative.split('/'));
    writeFileSync(filename, content, { mode }); chmodSync(filename, mode);
    artifacts[section].push({ path: relative, bytes: Buffer.byteLength(content), sha256: createHash('sha256').update(content).digest('hex'), mode });
  }
  const manifest = {
    schema: 'shieldkit-v2-beta-offline-release-bundle-v1',
    status: 'offline-beta-unqualified',
    claims: { productionQualified: false, releaseQualified: false },
    releaseId: 'test-r1', artifacts,
  };
  writeFileSync(path.join(bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST), canonicalizeJcs(manifest), { mode: 0o600 });
  chmodSync(path.join(bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST), 0o600);
  return { root, product, bundle, manifest };
}

function releasePin(subject) {
  return {
    schema: 'shieldkit-v2-beta-product-release-pin-v1',
    status: 'pinned-beta-unqualified',
    claims: { productionQualified: false, releaseQualified: false },
    releaseId: subject.manifest.releaseId,
    bundleSchema: subject.manifest.schema,
    releaseManifestSha256: createHash('sha256')
      .update(readFileSync(path.join(subject.bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST)))
      .digest('hex'),
  };
}

const installFixture = (subject, injected) => installV2BetaProductOfflineBundleForTest(
  { bundleDirectory: subject.bundle, productDataDirectory: subject.product },
  injected,
  releasePin(subject),
);

function dependencies({ failInstall = false, publishThenFail = false } = {}) {
  const calls = { install: 0, load: 0 };
  let published;
  return {
    calls,
    value: {
      install: async (input) => {
        calls.install += 1;
        assert.equal(input.sourceRuntimeDirectory.endsWith('/runtime'), true);
        assert.equal(input.nativeProverInstallationDirectory.endsWith('/native'), true);
        if (failInstall) throw new Error('simulated crash before publication');
        published = 'ab'.repeat(32);
        if (publishThenFail) throw new Error('simulated crash after publication');
        return { receiptSha256: published };
      },
      inspect: async () => published,
      load: async () => { calls.load += 1; return Object.freeze({}); },
    },
  };
}

function waitForChildReady(child) {
  return new Promise((resolve, reject) => {
    let output = '';
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.includes('ready\n')) resolve();
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (!output.includes('ready\n')) reject(new Error(`lock owner exited before ready: ${code ?? signal}`));
    });
  });
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
}

test('stages an exact offline bundle, journals commit, and restarts idempotently', async (t) => {
  const subject = await fixture(t); const mocked = dependencies();
  const first = await installFixture(subject, mocked.value);
  assert.equal(first.status, 'installed-beta-unqualified');
  assert.deepEqual(first.claims, { productionQualified: false, releaseQualified: false });
  assert.equal(mocked.calls.install, 1);
  const stage = path.join(subject.product, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY);
  assert.equal(path.basename(stage), V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY);
  const second = await installFixture(subject, mocked.value);
  assert.equal(second.status, 'already-installed-beta-unqualified');
  assert.equal(mocked.calls.install, 1);
  assert.equal(mocked.calls.load, 2);
});

test('resumes a crash left before final artifact publication', async (t) => {
  const subject = await fixture(t); const failing = dependencies({ failInstall: true });
  await assert.rejects(
    () => installFixture(subject, failing.value),
    /simulated crash/u,
  );
  const resumed = dependencies();
  const result = await installFixture(subject, resumed.value);
  assert.equal(result.status, 'installed-beta-unqualified');
  assert.equal(resumed.calls.install, 1);
});

test('adopts a receipt-bound publish that crashed before journal commit', async (t) => {
  const subject = await fixture(t); const crashed = dependencies({ publishThenFail: true });
  await assert.rejects(
    () => installFixture(subject, crashed.value),
    /simulated crash after publication/u,
  );
  const resumed = dependencies();
  resumed.value.inspect = crashed.value.inspect;
  const result = await installFixture(subject, resumed.value);
  assert.equal(result.status, 'already-installed-beta-unqualified');
  assert.equal(resumed.calls.install, 0);
});

test('rejects manifest corruption, extra files, unsafe links, and corrupt journals', async (t) => {
  const badPath = await fixture(t);
  badPath.manifest.artifacts.runtime[0].path = '../escape';
  writeFileSync(path.join(badPath.bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST), canonicalizeJcs(badPath.manifest), { mode: 0o600 });
  await assert.rejects(() => installFixture(badPath, dependencies().value), rejects('BETA_OFFLINE_BOOTSTRAP_INVALID'));

  const extra = await fixture(t);
  writeFileSync(path.join(extra.bundle, 'runtime', 'extra.bin'), 'extra\n', { mode: 0o600 });
  await assert.rejects(() => installFixture(extra, dependencies().value), rejects('BETA_OFFLINE_BOOTSTRAP_INVALID'));

  const link = await fixture(t);
  rmSync(path.join(link.bundle, 'native', 'manifest.json'));
  symlinkSync('/dev/null', path.join(link.bundle, 'native', 'manifest.json'));
  await assert.rejects(() => installFixture(link, dependencies().value), rejects('BETA_OFFLINE_BOOTSTRAP_UNSAFE_PATH'));

  const corruptedJournal = await fixture(t);
  const journalRoot = directory(corruptedJournal.product, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY);
  writeFileSync(path.join(journalRoot, 'journal.json'), '{not-jcs}\n', { mode: 0o600 });
  await assert.rejects(() => installFixture(corruptedJournal, dependencies().value), rejects('BETA_OFFLINE_BOOTSTRAP_INVALID'));
});

test('uses the repository-tracked real release pin and rejects a self-authenticating replacement manifest', async (t) => {
  const tracked = await loadV2BetaProductTrackedReleasePin();
  assert.equal(tracked.releaseId, 'shieldkit-v2-beta-20260802-r3');
  assert.equal(tracked.releaseManifestSha256, '6aa1a3b8670b414e2beb4f8e08cd93519883f7920a899b73eacd743a28d780a0');

  const subject = await fixture(t);
  const trusted = releasePin(subject);
  const replacement = 'attacker-controlled-but-internally-consistent\n';
  writeFileSync(path.join(subject.bundle, 'runtime/proof/runtime.bin'), replacement, { mode: 0o600 });
  subject.manifest.artifacts.runtime[0].bytes = Buffer.byteLength(replacement);
  subject.manifest.artifacts.runtime[0].sha256 = createHash('sha256').update(replacement).digest('hex');
  writeFileSync(
    path.join(subject.bundle, V2_BETA_OFFLINE_RELEASE_MANIFEST),
    canonicalizeJcs(subject.manifest),
    { mode: 0o600 },
  );
  await assert.rejects(
    () => installV2BetaProductOfflineBundleForTest(
      { bundleDirectory: subject.bundle, productDataDirectory: subject.product },
      dependencies().value,
      trusted,
    ),
    rejects('BETA_OFFLINE_BOOTSTRAP_PIN_MISMATCH'),
  );
});

test('rejects a live SQLite lease and recovers immediately after actual SIGKILL', async (t) => {
  const subject = await fixture(t);
  const pin = releasePin(subject);
  const moduleUrl = new URL('./beta-product-offline-bootstrap.mjs', import.meta.url).href;
  const program = [
    `import { installV2BetaProductOfflineBundleForTest } from ${JSON.stringify(moduleUrl)};`,
    'await installV2BetaProductOfflineBundleForTest({ bundleDirectory: process.argv[1], productDataDirectory: process.argv[2] }, {',
    "install: async () => { process.stdout.write('ready\\n'); await new Promise(() => setInterval(() => {}, 1000)); },",
    `inspect: async () => undefined, load: async () => Object.freeze({}), }, ${JSON.stringify(pin)});`,
  ].join('\n');
  const child = spawn(process.execPath, ['--input-type=module', '--eval', program, subject.bundle, subject.product], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForChildReady(child);
  await assert.rejects(
    () => installFixture(subject, dependencies().value),
    rejects('BETA_OFFLINE_BOOTSTRAP_BUSY'),
  );
  child.kill('SIGKILL');
  const exited = await waitForExit(child);
  assert.equal(exited.signal, 'SIGKILL');
  const resumed = dependencies();
  const result = await installFixture(subject, resumed.value);
  assert.equal(result.status, 'installed-beta-unqualified');
  assert.equal(resumed.calls.install, 1);
  const lockPath = path.join(subject.product, V2_BETA_OFFLINE_BOOTSTRAP_DIRECTORY, 'install-lock.sqlite');
  assert.equal(lstatSync(lockPath).mode & 0o777, 0o600);
  const restart = await installFixture(subject, resumed.value);
  assert.equal(restart.status, 'already-installed-beta-unqualified');
});
