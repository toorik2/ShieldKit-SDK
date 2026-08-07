import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, renameSync,
  readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  installV2BetaProductArtifactsForTest,
  loadV2BetaProductArtifactInstallation,
} from '../../profile/v2/beta-product-artifact-installation.mjs';
import {
  createV2BetaProductConfig,
  createOrLoadV2BetaProductConfig,
  deriveV2BetaProductDataLayout,
  loadV2BetaProductConfig,
  toV2BetaProductContextConfig,
  V2_BETA_PRODUCT_CONFIG_FILENAME,
  V2BetaProductConfigError,
} from './beta-product-config.mjs';

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-beta-config-'));
  chmodSync(root, 0o700);
  const dataHome = path.join(root, 'data');
  mkdirSync(dataHome, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, dataHome };
}

const rejects = (code) => error => error instanceof V2BetaProductConfigError && error.code === code;
const hash = (value) => createHash('sha256').update(value).digest('hex');

function artifactSource(root, name, filename) {
  const directory = path.join(root, name);
  mkdirSync(directory, { mode: 0o700 }); chmodSync(directory, 0o700);
  const nested = path.join(directory, 'nested');
  mkdirSync(nested, { mode: 0o700 }); chmodSync(nested, 0o700);
  const artifact = path.join(nested, filename);
  writeFileSync(artifact, `${filename}\n`, { mode: 0o600 }); chmodSync(artifact, 0o600);
  return directory;
}

function nativeArtifactSource(root) {
  const directory = path.join(root, 'native-source');
  mkdirSync(directory, { mode: 0o700 }); chmodSync(directory, 0o700);
  const binaryDirectory = path.join(directory, 'bin');
  mkdirSync(binaryDirectory, { mode: 0o700 }); chmodSync(binaryDirectory, 0o700);
  const manifest = path.join(directory, 'manifest.json');
  const prover = path.join(binaryDirectory, 'prover');
  writeFileSync(manifest, 'manifest.json\n', { mode: 0o600 }); chmodSync(manifest, 0o600);
  writeFileSync(prover, 'prover\n', { mode: 0o700 }); chmodSync(prover, 0o700);
  return directory;
}

const testArtifactVerification = async () => ({
  runtime: { manifestSha256: '11'.repeat(32), runtimeMaterialSha256: '12'.repeat(32) },
  ceremony: { ceremonyId: 'test', resultSha256: '13'.repeat(32), betaProvingKeySha256: '14'.repeat(32), verificationKeySha256: '15'.repeat(32) },
  native: { manifestSha256: hash('manifest.json\n') }, binary: { sha256: hash('prover\n') },
});

test('load-only resume preflight does not create a missing product layout', (t) => {
  const subject = fixture(t);
  assert.throws(
    () => loadV2BetaProductConfig({ dataHome: subject.dataHome }),
    rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'),
  );
  assert.throws(() => lstatSync(path.join(subject.dataHome, 'shieldkit')), { code: 'ENOENT' });
});

test('records a planned artifact destination before install and accepts its exact native path only after atomic install', async (t) => {
  const subject = fixture(t);
  chmodSync(subject.dataHome, 0o755);
  const layout = deriveV2BetaProductDataLayout({ dataHome: subject.dataHome });
  assert.equal(layout.configPath, path.join(subject.dataHome, 'shieldkit', 'v2-beta-product', V2_BETA_PRODUCT_CONFIG_FILENAME));
  const created = createV2BetaProductConfig({ dataHome: subject.dataHome });
  assert.deepEqual(created, loadV2BetaProductConfig({ dataHome: subject.dataHome }));
  assert.equal(lstatSync(created.configPath).mode & 0o777, 0o600);
  assert.equal(lstatSync(created.configPath).nlink, 1);
  assert.equal(Object.keys(created.config).some((key) => /private|secret|witness|key/iu.test(key)), false);
  assert.equal(created.config.nativeProverDirectory, path.join(created.config.dataDirectory, 'v2-beta-product-artifacts', 'native'));
  assert.throws(() => lstatSync(created.config.nativeProverDirectory), { code: 'ENOENT' });
  assert.throws(() => toV2BetaProductContextConfig(created.config), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));
  const runtime = artifactSource(subject.root, 'runtime-source', 'runtime.bin');
  const ceremony = artifactSource(subject.root, 'ceremony-source', 'ceremony.bin');
  const native = nativeArtifactSource(subject.root);
  await installV2BetaProductArtifactsForTest({
    productDataDirectory: created.config.dataDirectory,
    sourceRuntimeDirectory: runtime,
    ceremonyDirectory: ceremony,
    nativeProverInstallationDirectory: native,
  }, { verify: testArtifactVerification });
  const installation = await loadV2BetaProductArtifactInstallation({ productDataDirectory: created.config.dataDirectory });
  assert.equal(installation.nativeProverInstallationDirectory, created.config.nativeProverDirectory);
  assert.equal(lstatSync(path.join(installation.nativeProverInstallationDirectory, 'manifest.json')).mode & 0o777, 0o600);
  assert.equal(lstatSync(path.join(installation.nativeProverInstallationDirectory, 'bin', 'prover')).mode & 0o777, 0o700);
  const context = toV2BetaProductContextConfig(created.config);
  assert.equal(context.nativeProverDirectory, installation.nativeProverInstallationDirectory);
  assert.equal(context.productDataDirectory, created.config.dataDirectory);
  assert.equal(Object.hasOwn(context, 'runtimeDirectory'), false);
  const receiptPath = path.join(created.config.dataDirectory, 'v2-beta-product-artifacts', 'receipt.json');
  const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
  receipt.native.binarySha256 = '00'.repeat(32);
  writeFileSync(receiptPath, canonicalizeJcs(receipt), { mode: 0o600 });
  await assert.rejects(
    () => loadV2BetaProductArtifactInstallation({ productDataDirectory: created.config.dataDirectory }),
    (error) => error?.code === 'BETA_ARTIFACT_INSTALL_INVALID',
  );
  chmodSync(created.config.nativeProverDirectory, 0o755);
  assert.throws(() => toV2BetaProductContextConfig(created.config), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));
  assert.throws(() => createV2BetaProductConfig({ dataHome: subject.dataHome }), rejects('BETA_PRODUCT_CONFIG_EXISTS'));
});

test('rejects noncanonical bytes, path escape, symlink, and hardlink tampering', (t) => {
  const subject = fixture(t);
  const created = createV2BetaProductConfig({ dataHome: subject.dataHome });
  const saved = path.join(path.dirname(created.configPath), 'saved.json');

  writeFileSync(created.configPath, JSON.stringify(created.config), { mode: 0o600 });
  assert.throws(() => loadV2BetaProductConfig({ dataHome: subject.dataHome }), rejects('BETA_PRODUCT_CONFIG_INVALID'));

  writeFileSync(created.configPath, canonicalizeJcs({ ...created.config, storeDatabasePath: path.join(subject.root, 'escape.sqlite') }), { mode: 0o600 });
  assert.throws(() => loadV2BetaProductConfig({ dataHome: subject.dataHome }), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));

  writeFileSync(created.configPath, canonicalizeJcs(created.config), { mode: 0o600 });
  linkSync(created.configPath, saved);
  assert.throws(() => loadV2BetaProductConfig({ dataHome: subject.dataHome }), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));

  rmSync(created.configPath);
  symlinkSync(saved, created.configPath);
  assert.throws(() => loadV2BetaProductConfig({ dataHome: subject.dataHome }), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));
});

test('rejects unresolved XDG data-home input and config-parent ancestry escapes', (t) => {
  const subject = fixture(t);
  assert.throws(() => deriveV2BetaProductDataLayout({ dataHome: 'relative-data' }), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));
  const parent = path.join(subject.root, 'world');
  mkdirSync(parent, { mode: 0o700 });
  chmodSync(parent, 0o777);
  assert.throws(() => createV2BetaProductConfig({ dataHome: parent }), rejects('BETA_PRODUCT_CONFIG_PATH_REJECTED'));
});

test('concurrent first-run creators publish or load one exact private config without replacement', async (t) => {
  const subject = fixture(t);
  const moduleUrl = new URL('./beta-product-config.mjs', import.meta.url).href;
  const program = `import { createOrLoadV2BetaProductConfig } from ${JSON.stringify(moduleUrl)}; createOrLoadV2BetaProductConfig({ dataHome: process.argv[1] });`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '--eval', program, subject.dataHome], {
      stdio: 'ignore',
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && signal === null) resolve();
      else reject(new Error(`first-run creator exited ${code ?? signal}`));
    });
  });
  await Promise.all([run(), run()]);
  const loaded = createOrLoadV2BetaProductConfig({ dataHome: subject.dataHome });
  assert.deepEqual(loaded, loadV2BetaProductConfig({ dataHome: subject.dataHome }));
  assert.equal(lstatSync(loaded.configPath).mode & 0o777, 0o600);
  assert.equal(lstatSync(loaded.configPath).nlink, 1);
});
