import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  installV2BetaProductOfflineBundleForTest,
  V2_BETA_OFFLINE_RELEASE_MANIFEST,
} from './beta-product-offline-bootstrap.mjs';
import {
  packV2BetaProductOfflineBundle,
  V2BetaOfflineBundlePackerError,
} from './beta-product-offline-bundle-packer.mjs';

const rejects = (code) => (error) => error instanceof V2BetaOfflineBundlePackerError && error.code === code;
function directory(parent, name) { const result = path.join(parent, name); mkdirSync(result, { mode: 0o700 }); chmodSync(result, 0o700); return result; }
function file(root, relative, content, mode = 0o600) {
  const destination = path.join(root, ...relative.split('/')); mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 }); chmodSync(path.dirname(destination), 0o700);
  writeFileSync(destination, content, { mode }); chmodSync(destination, mode); return destination;
}
function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-offline-pack-')); chmodSync(root, 0o700); t.after(() => rmSync(root, { recursive: true, force: true }));
  const runtime = directory(root, 'runtime'); const ceremony = directory(root, 'ceremony'); const native = directory(root, 'native'); const outputParent = directory(root, 'out'); const product = directory(root, 'product');
  file(runtime, 'proof/runtime.bin', 'runtime\n'); file(ceremony, 'result/ceremony.bin', 'ceremony\n'); file(native, 'manifest.json', 'manifest\n'); file(native, 'bin/prover', 'prover\n', 0o700);
  return { root, runtime, ceremony, native, outputParent, product };
}
function options(subject, outputDirectory) { return { runtimeDirectory: subject.runtime, ceremonyDirectory: subject.ceremony, nativeProverInstallationDirectory: subject.native, outputDirectory, releaseId: 'local-r1' }; }
function releasePin(packed) {
  const manifest = JSON.parse(readFileSync(path.join(packed.outputDirectory, V2_BETA_OFFLINE_RELEASE_MANIFEST)));
  return {
    schema: 'shieldkit-v2-beta-product-release-pin-v1',
    status: 'pinned-beta-unqualified',
    claims: { productionQualified: false, releaseQualified: false },
    releaseId: packed.releaseId,
    bundleSchema: manifest.schema,
    releaseManifestSha256: packed.manifestSha256,
  };
}

test('packs deterministic exact-JCS offline manifests and preserves source modes', async (t) => {
  const subject = fixture(t);
  const first = await packV2BetaProductOfflineBundle(options(subject, path.join(subject.outputParent, 'one')));
  const second = await packV2BetaProductOfflineBundle(options(subject, path.join(subject.outputParent, 'two')));
  assert.equal(first.manifestSha256, second.manifestSha256);
  const one = readFileSync(path.join(first.outputDirectory, V2_BETA_OFFLINE_RELEASE_MANIFEST));
  const two = readFileSync(path.join(second.outputDirectory, V2_BETA_OFFLINE_RELEASE_MANIFEST));
  assert.deepEqual(one, two);
  const manifest = JSON.parse(one);
  assert.deepEqual(manifest.claims, { productionQualified: false, releaseQualified: false });
  assert.equal(manifest.artifacts.native.find((entry) => entry.path === 'bin/prover').mode, 0o700);
  assert.equal(manifest.artifacts.runtime[0].sha256, createHash('sha256').update('runtime\n').digest('hex'));
  assert.equal(lstatSync(path.join(first.outputDirectory, 'native/bin/prover')).mode & 0o777, 0o700);
});

test('pack output feeds the resumable bootstrap unit seam without a qualifier substitute', async (t) => {
  const subject = fixture(t);
  const packed = await packV2BetaProductOfflineBundle(options(subject, path.join(subject.outputParent, 'bundle')));
  let published; let installs = 0;
  const result = await installV2BetaProductOfflineBundleForTest({ bundleDirectory: packed.outputDirectory, productDataDirectory: subject.product }, {
    install: async () => { installs += 1; published = 'cd'.repeat(32); return { receiptSha256: published }; },
    inspect: async () => published,
    load: async () => Object.freeze({}),
  }, releasePin(packed));
  assert.equal(result.status, 'installed-beta-unqualified'); assert.equal(installs, 1);
});

test('rejects unsafe source topology, wrong native mode, and existing output', async (t) => {
  const symlink = fixture(t); symlinkSync('/dev/null', path.join(symlink.runtime, 'proof', 'linked.bin'));
  await assert.rejects(() => packV2BetaProductOfflineBundle(options(symlink, path.join(symlink.outputParent, 'bundle'))), rejects('BETA_OFFLINE_PACK_UNSAFE_PATH'));

  const hardlink = fixture(t); linkSync(path.join(hardlink.runtime, 'proof', 'runtime.bin'), path.join(hardlink.runtime, 'proof', 'again.bin'));
  await assert.rejects(() => packV2BetaProductOfflineBundle(options(hardlink, path.join(hardlink.outputParent, 'bundle'))), rejects('BETA_OFFLINE_PACK_UNSAFE_PATH'));

  const mode = fixture(t); chmodSync(path.join(mode.native, 'bin', 'prover'), 0o600);
  await assert.rejects(() => packV2BetaProductOfflineBundle(options(mode, path.join(mode.outputParent, 'bundle'))), rejects('BETA_OFFLINE_PACK_UNSAFE_PATH'));

  const exists = fixture(t); const output = directory(exists.outputParent, 'bundle');
  await assert.rejects(() => packV2BetaProductOfflineBundle(options(exists, output)), rejects('BETA_OFFLINE_PACK_EXISTS'));
});
