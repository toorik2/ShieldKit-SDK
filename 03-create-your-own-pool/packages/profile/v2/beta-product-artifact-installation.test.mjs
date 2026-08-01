import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  V2BetaProductArtifactInstallationError,
  assertV2BetaProductArtifactInstallationCapability,
  assertV2BetaProductLinkedRuntimeTemplateCapability,
  deriveV2BetaProductNativeProverReceipt,
  deriveV2BetaProductLinkedRuntimeTemplate,
  installV2BetaProductArtifactsForTest,
  loadV2BetaProductArtifactInstallation,
} from './beta-product-artifact-installation.mjs';

const rejects = (code) => (error) => error instanceof V2BetaProductArtifactInstallationError && error.code === code;
const hash = (value) => createHash('sha256').update(value).digest('hex');
function dir(parent, name) { const value = path.join(parent, name); mkdirSync(value, { mode: 0o700 }); chmodSync(value, 0o700); return value; }
function privateFile(directory, name, mode = 0o600) {
  const file = path.join(directory, name);
  writeFileSync(file, `${name}\n`, { mode });
  chmodSync(file, mode);
  return file;
}

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-artifact-install-'));
  chmodSync(root, 0o700);
  const product = dir(root, 'product');
  const runtime = dir(root, 'runtime');
  const ceremony = dir(root, 'ceremony');
  const native = dir(root, 'native');
  privateFile(dir(runtime, 'nested'), 'runtime.bin');
  privateFile(dir(ceremony, 'nested'), 'beta.zkey');
  privateFile(native, 'manifest.json');
  privateFile(dir(native, 'bin'), 'prover', 0o700);
  const profile = dir(runtime, 'profile');
  const proof = dir(runtime, 'proof');
  for (const [base, name] of [
    [profile, 'profile-core.json'], [profile, 'beta-profile-package.json'],
    [proof, 'main-chipnet.r1cs'], [proof, 'main-chipnet.wasm'],
    [proof, 'beta.zkey'], [proof, 'verification_key.json'],
  ]) privateFile(base, name);
  return { root, product, runtime, ceremony, native };
}
const verify = async () => ({ runtime: { manifestSha256:'11'.repeat(32), runtimeMaterialSha256:'12'.repeat(32) }, ceremony: { ceremonyId:'test', resultSha256:'13'.repeat(32), betaProvingKeySha256:'14'.repeat(32), verificationKeySha256:'15'.repeat(32) }, native:{manifestSha256:hash('manifest.json\n')},binary:{sha256:hash('prover\n')} });

test('atomically installs a receipt-bound inventory with its native executable mode', async () => {
  const s = fixture();
  try {
    await assert.rejects(
      () => loadV2BetaProductArtifactInstallation({ productDataDirectory: s.product }),
      rejects('BETA_ARTIFACT_INSTALL_UNAVAILABLE'),
    );
    const installed = await installV2BetaProductArtifactsForTest({
      productDataDirectory: s.product,
      sourceRuntimeDirectory: s.runtime,
      ceremonyDirectory: s.ceremony,
      nativeProverInstallationDirectory: s.native,
    }, { verify });
    assert.ok(installed.bytes > 0);
    const loaded = await loadV2BetaProductArtifactInstallation({ productDataDirectory: s.product });
    assert.equal(assertV2BetaProductArtifactInstallationCapability(loaded), loaded);
    assert.equal(loaded.runtimeDirectory.endsWith('/runtime'), true);
    assert.equal(loaded.nativeProverInstallationDirectory, path.join(s.product, 'v2-beta-product-artifacts', 'native'));
    assert.equal(lstatSync(path.join(loaded.nativeProverInstallationDirectory, 'manifest.json')).mode & 0o777, 0o600);
    assert.equal(lstatSync(path.join(loaded.nativeProverInstallationDirectory, 'bin', 'prover')).mode & 0o777, 0o700);
    const nativeReceipt = deriveV2BetaProductNativeProverReceipt(loaded);
    assert.equal(nativeReceipt.installationDirectory, loaded.nativeProverInstallationDirectory);
    assert.equal(nativeReceipt.manifest.sha256, hash('manifest.json\n'));
    assert.equal(nativeReceipt.binary.sha256, hash('prover\n'));
    assert.throws(() => assertV2BetaProductArtifactInstallationCapability({ ...loaded }), rejects('BETA_ARTIFACT_INSTALL_CAPABILITY_REQUIRED'));
    assert.throws(() => deriveV2BetaProductNativeProverReceipt({ ...loaded }), rejects('BETA_ARTIFACT_INSTALL_CAPABILITY_REQUIRED'));
    writeFileSync(path.join(loaded.runtimeDirectory, 'nested', 'runtime.bin'), 'tampered\n', { mode: 0o600 });
    await assert.rejects(() => loadV2BetaProductArtifactInstallation({ productDataDirectory: s.product }), rejects('BETA_ARTIFACT_INSTALL_RACE'));
  } finally { rmSync(s.root, { recursive: true, force: true }); }
});

test('rejects a receipt path escape or an executable mode that differs from its native role', async () => {
  for (const mutate of [
    (receipt) => { receipt.inventory[0].path = 'runtime/../native/bin/prover'; },
    (receipt) => {
      const prover = receipt.inventory.find((entry) => entry.path === 'native/bin/prover');
      prover.identity.mode = String(0o100600);
    },
    (receipt) => { receipt.native.binarySha256 = '00'.repeat(32); },
  ]) {
    const s = fixture();
    try {
      await installV2BetaProductArtifactsForTest({
        productDataDirectory: s.product,
        sourceRuntimeDirectory: s.runtime,
        ceremonyDirectory: s.ceremony,
        nativeProverInstallationDirectory: s.native,
      }, { verify });
      const receiptPath = path.join(s.product, 'v2-beta-product-artifacts', 'receipt.json');
      const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
      mutate(receipt);
      writeFileSync(receiptPath, canonicalizeJcs(receipt), { mode: 0o600 });
      await assert.rejects(() => loadV2BetaProductArtifactInstallation({ productDataDirectory: s.product }), rejects('BETA_ARTIFACT_INSTALL_INVALID'));
    } finally { rmSync(s.root, { recursive: true, force: true }); }
  }
});

test('linked template has a fixed receipt allow-list and fails closed when a retained redeem is absent', async () => { const s=fixture(); try { await installV2BetaProductArtifactsForTest({productDataDirectory:s.product,sourceRuntimeDirectory:s.runtime,ceremonyDirectory:s.ceremony,nativeProverInstallationDirectory:s.native},{verify}); const loaded=await loadV2BetaProductArtifactInstallation({productDataDirectory:s.product}); await assert.rejects(()=>deriveV2BetaProductLinkedRuntimeTemplate(loaded),rejects('BETA_ARTIFACT_INSTALL_TEMPLATE_UNAVAILABLE')); } finally {rmSync(s.root,{recursive:true,force:true});} });

test('rejects serialized linked-template capability lookalikes', () => {
  assert.throws(
    () => assertV2BetaProductLinkedRuntimeTemplateCapability(Object.freeze({ template: {} })),
    rejects('BETA_ARTIFACT_INSTALL_TEMPLATE_CAPABILITY_REQUIRED'),
  );
});
