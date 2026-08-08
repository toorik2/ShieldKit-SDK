import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  installV2BetaProductArtifactsForTest,
  loadV2BetaProductArtifactInstallation,
} from '../../profile/v2/beta-product-artifact-installation.mjs';
import {
  GMP_SHA256,
  GMP_VERSION,
  RAPIDSNARK_COMMIT,
  RAPIDSNARK_REPOSITORY,
  RAPIDSNARK_SUBMODULES,
  V2_NATIVE_PROVER_MANIFEST_SCHEMA,
} from '../../../scripts/setup-v2-native-prover.mjs';
import {
  V2_NATIVE_GROTH16_PROVER_INSTALLATION_SCHEMA,
  consumeV2NativeGroth16ProverInstallation,
  deriveV2NativeGroth16ProverInstallationFromProductArtifact,
  loadV2NativeGroth16ProverInstallationForTest,
  setV2NativeGroth16ProverContentReadObserverForTest,
} from './native-groth16-prover-installation.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const rejects = (code) => (error) => error?.code === code;

function fixture({ canonical = true } = {}) {
  const root = mkdtempSync(path.join('/tmp', 'shieldkit-native-installation-'));
  chmodSync(root, 0o700);
  const bin = path.join(root, 'bin'); mkdirSync(bin, { mode: 0o700 }); chmodSync(bin, 0o700);
  const binary = Buffer.from('portable native-prover unit fixture\n');
  const binaryPath = path.join(bin, 'prover'); writeFileSync(binaryPath, binary, { mode: 0o700 }); chmodSync(binaryPath, 0o700);
  const binarySha256 = hash(binary);
  const manifest = {
    schema: V2_NATIVE_PROVER_MANIFEST_SCHEMA,
    source: { repository: RAPIDSNARK_REPOSITORY, commit: RAPIDSNARK_COMMIT, submodules: [...RAPIDSNARK_SUBMODULES] },
    gmp: { version: GMP_VERSION, archiveSha256: GMP_SHA256, staticLibrarySha256: '11'.repeat(32) },
    build: { useAsm: false, useOpenmp: true, sourceTreeUnchanged: true, cxxFlagsRelease: '-O3 -DNDEBUG -include cstdint', nproc: availableParallelism(), wallMs: 1 },
    toolchain: { compiler: 'unit-test', cmake: 'unit-test', node: process.version, platform: `${process.platform}/${process.arch}` },
    binary: { path: 'bin/prover', bytes: binary.length, sha256: binarySha256 },
  };
  const manifestPath = path.join(root, 'manifest.json');
  writeFileSync(manifestPath, canonical ? canonicalizeJcs(manifest) : `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 }); chmodSync(manifestPath, 0o600);
  return Object.freeze({ root, binaryPath, manifestPath, policy: Object.freeze({ binarySha256, nproc: availableParallelism() }) });
}

function productFixture() {
  const root = mkdtempSync(path.join('/tmp', 'shieldkit-native-product-receipt-')); chmodSync(root, 0o700);
  const directory = (name) => { const value = path.join(root, name); mkdirSync(value, { mode: 0o700 }); chmodSync(value, 0o700); return value; };
  const product = directory('product'); const runtime = directory('runtime'); const ceremony = directory('ceremony'); const native = directory('native');
  const file = (parent, name, content, mode = 0o600) => { const value = path.join(parent, name); writeFileSync(value, content, { mode }); chmodSync(value, mode); return value; };
  file(runtime, 'runtime.bin', 'runtime\n'); file(ceremony, 'ceremony.bin', 'ceremony\n');
  const bin = path.join(native, 'bin'); mkdirSync(bin, { mode: 0o700 }); chmodSync(bin, 0o700);
  file(native, 'manifest.json', 'manifest\n'); file(bin, 'prover', 'product-prover\n', 0o700);
  return Object.freeze({ root, product, runtime, ceremony, native, manifestSha256: hash('manifest\n'), binarySha256: hash('product-prover\n') });
}

const productVerify = (subject) => async () => ({
  runtime: { manifestSha256: '11'.repeat(32), runtimeMaterialSha256: '12'.repeat(32) },
  ceremony: { ceremonyId: 'test', resultSha256: '13'.repeat(32), betaProvingKeySha256: '14'.repeat(32), verificationKeySha256: '15'.repeat(32) },
  native: { manifestSha256: subject.manifestSha256 }, binary: { sha256: subject.binarySha256 },
});

function withEnvironment(name, value, run) {
  const prior = process.env[name];
  process.env[name] = value;
  return Promise.resolve().then(run).finally(() => {
    if (prior === undefined) delete process.env[name]; else process.env[name] = prior;
  });
}

test('loader capability cannot be forged from its compact public shape', async () => {
  await assert.rejects(() => consumeV2NativeGroth16ProverInstallation(Object.freeze({
    schema: V2_NATIVE_GROTH16_PROVER_INSTALLATION_SCHEMA,
    installationDirectory: '/not-an-installation', manifestSha256: '0'.repeat(64),
    binary: Object.freeze({ path: '/not-an-installation/bin/prover', bytes: 1, sha256: '1'.repeat(64) }),
  })), rejects('NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED'));
});

test('self-contained canonical fixture is rehashed at install and identity-checked at warm consume time', async () => {
  const subject = fixture();
  try {
    const installation = await loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: subject.root, policy: subject.policy });
    assert.equal(installation.binary.sha256, subject.policy.binarySha256);
    const binary = await consumeV2NativeGroth16ProverInstallation(installation);
    assert.deepEqual(binary, { path: subject.binaryPath, sha256: subject.policy.binarySha256, identity: installation.binary.identity });
    writeFileSync(subject.binaryPath, 'altered binary', { mode: 0o700 }); chmodSync(subject.binaryPath, 0o700);
    await assert.rejects(() => consumeV2NativeGroth16ProverInstallation(installation), rejects('NATIVE_PROVER_INSTALLATION_RACE'));
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('warm consume rejects a hardlink or mode change without rereading binary content', async () => {
  const subject = fixture();
  try {
    const installation = await loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: subject.root, policy: subject.policy });
    linkSync(subject.binaryPath, path.join(subject.root, 'prover-hardlink'));
    await assert.rejects(() => consumeV2NativeGroth16ProverInstallation(installation), rejects('NATIVE_PROVER_INSTALLATION_RACE'));
  } finally { rmSync(subject.root, { recursive: true, force: true }); }

  const changedMode = fixture();
  try {
    const installation = await loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: changedMode.root, policy: changedMode.policy });
    chmodSync(changedMode.binaryPath, 0o600);
    await assert.rejects(() => consumeV2NativeGroth16ProverInstallation(installation), rejects('NATIVE_PROVER_INSTALLATION_UNTRUSTED'));
  } finally { rmSync(changedMode.root, { recursive: true, force: true }); }
});

test('warm consume rejects replacement even when replacement has identical bytes', async () => {
  const subject = fixture();
  try {
    const installation = await loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: subject.root, policy: subject.policy });
    const replacement = path.join(subject.root, 'replacement');
    writeFileSync(replacement, 'portable native-prover unit fixture\n', { mode: 0o700 }); chmodSync(replacement, 0o700);
    renameSync(replacement, subject.binaryPath);
    await assert.rejects(() => consumeV2NativeGroth16ProverInstallation(installation), rejects('NATIVE_PROVER_INSTALLATION_RACE'));
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('receipt-bound product derivation is fresh-process-equivalent and performs zero warm binary reads', async () => {
  const subject = productFixture();
  try {
    await installV2BetaProductArtifactsForTest({
      productDataDirectory: subject.product,
      sourceRuntimeDirectory: subject.runtime,
      ceremonyDirectory: subject.ceremony,
      nativeProverInstallationDirectory: subject.native,
    }, { verify: productVerify(subject) });
    let firstArtifact;
    const reads = [];
    const restore = setV2NativeGroth16ProverContentReadObserverForTest((value) => reads.push(value));
    try {
      firstArtifact = await loadV2BetaProductArtifactInstallation({ productDataDirectory: subject.product });
      const first = await deriveV2NativeGroth16ProverInstallationFromProductArtifact(firstArtifact);
      const consumed = await consumeV2NativeGroth16ProverInstallation(first);
      const secondArtifact = await loadV2BetaProductArtifactInstallation({ productDataDirectory: subject.product });
      const second = await deriveV2NativeGroth16ProverInstallationFromProductArtifact(secondArtifact);
      assert.equal(first.binary.sha256, subject.binarySha256);
      assert.deepEqual(consumed.identity, first.binary.identity);
      assert.equal(second.binary.sha256, first.binary.sha256);
      assert.equal(reads.filter((entry) => entry.label === 'native prover binary').length, 0);
    } finally { restore(); }
    const installedBinary = path.join(subject.product, 'v2-beta-product-artifacts', 'native', 'bin', 'prover');
    const hardlink = path.join(subject.product, 'v2-beta-product-artifacts', 'native', 'prover-hardlink');
    linkSync(installedBinary, hardlink);
    await assert.rejects(
      () => deriveV2NativeGroth16ProverInstallationFromProductArtifact(firstArtifact),
      rejects('NATIVE_PROVER_INSTALLATION_UNTRUSTED'),
    );
    rmSync(hardlink);
    writeFileSync(installedBinary, 'mutated-prover\n', { mode: 0o700 }); chmodSync(installedBinary, 0o700);
    await assert.rejects(
      () => deriveV2NativeGroth16ProverInstallationFromProductArtifact(firstArtifact),
      rejects('NATIVE_PROVER_INSTALLATION_RACE'),
    );
    await assert.rejects(
      () => loadV2BetaProductArtifactInstallation({ productDataDirectory: subject.product }),
      (error) => error?.code === 'BETA_ARTIFACT_INSTALL_RACE',
    );
    await assert.rejects(
      () => deriveV2NativeGroth16ProverInstallationFromProductArtifact(Object.freeze({})),
      rejects('NATIVE_PROVER_INSTALLATION_CAPABILITY_REQUIRED'),
    );
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('rejects noncanonical manifest bytes before trusting manifest fields', async () => {
  const subject = fixture({ canonical: false });
  try {
    await assert.rejects(() => loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: subject.root, policy: subject.policy }), rejects('NATIVE_PROVER_INSTALLATION_INVALID'));
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

for (const [name, value] of [['NODE_OPTIONS', '--import=./contaminated.mjs'], ['NODE_PATH', '/tmp/contaminated'], ['LD_PRELOAD', '/tmp/contaminated.so'], ['DYLD_INSERT_LIBRARIES', '/tmp/contaminated.dylib']]) {
  test(`rejects ${name} runtime contamination before filesystem inspection`, async () => withEnvironment(name, value, async () => {
    await assert.rejects(() => loadV2NativeGroth16ProverInstallationForTest({ installationDirectory: '/definitely-absent', policy: { binarySha256: '0'.repeat(64), nproc: 1 } }), rejects('NATIVE_PROVER_RUNTIME_UNSUPPORTED'));
  }));
}
