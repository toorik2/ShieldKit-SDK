import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { openV2BetaIncrementalStore } from '../../profile/v2/beta-incremental-store.mjs';
import { installV2BetaProductArtifactsForTest, loadV2BetaProductArtifactInstallation } from '../../profile/v2/beta-product-artifact-installation.mjs';
import { deriveV2NativeGroth16ProverInstallationFromProductArtifact, setV2NativeGroth16ProverContentReadObserverForTest } from '../../prove/v2/native-groth16-prover-installation.mjs';
import {
  V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA,
  V2BetaProductContextError,
  deriveV2BetaRuntimeRefreshCommandForTest,
  openV2BetaProductContextForTest,
  validateV2BetaProductContextConfig,
} from './beta-product-context.mjs';

const profileId = '11'.repeat(32);
const instanceId = '22'.repeat(32);
const runtimeMaterialSha256 = '33'.repeat(32);
const runtimeManifestSha256 = '34'.repeat(32);
const zeroConfEvidenceSha256 = '35'.repeat(32);
const txid = '44'.repeat(32);
const testProfileCore = Object.freeze({
  schema: 'test-profile-core',
  network: Object.freeze({ id: 2, name: 'chipnet' }),
  denominationSats: '10000000',
});
const rejects = (code) => (error) => error instanceof V2BetaProductContextError && error.code === code;
const hash = (value) => createHash('sha256').update(value).digest('hex');

function directory(parent, name) {
  const value = path.join(parent, name); mkdirSync(value, { mode: 0o700 }); chmodSync(value, 0o700); return value;
}

function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-beta-context-')); chmodSync(root, 0o700);
  const deploymentDirectory = directory(root, 'deployment');
  const runtimeCacheRoot = directory(root, 'runtime-cache');
  const artifactsDirectory = directory(root, 'v2-beta-product-artifacts');
  const nativeProverDirectory = directory(artifactsDirectory, 'native');
  const proofWorkspaceDirectory = directory(root, 'proof-workspace');
  const storeParent = directory(root, 'store');
  const walletParent = directory(root, 'wallet');
  const journalParent = directory(root, 'journal');
  return {
    root,
    config: {
      schema: V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA,
      productDataDirectory: root,
      deploymentDirectory,
      runtimeCacheRoot,
      nativeProverDirectory,
      proofWorkspaceDirectory,
      storeDatabasePath: path.join(storeParent, 'store.sqlite'),
      walletDatabasePath: path.join(walletParent, 'wallet.sqlite'),
      journalDatabasePath: path.join(journalParent, 'journal.sqlite'),
    },
  };
}

function testDependencies(events) {
  const initialState = encodeStateNftCommitment(createDirectV2PoolModel({
    profileId, maximumLiveNotes: '32', denominationSats: '10000000',
  }).state, { denominationSats: '10000000' });
  const genesis = Object.freeze({
    profileId, instanceId, initialState, initialStateSha256: 'aa'.repeat(32),
    genesisOutpoint: Object.freeze({ txid, vout: 0 }), zeroConfEvidenceSha256,
  });
  const unboundRuntime = Object.freeze({
    identity: Object.freeze({ profileId, instanceId, maximumLiveNotes: '32', denominationSats: '10000000' }),
    runtimeMaterialSha256, runtimeManifestSha256,
  });
  const makeStore = () => {
    let binding;
    return {
      initialize(value) { events.push('store.initialize'); binding = value; },
      binding() { return Object.freeze({ profileId: Buffer.from(binding.profileId), instanceId: Buffer.from(binding.instanceId), networkId: binding.networkId, denominationSats: binding.denominationSats, runtimeMaterialSha256: Buffer.from(binding.runtimeMaterialSha256), runtimeManifestSha256: Buffer.from(binding.runtimeManifestSha256), deploymentZeroConfEvidenceSha256: Buffer.from(binding.deploymentZeroConfEvidenceSha256) }); },
      assertBootstrapFundingComplete() { return Object.freeze({ sourceTransactionId: Buffer.alloc(32, 0x51), outputCount: 10, setSha256: Buffer.alloc(32, 0x52) }); },
      close() { events.push('store.close'); },
    };
  };
  return Object.freeze({
    assertGenesis: (value) => value === genesis ? value : (() => { throw new Error('unbranded genesis'); })(),
    assertJournal: (value) => value,
    assertRpc: (value) => value,
    assertRuntime: (value) => value,
    assertWallet: (value) => value,
    bindRuntime: (value, binding) => Object.freeze({ ...value, descriptorSha256: binding.descriptorSha256, manifestSha256: binding.manifestSha256 }),
    deriveProfileCore: () => testProfileCore,
    loadArtifacts: async ({ productDataDirectory }) => {
      assert.equal(typeof productDataDirectory, 'string');
      return Object.freeze({ installed: true });
    },
    loadGenesis: () => genesis,
    loadNative: async ({ artifactInstallation }) => { assert.equal(artifactInstallation.installed, true); return Object.freeze({ schema: 'test-native-installation', installationDirectory: '/tmp/native', manifestSha256: '66'.repeat(32), binary: Object.freeze({ path: '/tmp/native/rapidsnark', bytes: 1, sha256: '67'.repeat(32), identity: Object.freeze({ dev: '1', ino: '1', mode: '33252', uid: '1', gid: '1', size: '1', nlink: '1', mtimeNs: '1', ctimeNs: '1', birthtimeNs: '1' }) }) }); },
    loadRuntime: async ({ artifactInstallation, instanceId: requested }) => {
      assert.equal(artifactInstallation.installed, true);
      assert.equal(requested, instanceId);
      return unboundRuntime;
    },
    openJournal: () => ({ close() { events.push('journal.close'); } }),
    openStore: () => makeStore(),
    openWallet: () => ({ publicSummary: () => ({ profileId, instanceId }), close() { events.push('wallet.close'); } }),
  });
}

function initializePersistentStore(store) {
  const initialState = encodeStateNftCommitment(createDirectV2PoolModel({
    profileId, maximumLiveNotes: '32', denominationSats: '10000000',
  }).state, { denominationSats: '10000000' });
  store.initialize({
    profileId: Buffer.from(profileId, 'hex'), instanceId: Buffer.from(instanceId, 'hex'),
    networkId: 2, denominationSats: '10000000', state: initialState,
    outpoint: { txid: Buffer.from(txid, 'hex'), vout: 0 },
    acceptanceId: Buffer.from(zeroConfEvidenceSha256, 'hex'),
    runtimeMaterialSha256: Buffer.from(runtimeMaterialSha256, 'hex'),
    runtimeManifestSha256: Buffer.from(runtimeManifestSha256, 'hex'),
    deploymentZeroConfEvidenceSha256: Buffer.from(zeroConfEvidenceSha256, 'hex'),
  });
}

function bootstrapFunding(sourceTransactionId = Buffer.alloc(32, 0x51)) {
  return {
    sourceTransactionId,
    utxos: Array.from({ length: 10 }, (_, index) => ({
      txid: sourceTransactionId,
      vout: index + 1,
      valueSats: index < 5 ? '10000000' : '1000000',
    })),
  };
}

test('validates an exact private, secret-free beta context config', () => {
  const subject = fixture();
  try {
    assert.deepEqual(validateV2BetaProductContextConfig(subject.config), subject.config);
    assert.throws(() => validateV2BetaProductContextConfig({ ...subject.config, fundingPrivateKeyHex: '00'.repeat(32) }), rejects('BETA_CONTEXT_INVALID'));
    assert.throws(() => validateV2BetaProductContextConfig({ ...subject.config, nativeProverDirectory: subject.config.deploymentDirectory }), rejects('BETA_CONTEXT_PATH_REJECTED'));
    assert.throws(() => validateV2BetaProductContextConfig({ ...subject.config, journalDatabasePath: subject.config.storeDatabasePath }), rejects('BETA_CONTEXT_INVALID'));
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('test-only context seam binds committed genesis, warm runtime, and store provenance without a secret', async () => {
  const subject = fixture(); const events = [];
  try {
    const context = await openV2BetaProductContextForTest({ config: subject.config, rpc: Object.freeze({ backend: 'test' }) }, testDependencies(events));
    assert.equal(context.identity.profileId, profileId);
    assert.equal(context.profileCore, testProfileCore);
    assert.equal(context.identity.maximumLiveNotes, '32');
    assert.equal(context.runtime.descriptorSha256, zeroConfEvidenceSha256);
    assert.equal(context.nativeProverInstallation.binary.sha256, '67'.repeat(32));
    assert.deepEqual(events, ['store.initialize']);
    context.close();
    assert.deepEqual(events, ['store.initialize', 'journal.close', 'wallet.close', 'store.close']);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('context maps only a missing linked runtime to the explicit refresh command', async () => {
  const subject = fixture(); const events = [];
  const unavailable = Object.assign(new Error('no current generation'), {
    code: 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE',
  });
  const dependencies = {
    ...testDependencies(events),
    loadRuntime: async () => { throw unavailable; },
  };
  try {
    await assert.rejects(
      () => openV2BetaProductContextForTest({
        config: subject.config,
        rpc: Object.freeze({ backend: 'test' }),
      }, dependencies),
      (error) => error instanceof V2BetaProductContextError
        && error.code === 'BETA_RUNTIME_REFRESH_REQUIRED'
        && error.cause === unavailable
        && error.message.includes('shieldkit pool refresh-runtime --data-home ')
        && error.message.includes(`'${path.dirname(path.dirname(subject.config.productDataDirectory))}'`),
    );
    assert.deepEqual(events, []);
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('runtime refresh guidance single-quotes shell metacharacters and embedded quotes', () => {
  const dataHome = "/tmp/data home/$USER/$(touch nope)/`id`/owner's";
  const command = deriveV2BetaRuntimeRefreshCommandForTest({
    productDataDirectory: path.join(dataHome, 'shieldkit', 'v2-beta-product'),
  });
  assert.equal(
    command,
    `shieldkit pool refresh-runtime --data-home '/tmp/data home/$USER/$(touch nope)/\`id\`/owner'"'"'s'`,
  );
});

test('context preserves invalid, stale, and ambiguous linked runtime failures', async () => {
  for (const code of [
    'BETA_LINKED_RUNTIME_CACHE_INVALID',
    'BETA_LINKED_RUNTIME_CACHE_STALE',
    'BETA_LINKED_RUNTIME_CACHE_AMBIGUOUS',
  ]) {
    const subject = fixture(); const events = [];
    const failure = Object.assign(new Error(code), { code });
    const dependencies = {
      ...testDependencies(events),
      loadRuntime: async () => { throw failure; },
    };
    try {
      await assert.rejects(
        () => openV2BetaProductContextForTest({
          config: subject.config,
          rpc: Object.freeze({ backend: 'test' }),
        }, dependencies),
        (error) => error === failure,
      );
      assert.deepEqual(events, []);
    } finally { rmSync(subject.root, { recursive: true, force: true }); }
  }
});

test('warm context derives native capability from the loaded artifact receipt with zero binary content reads', async () => {
  const subject = fixture(); const events = [];
  try {
    rmSync(path.join(subject.root, 'v2-beta-product-artifacts'), { recursive: true, force: true });
    const sourceRuntime = directory(subject.root, 'source-runtime');
    const sourceCeremony = directory(subject.root, 'source-ceremony');
    const sourceNative = directory(subject.root, 'source-native');
    writeFileSync(path.join(sourceRuntime, 'runtime.bin'), 'runtime\n', { mode: 0o600 }); chmodSync(path.join(sourceRuntime, 'runtime.bin'), 0o600);
    writeFileSync(path.join(sourceCeremony, 'ceremony.bin'), 'ceremony\n', { mode: 0o600 }); chmodSync(path.join(sourceCeremony, 'ceremony.bin'), 0o600);
    writeFileSync(path.join(sourceNative, 'manifest.json'), 'manifest\n', { mode: 0o600 }); chmodSync(path.join(sourceNative, 'manifest.json'), 0o600);
    const bin = directory(sourceNative, 'bin'); writeFileSync(path.join(bin, 'prover'), 'prover\n', { mode: 0o700 }); chmodSync(path.join(bin, 'prover'), 0o700);
    await installV2BetaProductArtifactsForTest({ productDataDirectory: subject.root, sourceRuntimeDirectory: sourceRuntime, ceremonyDirectory: sourceCeremony, nativeProverInstallationDirectory: sourceNative }, { verify: async () => ({ runtime: { manifestSha256: '11'.repeat(32), runtimeMaterialSha256: '12'.repeat(32) }, ceremony: { ceremonyId: 'test', resultSha256: '13'.repeat(32), betaProvingKeySha256: '14'.repeat(32), verificationKeySha256: '15'.repeat(32) }, native: { manifestSha256: hash('manifest\n') }, binary: { sha256: hash('prover\n') } }) });
    const reads = []; const restore = setV2NativeGroth16ProverContentReadObserverForTest((entry) => reads.push(entry));
    try {
      const dependencies = { ...testDependencies(events), loadArtifacts: loadV2BetaProductArtifactInstallation, loadRuntime: async ({ artifactInstallation, instanceId: requested }) => { assert.equal(artifactInstallation.nativeProverInstallationDirectory, subject.config.nativeProverDirectory); assert.equal(requested, instanceId); return Object.freeze({ identity: Object.freeze({ profileId, instanceId, maximumLiveNotes: '32', denominationSats: '10000000' }), runtimeMaterialSha256, runtimeManifestSha256 }); }, loadNative: ({ artifactInstallation }) => deriveV2NativeGroth16ProverInstallationFromProductArtifact(artifactInstallation) };
      const context = await openV2BetaProductContextForTest({ config: subject.config, rpc: Object.freeze({ backend: 'test' }) }, dependencies);
      assert.equal(context.nativeProverInstallation.binary.sha256, hash('prover\n'));
      assert.equal(reads.filter((entry) => entry.label === 'native prover binary').length, 0);
      context.close();
    } finally { restore(); }
  } finally { rmSync(subject.root, { recursive: true, force: true }); }
});

test('context rejects an initialized store with no bootstrap funding marker', async () => {
  const subject = fixture(); const events = [];
  const store = openV2BetaIncrementalStore({ databasePath: subject.config.storeDatabasePath });
  const dependencies = { ...testDependencies(events), openStore: () => store };
  try {
    initializePersistentStore(store);
    await assert.rejects(
      () => openV2BetaProductContextForTest({
        config: subject.config, rpc: Object.freeze({ backend: 'test' }),
      }, dependencies),
      rejects('BETA_CONTEXT_STORE_BINDING_REJECTED'),
    );
  } finally { try { store.close(); } catch {} rmSync(subject.root, { recursive: true, force: true }); }
});

test('context rejects a partial bootstrap funding set under its branded store error', async () => {
  const subject = fixture(); const events = [];
  const store = openV2BetaIncrementalStore({ databasePath: subject.config.storeDatabasePath });
  const dependencies = { ...testDependencies(events), openStore: () => store };
  try {
    initializePersistentStore(store);
    const sourceTransactionId = Buffer.alloc(32, 0x51);
    store.putFundingUtxo({ txid: sourceTransactionId, vout: 1, valueSats: '10000000' });
    await assert.rejects(
      () => openV2BetaProductContextForTest({
        config: subject.config, rpc: Object.freeze({ backend: 'test' }),
      }, dependencies),
      rejects('BETA_CONTEXT_STORE_BINDING_REJECTED'),
    );
  } finally { try { store.close(); } catch {} rmSync(subject.root, { recursive: true, force: true }); }
});

test('context rejects a published marker with one bootstrap reserve row missing', async () => {
  const subject = fixture(); const events = [];
  let store = openV2BetaIncrementalStore({ databasePath: subject.config.storeDatabasePath });
  try {
    initializePersistentStore(store);
    store.initializeBootstrapFunding(bootstrapFunding());
    store.close();
    store = null;
    const db = new DatabaseSync(subject.config.storeDatabasePath);
    try { db.exec('DELETE FROM funding_utxos WHERE vout=10'); }
    finally { db.close(); }
    const dependencies = {
      ...testDependencies(events),
      openStore: ({ databasePath }) => openV2BetaIncrementalStore({ databasePath }),
    };
    await assert.rejects(
      () => openV2BetaProductContextForTest({
        config: subject.config, rpc: Object.freeze({ backend: 'test' }),
      }, dependencies),
      rejects('BETA_CONTEXT_STORE_BINDING_REJECTED'),
    );
  } finally { try { store?.close(); } catch {} rmSync(subject.root, { recursive: true, force: true }); }
});

test('context rejects a bootstrap marker whose persisted reserve digest is corrupted', async () => {
  const subject = fixture(); const events = [];
  let store = openV2BetaIncrementalStore({ databasePath: subject.config.storeDatabasePath });
  try {
    initializePersistentStore(store);
    store.initializeBootstrapFunding(bootstrapFunding());
    store.close();
    store = null;
    const db = new DatabaseSync(subject.config.storeDatabasePath);
    try { db.exec("UPDATE funding_utxos SET value_sats='9999999' WHERE vout=1"); }
    finally { db.close(); }
    const dependencies = {
      ...testDependencies(events),
      openStore: ({ databasePath }) => openV2BetaIncrementalStore({ databasePath }),
    };
    await assert.rejects(
      () => openV2BetaProductContextForTest({
        config: subject.config, rpc: Object.freeze({ backend: 'test' }),
      }, dependencies),
      rejects('BETA_CONTEXT_STORE_BINDING_REJECTED'),
    );
  } finally { try { store?.close(); } catch {} rmSync(subject.root, { recursive: true, force: true }); }
});

test('context preserves the ten pool-create bootstrap reserves for the first deposit', async () => {
  const subject = fixture(); const events = [];
  const store = openV2BetaIncrementalStore({ databasePath: subject.config.storeDatabasePath });
  try {
    initializePersistentStore(store);
    store.initializeBootstrapFunding(bootstrapFunding());
    const dependencies = { ...testDependencies(events), openStore: () => store };
    const context = await openV2BetaProductContextForTest({
      config: subject.config, rpc: Object.freeze({ backend: 'test' }),
    }, dependencies);
    assert.equal(context.store.availableFundingUtxos().length, 10);
    assert.equal(context.store.availableFundingUtxos()[0].vout, 1);
    context.close();
  } finally { try { store.close(); } catch {} rmSync(subject.root, { recursive: true, force: true }); }
});
