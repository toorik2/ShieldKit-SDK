/**
 * Secret-free assembly boundary for a locally committed V2 beta deployment.
 * It deliberately returns resources for a future lifecycle constructor rather
 * than creating or sending an action itself.
 */
import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { decodeStateNftCommitment } from '../../action/v2/state.mjs';
import { assertBchnChipnetRpc } from '../chipnet-rpc.mjs';
import {
  assertV2BetaChipnetCommittedGenesisCapability,
  loadV2BetaChipnetCommittedGenesis,
} from '../../profile/v2/beta-chipnet-deployment.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  bindV2BetaChipnetRuntimeResolution,
  deriveV2BetaChipnetProfileCore,
  loadV2BetaProductLinkedRuntimeCache,
} from '../../profile/v2/beta-chipnet-runtime.mjs';
import {
  loadV2BetaProductArtifactInstallation,
} from '../../profile/v2/beta-product-artifact-installation.mjs';
import { openV2BetaIncrementalStore } from '../../profile/v2/beta-incremental-store.mjs';
import { assertV2BetaProductWallet, openV2BetaProductWallet } from './beta-product-wallet.mjs';
import { assertV2DeliveryJournal, openV2DeliveryJournal } from './delivery-journal.mjs';

export const V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA =
  'shieldkit-v2-beta-product-context-config-v1';

const HASH = /^[0-9a-f]{64}$/u;
const productContexts = new WeakSet();

export class V2BetaProductContextError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductContextError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductContextError(code, message, options);
};

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_CONTEXT_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_CONTEXT_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
    || path.normalize(value) !== value || value.includes('\0')) {
    fail('BETA_CONTEXT_INVALID', `${label} must be a normalized absolute path`);
  }
  return value;
}

function privateDirectory(value, label) {
  const directory = absolute(value, label);
  let stat;
  try { stat = lstatSync(directory); }
  catch (error) { fail('BETA_CONTEXT_PATH_REJECTED', `${label} is unavailable`, { cause: error }); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700
    || realpathSync(directory) !== directory
    || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    fail('BETA_CONTEXT_PATH_REJECTED', `${label} must be a private canonical owner-controlled directory`);
  }
  return directory;
}

function privateDatabasePath(value, label) {
  const filename = absolute(value, label);
  const parent = privateDirectory(path.dirname(filename), `${label} parent`);
  if (filename === parent || path.basename(filename) === '.') {
    fail('BETA_CONTEXT_INVALID', `${label} must name a database file below its private parent`);
  }
  try {
    const stat = lstatSync(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || (stat.mode & 0o777) !== 0o600 || realpathSync(filename) !== filename
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
      fail('BETA_CONTEXT_PATH_REJECTED', `${label} must be a private canonical single-link file when it exists`);
    }
  } catch (error) {
    if (error instanceof V2BetaProductContextError) throw error;
    if (error?.code !== 'ENOENT') fail('BETA_CONTEXT_PATH_REJECTED', `${label} cannot be inspected`, { cause: error });
  }
  return filename;
}

function descendant(child, parent, label) {
  const relative = path.relative(parent, child);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('BETA_CONTEXT_PATH_REJECTED', `${label} must be a strict descendant of productDataDirectory`);
  }
}

/** Validate only secret-free, private, canonical filesystem configuration. */
export function validateV2BetaProductContextConfig(value) {
  exact(value, [
    'deploymentDirectory', 'journalDatabasePath', 'nativeProverDirectory',
    'productDataDirectory', 'proofWorkspaceDirectory', 'runtimeCacheRoot', 'schema',
    'storeDatabasePath', 'walletDatabasePath',
  ], 'beta product context config');
  if (value.schema !== V2_BETA_PRODUCT_CONTEXT_CONFIG_SCHEMA) {
    fail('BETA_CONTEXT_INVALID', 'beta product context config schema is unsupported');
  }
  const productDataDirectory = privateDirectory(value.productDataDirectory, 'productDataDirectory');
  const config = Object.freeze({
    schema: value.schema,
    productDataDirectory,
    deploymentDirectory: privateDirectory(value.deploymentDirectory, 'deploymentDirectory'),
    runtimeCacheRoot: privateDirectory(value.runtimeCacheRoot, 'runtimeCacheRoot'),
    nativeProverDirectory: privateDirectory(value.nativeProverDirectory, 'nativeProverDirectory'),
    proofWorkspaceDirectory: privateDirectory(value.proofWorkspaceDirectory, 'proofWorkspaceDirectory'),
    storeDatabasePath: privateDatabasePath(value.storeDatabasePath, 'storeDatabasePath'),
    walletDatabasePath: privateDatabasePath(value.walletDatabasePath, 'walletDatabasePath'),
    journalDatabasePath: privateDatabasePath(value.journalDatabasePath, 'journalDatabasePath'),
  });
  for (const name of [
    'deploymentDirectory', 'runtimeCacheRoot', 'nativeProverDirectory',
    'proofWorkspaceDirectory', 'storeDatabasePath', 'walletDatabasePath',
    'journalDatabasePath',
  ]) descendant(config[name], productDataDirectory, name);
  if (config.nativeProverDirectory !== path.join(
    productDataDirectory,
    'v2-beta-product-artifacts',
    'native',
  )) fail('BETA_CONTEXT_PATH_REJECTED', 'nativeProverDirectory differs from the pinned product artifact installation');
  if (new Set([config.storeDatabasePath, config.walletDatabasePath, config.journalDatabasePath]).size !== 3) {
    fail('BETA_CONTEXT_INVALID', 'store, wallet, and journal database paths must be distinct');
  }
  return config;
}

function nativeInstallation(value) {
  exact(value, ['binary', 'installationDirectory', 'manifestSha256', 'schema'], 'native prover installation');
  exact(value.binary, ['bytes', 'identity', 'path', 'sha256'], 'native prover installation.binary');
  if (!path.isAbsolute(value.installationDirectory) || !path.isAbsolute(value.binary.path)
    || !HASH.test(value.manifestSha256) || !HASH.test(value.binary.sha256)) {
    fail('BETA_CONTEXT_NATIVE_REJECTED', 'native prover installation did not expose exact installation and binary pins');
  }
  // Preserve the loader object itself: the proof worker consumes its WeakMap
  // brand and requires this exact install-time receipt identity.
  return value;
}

async function productionNativeInstallation({ artifactInstallation }) {
  let native;
  try {
    native = await import('../../prove/v2/native-groth16-prover-installation.mjs');
  } catch (error) {
    fail('BETA_CONTEXT_NATIVE_INSTALLATION_UNAVAILABLE', 'native-groth16-prover-installation.mjs is required before a production beta context can open', { cause: error });
  }
  if (typeof native.deriveV2NativeGroth16ProverInstallationFromProductArtifact !== 'function'
    || typeof native.consumeV2NativeGroth16ProverInstallation !== 'function') {
    fail('BETA_CONTEXT_NATIVE_INSTALLATION_UNAVAILABLE', 'native prover installation module does not export the required receipt derivation and consumer capability boundary');
  }
  const installation = await native.deriveV2NativeGroth16ProverInstallationFromProductArtifact(artifactInstallation);
  return nativeInstallation(installation);
}

function assertRuntimeGenesisAgreement(genesis, runtime, assertGenesis, assertRuntime) {
  try { assertGenesis(genesis); assertRuntime(runtime); }
  catch (error) { fail('BETA_CONTEXT_CAPABILITY_REJECTED', 'deployment genesis or cached runtime capability is unbranded', { cause: error }); }
  let decoded;
  try { decoded = decodeStateNftCommitment(genesis.initialState, { denominationSats: runtime.identity.denominationSats }); }
  catch (error) { fail('BETA_CONTEXT_GENESIS_REJECTED', 'committed genesis state cannot be decoded under the cached runtime denomination', { cause: error }); }
  if (runtime.identity?.profileId !== genesis.profileId || runtime.identity?.instanceId !== genesis.instanceId
    || runtime.identity?.maximumLiveNotes !== decoded.maximumLiveNotes
    || decoded.profileId !== genesis.profileId || decoded.actionSequence !== '0'
    || runtime.descriptorSha256 !== genesis.zeroConfEvidenceSha256
    || runtime.manifestSha256 !== runtime.runtimeManifestSha256
    || !HASH.test(runtime.runtimeMaterialSha256) || !HASH.test(runtime.runtimeManifestSha256)) {
    fail('BETA_CONTEXT_BINDING_REJECTED', 'committed genesis, zero-conf evidence, and warm runtime identity/hash/capacity bindings differ');
  }
  return Object.freeze({
    profileId: genesis.profileId,
    instanceId: genesis.instanceId,
    maximumLiveNotes: decoded.maximumLiveNotes,
    denominationSats: runtime.identity.denominationSats,
  });
}

function assertStoreProvenance(store, expected) {
  const binding = store.binding();
  if (!Buffer.from(binding.profileId).equals(Buffer.from(expected.profileId, 'hex'))
    || !Buffer.from(binding.instanceId).equals(Buffer.from(expected.instanceId, 'hex'))
    || binding.networkId !== 2 || binding.denominationSats !== expected.denominationSats
    || !Buffer.from(binding.runtimeMaterialSha256).equals(Buffer.from(expected.runtimeMaterialSha256, 'hex'))
    || !Buffer.from(binding.runtimeManifestSha256).equals(Buffer.from(expected.runtimeManifestSha256, 'hex'))
    || !Buffer.from(binding.deploymentZeroConfEvidenceSha256).equals(Buffer.from(expected.deploymentZeroConfEvidenceSha256, 'hex'))) {
    fail('BETA_CONTEXT_STORE_BINDING_REJECTED', 'incremental store immutable genesis/runtime/deployment provenance differs');
  }
}

function closeAll(resources) {
  let first;
  for (const resource of [resources.journal, resources.wallet, resources.store]) {
    try { resource?.close?.(); } catch (error) { first ??= error; }
  }
  if (first) throw first;
}

function shellSingleQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function runtimeRefreshCommand(config) {
  const dataHome = path.dirname(path.dirname(config.productDataDirectory));
  return `shieldkit pool refresh-runtime --data-home ${shellSingleQuote(dataHome)}`;
}

/** Pure test seam for the copy/paste-safe local remediation command. */
export function deriveV2BetaRuntimeRefreshCommandForTest(config) {
  return runtimeRefreshCommand(config);
}

function productionDependencies() {
  return Object.freeze({
    loadGenesis: loadV2BetaChipnetCommittedGenesis,
    assertGenesis: assertV2BetaChipnetCommittedGenesisCapability,
    loadArtifacts: loadV2BetaProductArtifactInstallation,
    loadRuntime: loadV2BetaProductLinkedRuntimeCache,
    bindRuntime: bindV2BetaChipnetRuntimeResolution,
    deriveProfileCore: deriveV2BetaChipnetProfileCore,
    assertRuntime: assertV2BetaChipnetRuntimeResolution,
    loadNative: productionNativeInstallation,
    openStore: openV2BetaIncrementalStore,
    openWallet: openV2BetaProductWallet,
    assertWallet: assertV2BetaProductWallet,
    openJournal: openV2DeliveryJournal,
    assertJournal: assertV2DeliveryJournal,
    assertRpc: assertBchnChipnetRpc,
  });
}

function testDependencies(value) {
  exact(value, ['assertGenesis', 'assertJournal', 'assertRpc', 'assertRuntime', 'assertWallet', 'bindRuntime', 'deriveProfileCore', 'loadArtifacts', 'loadGenesis', 'loadNative', 'loadRuntime', 'openJournal', 'openStore', 'openWallet'], 'beta product context test dependencies');
  for (const [name, fn] of Object.entries(value)) if (typeof fn !== 'function') fail('BETA_CONTEXT_INVALID', `${name} test dependency must be a function`);
  return Object.freeze({ ...value });
}

async function openContext(value, dependencies) {
  exact(value, ['config', 'rpc'], 'beta product context open options');
  const config = validateV2BetaProductContextConfig(value.config);
  let rpc;
  try { rpc = dependencies.assertRpc(value.rpc); }
  catch (error) { fail('BETA_CONTEXT_RPC_REJECTED', 'a branded Chipnet product RPC is required', { cause: error }); }
  const genesis = dependencies.loadGenesis({ deploymentDirectory: config.deploymentDirectory });
  dependencies.assertGenesis(genesis);
  const artifactInstallation = await dependencies.loadArtifacts({
    productDataDirectory: config.productDataDirectory,
  });
  let unboundRuntime;
  try {
    unboundRuntime = await dependencies.loadRuntime({
      artifactInstallation,
      cacheRoot: config.runtimeCacheRoot,
      instanceId: genesis.instanceId,
    });
  } catch (error) {
    if (error?.code === 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE') {
      fail(
        'BETA_RUNTIME_REFRESH_REQUIRED',
        `linked runtime cache is unavailable; run ${runtimeRefreshCommand(config)}`,
        { cause: error },
      );
    }
    throw error;
  }
  dependencies.assertRuntime(unboundRuntime);
  const runtime = dependencies.bindRuntime(unboundRuntime, {
    descriptorSha256: genesis.zeroConfEvidenceSha256,
    manifestSha256: unboundRuntime.runtimeManifestSha256,
  });
  dependencies.assertRuntime(runtime);
  const profileCore = dependencies.deriveProfileCore(runtime);
  const identity = assertRuntimeGenesisAgreement(genesis, runtime, dependencies.assertGenesis, dependencies.assertRuntime);
  const nativeProverInstallation = await dependencies.loadNative({ artifactInstallation });
  let store; let wallet; let journal;
  try {
    // Never pass a key into this persistence API: its first-open mode stores
    // the supplied key, which is outside this context's secret-free contract.
    wallet = dependencies.openWallet({ databasePath: config.walletDatabasePath, profileId: identity.profileId, instanceId: identity.instanceId });
    dependencies.assertWallet(wallet);
    const walletIdentity = wallet.publicSummary();
    if (walletIdentity.profileId !== identity.profileId || walletIdentity.instanceId !== identity.instanceId) {
      fail('BETA_CONTEXT_WALLET_BINDING_REJECTED', 'wallet identity differs from committed deployment identity');
    }
    journal = dependencies.openJournal(config.journalDatabasePath);
    dependencies.assertJournal(journal);
    store = dependencies.openStore({ databasePath: config.storeDatabasePath });
    store.initialize({
      profileId: Buffer.from(identity.profileId, 'hex'),
      instanceId: Buffer.from(identity.instanceId, 'hex'),
      networkId: 2,
      denominationSats: identity.denominationSats,
      state: Buffer.from(genesis.initialState),
      outpoint: { txid: Buffer.from(genesis.genesisOutpoint.txid, 'hex'), vout: genesis.genesisOutpoint.vout },
      // The durable accepted zero-conf evidence is the unique genesis-tip acceptance anchor.
      acceptanceId: Buffer.from(genesis.zeroConfEvidenceSha256, 'hex'),
      runtimeMaterialSha256: Buffer.from(runtime.runtimeMaterialSha256, 'hex'),
      runtimeManifestSha256: Buffer.from(runtime.runtimeManifestSha256, 'hex'),
      deploymentZeroConfEvidenceSha256: Buffer.from(genesis.zeroConfEvidenceSha256, 'hex'),
    });
    assertStoreProvenance(store, {
      ...identity,
      runtimeMaterialSha256: runtime.runtimeMaterialSha256,
      runtimeManifestSha256: runtime.runtimeManifestSha256,
      deploymentZeroConfEvidenceSha256: genesis.zeroConfEvidenceSha256,
    });
    if (typeof store.assertBootstrapFundingComplete !== 'function') {
      fail('BETA_CONTEXT_STORE_BINDING_REJECTED', 'incremental store lacks the atomic bootstrap-funding completeness gate');
    }
    let bootstrapFunding;
    try { bootstrapFunding = store.assertBootstrapFundingComplete(); }
    catch (error) {
      fail(
        'BETA_CONTEXT_STORE_BINDING_REJECTED',
        'incremental store bootstrap-funding set is absent, partial, or changed',
        { cause: error },
      );
    }
    if (bootstrapFunding?.outputCount !== 10
      || !(bootstrapFunding.sourceTransactionId instanceof Uint8Array)
      || bootstrapFunding.sourceTransactionId.length !== 32
      || !(bootstrapFunding.setSha256 instanceof Uint8Array)
      || bootstrapFunding.setSha256.length !== 32) {
      fail('BETA_CONTEXT_STORE_BINDING_REJECTED', 'incremental store bootstrap-funding marker is invalid');
    }
  } catch (error) {
    try { closeAll({ store, wallet, journal }); } catch { /* preserve the opening error */ }
    throw error;
  }
  let closed = false;
  const context = Object.freeze({
    config,
    identity,
    deployment: genesis,
    runtime,
    profileCore,
    nativeProverInstallation,
    store,
    wallet,
    journal,
    rpc,
    proofWorkspaceDirectory: config.proofWorkspaceDirectory,
    close() {
      if (!closed) { closed = true; closeAll({ store, wallet, journal }); }
    },
  });
  productContexts.add(context);
  return context;
}

/** Production factory: it contains no dependency injection or test fallback. */
export async function openV2BetaProductContext(value) {
  return openContext(value, productionDependencies());
}

/** Reject structural lookalikes at the production session boundary. */
export function assertV2BetaProductContext(value) {
  if (!productContexts.has(value)) {
    fail('BETA_CONTEXT_CAPABILITY_REJECTED', 'a context issued by the beta product context factory is required');
  }
  return value;
}

/** Explicit test-only seam for unit tests; never call from production code. */
export async function openV2BetaProductContextForTest(value, injectedDependencies) {
  return openContext(value, testDependencies(injectedDependencies));
}
