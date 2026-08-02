/**
 * Warm, instance-specific V2 beta Chipnet pool creation.
 *
 * This module is deliberately only the consumer of a fully verified,
 * instance-bound runtime/cache. It never compiles a covenant, generates
 * qualification fixtures, or falls back to an unverified artifact. The exact
 * signed bootstrap is held by the funding capability until the genesis package
 * has been independently finalized and staged by the deployment coordinator.
 */
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import path from 'node:path';

import {
  acceptV2BetaChipnetZeroConfDeployment,
  broadcastV2BetaChipnetDeployment,
  commitV2BetaChipnetDeployment,
  deriveV2BetaChipnetDeploymentBinding,
  loadV2BetaChipnetCommittedGenesis,
  loadV2BetaChipnetDeploymentRecovery,
  stageV2BetaChipnetDeployment,
  V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
} from '../../profile/v2/beta-chipnet-deployment.mjs';
import {
  assertV2BetaChipnetRuntimeResolution,
  deriveV2BetaChipnetProfileCore,
  deriveV2BetaChipnetSettlementPins,
  installV2BetaProductLinkedRuntimeCache,
  loadV2BetaProductLinkedRuntimeCache,
  loadV2BetaProductLinkedRuntimeTemplate,
} from '../../profile/v2/beta-chipnet-runtime.mjs';
import {
  loadV2BetaProductArtifactInstallation,
} from '../../profile/v2/beta-product-artifact-installation.mjs';
import {
  assertV2BetaPoolCreateRuntimeWork,
  observeV2BetaRuntimeWork,
} from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS,
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DUST_SATS,
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS,
} from '../../profile/v2/beta-chipnet-funding.mjs';
import {
  createV2BetaChipnetGenesisRuntimeFromResolution,
  deriveV2FinalizedGenesisPackagePins,
} from '../../profile/v2/genesis.mjs';
import {
  createOrLoadV2BetaProductConfig,
} from './beta-product-config.mjs';
import {
  assertV2BetaProductPoolFundingCapability,
  consumeV2BetaProductPoolCreateRpc,
  createV2BetaProductPoolCreateRpc,
  createV2BetaProductPoolFundingWithPoolCreateRpc,
  recoverV2BetaProductPoolFunding,
  V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
  V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS,
  V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
} from './beta-product-pool-funding.mjs';
import { observeLayer1BchnChipnetRpc } from '../chipnet-rpc.mjs';
import {
  openV2BetaProductPoolCreateJournal,
} from './beta-product-pool-create-journal.mjs';
import {
  openV2BetaIncrementalStore,
} from '../../profile/v2/beta-incremental-store.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';
import {
  authenticateV2Pf10ReceiptLinkedRuntimeTemplate,
  relocateV2Pf10BetaRuntime,
} from '../../unlock-builder/v2/pf10-instance-specializer.mjs';

export const V2_BETA_PRODUCT_POOL_CREATE_RESULT_SCHEMA =
  'shieldkit-v2-beta-product-pool-create-result-v1';
export const V2_BETA_PRODUCT_CAPACITY = '100000';

const HASH = /^[0-9a-f]{64}$/u;
const REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../..');

export class V2BetaProductPoolCreateError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductPoolCreateError';
    this.code = code;
    this.recoverable = options?.recoverable === true;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductPoolCreateError(code, message, options);
};

function exactOptional(value, allowed, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => !allowed.includes(key))) {
    fail('BETA_POOL_CREATE_INVALID', `${label} has unknown properties or is not a plain object`);
  }
  return value;
}

function now() { return performance.now(); }

function fundingRequired(funding, started, request, rpcObservation) {
  const command = [
    'shieldkit', 'pool', 'create',
    ...(request.dataHome === undefined ? [] : ['--data-home', request.dataHome]),
    '--funding-txid', '<64-lowercase-hex-bchn-transaction-id>',
  ].join(' ');
  return Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_CREATE_RESULT_SCHEMA,
    status: 'funding-required',
    command: 'pool-create',
    capacity: V2_BETA_PRODUCT_CAPACITY,
    fundingAddress: funding.fundingWallet.cashAddress,
    fundingWallet: funding.fundingWallet,
    required: funding.required,
    rerunCommand: command,
    claims: Object.freeze({
      broadcasted: false,
      confirmed: false,
      mined: false,
      productionQualified: false,
    }),
    rpcObservation,
    timingsMs: Object.freeze({ commandTotal: now() - started }),
  });
}

function fundingJournalBinding(bootstrap) {
  const outpoint = bootstrap?.sourceFundingOutpoint;
  const lockingBytecodeHex = bootstrap?.fundingWallet?.lockingBytecodeHex;
  if (!HASH.test(outpoint?.transactionId)
    || !Number.isSafeInteger(outpoint?.outputIndex)
    || outpoint.outputIndex < 0 || outpoint.outputIndex > 0xffff_ffff
    || typeof lockingBytecodeHex !== 'string'
    || !/^76a914[0-9a-f]{40}88ac$/u.test(lockingBytecodeHex)) {
    fail('BETA_POOL_FUNDING_REJECTED', 'bootstrap lacks an exact user funding outpoint and P2PKH lock binding');
  }
  return Object.freeze({
    fundingLockingBytecodeSha256: createHash('sha256').update(Buffer.from(lockingBytecodeHex, 'hex')).digest('hex'),
    fundingOutpointTransactionId: outpoint.transactionId,
    fundingOutpointVout: outpoint.outputIndex,
  });
}

const OBSERVED_RPC_METHODS = Object.freeze([
  'getblockhash', 'getrawtransaction', 'gettxout', 'scantxoutset',
  'sendrawtransaction', 'testmempoolaccept',
]);

function rpcObservation(value, label) {
  exactOptional(value, ['backend', 'genesis', 'methodCounts'], label);
  if (value.backend !== 'layer1-bchn-chipnet' || !HASH.test(value.genesis)) {
    fail('BETA_POOL_RPC_OBSERVATION_REJECTED', `${label} has an unexpected backend or genesis`);
  }
  exactOptional(value.methodCounts, OBSERVED_RPC_METHODS, `${label} method counts`);
  for (const method of OBSERVED_RPC_METHODS) {
    if (!Number.isSafeInteger(value.methodCounts[method]) || value.methodCounts[method] < 0) {
      fail('BETA_POOL_RPC_OBSERVATION_REJECTED', `${label} count ${method} is invalid`);
    }
  }
  return Object.freeze({
    backend: value.backend,
    genesis: value.genesis,
    methodCounts: Object.freeze({ ...value.methodCounts }),
  });
}

function oneShotAdmissionObservation(before, after) {
  const prior = rpcObservation(before, 'pre-admission RPC observation');
  const current = rpcObservation(after, 'post-admission RPC observation');
  if (prior.backend !== current.backend || prior.genesis !== current.genesis) {
    fail('BETA_POOL_RPC_OBSERVATION_REJECTED', 'RPC backend or genesis changed during zero-conf admission');
  }
  const delta = Object.fromEntries(OBSERVED_RPC_METHODS.map((method) => [
    method, current.methodCounts[method] - prior.methodCounts[method],
  ]));
  if (delta.getblockhash !== 0 || delta.scantxoutset !== 0
    || delta.getrawtransaction !== 2 || delta.gettxout !== 1
    || delta.testmempoolaccept !== 2 || delta.sendrawtransaction !== 2) {
    fail('BETA_POOL_RPC_OBSERVATION_REJECTED', 'the exact two-transaction pool-create package requires one testmempoolaccept/send per transaction, two raw readbacks, and one state-output readback');
  }
  return Object.freeze({
    backend: current.backend,
    genesis: current.genesis,
    methodCounts: Object.freeze(delta),
  });
}

function assertBootstrapRuntime(binding, runtime) {
  if (binding === null || typeof binding !== 'object'
    || !HASH.test(binding.sourceTransactionId)
    || !HASH.test(binding.instanceId)
    || !HASH.test(binding.rawTransactionSha256)
    || runtime.identity?.instanceId !== binding.instanceId
    || runtime.identity?.maximumLiveNotes !== V2_BETA_PRODUCT_CAPACITY) {
    fail(
      'BETA_POOL_RUNTIME_REJECTED',
      'the receipt-authenticated linked runtime is not bound to this exact signed bootstrap and 100000-note capacity',
      { recoverable: true },
    );
  }
}

function isLinkedCacheUnavailable(error) {
  return error?.code === 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE';
}

async function loadOrCreateLinkedRuntime({ bootstrap, config }, dependencies) {
  const timings = {
    artifactLoad: 0,
    templateLoad: 0,
    templateReceiptAttestation: 0,
    instanceSpecialization: 0,
    runtimeCacheInstall: 0,
    runtimeLoad: 0,
  };
  const artifactStarted = now();
  let artifactInstallation;
  try {
    artifactInstallation = await dependencies.loadArtifactInstallation({
      productDataDirectory: config.dataDirectory,
    });
  } catch (error) {
    fail(
      'BETA_POOL_ARTIFACT_INSTALLATION_REQUIRED',
      'the once-verified pinned V2 beta product artifacts are unavailable or changed',
      { cause: error, recoverable: true },
    );
  }
  timings.artifactLoad = now() - artifactStarted;
  const load = async () => {
    const started = now();
    try {
      const resolution = await dependencies.loadRuntime({
        artifactInstallation,
        cacheRoot: config.runtimeCacheRoot,
        instanceId: bootstrap.instanceId,
      });
      dependencies.assertRuntime(resolution);
      return resolution;
    } finally {
      timings.runtimeLoad += now() - started;
    }
  };
  try {
    return Object.freeze({
      runtimeResolution: await load(),
      linkedNow: false,
      timings: Object.freeze({ ...timings }),
    });
  } catch (error) {
    if (!isLinkedCacheUnavailable(error)) {
      fail('BETA_POOL_RUNTIME_REJECTED', 'the exact linked runtime cache is invalid or stale', {
        cause: error,
        recoverable: true,
      });
    }
  }

  let linkedTemplate;
  const templateStarted = now();
  try {
    linkedTemplate = await dependencies.loadTemplate({ artifactInstallation });
  } catch (error) {
    fail('BETA_POOL_RUNTIME_REJECTED', 'the receipt-authenticated linker template is unavailable', {
      cause: error,
      recoverable: true,
    });
  } finally {
    timings.templateLoad = now() - templateStarted;
  }
  let templateCapability;
  const authenticationStarted = now();
  try {
    templateCapability = await dependencies.attestTemplate({ linkedTemplate });
  } catch (error) {
    fail('BETA_POOL_RUNTIME_REJECTED', 'the retained PF10 linker template failed its exact source attestation', {
      cause: error,
      recoverable: true,
    });
  } finally {
    timings.templateReceiptAttestation = now() - authenticationStarted;
  }
  let specializedRuntime;
  const specializationStarted = now();
  try {
    specializedRuntime = await dependencies.specializeRuntime({
      instanceId: bootstrap.instanceId,
      templateCapability,
    });
  } catch (error) {
    fail('BETA_POOL_RUNTIME_REJECTED', 'exact PF10 specialization for the signed bootstrap failed', {
      cause: error,
      recoverable: true,
    });
  } finally {
    timings.instanceSpecialization = now() - specializationStarted;
  }
  const installStarted = now();
  try {
    await dependencies.installRuntime({
      artifactInstallation,
      cacheRoot: config.runtimeCacheRoot,
      specializedRuntime,
    });
  } catch (error) {
    // A concurrent command may have atomically installed the same deterministic
    // instance cache. Only the subsequent exact loader may resolve that race.
    try {
      const runtimeResolution = await load();
      timings.runtimeCacheInstall = now() - installStarted;
      return Object.freeze({
        runtimeResolution,
        linkedNow: false,
        timings: Object.freeze({ ...timings }),
      });
    } catch (loadError) {
      fail('BETA_POOL_RUNTIME_REJECTED', 'the exact linked runtime cache could not be installed', {
        cause: new AggregateError([error, loadError], 'linked runtime install and race recovery both failed'),
        recoverable: true,
      });
    }
  }
  timings.runtimeCacheInstall = now() - installStarted;
  let runtimeResolution;
  try {
    runtimeResolution = await load();
  } catch (error) {
    fail('BETA_POOL_RUNTIME_REJECTED', 'the newly installed linked runtime cache failed exact reload', {
      cause: error,
      recoverable: true,
    });
  }
  return Object.freeze({
    runtimeResolution,
    linkedNow: true,
    timings: Object.freeze({ ...timings }),
  });
}

function assertRecoveredBootstrap(recovery, binding) {
  if (recovery === null) return;
  if (typeof recovery !== 'object'
    || typeof recovery.operationId !== 'string' || recovery.operationId.length === 0
    || recovery.record?.source?.transactionId !== binding.sourceTransactionId
    || recovery.record?.source?.rawTransactionSha256 !== binding.rawTransactionSha256
    || typeof recovery.sourceFundingRawTxHex !== 'string'
    || typeof recovery.genesisRawTxHex !== 'string') {
    fail(
      'BETA_POOL_RECOVERY_REJECTED',
      'the recovered deployment does not bind the exact retained bootstrap and operation',
      { recoverable: true },
    );
  }
}

function assertRecoveredCoordinatorOperation(recovery, staged) {
  if (recovery === null) return;
  if (staged?.operationId !== recovery.operationId) {
    fail(
      'BETA_POOL_RECOVERY_REJECTED',
      'deployment coordinator operation differs from the exact retained recovery operation',
      { recoverable: true },
    );
  }
}

function assertRecoveredPackage(recovery, packageValue, finalized) {
  if (recovery === null) return;
  const sourceHex = Buffer.from(packageValue.rawSourceTransaction).toString('hex');
  const genesisHex = Buffer.from(packageValue.rawGenesisTransaction).toString('hex');
  if (sourceHex !== recovery.sourceFundingRawTxHex
    || genesisHex !== recovery.genesisRawTxHex
    || finalized.source.transactionId !== recovery.record.source.transactionId
    || finalized.genesis.transactionId !== recovery.record.genesis.transactionId) {
    fail(
      'BETA_POOL_RECOVERY_REJECTED',
      'the rebuilt deployment package differs from exact durable recovery bytes or transaction bindings',
      { recoverable: true },
    );
  }
}

function projectGenesisSettlementPins(value) {
  const runtimeKeys = [
    'bindingBaseSats', 'bindingLockingBytecode', 'bindingRedeemBytecode',
    'stateBaseSats', 'stateHelperBytecode', 'stateLockingBytecode',
    'stateUnlockingBytecode', 'topologyId', 'verifierCarriers', 'verifierRoles',
  ];
  exactOptional(value, runtimeKeys, 'beta runtime settlement pins');
  if (Object.keys(value).length !== runtimeKeys.length
    || !Array.isArray(value.verifierRoles)
    || !Array.isArray(value.verifierCarriers)) {
    fail(
      'BETA_POOL_RUNTIME_REJECTED',
      'the linked runtime did not provide the complete authenticated settlement pins',
      { recoverable: true },
    );
  }
  // The deployment package intentionally carries only public settlement
  // locks and base values. The state helper and state unlock remain private to
  // the branded runtime/genesis capability and are not part of that schema.
  return Object.freeze({
    topologyId: value.topologyId,
    verifierRoles: Object.freeze([...value.verifierRoles]),
    verifierCarriers: Object.freeze(value.verifierCarriers.map((entry) => Object.freeze({
      baseValueSats: entry.baseValueSats,
      lockingBytecode: Buffer.from(entry.lockingBytecode),
    }))),
    bindingBaseSats: value.bindingBaseSats,
    bindingLockingBytecode: Buffer.from(value.bindingLockingBytecode),
    bindingRedeemBytecode: Buffer.from(value.bindingRedeemBytecode),
    stateBaseSats: value.stateBaseSats,
    stateLockingBytecode: Buffer.from(value.stateLockingBytecode),
  });
}

function packagedGenesis(finalized, genesisRuntime, runtimeResolution, dependencies) {
  const pins = dependencies.deriveGenesisPins(finalized, genesisRuntime);
  const settlementPins = projectGenesisSettlementPins(
    dependencies.deriveSettlementPins(runtimeResolution),
  );
  return Object.freeze({
    descriptor: Object.freeze({
      profileId: pins.profileId,
      instanceId: pins.instanceId,
      genesis: Object.freeze({
        transactionId: pins.genesis.transactionId,
        outpointIndex: pins.genesis.outputIndex,
      }),
      initialState: Buffer.from(pins.initialStateHex, 'hex'),
    }),
    rawGenesisTransaction: Buffer.from(pins.genesis.rawTransactionHex, 'hex'),
    rawSourceTransaction: Buffer.from(pins.source.rawTransactionHex, 'hex'),
    settlementPins,
  });
}

function assertAccepted(value) {
  if (value?.accepted !== true
    || value.status !== 'accepted-zero-conf'
    || value.evidence?.status !== 'accepted-zero-conf-beta-unqualified'
    || value.evidence?.claims?.broadcasted !== true
    || value.evidence?.claims?.confirmed !== false
    || value.evidence?.claims?.mined !== false
    || value.evidence?.claims?.productionQualified !== false) {
    fail(
      'BETA_POOL_ZERO_CONF_PENDING',
      'BCHN did not expose the exact bootstrap, genesis, and state NFT in its zero-conf view; no local success was committed',
      { recoverable: true },
    );
  }
  return value;
}

function bootstrapFundingSources({ bootstrap, rawTransaction, wallet }) {
  if (!(rawTransaction instanceof Uint8Array)
    || !HASH.test(bootstrap?.sourceTransactionId)
    || !HASH.test(bootstrap?.rawTransactionSha256)
    || bootstrap?.fundingWallet === null || typeof bootstrap?.fundingWallet !== 'object'
    || typeof wallet?.spendableFundingWallets !== 'function') {
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'bootstrap binding or product wallet is incomplete');
  }
  let transaction;
  try { transaction = parseV2RawTransaction(Buffer.from(rawTransaction).toString('hex')); }
  catch (error) {
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'retained signed bootstrap transaction cannot be parsed', { cause: error });
  }
  const fundingWallets = wallet.spendableFundingWallets();
  const matches = Array.isArray(fundingWallets) ? fundingWallets.filter((entry) =>
    entry?.compressedPublicKeyHex === bootstrap.fundingWallet.compressedPublicKeyHex
      && entry.lockingBytecodeHex === bootstrap.fundingWallet.lockingBytecodeHex
      && entry.cashAddress === bootstrap.fundingWallet.cashAddress,
  ) : [];
  if (matches.length !== 1
    || transaction.txid !== bootstrap.sourceTransactionId
    || createHash('sha256').update(transaction.bytes).digest('hex') !== bootstrap.rawTransactionSha256
    || transaction.inputs.length !== 1 || transaction.outputs.length !== 12) {
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'retained bootstrap bytes, funding identity, or exact 12-output layout differs');
  }
  const expectedValues = new Map([
    [0, V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS],
    ...V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS.map((vout) => [vout, V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS]),
    ...V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS.map((vout) => [vout, V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS]),
  ]);
  const sources = [];
  for (const [vout, output] of transaction.outputs.entries()) {
    let parsed;
    try { parsed = parseSerializedSourceOutput(output.serializedHex); }
    catch (error) {
      fail('BETA_POOL_ACTION_STORE_REJECTED', `bootstrap output ${vout} cannot be parsed exactly`, { cause: error });
    }
    const expectedValue = expectedValues.get(vout);
    if (parsed.token !== null
      || parsed.lockingBytecodeHex !== bootstrap.fundingWallet.lockingBytecodeHex
      || (expectedValue === undefined
        ? parsed.valueSatoshis < BigInt(V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DUST_SATS)
        : parsed.valueSatoshis.toString() !== expectedValue)) {
      fail('BETA_POOL_ACTION_STORE_REJECTED', `bootstrap output ${vout} differs from the exact tokenless funding layout`);
    }
    if (vout >= 1 && vout <= 10) {
      sources.push(Object.freeze({
        txid: transaction.txid,
        vout,
        valueSats: parsed.valueSatoshis.toString(),
      }));
    }
  }
  if (sources.length !== 10) {
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'bootstrap did not expose exactly ten action funding outputs');
  }
  return Object.freeze(sources);
}

function initializeActionStore({ bootstrap, config, deploymentBinding, rawSourceTransaction, runtime, wallet }, dependencies) {
  const genesis = dependencies.loadCommittedGenesis({
    deploymentDirectory: config.deploymentDirectory,
  });
  if (!HASH.test(genesis?.profileId)
    || !HASH.test(genesis.instanceId)
    || !HASH.test(genesis.genesisOutpoint?.txid)
    || !HASH.test(deploymentBinding?.sourceTransactionId)
    || !HASH.test(deploymentBinding?.genesisOutpoint?.txid)
    || !HASH.test(deploymentBinding?.zeroConfEvidenceSha256)
    || !HASH.test(runtime?.runtimeMaterialSha256)
    || !HASH.test(runtime?.runtimeManifestSha256)
    || genesis.profileId !== runtime.identity?.profileId
    || genesis.instanceId !== runtime.identity.instanceId
    || deploymentBinding.sourceTransactionId !== bootstrap.sourceTransactionId
    || genesis.initialState?.length !== 128
    || genesis.genesisOutpoint?.vout !== 0
    || genesis.genesisOutpoint?.txid !== deploymentBinding.genesisOutpoint?.txid
    || genesis.zeroConfEvidenceSha256 !== deploymentBinding.zeroConfEvidenceSha256
    || !HASH.test(genesis.zeroConfEvidenceSha256)
    || typeof runtime.identity.denominationSats !== 'string') {
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'committed zero-conf genesis or runtime provenance differs from pool creation');
  }
  const sources = bootstrapFundingSources({
    bootstrap,
    rawTransaction: rawSourceTransaction,
    wallet,
  });
  let store;
  try {
    store = dependencies.openStore({ databasePath: config.storeDatabasePath });
    store.initialize({
      profileId: Buffer.from(genesis.profileId, 'hex'),
      instanceId: Buffer.from(genesis.instanceId, 'hex'),
      networkId: 2,
      denominationSats: runtime.identity.denominationSats,
      state: Buffer.from(genesis.initialState),
      outpoint: {
        txid: Buffer.from(genesis.genesisOutpoint.txid, 'hex'),
        vout: genesis.genesisOutpoint.vout,
      },
      acceptanceId: Buffer.from(genesis.zeroConfEvidenceSha256, 'hex'),
      runtimeMaterialSha256: Buffer.from(runtime.runtimeMaterialSha256, 'hex'),
      runtimeManifestSha256: Buffer.from(runtime.runtimeManifestSha256, 'hex'),
      deploymentZeroConfEvidenceSha256: Buffer.from(genesis.zeroConfEvidenceSha256, 'hex'),
    });
    const fundingSet = store.initializeBootstrapFunding({
      sourceTransactionId: Buffer.from(bootstrap.sourceTransactionId, 'hex'),
      utxos: sources.map((source) => Object.freeze({
        txid: Buffer.from(source.txid, 'hex'),
        vout: source.vout,
        valueSats: source.valueSats,
      })),
    });
    if (fundingSet.outputCount !== sources.length
      || !Buffer.from(fundingSet.sourceTransactionId).equals(
        Buffer.from(bootstrap.sourceTransactionId, 'hex'),
      )) {
      fail('BETA_POOL_ACTION_STORE_REJECTED', 'persistent bootstrap funding marker differs');
    }
    return Object.freeze({
      actionFundingOutputs: fundingSet.outputCount,
      actionFundingSetSha256: Buffer.from(fundingSet.setSha256).toString('hex'),
    });
  } catch (error) {
    if (error instanceof V2BetaProductPoolCreateError) throw error;
    fail('BETA_POOL_ACTION_STORE_REJECTED', 'persistent beta action store could not be initialized from the accepted bootstrap', { cause: error });
  } finally {
    try { store?.close(); } catch { /* preserve the initialization failure */ }
  }
}

/** Test-only seam for exact accepted-bootstrap store qualification. */
export function initializeV2BetaProductActionStoreForTest(value, dependencies) {
  exactOptional(value, [
    'bootstrap', 'config', 'deploymentBinding', 'rawSourceTransaction', 'runtime', 'wallet',
  ], 'beta action store test input');
  exactOptional(dependencies, ['loadCommittedGenesis', 'openStore'], 'beta action store test dependencies');
  if (typeof dependencies.loadCommittedGenesis !== 'function' || typeof dependencies.openStore !== 'function') {
    fail('BETA_POOL_CREATE_INVALID', 'beta action store test dependencies are incomplete');
  }
  return initializeActionStore(value, dependencies);
}

function productionDependencies() {
  return Object.freeze({
    acceptDeployment: acceptV2BetaChipnetZeroConfDeployment,
    assertFunding: assertV2BetaProductPoolFundingCapability,
    assertRuntime: assertV2BetaChipnetRuntimeResolution,
    broadcastDeployment: broadcastV2BetaChipnetDeployment,
    commitDeployment: commitV2BetaChipnetDeployment,
    attestTemplate: ({ linkedTemplate }) => authenticateV2Pf10ReceiptLinkedRuntimeTemplate({
      repositoryRoot: REPOSITORY_ROOT,
      linkedTemplate,
    }),
    consumeRpc: consumeV2BetaProductPoolCreateRpc,
    observeRpc: observeLayer1BchnChipnetRpc,
    createFunding: createV2BetaProductPoolFundingWithPoolCreateRpc,
    createGenesisRuntime: createV2BetaChipnetGenesisRuntimeFromResolution,
    createRpc: createV2BetaProductPoolCreateRpc,
    createOrLoadConfig: createOrLoadV2BetaProductConfig,
    deriveDeploymentBinding: deriveV2BetaChipnetDeploymentBinding,
    deriveGenesisPins: deriveV2FinalizedGenesisPackagePins,
    deriveProfileCore: deriveV2BetaChipnetProfileCore,
    deriveSettlementPins: deriveV2BetaChipnetSettlementPins,
    initializeActionStore: (value) => initializeActionStore(value, {
      loadCommittedGenesis: loadV2BetaChipnetCommittedGenesis,
      openStore: openV2BetaIncrementalStore,
    }),
    installRuntime: installV2BetaProductLinkedRuntimeCache,
    loadArtifactInstallation: loadV2BetaProductArtifactInstallation,
    loadDeploymentRecovery: loadV2BetaChipnetDeploymentRecovery,
    loadRuntime: loadV2BetaProductLinkedRuntimeCache,
    loadTemplate: loadV2BetaProductLinkedRuntimeTemplate,
    openCreateJournal: openV2BetaProductPoolCreateJournal,
    recoverFunding: recoverV2BetaProductPoolFunding,
    specializeRuntime: ({ instanceId, templateCapability }) => relocateV2Pf10BetaRuntime({
      repositoryRoot: REPOSITORY_ROOT,
      instanceId,
      templateCapability,
    }),
    stageDeployment: stageV2BetaChipnetDeployment,
  });
}

function testDependencies(value) {
  const names = [
    'acceptDeployment', 'assertFunding', 'assertRuntime', 'attestTemplate',
    'broadcastDeployment', 'commitDeployment', 'consumeRpc', 'createFunding', 'observeRpc',
    'createGenesisRuntime', 'createOrLoadConfig', 'createRpc', 'deriveDeploymentBinding',
    'deriveGenesisPins', 'deriveProfileCore', 'deriveSettlementPins',
    'initializeActionStore', 'installRuntime', 'loadArtifactInstallation', 'loadDeploymentRecovery',
    'loadRuntime', 'loadTemplate', 'openCreateJournal', 'recoverFunding',
    'specializeRuntime', 'stageDeployment',
  ];
  exactOptional(value, names, 'beta pool create test dependencies');
  if (Object.keys(value).length !== names.length
    || names.some((name) => typeof value[name] !== 'function')) {
    fail('BETA_POOL_CREATE_INVALID', 'beta pool create test dependencies are incomplete');
  }
  return Object.freeze({ ...value });
}

async function create(value, dependencies) {
  exactOptional(value, ['dataHome', 'fundingTxid', 'fundingUtxo', 'fundingWalletPath'], 'beta pool create options');
  if (value.fundingTxid !== undefined && !HASH.test(value.fundingTxid)) {
    fail('BETA_POOL_FUNDING_TXID_REJECTED', 'fundingTxid must be exactly 64 lowercase hexadecimal characters');
  }
  const directFunding = value.fundingWalletPath !== undefined || value.fundingUtxo !== undefined;
  if (directFunding && (typeof value.fundingWalletPath !== 'string' || typeof value.fundingUtxo !== 'string')) {
    fail('BETA_POOL_USER_FUNDING_REQUIRED', 'fundingWalletPath and fundingUtxo are required together');
  }
  if (directFunding && value.fundingTxid !== undefined) {
    fail('BETA_POOL_FUNDING_TXID_REJECTED', 'fundingTxid cannot be combined with direct user funding');
  }
  const started = now();
  const configOptions = value.dataHome === undefined ? {} : { dataHome: value.dataHome };
  // Recovery is local-only and deliberately precedes ordinary funding
  // discovery. Once exact source/genesis bytes are durable, source UTXO
  // scanning is unnecessary and unsafe because the source may be spent.
  const loaded = await dependencies.createOrLoadConfig(configOptions);
  const recovery = dependencies.loadDeploymentRecovery({
    deploymentDirectory: loaded.config.deploymentDirectory,
  });
  if (value.fundingTxid !== undefined && recovery === null) {
    fail('BETA_POOL_LEGACY_FUNDING_TXID_REJECTED', 'fundingTxid is retained only for an existing local recovery operation; new pool creation requires user-owned funding');
  }
  const rpcCapability = await dependencies.createRpc();
  const rpc = dependencies.consumeRpc(rpcCapability);
  const fundingStarted = now();
  const funding = recovery === null
    ? await dependencies.createFunding(value, rpcCapability)
    : await dependencies.recoverFunding({
      ...(value.dataHome === undefined ? {} : { dataHome: value.dataHome }),
      sourceFundingRawTxHex: recovery.sourceFundingRawTxHex,
    });
  const fundingMs = now() - fundingStarted;
  if (funding?.status === 'funding-required') {
    return fundingRequired(funding, started, value, rpcObservation(dependencies.observeRpc(rpc), 'funding-required RPC observation'));
  }
  if (funding?.status !== 'bootstrap-ready') {
    fail('BETA_POOL_FUNDING_REJECTED', 'pool funding did not return an exact funding-required or bootstrap-ready result');
  }
  const capability = dependencies.assertFunding(funding.capability);
  const bootstrap = capability.bootstrapBinding();
  const operationId = `pool-create.${bootstrap.instanceId}`;
  assertRecoveredBootstrap(recovery, bootstrap);
  const observedRuntime = await observeV2BetaRuntimeWork(() =>
    loadOrCreateLinkedRuntime({
      bootstrap,
      config: loaded.config,
    }, dependencies));
  const linkedRuntime = observedRuntime.value;
  const runtimeWork = assertV2BetaPoolCreateRuntimeWork(
    observedRuntime.observation,
    { linkedDuringCommand: linkedRuntime.linkedNow },
  );
  const { runtimeResolution } = linkedRuntime;
  assertBootstrapRuntime(bootstrap, runtimeResolution);
  const profileCore = dependencies.deriveProfileCore(runtimeResolution);
  const genesisRuntime = dependencies.createGenesisRuntime({
    profileCore,
    runtimeResolution,
  });
  let wallet;
  let createJournal;
  let createClaim;
  let change;
  let sendAttempted = false;
  try {
    createJournal = dependencies.openCreateJournal({
      databasePath: loaded.config.poolCreateJournalDatabasePath,
    });
    createClaim = createJournal.claimOrRecover({
      operationId,
      profileId: runtimeResolution.identity.profileId,
      instanceId: bootstrap.instanceId,
      sourceTransactionId: bootstrap.sourceTransactionId,
      bootstrapRawSha256: bootstrap.rawTransactionSha256,
      ...fundingJournalBinding(bootstrap),
    });
    wallet = capability.openProductWallet({
      databasePath: loaded.config.walletDatabasePath,
      profileId: runtimeResolution.identity.profileId,
      instanceId: runtimeResolution.identity.instanceId,
    });
    change = wallet.stageChangeWallet({ operationId });
    const genesisStarted = now();
    const prepared = capability.prepareGenesis({
      changeLockingBytecodeHex: change.lockingBytecodeHex,
      maximumLiveNotes: V2_BETA_PRODUCT_CAPACITY,
      profileCore,
      runtime: genesisRuntime,
    });
    const finalized = capability.finalizeGenesis({ prepared });
    const packageValue = packagedGenesis(
      finalized,
      genesisRuntime,
      runtimeResolution,
      dependencies,
    );
    assertRecoveredPackage(recovery, packageValue, finalized);
    const genesisMs = now() - genesisStarted;
    const sourceRawTransactionHex = Buffer.from(packageValue.rawSourceTransaction).toString('hex');
    const stageStarted = now();
    const staged = dependencies.stageDeployment({
      acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
      deploymentDirectory: loaded.config.deploymentDirectory,
      packagedGenesis: packageValue,
      rpc,
      sourceFundingRawTxHex: sourceRawTransactionHex,
    });
    assertRecoveredCoordinatorOperation(recovery, staged);
    const stageMs = now() - stageStarted;
    const broadcastStarted = now();
    const admissionObservationBefore = rpcObservation(dependencies.observeRpc(rpc), 'pre-admission RPC observation');
    if (createClaim.mode === 'send-allowed') {
      createJournal.markSendAttempt({
        claim: createClaim,
        genesisTransactionId: finalized.genesis.transactionId,
      });
      sendAttempted = true;
      // Persist uncertainty before the network call. A crash after this point
      // can reconcile exact bytes, but can never classify this key as safely
      // pre-send or silently authorize another transaction.
      wallet.markChangeWalletSent({ operationId });
    } else if (createClaim.mode === 'reconcile-only') {
      sendAttempted = true;
      if (change.state === 'prepared') wallet.markChangeWalletIndeterminate({ operationId });
    }
    let broadcast;
    if (createClaim.mode === 'completed' || createClaim.mode === 'commit-only') {
      broadcast = Object.freeze({
        broadcast: false,
        record: Object.freeze({
          status: createClaim.mode === 'completed' ? 'committed' : 'accepted-zero-conf',
        }),
      });
    } else {
      broadcast = await dependencies.broadcastDeployment({
        acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
        deploymentDirectory: loaded.config.deploymentDirectory,
        rpc,
      });
    }
    if (broadcast.broadcast !== true
      && !['broadcast', 'accepted-zero-conf', 'committed'].includes(broadcast.record?.status)) {
      fail('BETA_POOL_BROADCAST_REJECTED', 'deployment coordinator did not retain an exact broadcast or later durable state');
    }
    const broadcastMs = now() - broadcastStarted;
    const readbackStarted = now();
    const acceptance = assertAccepted(await dependencies.acceptDeployment({
      acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
      deploymentDirectory: loaded.config.deploymentDirectory,
      rpc,
    }));
    if (createClaim.mode !== 'completed') {
      createJournal.markAccepted({
        claim: createClaim,
        genesisTransactionId: finalized.genesis.transactionId,
      });
    }
    const readbackMs = now() - readbackStarted;
    const admissionObservation = createClaim.mode === 'send-allowed'
      ? oneShotAdmissionObservation(admissionObservationBefore, dependencies.observeRpc(rpc))
      : rpcObservation(dependencies.observeRpc(rpc), 'post-admission RPC observation');
    const commitStarted = now();
    const committed = dependencies.commitDeployment({
      acknowledgement: V2_BETA_CHIPNET_DEPLOYMENT_ACKNOWLEDGEMENT,
      deploymentDirectory: loaded.config.deploymentDirectory,
    });
    if (committed.record?.status !== 'committed') {
      fail('BETA_POOL_COMMIT_REJECTED', 'zero-conf deployment did not atomically commit');
    }
    const binding = dependencies.deriveDeploymentBinding({
      deploymentDirectory: loaded.config.deploymentDirectory,
    });
    if (binding.profileId !== runtimeResolution.identity.profileId
      || binding.instanceId !== bootstrap.instanceId
      || binding.sourceTransactionId !== bootstrap.sourceTransactionId
      || binding.genesisOutpoint?.txid !== finalized.genesis.transactionId
      || binding.genesisOutpoint?.vout !== 0
      || !HASH.test(binding.zeroConfEvidenceSha256)) {
      fail('BETA_POOL_COMMIT_REJECTED', 'committed deployment binding differs from the exact warm bootstrap/genesis');
    }
    const actionStoreStarted = now();
    const actionStore = dependencies.initializeActionStore({
      bootstrap,
      config: loaded.config,
      deploymentBinding: binding,
      rawSourceTransaction: packageValue.rawSourceTransaction,
      runtime: runtimeResolution,
      wallet,
    });
    const actionStoreMs = now() - actionStoreStarted;
    if (createClaim.mode !== 'completed') {
      createJournal.markCommitted({
        claim: createClaim,
        genesisTransactionId: finalized.genesis.transactionId,
      });
    }
    if (change.state === 'prepared' && createClaim.mode === 'completed') {
      wallet.markChangeWalletIndeterminate({ operationId });
    }
    wallet.attachChangeWallet({
      operationId,
      txid: finalized.genesis.transactionId,
      vout: 12,
      valueSats: finalized.measurements.changeSats,
      acceptedCommit: true,
    });
    const commitMs = now() - commitStarted;
    return Object.freeze({
      schema: V2_BETA_PRODUCT_POOL_CREATE_RESULT_SCHEMA,
      status: 'accepted-zero-conf-beta-unqualified',
      command: 'pool-create',
      profileId: finalized.profileId,
      instanceId: finalized.instanceId,
      capacity: V2_BETA_PRODUCT_CAPACITY,
      sourceTransactionId: finalized.source.transactionId,
      genesisTransactionId: finalized.genesis.transactionId,
      transactions: Object.freeze({
        source: Object.freeze({
          transactionId: finalized.source.transactionId,
          serializedBytes: dependencies.deriveGenesisPins(finalized, genesisRuntime).source.serializedBytes,
          rawTransactionSha256: bootstrap.rawTransactionSha256,
        }),
        genesis: Object.freeze({
          transactionId: finalized.genesis.transactionId,
          serializedBytes: finalized.genesis.serializedBytes,
          feeSats: finalized.measurements.feeSats,
          feeRateSatsPerByte: finalized.measurements.feeRateSatsPerByte,
          bch2026StandardVmAccepted: finalized.measurements.bch2026StandardVmAccepted,
          inputMetrics: Object.freeze([Object.freeze({
            index: 0,
            accepted: true,
            metrics: Object.freeze({ ...finalized.measurements.inputMetrics }),
          })]),
        }),
      }),
      zeroConfEvidenceSha256: binding.zeroConfEvidenceSha256,
      claims: Object.freeze({
        broadcasted: true,
        confirmed: false,
        mined: false,
        productionQualified: false,
      }),
      timingsMs: Object.freeze({
        funding: fundingMs,
        ...linkedRuntime.timings,
        genesis: genesisMs,
        durableStage: stageMs,
        admissionAndBroadcast: broadcastMs,
        exactReadback: readbackMs,
        atomicCommit: commitMs,
        actionStoreBootstrap: actionStoreMs,
        commandTotal: now() - started,
      }),
      operationId: staged.operationId,
      rpcBackend: rpc.backend,
      rpcObservation: admissionObservation,
      runtimeManifestSha256: runtimeResolution.runtimeManifestSha256,
      runtimeMaterialSha256: runtimeResolution.runtimeMaterialSha256,
      runtimeLinkedDuringCommand: linkedRuntime.linkedNow,
      runtimeWork,
      acceptance,
      actionFundingOutputs: actionStore.actionFundingOutputs,
      actionFundingSetSha256: actionStore.actionFundingSetSha256,
    });
  } catch (error) {
    if (wallet !== undefined && change !== undefined) {
      try {
        if (sendAttempted) wallet.markChangeWalletIndeterminate({ operationId });
        else if (createJournal !== undefined && createClaim?.mode === 'send-allowed') {
          // Keep the exact staged key and bootstrap recoverable for a retry;
          // do not misclassify it as an abandoned orphan.
          createJournal.releaseSafePreSend({ claim: createClaim });
        }
      } catch { /* preserve the protocol failure; wallet reopen exposes recovery state */ }
    }
    throw error;
  } finally {
    wallet?.close();
    createJournal?.close();
  }
}

/** Production entry point. There is no runtime build, proof, or RPC seam. */
export async function createV2BetaProductPool(value = {}) {
  return create(value, productionDependencies());
}

/** Explicit isolated-test seam; production never accepts injected dependencies. */
export async function createV2BetaProductPoolForTest(value, dependencies) {
  return create(value, testDependencies(dependencies));
}
