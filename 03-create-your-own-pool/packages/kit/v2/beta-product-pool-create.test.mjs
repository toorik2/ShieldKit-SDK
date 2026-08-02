import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  createV2BetaProductPoolForTest,
  V2BetaProductPoolCreateError,
} from './beta-product-pool-create.mjs';
import { recordV2BetaRuntimeWork } from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../../action/v2/topology.mjs';

const H = (byte) => byte.repeat(64);

function fixture({
  funded = true,
  runtimeInstance = H('2'),
  accept = true,
  recovery = null,
  claimMode = 'send-allowed',
  cacheAvailable = true,
} = {}) {
  const calls = [];
  const stagedPackages = [];
  let observationCalls = 0;
  let linkedCacheAvailable = cacheAvailable;
  const bootstrap = Object.freeze({
    sourceTransactionId: H('1'),
    instanceId: H('2'),
    rawTransactionSha256: H('3'),
    sourceFundingOutpoint: Object.freeze({ transactionId: H('4'), outputIndex: 0 }),
    fundingWallet: Object.freeze({
      compressedPublicKeyHex: `02${'11'.repeat(32)}`,
      lockingBytecodeHex: '76a914'.concat('11'.repeat(20), '88ac'),
      cashAddress: 'bchtest:qtest',
    }),
  });
  const change = Object.freeze({
    lockingBytecodeHex: '76a914'.concat('11'.repeat(20), '88ac'),
    state: 'prepared',
  });
  const wallet = {
    stageChangeWallet: ({ operationId }) => { calls.push(`change:stage:${operationId}`); return change; },
    markChangeWalletSent: () => calls.push('change:sent'),
    markChangeWalletIndeterminate: () => calls.push('change:indeterminate'),
    markChangeOrphanRecoverable: () => calls.push('change:orphan'),
    attachChangeWallet: ({ txid }) => calls.push(`change:attach:${txid}`),
    close: () => calls.push('wallet:close'),
  };
  const capability = {
    bootstrapBinding: () => bootstrap,
    openProductWallet: () => wallet,
    prepareGenesis: () => Object.freeze({ prepared: true }),
    finalizeGenesis: () => Object.freeze({
      profileId: H('5'), instanceId: H('2'),
      source: Object.freeze({ transactionId: H('1'), outputIndex: 0 }),
      genesis: Object.freeze({ transactionId: H('6'), outputIndex: 0, rawTransactionHex: '00', serializedBytes: 200 }),
      measurements: Object.freeze({ changeSats: '546', feeSats: '200', feeRateSatsPerByte: '1', bch2026StandardVmAccepted: true, inputMetrics: Object.freeze([]) }),
    }),
  };
  const createClaim = Object.freeze({ mode: claimMode });
  const createJournal = {
    claimOrRecover: (value) => { calls.push('journal:claim'); journalBindings.push(value); return createClaim; },
    markSendAttempt: () => calls.push('journal:send-attempt'),
    markAccepted: () => calls.push('journal:accepted'),
    markCommitted: () => calls.push('journal:committed'),
    releaseSafePreSend: () => calls.push('journal:released'),
    close: () => calls.push('journal:close'),
  };
  const runtime = Object.freeze({
    identity: Object.freeze({ profileId: H('5'), instanceId: runtimeInstance, maximumLiveNotes: '100000' }),
    runtimeManifestSha256: H('7'), runtimeMaterialSha256: H('8'),
  });
  const pins = Object.freeze({
    profileId: H('5'), instanceId: H('2'), initialStateHex: '00'.repeat(128),
    source: Object.freeze({ transactionId: H('1'), outputIndex: 0, rawTransactionHex: '01000000000000000000', serializedBytes: 10 }),
    genesis: Object.freeze({ transactionId: H('6'), outputIndex: 0, rawTransactionHex: '02000000000000000000', serializedBytes: 10 }),
  });
  const settlementPins = Object.freeze({
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
    verifierCarriers: Object.freeze(DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.map(() => Object.freeze({
      baseValueSats: '1000', lockingBytecode: Buffer.from('51', 'hex'),
    }))),
    bindingBaseSats: '1000',
    bindingLockingBytecode: Buffer.from('51', 'hex'),
    bindingRedeemBytecode: Buffer.from('52', 'hex'),
    stateBaseSats: '1000',
    stateHelperBytecode: Buffer.from('53', 'hex'),
    stateLockingBytecode: Buffer.from('54', 'hex'),
    stateUnlockingBytecode: Buffer.from('55', 'hex'),
  });
  const funding = funded
    ? Object.freeze({ status: 'bootstrap-ready', capability })
    : Object.freeze({ status: 'funding-required', fundingWallet: Object.freeze({ cashAddress: 'bchtest:qtest' }), required: Object.freeze({ total: '1' }) });
  const dependencies = {
    acceptDeployment: async () => { calls.push('accept'); return accept ? { accepted: true, status: 'accepted-zero-conf', evidence: { status: 'accepted-zero-conf-beta-unqualified', claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false } } } : { accepted: false, status: 'broadcast' }; },
    assertFunding: (value) => value,
    assertRuntime: (value) => value,
    attestTemplate: async ({ linkedTemplate }) => { calls.push('template:attest'); assert.equal(linkedTemplate.template.retained, true); return Object.freeze({ authenticated: true }); },
    broadcastDeployment: async () => { calls.push('broadcast'); return { broadcast: true, record: { status: 'broadcast' } }; },
    commitDeployment: () => { calls.push('commit'); return { record: { status: 'committed' } }; },
    consumeRpc: (value) => { assert.equal(value.capability, true); return Object.freeze({ backend: 'layer1-bchn-chipnet' }); },
    createFunding: async (_value, rpcCapability) => { assert.equal(rpcCapability.capability, true); calls.push('funding'); return funding; },
    createGenesisRuntime: () => Object.freeze({ genesisRuntime: true }),
    createOrLoadConfig: () => Object.freeze({ config: Object.freeze({ dataDirectory: '/tmp/data', deploymentDirectory: '/tmp/deployment', runtimeCacheRoot: '/tmp/cache', walletDatabasePath: '/tmp/wallet.sqlite', poolCreateJournalDatabasePath: '/tmp/pool-create.sqlite' }) }),
    createRpc: async () => { calls.push('rpc:create'); return Object.freeze({ capability: true }); },
    deriveDeploymentBinding: () => Object.freeze({ profileId: H('5'), instanceId: H('2'), sourceTransactionId: H('1'), genesisOutpoint: Object.freeze({ txid: H('6'), vout: 0 }), zeroConfEvidenceSha256: H('9') }),
    deriveGenesisPins: () => pins,
    deriveProfileCore: () => Object.freeze({ profile: true }),
    deriveSettlementPins: () => settlementPins,
    installRuntime: async ({ specializedRuntime }) => { assert.equal(specializedRuntime.specialized, true); calls.push('runtime:install'); linkedCacheAvailable = true; },
    initializeActionStore: ({ rawSourceTransaction }) => {
      assert.equal(rawSourceTransaction instanceof Uint8Array, true);
      calls.push('action-store:init');
      return Object.freeze({ actionFundingOutputs: 10, actionFundingSetSha256: '9a'.repeat(32) });
    },
    loadArtifactInstallation: async ({ productDataDirectory }) => { assert.equal(productDataDirectory, '/tmp/data'); calls.push('artifacts:load'); return Object.freeze({ installed: true }); },
    loadDeploymentRecovery: () => recovery,
    loadRuntime: async ({ instanceId: requested }) => {
      calls.push('runtime:load');
      assert.equal(requested, H('2'));
      if (!linkedCacheAvailable) throw Object.assign(new Error('missing linked cache'), { code: 'BETA_LINKED_RUNTIME_CACHE_UNAVAILABLE' });
      recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
      return runtime;
    },
    loadTemplate: async () => { calls.push('template:load'); return Object.freeze({ template: Object.freeze({ retained: true }) }); },
    openCreateJournal: () => { calls.push('journal:open'); return createJournal; },
    observeRpc: () => {
      observationCalls += 1;
      const admissionObserved = observationCalls > 1;
      return Object.freeze({
        backend: 'layer1-bchn-chipnet', genesis: H('f'),
        methodCounts: Object.freeze({
          getblockhash: 1,
          getrawtransaction: (funded ? 1 : 0) + (admissionObserved ? 2 : 0),
          gettxout: (funded ? 1 : 0) + (admissionObserved ? 1 : 0),
          scantxoutset: 0,
          sendrawtransaction: admissionObserved ? 2 : 0,
          testmempoolaccept: admissionObserved ? 2 : 0,
        }),
      });
    },
    recoverFunding: async ({ sourceFundingRawTxHex }) => { calls.push(`funding:recover:${sourceFundingRawTxHex}`); return funding; },
    specializeRuntime: async ({ instanceId: requested, templateCapability }) => {
      assert.equal(requested, H('2'));
      assert.equal(templateCapability.authenticated, true);
      calls.push('runtime:specialize');
      recordV2BetaRuntimeWork({ type: 'instance-specialization' });
      return Object.freeze({ specialized: true });
    },
    stageDeployment: ({ packagedGenesis }) => { stagedPackages.push(packagedGenesis); calls.push('stage'); return { operationId: 'deployment-op', record: { status: 'prepared' } }; },
  };
  const journalBindings = [];
  return { calls, dependencies, funding, journalBindings, stagedPackages };
}

function exactRecovery() {
  return Object.freeze({
    operationId: 'deployment-op',
    journalStatus: 'ambiguous',
    sourceFundingRawTxHex: '01000000000000000000',
    genesisRawTxHex: '02000000000000000000',
    record: Object.freeze({
      source: Object.freeze({ transactionId: H('1'), rawTransactionSha256: H('3') }),
      genesis: Object.freeze({ transactionId: H('6'), rawTransactionSha256: H('4') }),
    }),
  });
}

test('returns a secret-free actionable funding address without loading or sending a runtime', async () => {
  const subject = fixture({ funded: false });
  const result = await createV2BetaProductPoolForTest({}, subject.dependencies);
  assert.equal(result.status, 'funding-required');
  assert.equal(result.fundingAddress, 'bchtest:qtest');
  assert.deepEqual(subject.calls, ['rpc:create', 'funding']);
  assert.equal(result.claims.productionQualified, false);
  assert.deepEqual(result.rpcObservation.methodCounts, {
    getblockhash: 1, getrawtransaction: 0, gettxout: 0, scantxoutset: 0,
    sendrawtransaction: 0, testmempoolaccept: 0,
  });
});

test('rejects legacy external funding txids for a new pool before any RPC funding discovery', async () => {
  const subject = fixture({ funded: false });
  await assert.rejects(
    createV2BetaProductPoolForTest({ dataHome: '/tmp/shieldkit-test', fundingTxid: H('a') }, subject.dependencies),
    error => error?.code === 'BETA_POOL_LEGACY_FUNDING_TXID_REJECTED',
  );
  assert.deepEqual(subject.calls, []);
});

test('one direct user funding invocation reaches the normal staged package flow and binds its exact source', async () => {
  const subject = fixture();
  let fundingInput;
  subject.dependencies.createFunding = async (value) => {
    fundingInput = value;
    subject.calls.push('funding');
    return subject.funding;
  };
  const walletPath = '/tmp/shieldkit-user-wallet.json';
  const result = await createV2BetaProductPoolForTest({
    dataHome: '/tmp/shieldkit-test', fundingWalletPath: walletPath, fundingUtxo: `${H('4')}:0`,
  }, subject.dependencies);
  assert.equal(result.status, 'accepted-zero-conf-beta-unqualified');
  assert.deepEqual(fundingInput, {
    dataHome: '/tmp/shieldkit-test', fundingWalletPath: walletPath, fundingUtxo: `${H('4')}:0`,
  });
  assert.equal(JSON.stringify(result).includes(walletPath), false);
  assert.deepEqual(
    Object.keys(subject.stagedPackages[0].settlementPins).sort(),
    [
      'bindingBaseSats', 'bindingLockingBytecode', 'bindingRedeemBytecode',
      'stateBaseSats', 'stateLockingBytecode', 'topologyId',
      'verifierCarriers', 'verifierRoles',
    ],
  );
  assert.equal(Object.hasOwn(subject.stagedPackages[0].settlementPins, 'stateHelperBytecode'), false);
  assert.equal(Object.hasOwn(subject.stagedPackages[0].settlementPins, 'stateUnlockingBytecode'), false);
  assert.deepEqual(subject.journalBindings[0], {
    operationId: `pool-create.${H('2')}`,
    profileId: H('5'), instanceId: H('2'), sourceTransactionId: H('1'), bootstrapRawSha256: H('3'),
    fundingOutpointTransactionId: H('4'), fundingOutpointVout: 0,
    fundingLockingBytecodeSha256: createHash('sha256')
      .update(Buffer.from(`76a914${'11'.repeat(20)}88ac`, 'hex')).digest('hex'),
  });
});

test('warm create consumes one exact instance runtime and commits only after exact zero-conf readback', async () => {
  const subject = fixture();
  const result = await createV2BetaProductPoolForTest({}, subject.dependencies);
  assert.equal(result.status, 'accepted-zero-conf-beta-unqualified');
  assert.equal(result.instanceId, H('2'));
  assert.equal(result.capacity, '100000');
  assert.deepEqual(result.claims, { broadcasted: true, confirmed: false, mined: false, productionQualified: false });
  assert.deepEqual(result.rpcObservation, {
    backend: 'layer1-bchn-chipnet', genesis: H('f'),
    methodCounts: {
      getblockhash: 0, getrawtransaction: 2, gettxout: 1, scantxoutset: 0,
      sendrawtransaction: 2, testmempoolaccept: 2,
    },
  });
  assert.deepEqual(result.runtimeWork.counts, {
    'linked-runtime-cache-load': 1,
    'cold-runtime-build': 0,
    'full-runtime-verification': 0,
    'compiler-child-spawn': 0,
    'instance-specialization': 0,
  });
  assert.deepEqual(result.runtimeWork.events, [
    { type: 'linked-runtime-cache-load' },
  ]);
  assert.deepEqual(subject.calls, [
    'rpc:create', 'funding', 'artifacts:load', 'runtime:load',
    'journal:open', 'journal:claim',
    `change:stage:pool-create.${H('2')}`, 'stage', 'journal:send-attempt',
    'change:sent', 'broadcast', 'accept', 'journal:accepted', 'commit', 'action-store:init',
    'journal:committed', `change:attach:${H('6')}`, 'wallet:close',
    'journal:close',
  ]);
});

test('refuses a duplicate zero-conf admission transport attempt before committing pool creation', async () => {
  const subject = fixture();
  let observationCalls = 0;
  subject.dependencies.observeRpc = () => {
    observationCalls += 1;
    return Object.freeze({
      backend: 'layer1-bchn-chipnet', genesis: H('f'),
      methodCounts: Object.freeze({
        getblockhash: 1,
        getrawtransaction: observationCalls > 1 ? 2 : 0,
        gettxout: observationCalls > 1 ? 1 : 0,
        scantxoutset: 0,
        sendrawtransaction: observationCalls > 1 ? 3 : 0,
        testmempoolaccept: observationCalls > 1 ? 3 : 0,
      }),
    });
  };
  await assert.rejects(
    createV2BetaProductPoolForTest({}, subject.dependencies),
    error => error instanceof V2BetaProductPoolCreateError
      && error.code === 'BETA_POOL_RPC_OBSERVATION_REJECTED',
  );
  assert.equal(subject.calls.includes('commit'), false);
});

test('refuses runtime retargeting and keeps a pre-send change key recoverable', async () => {
  const subject = fixture({ runtimeInstance: H('a') });
  await assert.rejects(
    createV2BetaProductPoolForTest({}, subject.dependencies),
    (error) => error instanceof V2BetaProductPoolCreateError
      && error.code === 'BETA_POOL_RUNTIME_REJECTED',
  );
  assert.deepEqual(subject.calls, ['rpc:create', 'funding', 'artifacts:load', 'runtime:load']);
});

test('first pool create links the exact signed bootstrap inside the measured command and reloads its durable cache', async () => {
  const subject = fixture({ cacheAvailable: false });
  const result = await createV2BetaProductPoolForTest({}, subject.dependencies);
  assert.equal(result.runtimeLinkedDuringCommand, true);
  assert.deepEqual(result.runtimeWork.counts, {
    'linked-runtime-cache-load': 1,
    'cold-runtime-build': 0,
    'full-runtime-verification': 0,
    'compiler-child-spawn': 0,
    'instance-specialization': 1,
  });
  assert.deepEqual(result.runtimeWork.events, [
    { type: 'instance-specialization' },
    { type: 'linked-runtime-cache-load' },
  ]);
  assert.deepEqual(subject.calls.slice(0, 10), [
    'rpc:create', 'funding', 'artifacts:load', 'runtime:load',
    'template:load', 'template:attest', 'runtime:specialize',
    'runtime:install', 'runtime:load', 'journal:open',
  ]);
  for (const name of [
    'artifactLoad', 'templateLoad', 'templateReceiptAttestation',
    'instanceSpecialization', 'runtimeCacheInstall', 'runtimeLoad',
  ]) assert.equal(typeof result.timingsMs[name], 'number', name);
});

test('does not commit on missing exact zero-conf readback and marks the sent change indeterminate', async () => {
  const subject = fixture({ accept: false });
  await assert.rejects(
    createV2BetaProductPoolForTest({}, subject.dependencies),
    (error) => error instanceof V2BetaProductPoolCreateError
      && error.code === 'BETA_POOL_ZERO_CONF_PENDING'
      && error.recoverable === true,
  );
  assert.equal(subject.calls.includes('commit'), false);
  assert.equal(subject.calls.at(-3), 'change:indeterminate');
  assert.equal(subject.calls.at(-2), 'wallet:close');
  assert.equal(subject.calls.at(-1), 'journal:close');
});

test('post-send restart recovers exact funding before any UTXO scan and delegates only reconciliation', async () => {
  const subject = fixture({ recovery: exactRecovery(), claimMode: 'reconcile-only' });
  let ordinaryFundingCalls = 0;
  let reconciliationCalls = 0;
  subject.dependencies.createFunding = async () => {
    ordinaryFundingCalls += 1;
    throw new Error('spent source must never be rescanned');
  };
  subject.dependencies.broadcastDeployment = async () => {
    reconciliationCalls += 1;
    subject.calls.push('reconcile');
    return { broadcast: false, record: { status: 'broadcast' } };
  };
  const result = await createV2BetaProductPoolForTest({}, subject.dependencies);
  assert.equal(result.status, 'accepted-zero-conf-beta-unqualified');
  assert.equal(ordinaryFundingCalls, 0);
  assert.equal(reconciliationCalls, 1);
  assert.equal(subject.calls.includes('journal:send-attempt'), false);
  assert.equal(subject.calls.includes('change:sent'), false);
  assert.equal(subject.calls.filter((call) => call.startsWith('funding:recover:')).length, 1);
});

test('accepted and committed restarts recover retained bytes without source rescans or sends', async () => {
  for (const claimMode of ['commit-only', 'completed']) {
    const subject = fixture({ recovery: exactRecovery(), claimMode });
    let ordinaryFundingCalls = 0;
    let broadcastCalls = 0;
    subject.dependencies.createFunding = async () => {
      ordinaryFundingCalls += 1;
      throw new Error('spent source must never be rescanned');
    };
    subject.dependencies.broadcastDeployment = async () => {
      broadcastCalls += 1;
      throw new Error('a recovered accepted deployment must never resend');
    };
    const result = await createV2BetaProductPoolForTest({}, subject.dependencies);
    assert.equal(result.status, 'accepted-zero-conf-beta-unqualified');
    assert.equal(ordinaryFundingCalls, 0, claimMode);
    assert.equal(broadcastCalls, 0, claimMode);
    assert.equal(subject.calls.includes('journal:send-attempt'), false, claimMode);
    assert.equal(subject.calls.includes('change:sent'), false, claimMode);
    assert.equal(subject.calls.includes('action-store:init'), true, claimMode);
    assert.equal(subject.calls.filter((call) => call.startsWith('funding:recover:')).length, 1, claimMode);
  }
});

test('an action-store failure happens only after commit and leaves restart reconciliation send-free', async () => {
  const subject = fixture();
  subject.dependencies.initializeActionStore = () => {
    subject.calls.push('action-store:init');
    throw new Error('test action-store failure');
  };
  await assert.rejects(
    createV2BetaProductPoolForTest({}, subject.dependencies),
    error => error?.message === 'test action-store failure',
  );
  assert.ok(subject.calls.indexOf('accept') < subject.calls.indexOf('commit'));
  assert.ok(subject.calls.indexOf('commit') < subject.calls.indexOf('action-store:init'));
  assert.equal(subject.calls.includes('journal:committed'), false);
});

test('recovery rejects a coordinator operation rebinding before any send', async () => {
  const subject = fixture({ recovery: exactRecovery(), claimMode: 'reconcile-only' });
  subject.dependencies.stageDeployment = () => {
    subject.calls.push('stage');
    return { operationId: 'different-deployment-op', record: { status: 'prepared' } };
  };
  await assert.rejects(
    createV2BetaProductPoolForTest({}, subject.dependencies),
    (error) => error instanceof V2BetaProductPoolCreateError
      && error.code === 'BETA_POOL_RECOVERY_REJECTED',
  );
  assert.equal(subject.calls.includes('broadcast'), false);
  assert.equal(subject.calls.includes('journal:send-attempt'), false);
});
