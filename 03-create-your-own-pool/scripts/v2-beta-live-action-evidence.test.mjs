import assert from 'node:assert/strict';
import test from 'node:test';

import { CHIPNET_GENESIS_HASH } from '../packages/kit/chipnet-rpc.mjs';
import {
  inspectV2BetaLiveActionEvidence,
  inspectV2BetaLivePoolRuntimeWork,
  V2BetaLiveActionEvidenceError,
} from './v2-beta-live-action-evidence.mjs';

const H = (nibble) => nibble.repeat(64);
const runtimeWork = () => ({
  schema: 'shieldkit-v2-beta-runtime-work-observation-v1',
  counts: {
    'linked-runtime-cache-load': 1,
    'cold-runtime-build': 0,
    'full-runtime-verification': 0,
    'compiler-child-spawn': 0,
    'instance-specialization': 0,
  },
  events: [{ type: 'linked-runtime-cache-load' }],
});
const metrics = () => ({
  arithmeticCost: '1', definedFunctions: '1', densityControlLength: '1',
  evaluatedInstructionCount: '1', hashDigestIterations: '1',
  maximumHashDigestIterations: '1', maximumOperationCost: '1',
  maximumSignatureCheckCount: '1', operationCost: '1', signatureCheckCount: '1',
  stackPushedBytes: '1',
});
const timings = () => ({
  admission: 1, commit: 1, fundingRead: 1, localVm: 1,
  proofGeneration: 1, proofTotal: 2, proofVerification: 1, signingAndVm: 1,
  stateRead: 1, total: 2, treeAndPreparation: 1, witnessAssembly: 1,
  witnessCalculation: 1,
});

function valid() {
  const proof = {
    activeCpuThreads: 4,
    containment: { backend: 'linux-systemd-cgroup-v2', memoryMaxBytes: '4294967296', memorySwapMaxBytes: '0', memoryPeakBytes: '1', oomDelta: 0, oomKillDelta: 0, terminatedSuccessfully: true },
    cpuTicksPerWallMillisecond: 2,
    observedThreads: 4,
    ompThreads: 4,
    peakRssKiB: 1,
    proofGenerationMs: 1,
    systemTicks: 1,
    totalTicks: 2,
    userTicks: 1,
  };
  const vm = {
    schema: 'shieldkit-v2-local-vm-telemetry-v1',
    allInputsAccepted: true,
    inputs: [0, 1].map((index) => ({ accepted: true, index, metrics: metrics() })),
  };
  const store = {
    pre: { schema: 'shieldkit-v2-beta-incremental-store-telemetry-v1', databaseBytes: 100, walBytes: 0, noteCount: 2, nullifierCount: 1, liveCount: 1 },
    post: { schema: 'shieldkit-v2-beta-incremental-store-telemetry-v1', databaseBytes: 120, walBytes: 5, noteCount: 3, nullifierCount: 1, liveCount: 2 },
    delta: { databaseBytes: 20, walBytes: 5, noteCount: 1, nullifierCount: 0, liveCount: 1 },
  };
  const telemetry = { schema: 'shieldkit-v2-beta-product-action-telemetry-v1', proof, vm, store };
  const actionTimings = timings();
  const action = {
    schema: 'shieldkit-v2-beta-product-action-result-v3',
    status: 'accepted-zero-conf-beta-unqualified', kind: 'deposit', operationId: 'operation-1', transactionId: H('a'),
    admissionRoute: 'fresh-single-pass',
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
    cache: { runtimeManifestSha256: H('b'), runtimeMaterialSha256: H('c') },
    proof: {
      nativeBackend: 'rapidsnark', nativeProverSha256: H('d'), resultSha256: H('e'), verified: true,
      ompThreads: 4, observedThreads: 4, peakRssKiB: 1,
      activeCpuThreads: 4, containment: { ...proof.containment },
      userCpuTicks: 1, systemCpuTicks: 1, totalCpuTicks: 2, cpuTicksPerWallMillisecond: 2,
    },
    vm: { evidenceHash: H('f'), inputCount: 2, acceptedInputCount: 2, allInputsAccepted: true },
    telemetry,
    timingsMs: actionTimings,
    transaction: { bytes: 100, changeValueSats: '1', changeVout: 1, feeRateSatsPerByte: '2', feeSats: '200' },
    readback: { rawTransactionSha256: H('1'), stateCategoryWire: H('2'), stateCommitmentSha256: H('3'), stateOutpoint: { txid: H('a'), vout: 0 } },
    rpcObservation: {
      backend: 'layer1-bchn-chipnet', genesis: CHIPNET_GENESIS_HASH,
      methodCounts: { getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0, sendrawtransaction: 1, testmempoolaccept: 0 },
    },
  };
  return {
    schema: 'shieldkit-v2-beta-product-command-result-v3', status: action.status,
    command: 'deposit', operationId: action.operationId, transactionId: action.transactionId,
    claims: { ...action.claims }, runtimeWork: runtimeWork(), telemetry, action,
    timingsMs: { action: actionTimings.total, sessionOpen: 1, commandTotal: 3 },
  };
}

const rejects = (code) => (error) => error instanceof V2BetaLiveActionEvidenceError
  && error.code === code;

test('portable live-action validator accepts a complete exact secret-free measured deposit projection', () => {
  const result = valid();
  const inspected = inspectV2BetaLiveActionEvidence(result, {
    command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
  });
  assert.equal(inspected.runtimeWork.counts['instance-specialization'], 0);
  assert.equal(inspected.vm.inputs.length, 2);
  assert.equal(inspected.feeSats, '200');
  const miss = structuredClone(runtimeWork());
  miss.counts['instance-specialization'] = 1;
  miss.events.unshift({ type: 'instance-specialization' });
  assert.equal(inspectV2BetaLivePoolRuntimeWork(miss, true).events.length, 2);
  assert.throws(() => inspectV2BetaLivePoolRuntimeWork(miss, false), rejects('LIVE_ACTION_RUNTIME_WORK_INVALID'));
});

test('portable live-action validator requires exact public Fulcrum method counts when the product route is public', () => {
  const value = valid();
  value.action.rpcObservation = {
    backend: 'public-chipnet-fulcrum-tls',
    genesis: CHIPNET_GENESIS_HASH,
    methodCounts: { ...value.action.rpcObservation.methodCounts },
    physicalMethodCounts: {
      'server.features': 0, 'server.version': 0,
      'blockchain.transaction.broadcast': 1,
      'blockchain.transaction.get': 1,
      'blockchain.utxo.get_info': 1,
      'blockchain.scripthash.listunspent': 0,
    },
  };
  assert.equal(inspectV2BetaLiveActionEvidence(value, {
    command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
  }).rpcObservation.backend, 'public-chipnet-fulcrum-tls');
  value.action.rpcObservation.physicalMethodCounts['blockchain.transaction.get'] = 2;
  assert.throws(() => inspectV2BetaLiveActionEvidence(value, {
    command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
  }), rejects('LIVE_ACTION_RPC_OBSERVATION_INVALID'));
});

test('portable live-action validator rejects telemetry, work, VM, store, RPC, timing, fee, secret, and unknown-wrapper tampering', () => {
  const cases = [
    ['missing telemetry', (value) => { delete value.telemetry.proof.totalTicks; }, 'LIVE_ACTION_EVIDENCE_INVALID'],
    ['fake all-core count', (value) => { value.action.proof.ompThreads = 3; value.telemetry.proof.ompThreads = 3; }, 'LIVE_ACTION_PROOF_TELEMETRY_INVALID'],
    ['runtime count mismatch', (value) => { value.runtimeWork.counts['linked-runtime-cache-load'] = 2; }, 'LIVE_ACTION_RUNTIME_WORK_INVALID'],
    ['runtime event reorder', (value) => { value.runtimeWork.events.unshift({ type: 'instance-specialization' }); value.runtimeWork.counts['instance-specialization'] = 1; }, 'LIVE_ACTION_RUNTIME_WORK_INVALID'],
    ['partial VM inputs', (value) => { value.telemetry.vm.inputs.pop(); }, 'LIVE_ACTION_VM_TELEMETRY_INVALID'],
    ['reordered VM inputs', (value) => { value.telemetry.vm.inputs.reverse(); }, 'LIVE_ACTION_VM_TELEMETRY_INVALID'],
    ['VM resource overage', (value) => { value.telemetry.vm.inputs[0].metrics.operationCost = '2'; }, 'LIVE_ACTION_VM_TELEMETRY_INVALID'],
    ['inconsistent store delta', (value) => { value.telemetry.store.delta.liveCount = 0; }, 'LIVE_ACTION_STORE_TELEMETRY_INVALID'],
    ['nonexact RPC count', (value) => { value.action.rpcObservation.methodCounts.sendrawtransaction = 2; }, 'LIVE_ACTION_RPC_OBSERVATION_INVALID'],
    ['inconsistent proof timing', (value) => { value.action.timingsMs.proofTotal = 0.5; }, 'LIVE_ACTION_EVIDENCE_INVALID'],
    ['inconsistent fee', (value) => { value.action.transaction.feeSats = '201'; }, 'LIVE_ACTION_EVIDENCE_INVALID'],
    ['secret wrapper', (value) => { value.action.telemetry.proof.spendSecret = 'never-exported'; }, 'LIVE_ACTION_SECRET_FIELD'],
    ['unknown wrapper', (value) => { value.action.unexpected = {}; }, 'LIVE_ACTION_EVIDENCE_INVALID'],
  ];
  for (const [label, mutate, code] of cases) {
    const value = valid();
    mutate(value);
    assert.throws(
      () => inspectV2BetaLiveActionEvidence(value, {
        command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
      }),
      rejects(code),
      label,
    );
  }
});

test('portable live-action validator accepts each exact recovery route and rejects route/count relabeling', () => {
  const profiles = {
    'fresh-single-pass': [1, 1, 1],
    'fresh-reconciled-after-indeterminate-send': [2, 2, 1],
    'read-only-reconciliation': [1, 1, 0],
    'explicit-rebroadcast-precheck-visible': [1, 1, 0],
    'explicit-rebroadcast-single-pass': [2, 1, 1],
    'explicit-rebroadcast-reconciled-after-indeterminate-send': [3, 2, 1],
  };
  for (const [route, [raw, state, send]] of Object.entries(profiles)) {
    const value = valid();
    value.action.admissionRoute = route;
    value.action.rpcObservation.methodCounts.getrawtransaction = raw;
    value.action.rpcObservation.methodCounts.gettxout = state;
    value.action.rpcObservation.methodCounts.sendrawtransaction = send;
    assert.equal(inspectV2BetaLiveActionEvidence(value, {
      command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
    }).admissionRoute, route);
  }
  const relabeled = valid();
  relabeled.action.admissionRoute = 'read-only-reconciliation';
  assert.throws(() => inspectV2BetaLiveActionEvidence(relabeled, {
    command: 'deposit', operationId: 'operation-1', testAvailableCores: 4,
  }), rejects('LIVE_ACTION_RPC_OBSERVATION_INVALID'));
});
