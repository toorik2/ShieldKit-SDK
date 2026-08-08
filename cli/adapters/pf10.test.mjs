/**
 * PF10 adapter gates: real product CLI delegation + identity envelopes.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';

import {
  PF10_BACKEND_ID,
  PF10_LIFECYCLE_VERBS,
  listDelegatedLifecycleVerbs,
  runPf10Cli,
  pf10Doctor,
  pf10PoolStatus,
  pf10Action,
  pf10PoolCreate,
  isExactPf10ActionResult,
  isExactPf10ProductCommandResult,
  isExactPf10PoolCreateResult,
  productDataHomeFromContext,
} from './pf10.mjs';
import { dispatch } from '../front-controller.mjs';
import { loadClosedCatalog } from '../registry/designs.mjs';
import { RESULT_SCHEMA } from '../contracts/envelopes.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '../bin/shieldkit.mjs');
const catalog = loadClosedCatalog();
const pf10Design = catalog.designs.find((d) => d.id === 'pf10');
const CHIPNET_GENESIS = '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';

function acceptedAction({
  kind = 'deposit',
  operationId = `deposit.${'22'.repeat(32)}`,
  transactionId = '11'.repeat(32),
  instanceId = 'aa'.repeat(32),
  route = 'fresh-single-pass',
} = {}) {
  const profiles = {
    'fresh-single-pass': [1, 1, 1],
    'fresh-reconciled-after-indeterminate-send': [2, 2, 1],
    'read-only-reconciliation': [1, 1, 0],
    'explicit-rebroadcast-precheck-visible': [1, 1, 0],
    'explicit-rebroadcast-single-pass': [2, 1, 1],
    'explicit-rebroadcast-reconciled-after-indeterminate-send': [3, 2, 1],
  };
  const [raw, state, send] = profiles[route];
  return {
    schema: 'shieldkit-v2-beta-product-action-result-v3',
    status: 'accepted-zero-conf-beta-unqualified',
    operationId,
    kind,
    transactionId,
    admissionRoute: route,
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
    cache: {
      runtimeManifestSha256: '33'.repeat(32),
      runtimeMaterialSha256: '44'.repeat(32),
    },
    proof: {
      verified: true,
      nativeBackend: 'rapidsnark',
      resultSha256: '55'.repeat(32),
      nativeProverSha256: '66'.repeat(32),
    },
    vm: {
      evidenceHash: '77'.repeat(32),
      allInputsAccepted: true,
      acceptedInputCount: 13,
      inputCount: 13,
    },
    telemetry: { schema: 'shieldkit-v2-beta-product-action-telemetry-v1' },
    transaction: {
      bytes: 100,
      feeSats: '100',
      feeRateSatsPerByte: '1',
      changeVout: 1,
      changeValueSats: '1000',
    },
    readback: {
      rawTransactionSha256: '88'.repeat(32),
      stateCategoryWire: Buffer.from(instanceId, 'hex').reverse().toString('hex'),
      stateCommitmentSha256: '99'.repeat(32),
      stateOutpoint: { txid: transactionId, vout: 0 },
    },
    rpcObservation: {
      backend: 'layer1-bchn-chipnet',
      genesis: CHIPNET_GENESIS,
      methodCounts: {
        getblockhash: 0,
        getrawtransaction: raw,
        gettxout: state,
        scantxoutset: 0,
        sendrawtransaction: send,
        testmempoolaccept: 0,
      },
    },
    timingsMs: { total: 1 },
  };
}

function acceptedCommand(action, command = 'deposit') {
  return {
    schema: 'shieldkit-v2-beta-product-command-result-v3',
    command,
    status: action.status,
    operationId: action.operationId,
    transactionId: action.transactionId,
    claims: structuredClone(action.claims),
    action,
    telemetry: structuredClone(action.telemetry),
    runtimeWork: { counts: {}, events: [] },
    timingsMs: { sessionOpen: 0, action: action.timingsMs.total, commandTotal: 1 },
  };
}

function capture(argv) {
  let out = '';
  const stdout = new Writable({
    write(chunk, _e, cb) { out += String(chunk); cb(); },
  });
  return dispatch(argv, { stdout }).then((r) => ({ ...r, out }));
}

test('PF10 lifecycle verb map covers complete product surface', () => {
  const verbs = listDelegatedLifecycleVerbs();
  assert.ok(verbs.length >= 10);
  assert.ok(verbs.every((v) => v.cliExists === true));
  assert.ok(PF10_LIFECYCLE_VERBS['action deposit']);
  assert.ok(PF10_LIFECYCLE_VERBS['action transfer']);
  assert.ok(PF10_LIFECYCLE_VERBS['action withdraw']);
  assert.ok(PF10_LIFECYCLE_VERBS['pool create']);
  assert.ok(PF10_LIFECYCLE_VERBS['operation rebroadcast']);
  assert.ok(PF10_LIFECYCLE_VERBS['design doctor']);
});

test('runPf10Cli drives real product pool doctor', () => {
  const r = runPf10Cli(['pool', 'doctor', '--json']);
  assert.equal(r.delegated, true);
  assert.equal(r.parallelSendPath, false);
  assert.equal(r.ok, true);
  assert.equal(r.envelope.ok, true);
  assert.equal(r.envelope.verb, 'pool-doctor');
  assert.equal(r.envelope.status, 'local-ok');
  assert.ok(r.cliPath.endsWith('designs/pf10/scripts/shieldkit.mjs'));
});

test('pf10 doctor has design-family identity only; status never invents an instance', async () => {
  const ctx = {
    design: pf10Design,
    home: null,
    flags: {},
  };
  const doctor = await pf10Doctor(ctx);
  assert.equal(doctor.schema, RESULT_SCHEMA);
  assert.equal(doctor.ok, true);
  assert.equal(doctor.identity.backendId, PF10_BACKEND_ID);
  assert.equal(doctor.identity.profileId, null);
  assert.equal(doctor.identity.profileStatus, 'unselected');
  assert.equal(doctor.identity.network, pf10Design.network);
  assert.equal(doctor.result.delegated, true);
  assert.deepEqual(doctor.result.delegatedArgv.slice(0, 2), ['pool', 'doctor']);
  assert.equal(doctor.result.productDoctor.verb, 'pool-doctor');

  const status = await pf10PoolStatus(ctx);
  assert.equal(status.ok, false);
  assert.equal(status.code, 'HOME_NOT_FOUND');
  assert.equal(status.identity.backendId, PF10_BACKEND_ID);
  assert.equal(status.identity.profileStatus, 'unselected');
  assert.equal(status.result.instanceObserved, false);
});

test('unified CLI design doctor + pool status for pf10 (new grammar)', async () => {
  const doctor = await capture(['--design', 'pf10', 'design', 'doctor']);
  assert.equal(doctor.exitCode, 0, doctor.out);
  const dEnv = JSON.parse(doctor.out);
  assert.equal(dEnv.ok, true);
  assert.equal(dEnv.identity.backendId, PF10_BACKEND_ID);
  assert.equal(dEnv.identity.profileId, null);
  assert.equal(dEnv.identity.profileStatus, 'unselected');
  assert.equal(dEnv.result.delegated, true);
  assert.equal(dEnv.result.productDoctor.verb, 'pool-doctor');

  const status = await capture(['--design', 'pf10', 'pool', 'status']);
  assert.equal(status.exitCode, 2, status.out);
  const sEnv = JSON.parse(status.out);
  assert.equal(sEnv.ok, false);
  assert.equal(sEnv.code, 'HOME_NOT_FOUND');
  assert.equal(sEnv.identity.backendId, PF10_BACKEND_ID);
  assert.equal(sEnv.identity.profileStatus, 'unselected');
  assert.equal(sEnv.result.instanceObserved, false);
});

test('action deposit without home is honest fail-closed with identity', async () => {
  const r = await capture(['--design', 'pf10', 'action', 'deposit']);
  assert.equal(r.exitCode, 2);
  const env = JSON.parse(r.out);
  assert.equal(env.ok, false);
  assert.equal(env.code, 'HOME_NOT_FOUND');
  assert.equal(env.identity.backendId, PF10_BACKEND_ID);
  assert.equal(env.identity.profileId, null);
  assert.equal(env.identity.profileStatus, 'unselected');
  assert.equal(env.result.parallelSendPath, false);
});

test('every PF10 delegation re-derives and exactly matches the imported product authority', async () => {
  const home = {
    path: '/tmp/unified-pf10-home',
    homeId: '50'.repeat(32),
    backendId: PF10_BACKEND_ID,
    designId: 'pf10',
    profileId: '10'.repeat(32),
    instanceId: '20'.repeat(32),
    network: 'bch-chipnet',
    genesisDescriptorHash: '30'.repeat(32),
  };
  const pointer = {
    schema: 'shieldkit-pf10-legacy-pointer/v1',
    backendId: home.backendId,
    designId: home.designId,
    profileId: home.profileId,
    instanceId: home.instanceId,
    network: home.network,
    genesisDescriptorHash: home.genesisDescriptorHash,
    genesisOutpoint: { txid: '40'.repeat(32), vout: 0 },
    legacyDataHome: '/tmp/legacy-pf10-home',
    sourceDataDirectory: '/tmp/legacy-pf10-home/shieldkit/v2-beta-product',
  };
  const receipt = {
    schema: 'shieldkit-pf10-legacy-migration-receipt/v1',
    backendId: pointer.backendId,
    designId: pointer.designId,
    profileId: pointer.profileId,
    instanceId: pointer.instanceId,
    network: pointer.network,
    genesisDescriptorHash: pointer.genesisDescriptorHash,
    genesisOutpoint: { ...pointer.genesisOutpoint },
    sourceDataHome: pointer.legacyDataHome,
    sourceDataDirectory: pointer.sourceDataDirectory,
  };
  const ctx = { design: pf10Design, home, flags: {} };
  const authority = {
    readPointer: () => pointer,
    deriveReceipt: () => receipt,
  };
  assert.equal(await productDataHomeFromContext(ctx, authority), pointer.legacyDataHome);

  let delegated = 0;
  const stale = {
    ...authority,
    deriveReceipt: () => ({ ...receipt, instanceId: 'ff'.repeat(32) }),
    run: () => { delegated += 1; return { ok: true }; },
  };
  await assert.rejects(
    pf10Action(ctx, 'deposit', stale),
    (error) => error?.code === 'MIGRATION_REQUIRED',
  );
  assert.equal(delegated, 0, 'stale authority must fail before product delegation');
});

test('pool create refuses a bound home before product delegation, including resume', () => {
  let delegated = 0;
  const result = pf10PoolCreate({
    design: pf10Design,
    home: {
      path: '/tmp/unified-pf10-home',
      homeId: '50'.repeat(32),
      backendId: PF10_BACKEND_ID,
      designId: 'pf10',
      profileId: '10'.repeat(32),
      instanceId: '20'.repeat(32),
      network: 'bch-chipnet',
      genesisDescriptorHash: '30'.repeat(32),
    },
    flags: { dataHome: '/tmp/legacy-pf10-home', resume: true },
  }, {
    run: () => { delegated += 1; return { ok: true }; },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'CAPABILITY_BLOCKED');
  assert.equal(result.result.delegated, false);
  assert.equal(delegated, 0);
});

test('PF10 success translation requires the exact product acceptance contract', () => {
  const instanceId = 'aa'.repeat(32);
  const action = acceptedAction({ instanceId });
  const options = {
    expectedInstanceId: instanceId,
    expectedOperationId: action.operationId,
    routeMode: 'action',
  };
  assert.equal(isExactPf10ActionResult(action, 'deposit', options), true);
  assert.equal(isExactPf10ProductCommandResult(acceptedCommand(action), 'deposit', options), true);
  assert.equal(isExactPf10ActionResult({ ...action, proof: { ...action.proof, verified: false } }, 'deposit', options), false);
  assert.equal(isExactPf10ActionResult({ ...action, transactionId: '44'.repeat(32) }, 'deposit', options), false);
  assert.equal(isExactPf10ActionResult({ ...action, admissionRoute: undefined }, 'deposit', options), false);
  assert.equal(isExactPf10ActionResult({
    ...action,
    rpcObservation: {
      ...action.rpcObservation,
      methodCounts: { ...action.rpcObservation.methodCounts, sendrawtransaction: 0 },
    },
  }, 'deposit', options), false);
  assert.equal(isExactPf10ActionResult({
    ...action,
    rpcObservation: { ...action.rpcObservation, genesis: 'ff'.repeat(32) },
  }, 'deposit', options), false);
  assert.equal(isExactPf10ActionResult({
    ...action,
    readback: { ...action.readback, stateCategoryWire: 'bb'.repeat(32) },
  }, 'deposit', options), false);
  const incomplete = structuredClone(action);
  delete incomplete.readback.stateCommitmentSha256;
  assert.equal(isExactPf10ActionResult(incomplete, 'deposit', options), false);
  const wrongOuter = acceptedCommand(action);
  wrongOuter.transactionId = 'cc'.repeat(32);
  assert.equal(isExactPf10ProductCommandResult(wrongOuter, 'deposit', options), false);

  const rebroadcast = acceptedAction({
    instanceId,
    kind: 'withdrawal',
    operationId: `withdraw.${'12'.repeat(32)}`,
    route: 'explicit-rebroadcast-single-pass',
  });
  assert.equal(isExactPf10ProductCommandResult(
    acceptedCommand(rebroadcast, 'recover-exact-rebroadcast'),
    null,
    {
      expectedInstanceId: instanceId,
      expectedOperationId: rebroadcast.operationId,
      routeMode: 'rebroadcast',
    },
  ), true);
  assert.equal(isExactPf10ActionResult(rebroadcast, null, {
    expectedInstanceId: instanceId,
    expectedOperationId: rebroadcast.operationId,
    routeMode: 'action',
  }), false);

  const sourceTransactionId = 'ab'.repeat(32);
  const genesisTransactionId = '88'.repeat(32);
  const poolInstanceId = Buffer.from(sourceTransactionId, 'hex').reverse().toString('hex');
  const profileId = '55'.repeat(32);
  const zeroConfEvidenceSha256 = '99'.repeat(32);
  const operationId = `pool-create.${'77'.repeat(32)}`;
  const sourceRawTransactionSha256 = '12'.repeat(32);
  const created = {
    schema: 'shieldkit-v2-beta-product-pool-create-result-v1',
    status: 'accepted-zero-conf-beta-unqualified',
    command: 'pool-create',
    profileId,
    instanceId: poolInstanceId,
    capacity: '100000',
    sourceTransactionId,
    genesisTransactionId,
    operationId,
    zeroConfEvidenceSha256,
    transactions: {
      source: {
        transactionId: sourceTransactionId,
        serializedBytes: 100,
        rawTransactionSha256: sourceRawTransactionSha256,
      },
      genesis: {
        transactionId: genesisTransactionId,
        serializedBytes: 200,
        feeSats: '200',
        feeRateSatsPerByte: '1',
        bch2026StandardVmAccepted: true,
        inputMetrics: [{ index: 0, accepted: true, metrics: {} }],
      },
    },
    acceptance: {
      accepted: true,
      status: 'accepted-zero-conf',
      operationId,
      rpcBackend: 'layer1-bchn-chipnet',
      evidence: {
        schema: 'shieldkit-v2-beta-chipnet-deployment-v1-zero-conf-acceptance',
        status: 'accepted-zero-conf-beta-unqualified',
        eligibility: 'beta-single-contributor-unqualified',
        claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
        profileId,
        instanceId: poolInstanceId,
        source: {
          transactionId: sourceTransactionId,
          rawTransactionSha256: sourceRawTransactionSha256,
        },
        genesis: {
          transactionId: genesisTransactionId,
          rawTransactionSha256: '13'.repeat(32),
        },
        stateOutput: {
          category: sourceTransactionId,
          amount: '0',
          capability: 'mutable',
          commitmentSha256: '14'.repeat(32),
        },
        evidenceSha256: zeroConfEvidenceSha256,
      },
    },
    claims: { broadcasted: true, confirmed: false, mined: false, productionQualified: false },
    rpcBackend: 'layer1-bchn-chipnet',
    rpcObservation: {
      backend: 'layer1-bchn-chipnet',
      genesis: CHIPNET_GENESIS,
      methodCounts: {
        getblockhash: 0,
        getrawtransaction: 2,
        gettxout: 1,
        scantxoutset: 0,
        sendrawtransaction: 2,
        testmempoolaccept: 2,
      },
    },
    runtimeManifestSha256: '15'.repeat(32),
    runtimeMaterialSha256: '16'.repeat(32),
    runtimeLinkedDuringCommand: false,
    runtimeWork: { counts: {}, events: [] },
    timingsMs: { commandTotal: 1 },
    actionFundingOutputs: 10,
    actionFundingSetSha256: '17'.repeat(32),
  };
  assert.equal(isExactPf10PoolCreateResult(created), true);
  assert.equal(isExactPf10PoolCreateResult(created, {
    profileId: created.profileId,
    instanceId: created.instanceId,
  }), true);
  assert.equal(isExactPf10PoolCreateResult(created, {
    profileId: 'aa'.repeat(32),
    instanceId: created.instanceId,
  }), false);
  assert.equal(isExactPf10PoolCreateResult({
    ...created,
    acceptance: { ...created.acceptance, accepted: false },
  }), false);
  assert.equal(isExactPf10PoolCreateResult({
    ...created,
    rpcObservation: { ...created.rpcObservation, genesis: 'ff'.repeat(32) },
  }), false);
});

test('spawned binary matches in-process dispatch for design doctor', () => {
  const a = spawnSync(process.execPath, [BIN, '--design', 'pf10', 'design', 'doctor'], {
    encoding: 'utf8',
  });
  assert.equal(a.status, 0, a.stderr + a.stdout);
  const env = JSON.parse(a.stdout);
  assert.equal(env.ok, true);
  assert.equal(env.identity.backendId, PF10_BACKEND_ID);
  assert.equal(env.result.productDoctor.status, 'local-ok');
});
