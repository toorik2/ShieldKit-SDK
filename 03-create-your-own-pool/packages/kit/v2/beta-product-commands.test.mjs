import assert from 'node:assert/strict';
import { availableParallelism } from 'node:os';
import test from 'node:test';

import {
  executeV2BetaProductDepositForTest,
  executeV2BetaProductExactRebroadcastRecoveryForTest,
  inspectV2BetaProductRecoveryForTest,
  executeV2BetaProductWithdrawalForTest,
  V2BetaProductCommandError,
} from './beta-product-commands.mjs';
import { recordV2BetaRuntimeWork } from '../../profile/v2/beta-runtime-work-observer.mjs';

const address = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';

function result(kind, operationId) {
  const cores = availableParallelism();
  return Object.freeze({
    status: 'accepted-zero-conf-beta-unqualified',
    operationId,
    kind,
    transactionId: '11'.repeat(32),
    claims: Object.freeze({
      broadcasted: true,
      confirmed: false,
      mined: false,
      productionQualified: false,
    }),
    telemetry: Object.freeze({
      schema: 'shieldkit-v2-beta-product-action-telemetry-v1',
      proof: Object.freeze({
        ompThreads: cores,
        observedThreads: cores,
        activeCpuThreads: cores,
        peakRssKiB: 1,
        userTicks: 1,
        systemTicks: 2,
        totalTicks: 3,
        proofGenerationMs: 3,
        cpuTicksPerWallMillisecond: 1,
        containment: Object.freeze({
          backend: 'linux-systemd-cgroup-v2',
          memoryMaxBytes: '4294967296',
          memorySwapMaxBytes: '0',
          memoryPeakBytes: '1',
          oomDelta: 0,
          oomKillDelta: 0,
          terminatedSuccessfully: true,
        }),
      }),
      vm: Object.freeze({
        schema: 'shieldkit-v2-local-vm-telemetry-v1',
        allInputsAccepted: true,
        inputs: Object.freeze([Object.freeze({ index: 0, accepted: true, metrics: Object.freeze({}) })]),
      }),
      store: Object.freeze({
        pre: Object.freeze({ databaseBytes: 1, walBytes: 1, noteCount: 0, nullifierCount: 0, liveCount: 0 }),
        post: Object.freeze({ databaseBytes: 2, walBytes: 2, noteCount: 1, nullifierCount: 0, liveCount: 1 }),
        delta: Object.freeze({ databaseBytes: 1, walBytes: 1, noteCount: 1, nullifierCount: 0, liveCount: 1 }),
      }),
    }),
    timingsMs: Object.freeze({ total: 3 }),
  });
}

function fixture({ active = null, resumable = false, runtimeEvents = [] } = {}) {
  const calls = [];
  const session = {
    lifecycle: {
      async recoverOrResumeActive(value) {
        calls.push(['recover-active', value]);
        return active === null ? null : result(active.kind, active.operationId);
      },
      async resume(value) {
        calls.push(['resume', value]);
        if (resumable) return result(value.operationId.split('.')[0] === 'withdraw' ? 'withdrawal' : 'deposit', value.operationId);
        const error = new Error('no staged action');
        error.code = 'BETA_STAGED_ACTION_REQUIRED';
        throw error;
      },
      async executeDeposit(value) { calls.push(['deposit', value]); return result('deposit', value.operationId); },
      async executeWithdrawal(value) { calls.push(['withdrawal', value]); return result('withdrawal', value.operationId); },
      async rebroadcast(value) { calls.push(['rebroadcast', value]); return result('deposit', value.operationId); },
      recoveryStatus(value) {
        calls.push(['recovery-status', value]);
        return {
          schema: 'shieldkit-v2-beta-product-recovery-status-v1',
          operationId: value.operationId,
          kind: 'deposit',
          localState: 'staged',
          safePreSendAborted: false,
          staged: true,
          delivery: {
            state: 'indeterminate',
            txid: '11'.repeat(32),
            attemptToken: '12345678-1234-4123-8123-123456789abc',
            attemptCount: 1,
          },
          exactRebroadcastAvailable: true,
          claims: { confirmed: false, mined: false, productionQualified: false },
        };
      },
    },
    close() { calls.push(['close']); },
  };
  return {
    calls,
    session,
    dependencies: {
      openSession: async () => {
        recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
        for (const type of runtimeEvents) recordV2BetaRuntimeWork({ type });
        return session;
      },
      randomBytes: () => Buffer.alloc(32, 7),
    },
  };
}

test('deposit owns session open, generated operation identity, accepted result, and close', async () => {
  const subject = fixture();
  const actual = await executeV2BetaProductDepositForTest(
    { config: {}, rpc: {} }, subject.dependencies,
  );
  assert.equal(actual.operationId, `deposit.${'07'.repeat(32)}`);
  assert.equal(actual.claims.confirmed, false);
  assert.deepEqual(actual.runtimeWork, {
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
  assert.deepEqual(subject.calls, [
    ['recover-active', { expectedKind: 'deposit' }],
    ['deposit', { operationId: actual.operationId }],
    ['close'],
  ]);
});

test('action commands preserve runtime refresh and fail-closed cache errors from session open', async () => {
  for (const code of [
    'BETA_RUNTIME_REFRESH_REQUIRED',
    'BETA_LINKED_RUNTIME_CACHE_INVALID',
    'BETA_LINKED_RUNTIME_CACHE_STALE',
    'BETA_LINKED_RUNTIME_CACHE_AMBIGUOUS',
  ]) {
    const failure = Object.assign(new Error(code), { code });
    await assert.rejects(
      executeV2BetaProductDepositForTest(
        { config: {}, rpc: {} },
        {
          openSession: async () => { throw failure; },
          randomBytes: () => Buffer.alloc(32, 7),
        },
      ),
      (error) => error === failure,
    );
  }
});

test('withdrawal requires a Chipnet P2PKH destination and passes exact bytecode', async () => {
  const subject = fixture();
  const actual = await executeV2BetaProductWithdrawalForTest(
    { config: {}, operationId: 'withdraw.1', rpc: {}, toCashAddress: address },
    subject.dependencies,
  );
  assert.equal(actual.command, 'withdraw');
  assert.equal(subject.calls[0][0], 'resume');
  assert.equal(subject.calls[1][0], 'recover-active');
  assert.equal(subject.calls[2][0], 'resume');
  assert.equal(subject.calls[3][1].payoutLockingBytecode.toString('hex'),
    '76a914233c0f9b7593aecb09dca11931965a16b90548c288ac');
  assert.deepEqual(subject.calls.at(-1), ['close']);

  await assert.rejects(
    executeV2BetaProductWithdrawalForTest(
      { config: {}, operationId: 'withdraw.2', rpc: {}, toCashAddress: 'bitcoincash:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcgrq3dy4zv' },
      subject.dependencies,
    ),
    (error) => error instanceof V2BetaProductCommandError
      && error.code === 'BETA_WITHDRAWAL_ADDRESS_REJECTED',
  );
});

test('an explicit operation ID reconciles the persisted action without preparing or sending again', async () => {
  const subject = fixture({ resumable: true });
  const actual = await executeV2BetaProductDepositForTest(
    { config: {}, operationId: 'deposit.qualification.01', rpc: {} },
    subject.dependencies,
  );
  assert.equal(actual.operationId, 'deposit.qualification.01');
  assert.deepEqual(subject.calls, [
    ['resume', {
      operationId: 'deposit.qualification.01',
      expectedKind: 'deposit',
    }],
    ['close'],
  ]);
});

test('each forbidden action-scoped runtime event fails closed before a command result is exposed', async () => {
  for (const type of [
    'cold-runtime-build',
    'full-runtime-verification',
    'compiler-child-spawn',
    'instance-specialization',
  ]) {
    const subject = fixture({ runtimeEvents: [type] });
    await assert.rejects(
      executeV2BetaProductDepositForTest({ config: {}, rpc: {} }, subject.dependencies),
      (error) => error?.code === 'BETA_RUNTIME_WARM_WORK_FORBIDDEN',
      type,
    );
    assert.deepEqual(subject.calls.at(-1), ['close']);
  }
});

test('command rejects an accepted-looking lifecycle result without action telemetry', async () => {
  const subject = fixture();
  subject.session.lifecycle.executeDeposit = async ({ operationId }) => {
    const { telemetry: ignored, ...withoutTelemetry } = result('deposit', operationId);
    return Object.freeze(withoutTelemetry);
  };
  await assert.rejects(
    executeV2BetaProductDepositForTest({ config: {}, rpc: {} }, subject.dependencies),
    (error) => error instanceof V2BetaProductCommandError
      && error.code === 'BETA_COMMAND_RESULT_REJECTED',
  );
  assert.deepEqual(subject.calls.at(-1), ['close']);
});

test('command boundary rejects incomplete, idle, partial-core, or uncontained proof telemetry', async () => {
  const cores = availableParallelism();
  const mutations = [
    (proof) => { delete proof.activeCpuThreads; },
    (proof) => { proof.activeCpuThreads = Math.max(0, cores - 1); },
    (proof) => { proof.observedThreads = Math.max(0, cores - 1); },
    (proof) => { proof.totalTicks = 0; proof.userTicks = 0; proof.systemTicks = 0; },
    (proof) => { proof.proofGenerationMs = 0; proof.cpuTicksPerWallMillisecond = null; },
    (proof) => { proof.containment.memorySwapMaxBytes = '1'; },
    (proof) => { proof.containment.oomKillDelta = 1; },
    (proof) => { proof.containment.terminatedSuccessfully = false; },
  ];
  for (const [index, mutate] of mutations.entries()) {
    const subject = fixture();
    subject.session.lifecycle.executeDeposit = async ({ operationId }) => {
      const tampered = structuredClone(result('deposit', operationId));
      mutate(tampered.telemetry.proof);
      return tampered;
    };
    await assert.rejects(
      executeV2BetaProductDepositForTest(
        { config: {}, operationId: `deposit.telemetry.${index}`, rpc: {} },
        subject.dependencies,
      ),
      (error) => error instanceof V2BetaProductCommandError
        && error.code === 'BETA_COMMAND_RESULT_REJECTED',
    );
  }
});

test('a command without an explicit ID resumes the exact active action before creating new material', async () => {
  const subject = fixture({ active: { kind: 'deposit', operationId: 'deposit.active' } });
  const actual = await executeV2BetaProductDepositForTest(
    { config: {}, rpc: {} }, subject.dependencies,
  );
  assert.equal(actual.operationId, 'deposit.active');
  assert.deepEqual(subject.calls, [
    ['recover-active', { expectedKind: 'deposit' }],
    ['close'],
  ]);
});

test('exact-rebroadcast recovery requires acknowledgement and current token, then uses only the dedicated lifecycle capability', async () => {
  const subject = fixture();
  const token = '12345678-1234-4123-8123-123456789abc';
  const actual = await executeV2BetaProductExactRebroadcastRecoveryForTest({
    acknowledgedExactRebroadcast: true,
    config: {},
    operationId: 'deposit.recovery.1',
    priorAttemptToken: token,
    rpc: {},
  }, subject.dependencies);
  assert.equal(actual.command, 'recover-exact-rebroadcast');
  assert.deepEqual(subject.calls, [
    ['rebroadcast', {
      acknowledgedExactRebroadcast: true,
      operationId: 'deposit.recovery.1',
      priorAttemptToken: token,
    }],
    ['close'],
  ]);

  for (const value of [
    {
      acknowledgedExactRebroadcast: false,
      config: {}, operationId: 'deposit.recovery.2', priorAttemptToken: token, rpc: {},
    },
    {
      acknowledgedExactRebroadcast: true,
      config: {}, operationId: 'deposit.recovery.3', priorAttemptToken: 'stale', rpc: {},
    },
  ]) {
    const rejected = fixture();
    await assert.rejects(
      executeV2BetaProductExactRebroadcastRecoveryForTest(value, rejected.dependencies),
      error => error instanceof V2BetaProductCommandError,
    );
    assert.equal(rejected.calls.includes('rebroadcast'), false);
  }
});

test('read-only recovery inspection exposes the current safe CAS token without sending', async () => {
  const subject = fixture();
  const actual = await inspectV2BetaProductRecoveryForTest({
    config: {}, operationId: 'deposit.recovery.1', rpc: {},
  }, subject.dependencies);
  assert.equal(actual.command, 'recovery-inspect');
  assert.equal(actual.recovery.exactRebroadcastAvailable, true);
  assert.equal(
    actual.recovery.delivery.attemptToken,
    '12345678-1234-4123-8123-123456789abc',
  );
  assert.deepEqual(subject.calls, [
    ['recovery-status', { operationId: 'deposit.recovery.1' }],
    ['close'],
  ]);
});
