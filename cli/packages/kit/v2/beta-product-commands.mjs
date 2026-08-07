import { createHash, randomBytes as systemRandomBytes } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { performance } from 'node:perf_hooks';

import { decodeCashAddress } from '@bitauth/libauth';

import { CHIPNET_GENESIS_HASH, isBchnChipnetBackend } from '../chipnet-rpc.mjs';
import { openV2BetaProductSession } from './beta-product-session.mjs';
import {
  V2_BETA_PRODUCT_ACTION_RESULT_SCHEMA,
} from './beta-product-action-lifecycle.mjs';
import {
  assertV2BetaWarmActionRuntimeWork,
  observeV2BetaActionRuntimeWork,
} from '../../profile/v2/beta-runtime-work-observer.mjs';

export const V2_BETA_PRODUCT_COMMAND_RESULT_SCHEMA =
  'shieldkit-v2-beta-product-command-result-v3';

export class V2BetaProductCommandError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductCommandError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductCommandError(code, message, options);
};

function actionTelemetryAvailable(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || value.schema !== 'shieldkit-v2-beta-product-action-telemetry-v1'
    || value.proof === null || Array.isArray(value.proof) || typeof value.proof !== 'object'
    || value.vm?.schema !== 'shieldkit-v2-local-vm-telemetry-v1'
    || value.vm?.allInputsAccepted !== true || !Array.isArray(value.vm.inputs)
    || value.vm.inputs.length === 0
    || value.store === null || Array.isArray(value.store) || typeof value.store !== 'object') {
    return false;
  }
  const proof = value.proof;
  const proofKeys = [
    'activeCpuThreads', 'containment', 'cpuTicksPerWallMillisecond',
    'observedThreads', 'ompThreads', 'peakRssKiB', 'proofGenerationMs',
    'systemTicks', 'totalTicks', 'userTicks',
  ];
  const containmentKeys = [
    'backend', 'memoryMaxBytes', 'memoryPeakBytes', 'memorySwapMaxBytes',
    'oomDelta', 'oomKillDelta', 'terminatedSuccessfully',
  ];
  const cores = availableParallelism();
  const containment = proof.containment;
  if (Object.keys(proof).sort().join(',') !== [...proofKeys].sort().join(',')
    || !['activeCpuThreads', 'ompThreads', 'observedThreads', 'peakRssKiB',
      'systemTicks', 'totalTicks', 'userTicks']
      .every((name) => Number.isSafeInteger(proof[name]) && proof[name] >= 0)
    || proof.ompThreads !== cores
    || proof.observedThreads < proof.ompThreads
    || proof.activeCpuThreads < proof.ompThreads
    || proof.activeCpuThreads > proof.observedThreads
    || proof.peakRssKiB <= 0
    || proof.totalTicks !== proof.userTicks + proof.systemTicks
    || proof.totalTicks <= 0
    || typeof proof.proofGenerationMs !== 'number' || !Number.isFinite(proof.proofGenerationMs)
    || proof.proofGenerationMs <= 0
    || typeof proof.cpuTicksPerWallMillisecond !== 'number'
    || !Number.isFinite(proof.cpuTicksPerWallMillisecond)
    || proof.cpuTicksPerWallMillisecond <= 0
    || proof.cpuTicksPerWallMillisecond !== proof.totalTicks / proof.proofGenerationMs
    || containment === null || Array.isArray(containment) || typeof containment !== 'object'
    || Object.keys(containment).sort().join(',') !== [...containmentKeys].sort().join(',')
    || containment.backend !== 'linux-systemd-cgroup-v2'
    || containment.memoryMaxBytes !== '4294967296'
    || containment.memorySwapMaxBytes !== '0'
    || typeof containment.memoryPeakBytes !== 'string'
    || !/^(0|[1-9][0-9]*)$/u.test(containment.memoryPeakBytes)
    || BigInt(containment.memoryPeakBytes) <= 0n
    || BigInt(containment.memoryPeakBytes) > 4294967296n
    || containment.oomDelta !== 0
    || containment.oomKillDelta !== 0
    || containment.terminatedSuccessfully !== true) return false;
  const snapshot = (entry, delta = false) => entry !== null && !Array.isArray(entry)
    && typeof entry === 'object'
    && ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes']
      .every((name) => Number.isSafeInteger(entry[name]))
    && (delta || ['databaseBytes', 'liveCount', 'noteCount', 'nullifierCount', 'walBytes']
      .every((name) => entry[name] >= 0))
    && entry.liveCount === entry.noteCount - entry.nullifierCount;
  return snapshot(value.store.pre) && snapshot(value.store.post)
    && snapshot(value.store.delta, true)
    && value.vm.inputs.every((input, index) => input !== null
      && typeof input === 'object' && input.index === index && input.accepted === true
      && input.metrics !== null && typeof input.metrics === 'object');
}

function exactOptional(value, allowed, required, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_COMMAND_INVALID', `${label} must be a plain object`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key))
    || required.some((key) => !Object.hasOwn(value, key))) {
    fail('BETA_COMMAND_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function operationId(value, kind, randomBytes) {
  if (value !== undefined) {
    if (typeof value !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) {
      fail('BETA_COMMAND_INVALID', 'operationId is malformed');
    }
    return value;
  }
  let bytes;
  try { bytes = randomBytes(32); }
  catch (error) { fail('BETA_COMMAND_CSPRNG_FAILURE', 'could not create an operation identifier', { cause: error }); }
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    fail('BETA_COMMAND_CSPRNG_FAILURE', 'operation identifier CSPRNG returned invalid bytes');
  }
  return `${kind}.${Buffer.from(bytes).toString('hex')}`;
}

function attemptToken(value) {
  if (typeof value !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
      .test(value)) {
    fail('BETA_EXACT_REBROADCAST_TOKEN_INVALID', 'attemptToken must be the current delivery CAS token');
  }
  return value;
}

function payoutLockingBytecode(cashAddress) {
  if (typeof cashAddress !== 'string') {
    fail('BETA_WITHDRAWAL_ADDRESS_REQUIRED', 'withdraw requires --to with a Chipnet P2PKH cash address');
  }
  const decoded = decodeCashAddress(cashAddress);
  if (typeof decoded === 'string'
    || decoded.prefix !== 'bchtest'
    || decoded.type !== 'p2pkh'
    || decoded.payload.length !== 20) {
    fail('BETA_WITHDRAWAL_ADDRESS_REJECTED', 'withdrawal destination must be an exact bchtest P2PKH cash address');
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(decoded.payload),
    Buffer.from([0x88, 0xac]),
  ]);
}

function inspectActionResult(value, kind, operation) {
  const rpc = value?.rpcObservation;
  const counts = rpc?.methodCounts;
  const expectedRpc = Object.freeze({
    'fresh-single-pass': Object.freeze({ allowed: true, raw: 1, state: 1, send: 1 }),
    'fresh-reconciled-after-indeterminate-send': Object.freeze({ allowed: null, raw: 2, state: 2, send: 1 }),
    'read-only-reconciliation': Object.freeze({ allowed: null, raw: 1, state: 1, send: 0 }),
    'explicit-rebroadcast-precheck-visible': Object.freeze({ allowed: null, raw: 1, state: 1, send: 0 }),
    'explicit-rebroadcast-single-pass': Object.freeze({ allowed: true, raw: 2, state: 1, send: 1 }),
    'explicit-rebroadcast-reconciled-after-indeterminate-send': Object.freeze({ allowed: null, raw: 3, state: 2, send: 1 }),
  })[value?.admissionRoute];
  if (value === null || typeof value !== 'object'
    || value.schema !== V2_BETA_PRODUCT_ACTION_RESULT_SCHEMA
    || value.status !== 'accepted-zero-conf-beta-unqualified'
    || value.kind !== kind || value.operationId !== operation
    || value.claims?.broadcasted !== true || value.claims?.mined !== false
    || value.claims?.confirmed !== false
    || value.claims?.productionQualified !== false
    || !actionTelemetryAvailable(value.telemetry)
    || typeof value.transactionId !== 'string'
    || !/^[0-9a-f]{64}$/u.test(value.transactionId)
    || !isBchnChipnetBackend(rpc?.backend)
    || rpc?.genesis !== CHIPNET_GENESIS_HASH
    || counts === null || typeof counts !== 'object' || Array.isArray(counts)
    || Object.keys(counts).sort().join(',')
      !== 'getblockhash,getrawtransaction,gettxout,scantxoutset,sendrawtransaction,testmempoolaccept'
    || expectedRpc === undefined
    || counts.getblockhash !== 0 || counts.getrawtransaction !== expectedRpc.raw
    || counts.gettxout !== expectedRpc.state || counts.scantxoutset !== 0
    || counts.sendrawtransaction !== expectedRpc.send || counts.testmempoolaccept !== 0) {
    fail('BETA_COMMAND_RESULT_REJECTED', 'action lifecycle returned a result outside its exact declared zero-conf route');
  }
  return value;
}

async function execute(value, dependencies) {
  const kind = value.kind;
  const requestedOperationWasExplicit = value.operationId !== undefined;
  let operation = operationId(value.operationId, kind, dependencies.randomBytes);
  const withdrawalLockingBytecode = kind === 'withdrawal'
    ? payoutLockingBytecode(value.toCashAddress)
    : null;
  const expectedWithdrawalLockingBytecodeHash = withdrawalLockingBytecode === null
    ? undefined
    : createHash('sha256').update(withdrawalLockingBytecode).digest('hex');
  const started = performance.now();
  let session;
  let action;
  let sessionOpenMs;
  let runtimeWork;
  const observed = await observeV2BetaActionRuntimeWork(async () => {
  try {
    const openStarted = performance.now();
    session = await dependencies.openSession({ config: value.config, rpc: value.rpc });
    sessionOpenMs = performance.now() - openStarted;
    if (session === null || typeof session !== 'object'
      || typeof session.close !== 'function'
      || session.lifecycle === null || typeof session.lifecycle !== 'object'
      || typeof session.lifecycle.resume !== 'function'
      || typeof session.lifecycle.recoverOrResumeActive !== 'function') {
      fail('BETA_COMMAND_SESSION_REJECTED', 'beta product session is malformed');
    }
    const intent = {
      expectedKind: kind,
      ...(value.noteId === undefined ? {} : { expectedNoteId: value.noteId }),
      ...(expectedWithdrawalLockingBytecodeHash === undefined
        ? {} : { expectedWithdrawalLockingBytecodeHash }),
    };
    if (requestedOperationWasExplicit) {
      try {
        // An explicit operation identity is an idempotency key. Reconcile an
        // immutable staged/accepted transaction before preparing anything new;
        // resume never automatically re-sends an indeterminate transaction.
        action = await session.lifecycle.resume({ operationId: operation, ...intent });
      } catch (error) {
        if (error?.code !== 'BETA_STAGED_ACTION_REQUIRED') throw error;
      }
      if (action === undefined) {
        action = await session.lifecycle.recoverOrResumeActive({
          ...intent,
          expectedOperationId: operation,
        });
        if (action === null) {
          try {
            // Distinguish no active operation from a reserved operation that
            // was just durably aborted. An aborted idempotency key is never
            // silently reused for different private material.
            action = await session.lifecycle.resume({ operationId: operation, ...intent });
          } catch (error) {
            if (error?.code !== 'BETA_STAGED_ACTION_REQUIRED') throw error;
          }
        }
      }
    } else {
      action = await session.lifecycle.recoverOrResumeActive(intent);
    }
    const startFresh = async () => {
      if (kind === 'deposit') {
        return session.lifecycle.executeDeposit({ operationId: operation });
      }
      if (kind === 'transfer') {
        return session.lifecycle.executeTransfer({
          operationId: operation,
          ...(value.noteId === undefined ? {} : { noteId: value.noteId }),
        });
      }
      return session.lifecycle.executeWithdrawal({
        operationId: operation,
        ...(value.noteId === undefined ? {} : { noteId: value.noteId }),
        payoutLockingBytecode: withdrawalLockingBytecode,
      });
    };
    if (action === undefined) {
      action = await startFresh();
    }
    if (action === null) {
      action = await startFresh();
    }
    operation = action.operationId;
    inspectActionResult(action, kind, operation);
  } finally {
    session?.close();
  }
    return Object.freeze({ action, sessionOpenMs });
  });
  action = observed.value.action;
  sessionOpenMs = observed.value.sessionOpenMs;
  runtimeWork = assertV2BetaWarmActionRuntimeWork(observed.observation);
  return Object.freeze({
    schema: V2_BETA_PRODUCT_COMMAND_RESULT_SCHEMA,
    command: kind === 'withdrawal' ? 'withdraw' : kind === 'transfer' ? 'transfer' : kind,
    status: action.status,
    operationId: operation,
    transactionId: action.transactionId,
    claims: action.claims,
    action,
    telemetry: action.telemetry,
    runtimeWork,
    timingsMs: Object.freeze({
      sessionOpen: sessionOpenMs,
      action: action.timingsMs.total,
      commandTotal: performance.now() - started,
    }),
  });
}

async function executeRecovery(value, dependencies) {
  if (value.acknowledgedExactRebroadcast !== true) {
    fail(
      'BETA_EXACT_REBROADCAST_ACK_REQUIRED',
      'recovery requires explicit acknowledgement of an identical-byte rebroadcast',
    );
  }
  const operation = operationId(value.operationId, 'recovery', dependencies.randomBytes);
  const priorAttemptToken = attemptToken(value.priorAttemptToken);
  const started = performance.now();
  let session;
  const observed = await observeV2BetaActionRuntimeWork(async () => {
    try {
      const openStarted = performance.now();
      session = await dependencies.openSession({ config: value.config, rpc: value.rpc });
      const sessionOpenMs = performance.now() - openStarted;
      if (session === null || typeof session !== 'object'
        || typeof session.close !== 'function'
        || session.lifecycle === null || typeof session.lifecycle !== 'object'
        || typeof session.lifecycle.rebroadcast !== 'function') {
        fail('BETA_COMMAND_SESSION_REJECTED', 'beta product session has no exact-rebroadcast recovery capability');
      }
      const action = await session.lifecycle.rebroadcast({
        acknowledgedExactRebroadcast: true,
        operationId: operation,
        priorAttemptToken,
      });
      if (!['deposit', 'withdrawal'].includes(action?.kind)) {
        fail('BETA_COMMAND_RESULT_REJECTED', 'exact-rebroadcast recovery returned an unknown action kind');
      }
      inspectActionResult(action, action.kind, operation);
      return Object.freeze({ action, sessionOpenMs });
    } finally {
      session?.close();
    }
  });
  const runtimeWork = assertV2BetaWarmActionRuntimeWork(observed.observation);
  const action = observed.value.action;
  return Object.freeze({
    schema: V2_BETA_PRODUCT_COMMAND_RESULT_SCHEMA,
    command: 'recover-exact-rebroadcast',
    status: action.status,
    operationId: operation,
    transactionId: action.transactionId,
    claims: action.claims,
    action,
    telemetry: action.telemetry,
    runtimeWork,
    timingsMs: Object.freeze({
      sessionOpen: observed.value.sessionOpenMs,
      action: action.timingsMs.total,
      commandTotal: performance.now() - started,
    }),
  });
}

function inspectRecoveryStatus(value, operation) {
  const keys = [
    'claims', 'delivery', 'exactRebroadcastAvailable', 'kind', 'localState',
    'operationId', 'safePreSendAborted', 'schema', 'staged',
  ];
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')
    || value.schema !== 'shieldkit-v2-beta-product-recovery-status-v1'
    || value.operationId !== operation
    || ![null, 'deposit', 'withdrawal'].includes(value.kind)
    || !(value.localState === null || typeof value.localState === 'string')
    || typeof value.safePreSendAborted !== 'boolean'
    || typeof value.staged !== 'boolean'
    || typeof value.exactRebroadcastAvailable !== 'boolean'
    || value.claims?.confirmed !== false
    || value.claims?.mined !== false
    || value.claims?.productionQualified !== false) {
    fail('BETA_RECOVERY_STATUS_REJECTED', 'lifecycle returned a malformed beta recovery status');
  }
  if (value.delivery !== null) {
    const deliveryKeys = ['attemptCount', 'attemptToken', 'state', 'txid'];
    if (Array.isArray(value.delivery) || typeof value.delivery !== 'object'
      || Object.keys(value.delivery).sort().join(',') !== [...deliveryKeys].sort().join(',')
      || !['attempted', 'indeterminate', 'submitted', 'locally_reconciled']
        .includes(value.delivery.state)
      || typeof value.delivery.txid !== 'string'
      || !/^[0-9a-f]{64}$/u.test(value.delivery.txid)
      || !Number.isSafeInteger(value.delivery.attemptCount)
      || value.delivery.attemptCount < 1
      || attemptToken(value.delivery.attemptToken) !== value.delivery.attemptToken) {
      fail('BETA_RECOVERY_STATUS_REJECTED', 'lifecycle returned malformed delivery recovery state');
    }
  }
  if (value.exactRebroadcastAvailable !== (
    value.staged === true
    && value.delivery !== null
    && ['attempted', 'indeterminate'].includes(value.delivery.state)
  )) {
    fail('BETA_RECOVERY_STATUS_REJECTED', 'exact-rebroadcast availability differs from durable recovery state');
  }
  return value;
}

async function executeRecoveryInspection(value, dependencies) {
  const operation = operationId(value.operationId, 'recovery', dependencies.randomBytes);
  const started = performance.now();
  let session;
  const observed = await observeV2BetaActionRuntimeWork(async () => {
    try {
      const openStarted = performance.now();
      session = await dependencies.openSession({ config: value.config, rpc: value.rpc });
      const sessionOpenMs = performance.now() - openStarted;
      if (session === null || typeof session !== 'object'
        || typeof session.close !== 'function'
        || session.lifecycle === null || typeof session.lifecycle !== 'object'
        || typeof session.lifecycle.recoveryStatus !== 'function') {
        fail('BETA_COMMAND_SESSION_REJECTED', 'beta product session has no read-only recovery status capability');
      }
      const recovery = inspectRecoveryStatus(
        session.lifecycle.recoveryStatus({ operationId: operation }),
        operation,
      );
      return Object.freeze({ recovery, sessionOpenMs });
    } finally {
      session?.close();
    }
  });
  return Object.freeze({
    schema: V2_BETA_PRODUCT_COMMAND_RESULT_SCHEMA,
    command: 'recovery-inspect',
    status: 'recovery-inspected-beta-unqualified',
    operationId: operation,
    recovery: observed.value.recovery,
    runtimeWork: assertV2BetaWarmActionRuntimeWork(observed.observation),
    timingsMs: Object.freeze({
      sessionOpen: observed.value.sessionOpenMs,
      commandTotal: performance.now() - started,
    }),
  });
}

function productionDependencies() {
  return Object.freeze({ openSession: openV2BetaProductSession, randomBytes: systemRandomBytes });
}

function testDependencies(value) {
  exactOptional(value, ['openSession', 'randomBytes'], ['openSession', 'randomBytes'], 'beta command test dependencies');
  if (typeof value.openSession !== 'function' || typeof value.randomBytes !== 'function') {
    fail('BETA_COMMAND_INVALID', 'beta command test dependencies must be functions');
  }
  return Object.freeze({ ...value });
}

function depositInput(value) {
  exactOptional(value, ['config', 'operationId', 'rpc'], ['config', 'rpc'], 'beta deposit options');
  return Object.freeze({ ...value, kind: 'deposit' });
}

function transferInput(value) {
  exactOptional(value, ['config', 'noteId', 'operationId', 'rpc'], ['config', 'noteId', 'rpc'], 'beta transfer options');
  return Object.freeze({ ...value, kind: 'transfer' });
}

function withdrawalInput(value) {
  exactOptional(value, ['config', 'noteId', 'operationId', 'rpc', 'toCashAddress'], ['config', 'rpc', 'toCashAddress'], 'beta withdrawal options');
  return Object.freeze({ ...value, kind: 'withdrawal' });
}

function recoveryInput(value) {
  exactOptional(
    value,
    ['acknowledgedExactRebroadcast', 'config', 'operationId', 'priorAttemptToken', 'rpc'],
    ['acknowledgedExactRebroadcast', 'config', 'operationId', 'priorAttemptToken', 'rpc'],
    'beta exact-rebroadcast recovery options',
  );
  return Object.freeze({ ...value });
}

function recoveryInspectionInput(value) {
  exactOptional(
    value,
    ['config', 'operationId', 'rpc'],
    ['config', 'operationId', 'rpc'],
    'beta recovery inspection options',
  );
  return Object.freeze({ ...value });
}

export async function executeV2BetaProductDeposit(value) {
  return execute(depositInput(value), productionDependencies());
}

export async function executeV2BetaProductTransfer(value) {
  return execute(transferInput(value), productionDependencies());
}

export async function executeV2BetaProductWithdrawal(value) {
  return execute(withdrawalInput(value), productionDependencies());
}

export async function executeV2BetaProductExactRebroadcastRecovery(value) {
  return executeRecovery(recoveryInput(value), productionDependencies());
}

export async function inspectV2BetaProductRecovery(value) {
  return executeRecoveryInspection(recoveryInspectionInput(value), productionDependencies());
}

export async function executeV2BetaProductDepositForTest(value, dependencies) {
  return execute(depositInput(value), testDependencies(dependencies));
}

export async function executeV2BetaProductTransferForTest(value, dependencies) {
  return execute(transferInput(value), testDependencies(dependencies));
}

export async function executeV2BetaProductWithdrawalForTest(value, dependencies) {
  return execute(withdrawalInput(value), testDependencies(dependencies));
}

export async function executeV2BetaProductExactRebroadcastRecoveryForTest(value, dependencies) {
  return executeRecovery(recoveryInput(value), testDependencies(dependencies));
}

export async function inspectV2BetaProductRecoveryForTest(value, dependencies) {
  return executeRecoveryInspection(recoveryInspectionInput(value), testDependencies(dependencies));
}
