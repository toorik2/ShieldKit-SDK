/**
 * Narrow, zero-conf-only Chipnet admission boundary for the unqualified V2
 * beta lane. It never polls for blocks, retries a send, or changes durable
 * delivery state without exact raw-transaction and state-NFT readback.
 */
import { createHash } from 'node:crypto';

import { assertBchnChipnetRpc } from '../chipnet-rpc.mjs';
import { sendAndReadbackExactTransactionOnce } from '../transaction-coordinator.mjs';
import { assertV2DeliveryJournal } from './delivery-journal.mjs';
import { canonicalizeV2Evidence, inspectV2LocalVmEvidence } from './vm-evidence.mjs';
import { createV2InputRoleLayout, parseV2RawTransaction, sha256Hex } from './transaction-policy.mjs';

const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
// Immutable delivery identity schema. `identityFor` hashes this value into the
// durable journal metadata, so it must never track presentation-only changes.
export const V2_BETA_ZERO_CONF_ADMISSION_SCHEMA =
  'shieldkit-v2-beta-zero-conf-admission-v1';
export const V2_BETA_ZERO_CONF_ADMISSION_RESULT_SCHEMA =
  'shieldkit-v2-beta-zero-conf-admission-result-v2';
export const V2_BETA_ZERO_CONF_ADMISSION_ROUTES = Object.freeze([
  'fresh-single-pass',
  'fresh-reconciled-after-indeterminate-send',
  'read-only-reconciliation',
  'explicit-rebroadcast-precheck-visible',
  'explicit-rebroadcast-single-pass',
  'explicit-rebroadcast-reconciled-after-indeterminate-send',
]);
export const V2_BETA_ZERO_CONF_ADMISSION_CRASH_STAGES = Object.freeze([
  'admission.after_claim', 'admission.before_send', 'admission.after_send',
  'admission.after_raw_readback', 'admission.after_state_readback',
  'admission.after_commit',
]);

export class V2BetaZeroConfAdmissionError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaZeroConfAdmissionError';
    this.code = code;
    if (options?.operationId !== undefined) this.operationId = options.operationId;
    if (options?.transactionId !== undefined) this.transactionId = options.transactionId;
  }
}

export class V2BetaZeroConfAdmissionCrash extends Error {
  constructor(stage) {
    super(`injected beta zero-conf admission crash at ${stage}`);
    this.name = 'V2BetaZeroConfAdmissionCrash';
    this.stage = stage;
  }
}

const fail = (code, message, options = undefined) => { throw new V2BetaZeroConfAdmissionError(code, message, options); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail('ADMISSION_INVALID', `${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('ADMISSION_INVALID', `${label} has missing or unknown fields`);
  return value;
}
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail('ADMISSION_INVALID', `${label} must be lowercase SHA-256`); return value; }
function decimal(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value)) fail('ADMISSION_INVALID', `${label} must be a canonical unsigned decimal string`); return value; }
function carrierCount(value) { if (!Number.isSafeInteger(value) || value < 1 || value > 255) fail('ADMISSION_INVALID', 'carrierCount must be an integer from 1 through 255'); return value; }
function operationId(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) fail('ADMISSION_INVALID', 'operationId is invalid'); return value; }
function crashAt(value) { if (value === null || value === undefined) return null; if (!V2_BETA_ZERO_CONF_ADMISSION_CRASH_STAGES.includes(value)) fail('ADMISSION_INVALID', 'crashAt is unsupported'); return value; }
function crash(requested, stage) { if (requested === stage) throw new V2BetaZeroConfAdmissionCrash(stage); }

function submissionDependencies(value) {
  if (value === undefined) return Object.freeze({ beforeSendAttempt: undefined });
  exact(value, ['beforeSendAttempt'], 'admission dependencies');
  if (typeof value.beforeSendAttempt !== 'function') {
    fail('ADMISSION_INVALID', 'beforeSendAttempt must be a function');
  }
  return Object.freeze({ beforeSendAttempt: value.beforeSendAttempt });
}

function exactRecoveryOptions(value) {
  exact(
    value,
    ['acknowledgedExactRebroadcast', 'priorAttemptToken'],
    'exact rebroadcast options',
  );
  if (value.acknowledgedExactRebroadcast !== true) {
    fail(
      'ADMISSION_EXACT_REBROADCAST_ACK_REQUIRED',
      'exact rebroadcast requires acknowledgedExactRebroadcast: true',
    );
  }
  if (typeof value.priorAttemptToken !== 'string'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
      .test(value.priorAttemptToken)) {
    fail(
      'ADMISSION_EXACT_REBROADCAST_TOKEN_INVALID',
      'exact rebroadcast requires the current delivery attempt token',
    );
  }
  return Object.freeze({ ...value });
}

function expectedState(value, instanceId) {
  exact(value, ['capability', 'category', 'commitment', 'tokenAmount', 'valueSatoshis'], 'expectedState');
  if (value.category !== instanceId || value.capability !== 'mutable' || value.tokenAmount !== '0') fail('ADMISSION_STATE_INVALID', 'expected state must be the VM-bound mutable zero-amount instance NFT');
  if (typeof value.commitment !== 'string' || !/^[0-9a-f]{256}$/u.test(value.commitment)) fail('ADMISSION_STATE_INVALID', 'expectedState.commitment must be the exact 128-byte commitment');
  decimal(value.valueSatoshis, 'expectedState.valueSatoshis');
  return Object.freeze({ ...value });
}

function inspectInput(value) {
  exact(value, ['carrierCount', 'crashAt', 'expectedState', 'journal', 'localVmEvidence', 'operationId', 'rawTransactionHex', 'rpc'], 'admission input');
  const rpc = (() => { try { return assertBchnChipnetRpc(value.rpc); } catch (error) { fail('ADMISSION_RPC_REQUIRED', error instanceof Error ? error.message : 'branded Chipnet product RPC is required', { cause: error }); } })();
  const journal = (() => { try { return assertV2DeliveryJournal(value.journal); } catch (error) { fail('ADMISSION_JOURNAL_REQUIRED', error instanceof Error ? error.message : 'branded V2 delivery journal is required', { cause: error }); } })();
  const count = carrierCount(value.carrierCount); operationId(value.operationId);
  if (!(value.localVmEvidence instanceof Uint8Array) || value.localVmEvidence.length === 0) fail('ADMISSION_VM_REQUIRED', 'localVmEvidence must be nonempty canonical evidence bytes');
  let vm;
  try { vm = inspectV2LocalVmEvidence(value.localVmEvidence); } catch (error) { fail('ADMISSION_VM_INVALID', error instanceof Error ? error.message : 'local all-input VM evidence is invalid', { cause: error }); }
  let transaction;
  try { transaction = parseV2RawTransaction(value.rawTransactionHex); } catch (error) { fail('ADMISSION_TRANSACTION_INVALID', error instanceof Error ? error.message : 'raw signed transaction is invalid', { cause: error }); }
  const layout = createV2InputRoleLayout(count);
  if (vm.carrierCount !== count || vm.transaction.rawTransactionHex !== transaction.rawTransactionHex
    || vm.transaction.txid !== transaction.txid || vm.transaction.inputCount !== layout.length
    || vm.allInputsAccepted !== true || vm.inputs.length !== layout.length
    || canonicalizeV2Evidence(vm.inputRoleLayout) !== canonicalizeV2Evidence(layout)) fail('ADMISSION_VM_INVALID', 'local VM evidence does not prove every input of this exact carrier topology');
  return Object.freeze({ rpc, journal, carrierCount: count, operationId: value.operationId, crashAt: crashAt(value.crashAt), rawTransactionHex: transaction.rawTransactionHex, transaction, vm, expectedState: expectedState(value.expectedState, vm.instanceId) });
}

function claims() { return Object.freeze({ confirmed: false, mined: false, productionQualified: false }); }
function identityFor(input) {
  const roleLayoutHash = sha256(Buffer.from(canonicalizeV2Evidence(input.vm.inputRoleLayout), 'utf8'));
  const metadata = Object.freeze({
    schema: V2_BETA_ZERO_CONF_ADMISSION_SCHEMA,
    operationId: input.operationId,
    txid: input.transaction.txid,
    rawTransactionSha256: sha256Hex(Buffer.from(input.rawTransactionHex, 'hex')),
    carrierCount: input.carrierCount,
    vmEvidenceHash: input.vm.evidenceHash,
    roleLayoutHash,
    expectedState: input.expectedState,
    claims: claims(),
  });
  return Object.freeze({
    operationId: input.operationId,
    txid: input.transaction.txid,
    metadataHash: sha256(Buffer.from(canonicalizeV2Evidence(metadata), 'utf8')),
    evidenceHash: input.vm.evidenceHash,
    carrierCount: input.carrierCount,
    roleLayoutHash,
    rawTransactionSha256: metadata.rawTransactionSha256,
    metadata,
  });
}

function journalIdentity(identity) {
  return Object.freeze({
    operationId: identity.operationId,
    txid: identity.txid,
    metadataHash: identity.metadataHash,
    evidenceHash: identity.evidenceHash,
    carrierCount: identity.carrierCount,
    roleLayoutHash: identity.roleLayoutHash,
  });
}

function observedSatoshis(value) {
  if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) return value.valueSatoshis;
  if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) {
    const sats = Math.round(value.value * 1e8);
    if (Number.isSafeInteger(sats) && sats / 1e8 === value.value) return String(sats);
  }
  fail('ADMISSION_STATE_READBACK_INVALID', 'Chipnet state output has no exact safe satoshi value');
}

async function exactReadback(input, identity, requestedCrash, admitted = undefined) {
  let raw;
  if (admitted === undefined) {
    try { raw = await input.rpc.getrawtransaction(identity.txid, true); } catch (error) { fail('ADMISSION_RAW_READBACK_FAILED', error instanceof Error ? error.message : 'Chipnet raw readback failed', { cause: error }); }
  } else {
    raw = Object.freeze({
      txid: admitted.transactionId,
      hex: admitted.rawTransactionHex,
    });
  }
  if (raw?.txid !== identity.txid || raw?.hex !== input.rawTransactionHex) fail('ADMISSION_RAW_READBACK_INVALID', 'Chipnet raw readback differs from the exact signed transaction');
  crash(requestedCrash, 'admission.after_raw_readback');
  let state;
  if (admitted === undefined) {
    try { state = await input.rpc.gettxout(identity.txid, 0); } catch (error) { fail('ADMISSION_STATE_READBACK_FAILED', error instanceof Error ? error.message : 'Chipnet state readback failed', { cause: error }); }
  } else {
    state = admitted.stateOutput;
  }
  const token = state?.tokenData ?? state?.token;
  const expectedWireCategory = Buffer.from(input.expectedState.category, 'hex').reverse().toString('hex');
  if (state === null || token?.category !== expectedWireCategory || token?.nft?.capability !== input.expectedState.capability
    || String(token?.amount) !== input.expectedState.tokenAmount || token?.nft?.commitment !== input.expectedState.commitment
    || observedSatoshis(state) !== input.expectedState.valueSatoshis) fail('ADMISSION_STATE_READBACK_INVALID', 'Chipnet output-0 state NFT differs from the exact expected category, commitment, token, capability, or value');
  crash(requestedCrash, 'admission.after_state_readback');
  return Object.freeze({ rawTransactionSha256: identity.rawTransactionSha256, stateOutpoint: Object.freeze({ txid: identity.txid, vout: 0 }), stateCategoryWire: expectedWireCategory, stateCommitmentSha256: sha256(Buffer.from(input.expectedState.commitment, 'hex')) });
}

function admissionRoute(value) {
  if (!V2_BETA_ZERO_CONF_ADMISSION_ROUTES.includes(value)) {
    fail('ADMISSION_INVALID', 'admission route is unsupported');
  }
  return value;
}

function result(input, identity, journalRecord, admission, readback, status, route) {
  return Object.freeze({
    schema: V2_BETA_ZERO_CONF_ADMISSION_RESULT_SCHEMA,
    status, admissionRoute: admissionRoute(route), claims: claims(), operationId: input.operationId,
    txid: identity.txid, backend: input.rpc.backend, journal: Object.freeze({ state: journalRecord.state, attemptCount: journalRecord.attemptCount, attemptToken: journalRecord.attemptToken, metadataHash: identity.metadataHash, vmEvidenceHash: identity.evidenceHash, roleLayoutHash: identity.roleLayoutHash }),
    admission, readback,
  });
}

function markIndeterminate(input, claimed, reason) {
  try { return input.journal.markIndeterminate({ operationId: input.operationId, attemptToken: claimed.attemptToken, reason: String(reason).replace(/[\u0000-\u001f\u007f]/gu, ' ').slice(0, 256) || 'send outcome is indeterminate' }); } catch { return input.journal.record(input.operationId); }
}

async function reconcileAfterIndeterminateSend(input, identity, claimed, sendError, route) {
  try {
    const readback = await exactReadback(input, identity, input.crashAt);
    const observed = input.journal.reconcileObserved({
      operationId: input.operationId,
      txid: identity.txid,
      rawTransactionSha256: identity.rawTransactionSha256,
    });
    const reconciled = input.journal.markLocallyReconciled({
      operationId: input.operationId,
      txid: identity.txid,
      rawTransactionSha256: identity.rawTransactionSha256,
    });
    crash(input.crashAt, 'admission.after_commit');
    return result(
      input,
      identity,
      reconciled ?? observed,
      Object.freeze({ allowed: null, txid: identity.txid }),
      readback,
      'locally-reconciled-zero-conf-beta-unqualified',
      route,
    );
  } catch (error) {
    markIndeterminate(
      input,
      claimed,
      `${sendError instanceof Error ? sendError.message : String(sendError)}; read-only reconciliation failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    if (error instanceof V2BetaZeroConfAdmissionCrash) throw error;
    return null;
  }
}

/** Perform one Chipnet admission request, then require exact zero-conf readback. */
export async function submitV2BetaZeroConfAdmission(value, dependencies = undefined) {
  const input = inspectInput(value); const identity = identityFor(input);
  const hooks = submissionDependencies(dependencies);
  const claimed = input.journal.claimOrCreate(journalIdentity(identity));
  crash(input.crashAt, 'admission.after_claim'); crash(input.crashAt, 'admission.before_send');
  let gated;
  try {
    gated = await sendAndReadbackExactTransactionOnce({
      rpc: input.rpc,
      rawTransactionHex: input.rawTransactionHex,
      expectedTransactionId: identity.txid,
      stateOutputIndex: 0,
      network: 'chipnet',
      setupMode: 'development-only',
      beforeSendAttempt: async () => {
        if (hooks.beforeSendAttempt !== undefined) {
          await hooks.beforeSendAttempt(Object.freeze({
            operationId: input.operationId,
            txid: identity.txid,
            rawTransactionSha256: identity.rawTransactionSha256,
          }));
        }
      },
    });
  } catch (error) {
    if (error?.sendAttempted === true) {
      const recovered = await reconcileAfterIndeterminateSend(
        input,
        identity,
        claimed,
        error,
        'fresh-reconciled-after-indeterminate-send',
      );
      if (recovered !== null) return recovered;
      fail(
        'ADMISSION_SEND_INDETERMINATE',
        'Chipnet send outcome is indeterminate; reconcile read-only before any explicit recovery action',
        { cause: error, operationId: input.operationId, transactionId: identity.txid },
      );
    }
    if (error?.code === 'EXACT_BROADCAST_DURABILITY_FAILED') {
      fail('ADMISSION_BEFORE_SEND_FAILED', 'the durable pre-send callback failed before the Chipnet broadcast', { cause: error });
    }
    fail('ADMISSION_BROADCAST_GATE_REJECTED', 'the mandatory transaction broadcast gate rejected the beta admission', { cause: error });
  }
  const admission = gated.admission;
  try { crash(input.crashAt, 'admission.after_send'); } catch (error) { markIndeterminate(input, claimed, 'crash injected after Chipnet product send before readback'); throw error; }
  let readback;
  try { readback = await exactReadback(input, identity, input.crashAt, gated.readback); }
  catch (error) {
    markIndeterminate(input, claimed, error instanceof Error ? error.message : String(error));
    throw error;
  }
  const submitted = input.journal.markSubmitted({ operationId: input.operationId, txid: identity.txid, attemptToken: claimed.attemptToken, rawTransactionSha256: identity.rawTransactionSha256 });
  const reconciled = input.journal.markLocallyReconciled({ operationId: input.operationId, txid: identity.txid, rawTransactionSha256: identity.rawTransactionSha256 });
  crash(input.crashAt, 'admission.after_commit');
  return result(input, identity, reconciled ?? submitted, admission, readback, 'locally-reconciled-zero-conf-beta-unqualified', 'fresh-single-pass');
}

/** Read-only repair path: it never calls testmempoolaccept or sendrawtransaction. */
export async function reconcileV2BetaZeroConfAdmission(value) {
  const input = inspectInput(value); const identity = identityFor(input);
  const prior = input.journal.record(input.operationId);
  if (prior === null) fail('ADMISSION_NOT_CLAIMED', 'read-only reconciliation requires an existing delivery claim');
  if (prior.txid !== identity.txid || prior.metadataHash !== identity.metadataHash || prior.evidenceHash !== identity.evidenceHash
    || prior.carrierCount !== identity.carrierCount || prior.roleLayoutHash !== identity.roleLayoutHash) fail('ADMISSION_IDENTITY_MISMATCH', 'delivery journal does not bind this exact beta admission identity');
  const readback = await exactReadback(input, identity, input.crashAt);
  const submitted = prior.state === 'attempted' || prior.state === 'indeterminate'
    ? input.journal.reconcileObserved({ operationId: input.operationId, txid: identity.txid, rawTransactionSha256: identity.rawTransactionSha256 })
    : prior;
  const reconciled = input.journal.markLocallyReconciled({ operationId: input.operationId, txid: identity.txid, rawTransactionSha256: identity.rawTransactionSha256 });
  crash(input.crashAt, 'admission.after_commit');
  return result(input, identity, reconciled ?? submitted, Object.freeze({ allowed: null, txid: identity.txid }), readback, 'locally-reconciled-zero-conf-beta-unqualified', 'read-only-reconciliation');
}

/**
 * Explicit recovery only: reconcile read-only first, otherwise repeat the
 * identical VM-verified bytes after both a user acknowledgement and a
 * compare-and-swap claim over the current durable attempt token.
 */
export async function rebroadcastV2BetaZeroConfAdmission(value, options) {
  const input = inspectInput(value);
  const identity = identityFor(input);
  const recovery = exactRecoveryOptions(options);
  const prior = input.journal.record(input.operationId);
  if (prior === null) {
    fail('ADMISSION_NOT_CLAIMED', 'exact rebroadcast requires an unresolved prior delivery claim');
  }
  if (prior.txid !== identity.txid || prior.metadataHash !== identity.metadataHash
    || prior.evidenceHash !== identity.evidenceHash
    || prior.carrierCount !== identity.carrierCount
    || prior.roleLayoutHash !== identity.roleLayoutHash) {
    fail('ADMISSION_IDENTITY_MISMATCH', 'delivery journal does not bind this exact beta admission identity');
  }
  if (!['attempted', 'indeterminate'].includes(prior.state)) {
    fail('ADMISSION_EXACT_REBROADCAST_NOT_REQUIRED', `delivery state ${prior.state} is not unresolved`);
  }
  if (prior.attemptToken !== recovery.priorAttemptToken) {
    fail('ADMISSION_EXACT_REBROADCAST_TOKEN_STALE', 'delivery attempt token changed; inspect current state before retrying');
  }

  // If the exact transaction is already visible, never resend it even when
  // the operator supplied an acknowledgement. Any divergent raw/state result
  // also fails closed. Only an unavailable raw transaction proceeds to the
  // one-shot admission gate below.
  try {
    const readback = await exactReadback(input, identity, input.crashAt);
    const observed = input.journal.reconcileObserved({
      operationId: input.operationId,
      txid: identity.txid,
      rawTransactionSha256: identity.rawTransactionSha256,
    });
    const reconciled = input.journal.markLocallyReconciled({
      operationId: input.operationId,
      txid: identity.txid,
      rawTransactionSha256: identity.rawTransactionSha256,
    });
    return result(
      input,
      identity,
      reconciled ?? observed,
      Object.freeze({ allowed: null, txid: identity.txid }),
      readback,
      'locally-reconciled-zero-conf-beta-unqualified',
      'explicit-rebroadcast-precheck-visible',
    );
  } catch (error) {
    if (error?.code !== 'ADMISSION_RAW_READBACK_FAILED') throw error;
  }

  let claimed;
  let gated;
  try {
    gated = await sendAndReadbackExactTransactionOnce({
      rpc: input.rpc,
      rawTransactionHex: input.rawTransactionHex,
      expectedTransactionId: identity.txid,
      stateOutputIndex: 0,
      network: 'chipnet',
      setupMode: 'development-only',
      beforeSendAttempt: async () => {
        claimed = input.journal.claimExactResubmission({
          identity: journalIdentity(identity),
          priorAttemptToken: recovery.priorAttemptToken,
        });
      },
    });
  } catch (error) {
    if (error?.sendAttempted === true && claimed !== undefined) {
      const recovered = await reconcileAfterIndeterminateSend(
        input,
        identity,
        claimed,
        error,
        'explicit-rebroadcast-reconciled-after-indeterminate-send',
      );
      if (recovered !== null) return recovered;
      fail('ADMISSION_SEND_INDETERMINATE', 'Chipnet product exact rebroadcast outcome is indeterminate; reconcile read-only before another explicit recovery action', { cause: error });
    }
    if (error?.code === 'EXACT_BROADCAST_DURABILITY_FAILED') {
      fail('ADMISSION_EXACT_REBROADCAST_CLAIM_FAILED', 'the durable exact-rebroadcast claim failed before the Chipnet product send', { cause: error });
    }
    fail('ADMISSION_BROADCAST_GATE_REJECTED', 'the mandatory transaction broadcast gate rejected the exact beta rebroadcast', { cause: error });
  }
  try { crash(input.crashAt, 'admission.after_send'); }
  catch (error) {
    markIndeterminate(input, claimed, 'crash injected after exact Chipnet product rebroadcast before readback');
    throw error;
  }
  let readback;
  try { readback = await exactReadback(input, identity, input.crashAt, gated.readback); }
  catch (error) {
    markIndeterminate(input, claimed, error instanceof Error ? error.message : String(error));
    throw error;
  }
  const submitted = input.journal.markSubmitted({
    operationId: input.operationId,
    txid: identity.txid,
    attemptToken: claimed.attemptToken,
    rawTransactionSha256: identity.rawTransactionSha256,
  });
  const reconciled = input.journal.markLocallyReconciled({
    operationId: input.operationId,
    txid: identity.txid,
    rawTransactionSha256: identity.rawTransactionSha256,
  });
  crash(input.crashAt, 'admission.after_commit');
  return result(
    input,
    identity,
    reconciled ?? submitted,
    gated.admission,
    readback,
    'locally-reconciled-zero-conf-beta-unqualified',
    'explicit-rebroadcast-single-pass',
  );
}

export function deriveV2BetaZeroConfAdmissionIdentity(value) {
  return identityFor(inspectInput(value));
}
