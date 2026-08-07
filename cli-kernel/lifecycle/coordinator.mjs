/** Durable, single-delivery operation coordinator. */

import { createHash, randomUUID } from 'node:crypto';
import { assertTransition, isPostSend, isPreSend } from '../contracts/operation-states.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';
import { newOperationId } from '../contracts/identity.mjs';
import { createLifecycleObserver } from './observer.mjs';
import { DurableOperationStore, ReservationLedger } from './durable-store.mjs';
import { transactionIdFromHex } from '../chain/admission.mjs';

function validationBinding({ rawTransactionHex, expectedTransactionId, identity, destination }) {
  const profileId = identity?.profileId;
  const instanceId = identity?.instanceId;
  if (typeof profileId !== 'string' || !/^[0-9a-f]{64}$/.test(profileId)) {
    cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'exact profile identity is required before validation/send');
  }
  if (typeof instanceId !== 'string' || !/^[0-9a-f]{64}$/.test(instanceId)) {
    cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'exact instance identity is required before validation/send');
  }
  return Object.freeze({
    rawTransactionSha256: hashBytes(rawTransactionHex), expectedTransactionId, profileId, instanceId,
    destination: destination || null,
  });
}

function validValidationEvidence(evidence, binding) {
  if (!evidence || typeof evidence !== 'object'
    || evidence.wholeTxVm !== true
    || evidence.valid !== true
    || evidence.complete !== true
    || evidence.rawTransactionSha256 !== binding.rawTransactionSha256
    || evidence.transactionId !== binding.expectedTransactionId
    || evidence.profileId !== binding.profileId
    || evidence.instanceId !== binding.instanceId) return false;
  if (binding.destination !== null && evidence.destinationAddress !== binding.destination) return false;
  return true;
}

function exactAcceptedEvidence(evidence, operation) {
  return evidence?.accepted === true
    && evidence?.rejected === false
    && evidence?.indeterminate === false
    && evidence?.sendAttempted === true
    && evidence?.mutationCrossed === true
    && evidence?.txid === operation.expectedTransactionId
    && evidence?.readback?.transactionId === operation.expectedTransactionId
    && evidence?.readback?.rawTransactionHex === operation.rawTransactionHex
    && evidence?.readback?.match === true;
}

function exactRejectedEvidence(evidence) {
  return evidence?.accepted === false
    && evidence?.rejected === true
    && evidence?.indeterminate === false
    && evidence?.sendAttempted === true
    && evidence?.mutationCrossed === true;
}

export class OperationCoordinator {
  constructor({ admission, observer = null, homePath = null, store = null, reservations = null } = {}) {
    if (!admission || admission.kind !== 'SingleSendAdmission' || typeof admission.sendOnce !== 'function') {
      throw new Error('branded SingleSendAdmission with sendOnce required');
    }
    this.admission = admission;
    this.observer = observer || createLifecycleObserver();
    this.homePath = homePath;
    this.store = store || (homePath ? new DurableOperationStore(homePath) : null);
    this.home = this.store?.home ?? null;
    this.reservations = reservations || (this.store ? new ReservationLedger(homePath, this.store) : null);
    this._ops = new Map();
    if (this.store) this.store.loadAllIntoMap(this._ops);
  }

  allocateOperationId() { return newOperationId(); }
  _requireStore() {
    if (!this.store || !this.home) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'qualified mutation requires a validated home-bound transactional store');
    }
  }
  _reload(operationId) { const op = this.store ? this.store.load(operationId) : this._ops.get(operationId); if (op) this._ops.set(operationId, op); return op || null; }
  get(operationId) {
    const op = this._reload(operationId);
    return op ? Object.freeze({ ...op, history: Object.freeze([...(op.history || [])]) }) : null;
  }
  _transition(op, to) { assertTransition(op.state, to); op.state = to; op.history.push({ state: to, at: Date.now() }); }
  _update(operationId, predicate, mutate) {
    this._requireStore();
    const result = this.store.update(operationId, { predicate, mutate });
    if (result.next) this._ops.set(operationId, result.next);
    if (result.current) this._ops.set(operationId, result.current);
    return result;
  }

  begin({ operationId = null, kind, identity = null } = {}) {
    this._requireStore();
    if (identity?.profileId !== this.home?.profileId || identity?.instanceId !== this.home?.instanceId) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'operation identity must exactly match the bound home profile and instance');
    }
    if (identity?.homeId !== undefined && identity.homeId !== this.home.homeId) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'operation home identity conflicts with the durable store');
    }
    if (identity?.network !== undefined && identity.network !== this.home.network) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'operation network identity conflicts with the durable store');
    }
    const id = operationId || this.allocateOperationId();
    const boundIdentity = Object.freeze({
      backendId: this.home.backendId,
      profileId: this.home.profileId,
      instanceId: this.home.instanceId,
      homeId: this.home.homeId,
      network: this.home.network,
      networkGenesis: this.home.networkGenesis,
    });
    const op = {
      operationId: id, kind, identity: boundIdentity, state: 'preparing', rawTransactionHex: null,
      expectedTransactionId: null, casToken: null, sendAttempted: false,
      admissionEvidence: null, validationEvidence: null, reservations: null, destination: null,
      history: [{ state: 'preparing', at: Date.now() }],
    };
    const created = this.store.create(op); this._ops.set(id, created); return this.get(id);
  }

  reserve(operationId, options = {}) {
    this._requireStore();
    const op = this._reload(operationId);
    if (!op) cliFail(ERROR_CODES.INTERNAL, `unknown operation ${operationId}`);
    if (op.sendAttempted || isPostSend(op.state)) cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'cannot reserve after send');
    try { const next = this.store.reserve(operationId, options); this._ops.set(operationId, next); return this.get(operationId); }
    catch (error) { throw error; }
  }

  /** Validate first, then atomically persist bytes + bound validation evidence + send CAS. */
  async stageDurable(operationId, { rawTransactionHex, expectedTransactionId, validate = null } = {}) {
    this._requireStore();
    return this.observer.measure('durable_staging', async () => {
      const current = this._reload(operationId);
      if (!current) cliFail(ERROR_CODES.INTERNAL, `unknown operation ${operationId}`);
      if (current.sendAttempted || isPostSend(current.state)) cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'cannot restage after send attempt');
      if (typeof rawTransactionHex !== 'string' || !/^[0-9a-f]+$/i.test(rawTransactionHex) || rawTransactionHex.length < 2 || rawTransactionHex.length % 2) cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'valid rawTransactionHex required');
      if (typeof expectedTransactionId !== 'string' || !/^[0-9a-f]{64}$/.test(expectedTransactionId)) cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'expectedTransactionId must be 64-char hex');
      if (transactionIdFromHex(rawTransactionHex) !== expectedTransactionId) {
        cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'expectedTransactionId does not match the exact prepared transaction bytes');
      }
      const binding = validationBinding({ rawTransactionHex, expectedTransactionId, identity: current.identity, destination: current.destination });
      if (['withdraw', 'withdrawal'].includes(current.kind) && binding.destination === null) {
        cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'withdrawal must reserve and validate an exact destination before staging');
      }
      if (typeof validate !== 'function') cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'whole-transaction validator required before an operation is sendable');
      const evidence = await this.observer.measure('whole_transaction_validation', () => validate({ rawTransactionHex, expectedTransactionId, identity: current.identity, destination: current.destination }));
      if (!validValidationEvidence(evidence, binding)) cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'whole-transaction validation failed, was incomplete, or was not identity-bound');
      const result = this._update(operationId,
        (op) => !op.sendAttempted && (op.state === 'preparing' || op.state === 'prepared-durable'),
        (op) => {
          op.rawTransactionHex = rawTransactionHex; op.expectedTransactionId = expectedTransactionId;
          op.casToken = randomUUID();
          op.validationEvidence = Object.freeze({ ...evidence, binding });
          if (op.state === 'preparing') this._transition(op, 'prepared-durable');
        });
      if (!result.applied) cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'cannot restage after a concurrent send attempt');
      return this.get(operationId);
    });
  }

  _assertValidation(op) {
    const binding = validationBinding({ rawTransactionHex: op.rawTransactionHex, expectedTransactionId: op.expectedTransactionId, identity: op.identity, destination: op.destination });
    const evidence = op.validationEvidence;
    if (!validValidationEvidence(evidence, binding) || JSON.stringify(evidence.binding) !== JSON.stringify(binding)) {
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'durable whole-transaction validation evidence is absent or no longer bound to prepared bytes/profile/destination');
    }
  }

  async admitOnce(operationId, { beforeSend = null } = {}) {
    this._requireStore();
    let op = this._reload(operationId);
    if (!op) cliFail(ERROR_CODES.INTERNAL, 'unknown operation');
    if (op.state !== 'prepared-durable') {
      if (op.sendAttempted || op.state === 'send-attempted' || isPostSend(op.state)) cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'automatic second mutation forbidden; use explicit rebroadcast');
      cliFail(ERROR_CODES.DURABILITY_REQUIRED, 'operation must be prepared-durable before send');
    }
    this._assertValidation(op);
    if (typeof this.admission.preflight === 'function') {
      const preflight = await this.observer.measure('admission', () => this.admission.preflight(op.rawTransactionHex, op.expectedTransactionId));
      if (preflight?.rejected && !preflight.sendAttempted) {
        const failed = this._update(operationId, (x) => x.state === 'prepared-durable' && !x.sendAttempted, (x) => { x.admissionEvidence = { ...preflight, mutationCrossed: false, sendAttempted: false }; this._transition(x, 'safe-pre-send-failure'); });
        return failed.applied ? this.get(operationId) : (() => { cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'another coordinator consumed this operation'); })();
      }
    }
    // This conditional transition is the delivery lease. Exactly one process wins it.
    const claimed = this._update(operationId, (x) => x.state === 'prepared-durable' && !x.sendAttempted, (x) => { this._assertValidation(x); x.sendAttempted = true; this._transition(x, 'send-attempted'); });
    if (!claimed.applied) cliFail(ERROR_CODES.SEND_ALREADY_ATTEMPTED, 'another coordinator already owns or attempted delivery');
    op = claimed.next;
    if (typeof beforeSend === 'function') await beforeSend(this.get(operationId));
    let evidence;
    try { evidence = await this.observer.measure('admission', () => this.admission.sendOnce({ rawTransactionHex: op.rawTransactionHex, expectedTransactionId: op.expectedTransactionId, skipPreflight: true })); }
    catch (error) { evidence = { error: error instanceof Error ? error.message : String(error), indeterminate: true, sendAttempted: true, mutationCrossed: true }; }
    if (exactAcceptedEvidence(evidence, op)) {
      this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'accepted-zero-conf'); }); return this.get(operationId);
    }
    if (exactRejectedEvidence(evidence)) { this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'rejected'); }); return this.get(operationId); }
    this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'send-indeterminate'); });
    const error = new Error(`send-indeterminate: ${evidence?.error || 'no exact acceptance/readback evidence'}`); error.code = ERROR_CODES.SEND_INDETERMINATE; error.operationId = operationId; error.evidence = evidence; throw error;
  }

  async rebroadcastExplicit(operationId, { acknowledge = false, casToken = null, expectedBytes = null } = {}) {
    this._requireStore();
    if (!acknowledge) cliFail(ERROR_CODES.REBROADCAST_ACK_REQUIRED, 'explicit user acknowledgement required');
    const claimed = this._update(operationId,
      (op) => (op.state === 'send-indeterminate' || op.state === 'send-attempted') && op.casToken === casToken && op.rawTransactionHex && (expectedBytes === null || expectedBytes === op.rawTransactionHex),
      (op) => { op.casToken = randomUUID(); op.state = 'send-attempted'; op.history.push({ state: 'send-attempted', at: Date.now(), explicitRebroadcast: true }); });
    if (!claimed.applied) {
      const op = this._reload(operationId);
      if (!op?.rawTransactionHex || (expectedBytes !== null && expectedBytes !== op.rawTransactionHex)) cliFail(ERROR_CODES.REBROADCAST_BYTES_REQUIRED, 'preserved exact bytes required');
      if (op.casToken !== casToken) cliFail(ERROR_CODES.REBROADCAST_CAS_REQUIRED, 'current compare-and-swap token required');
      cliFail(ERROR_CODES.AUTOMATIC_REBROADCAST_FORBIDDEN, `rebroadcast unavailable in state ${op.state}`);
    }
    let evidence;
    try { evidence = await this.admission.sendOnce({ rawTransactionHex: claimed.next.rawTransactionHex, expectedTransactionId: claimed.next.expectedTransactionId, explicitRebroadcast: true, skipPreflight: true }); }
    catch (error) { evidence = { error: error instanceof Error ? error.message : String(error), indeterminate: true, sendAttempted: true, mutationCrossed: true }; }
    if (exactAcceptedEvidence(evidence, claimed.next)) { this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'accepted-zero-conf'); }); return this.get(operationId); }
    if (exactRejectedEvidence(evidence)) { this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'rejected'); }); return this.get(operationId); }
    this._update(operationId, (x) => x.state === 'send-attempted', (x) => { x.admissionEvidence = evidence; this._transition(x, 'send-indeterminate'); });
    const error = new Error(`send-indeterminate after explicit rebroadcast: ${evidence?.error || 'no exact readback evidence'}`); error.code = ERROR_CODES.SEND_INDETERMINATE; throw error;
  }

  /**
   * A local committer must be idempotent for `localCommitToken`. The token is
   * durably recorded before invocation, so crash recovery can retry safely.
   */
  async commitLocal(operationId, { commitFn = null } = {}) {
    this._requireStore();
    if (typeof commitFn !== 'function') cliFail(ERROR_CODES.INTERNAL, 'idempotent local commit function required');
    let pending = this._update(operationId, (op) => op.state === 'accepted-zero-conf' || op.state === 'local-commit-pending', (op) => {
      if (op.state === 'accepted-zero-conf') this._transition(op, 'local-commit-pending');
      op.localCommitToken ||= randomUUID();
    });
    if (!pending.applied) cliFail(ERROR_CODES.INTERNAL, 'cannot commit from current operation state');
    await this.observer.measure('local_commit', () => commitFn(this.get(operationId), { idempotencyKey: pending.next.localCommitToken }));
    const done = this.store.finalizeCommit(operationId, (op) => this._transition(op, 'committed'));
    if (done.next) this._ops.set(operationId, done.next);
    if (!done.applied) cliFail(ERROR_CODES.INTERNAL, 'local commit state changed concurrently');
    return this.get(operationId);
  }

  markPreSendFailure(operationId, reason) { const r = this._update(operationId, (op) => isPreSend(op.state), (op) => { op.failureReason = reason; if (op.state !== 'safe-pre-send-failure') this._transition(op, 'safe-pre-send-failure'); }); if (!r.applied) cliFail(ERROR_CODES.INTERNAL, 'safe-pre-send-failure only before send'); return this.get(operationId); }
  static recoverFromHome(homePath, { admission, observer = null } = {}) { return new OperationCoordinator({ homePath, admission, observer }); }
}

export function hashBytes(hex) { return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex'); }
