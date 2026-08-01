import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpcForTest, observeLayer1BchnChipnetRpc } from '../chipnet-rpc.mjs';
import { openV2DeliveryJournal } from './delivery-journal.mjs';
import { FIXTURE_CARRIER_COUNT, FIXTURE_INSTANCE_ID, buildRawTransaction, createFixtureEvidence } from './v2-test-fixtures.mjs';
import { transactionId } from './transaction-policy.mjs';
import {
  V2BetaZeroConfAdmissionCrash,
  V2BetaZeroConfAdmissionError,
  rebroadcastV2BetaZeroConfAdmission,
  reconcileV2BetaZeroConfAdmission,
  submitV2BetaZeroConfAdmission,
} from './beta-zero-conf-admission.mjs';

function testOnlyContext(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-beta-admission-')); chmodSync(directory, 0o700);
  const journal = openV2DeliveryJournal(join(directory, 'delivery.sqlite')); t.after(() => { journal.close(); rmSync(directory, { recursive: true, force: true }); });
  const rawTransactionHex = buildRawTransaction({ carrierCount: FIXTURE_CARRIER_COUNT });
  const txid = transactionId(Buffer.from(rawTransactionHex, 'hex'));
  const commitment = 'ab'.repeat(128); const calls = []; let sendAttempts = 0;
  const rpc = createLayer1BchnChipnetRpcForTest({ executeLayer1Cli: async (method, args) => {
    calls.push(method);
    if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
    if (method === 'testmempoolaccept') return JSON.stringify([{ txid, allowed: options.reject === true ? false : true }]);
    if (method === 'sendrawtransaction') {
      sendAttempts += 1;
      if (options.sendError || (options.sendErrorOnce === true && sendAttempts === 1)) {
        throw new Error('test-only send disconnect');
      }
      return options.sendTxid ?? txid;
    }
    if (method === 'getrawtransaction') {
      if (Number.isSafeInteger(options.rawAvailableAfterSendAttempt)
        && sendAttempts < options.rawAvailableAfterSendAttempt) {
        throw new Error('test-only transaction not found');
      }
      return JSON.stringify({ txid, hex: options.rawMismatch ? '00' : rawTransactionHex });
    }
    if (method === 'gettxout') return JSON.stringify({ value: 0.00001, tokenData: { category: Buffer.from(FIXTURE_INSTANCE_ID, 'hex').reverse().toString('hex'), amount: '0', nft: { capability: 'mutable', commitment } } });
    throw new Error(`unexpected test-only method ${method}`);
  } });
  return Promise.resolve(rpc).then((brandedRpc) => ({
    // TEST-ONLY local fixture: it exercises branded transport/journal mechanics
    // but is never a live BCHN or qualification artifact.
    input: { rpc: brandedRpc, journal, rawTransactionHex, carrierCount: FIXTURE_CARRIER_COUNT,
      localVmEvidence: createFixtureEvidence({ rawTransactionHex, carrierCount: FIXTURE_CARRIER_COUNT }),
      expectedState: { category: FIXTURE_INSTANCE_ID, capability: 'mutable', commitment, tokenAmount: '0', valueSatoshis: '1000' }, operationId: 'beta-op-1', crashAt: null }, calls, journal, operationId: 'beta-op-1',
  }));
}

const rejects = (code) => (error) => error instanceof V2BetaZeroConfAdmissionError && error.code === code;

test('one-shot admission uses one preflight/send then exact readbacks and unqualified claims', async (t) => {
  const context = await testOnlyContext(t); let beforeSend = 0;
  const result = await submitV2BetaZeroConfAdmission(context.input, {
    beforeSendAttempt: async (attempt) => {
      beforeSend += 1;
      assert.equal(attempt.operationId, context.operationId);
      assert.equal(context.calls.at(-1), 'testmempoolaccept');
      assert.equal(context.calls.includes('sendrawtransaction'), false);
      assert.equal(context.journal.record(context.operationId).state, 'attempted');
    },
  });
  assert.equal(beforeSend, 1);
  assert.equal(result.status, 'locally-reconciled-zero-conf-beta-unqualified');
  assert.deepEqual(result.claims, { confirmed: false, mined: false, productionQualified: false });
  assert.equal(context.calls.filter((name) => name === 'testmempoolaccept').length, 1);
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 1);
  assert.equal(context.calls.filter((name) => name === 'getrawtransaction').length, 1);
  assert.equal(context.calls.filter((name) => name === 'gettxout').length, 1);
  assert.equal(context.calls.some((name) => /(?:blockcount|confirmation|blockchaininfo|chaintips)/u.test(name)), false);
  assert.deepEqual(observeLayer1BchnChipnetRpc(context.input.rpc).methodCounts, {
    getblockhash: 1, getrawtransaction: 1, gettxout: 1, scantxoutset: 0,
    sendrawtransaction: 1, testmempoolaccept: 1,
  });
  assert.equal(context.journal.record(context.operationId).state, 'locally_reconciled');
  await assert.rejects(submitV2BetaZeroConfAdmission(context.input), (error) => error?.code === 'SEND_ALREADY_CLAIMED');
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 1);
});

test('rejection sends nothing and send uncertainty becomes indeterminate for read-only reconciliation', async (t) => {
  const rejected = await testOnlyContext(t, { reject: true });
  await assert.rejects(submitV2BetaZeroConfAdmission(rejected.input), rejects('ADMISSION_MEMPOOL_REJECTED'));
  assert.equal(rejected.calls.includes('sendrawtransaction'), false);
  const uncertain = await testOnlyContext(t, { sendError: true });
  await assert.rejects(submitV2BetaZeroConfAdmission(uncertain.input), rejects('ADMISSION_SEND_INDETERMINATE'));
  assert.equal(uncertain.journal.record(uncertain.operationId).state, 'indeterminate');
  const recovered = await reconcileV2BetaZeroConfAdmission(uncertain.input);
  assert.equal(recovered.status, 'locally-reconciled-zero-conf-beta-unqualified');
  assert.equal(uncertain.calls.filter((name) => name === 'sendrawtransaction').length, 1);

  const mismatchedSend = await testOnlyContext(t, { sendTxid: '00'.repeat(32) });
  await assert.rejects(
    submitV2BetaZeroConfAdmission(mismatchedSend.input),
    rejects('ADMISSION_SEND_INDETERMINATE'),
  );
  assert.equal(mismatchedSend.journal.record(mismatchedSend.operationId).state, 'indeterminate');
  await reconcileV2BetaZeroConfAdmission(mismatchedSend.input);
  assert.equal(mismatchedSend.calls.filter((name) => name === 'sendrawtransaction').length, 1);

  const hookFailure = await testOnlyContext(t);
  await assert.rejects(
    submitV2BetaZeroConfAdmission(hookFailure.input, {
      beforeSendAttempt: async () => { throw new Error('test-only durable hook failure'); },
    }),
    rejects('ADMISSION_BEFORE_SEND_FAILED'),
  );
  assert.equal(hookFailure.calls.includes('sendrawtransaction'), false);
});

test('a durable safe pre-send abort marker permanently forbids a later send claim', async (t) => {
  const context = await testOnlyContext(t);
  const marker = context.journal.markSafePreSendAbort({
    operationId: context.operationId,
    kind: 'deposit',
    reason: 'test-only pre-send failure',
  });
  assert.deepEqual(marker, {
    operationId: context.operationId,
    kind: 'deposit',
    reason: 'test-only pre-send failure',
  });
  await assert.rejects(
    submitV2BetaZeroConfAdmission(context.input),
    error => error?.code === 'DELIVERY_STATE_MISMATCH',
  );
  assert.equal(context.calls.includes('testmempoolaccept'), false);
  assert.equal(context.calls.includes('sendrawtransaction'), false);
});

test('raw mismatch and injected post-send crash do not claim successful local reconciliation', async (t) => {
  const mismatched = await testOnlyContext(t, { rawMismatch: true });
  await assert.rejects(submitV2BetaZeroConfAdmission(mismatched.input), rejects('ADMISSION_RAW_READBACK_INVALID'));
  assert.equal(mismatched.journal.record(mismatched.operationId).state, 'indeterminate');
  const crashed = await testOnlyContext(t); crashed.input.crashAt = 'admission.after_send';
  await assert.rejects(submitV2BetaZeroConfAdmission(crashed.input), V2BetaZeroConfAdmissionCrash);
  assert.equal(crashed.journal.record(crashed.operationId).state, 'indeterminate');
  crashed.input.crashAt = null; await reconcileV2BetaZeroConfAdmission(crashed.input);
  assert.equal(crashed.calls.filter((name) => name === 'sendrawtransaction').length, 1);
});

test('exact rebroadcast requires acknowledgement and current CAS token, then sends identical bytes once', async (t) => {
  const context = await testOnlyContext(t, {
    sendErrorOnce: true,
    rawAvailableAfterSendAttempt: 2,
  });
  await assert.rejects(
    submitV2BetaZeroConfAdmission(context.input),
    rejects('ADMISSION_SEND_INDETERMINATE'),
  );
  const prior = context.journal.record(context.operationId);
  assert.equal(prior.state, 'indeterminate');
  assert.equal(prior.attemptCount, 1);

  await assert.rejects(
    rebroadcastV2BetaZeroConfAdmission(context.input, {
      acknowledgedExactRebroadcast: false,
      priorAttemptToken: prior.attemptToken,
    }),
    rejects('ADMISSION_EXACT_REBROADCAST_ACK_REQUIRED'),
  );
  await assert.rejects(
    rebroadcastV2BetaZeroConfAdmission(context.input, {
      acknowledgedExactRebroadcast: true,
      priorAttemptToken: '00000000-0000-4000-8000-000000000000',
    }),
    rejects('ADMISSION_EXACT_REBROADCAST_TOKEN_STALE'),
  );
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 1);

  const recovered = await rebroadcastV2BetaZeroConfAdmission(context.input, {
    acknowledgedExactRebroadcast: true,
    priorAttemptToken: prior.attemptToken,
  });
  assert.equal(recovered.status, 'locally-reconciled-zero-conf-beta-unqualified');
  assert.equal(recovered.admission.allowed, true);
  assert.equal(context.journal.record(context.operationId).attemptCount, 2);
  assert.equal(context.journal.record(context.operationId).state, 'locally_reconciled');
  assert.equal(context.calls.filter((name) => name === 'testmempoolaccept').length, 2);
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 2);

  await assert.rejects(
    rebroadcastV2BetaZeroConfAdmission(context.input, {
      acknowledgedExactRebroadcast: true,
      priorAttemptToken: prior.attemptToken,
    }),
    rejects('ADMISSION_EXACT_REBROADCAST_NOT_REQUIRED'),
  );
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 2);
});

test('explicit recovery remains read-only when a post-send crash transaction is already visible', async (t) => {
  const context = await testOnlyContext(t);
  context.input.crashAt = 'admission.after_send';
  await assert.rejects(
    submitV2BetaZeroConfAdmission(context.input),
    V2BetaZeroConfAdmissionCrash,
  );
  const prior = context.journal.record(context.operationId);
  context.input.crashAt = null;
  const recovered = await rebroadcastV2BetaZeroConfAdmission(context.input, {
    acknowledgedExactRebroadcast: true,
    priorAttemptToken: prior.attemptToken,
  });
  assert.equal(recovered.admission.allowed, null);
  assert.equal(context.calls.filter((name) => name === 'testmempoolaccept').length, 1);
  assert.equal(context.calls.filter((name) => name === 'sendrawtransaction').length, 1);
  assert.equal(context.journal.record(context.operationId).state, 'locally_reconciled');
});
