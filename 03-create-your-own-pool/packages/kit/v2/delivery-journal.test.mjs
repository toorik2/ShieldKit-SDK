import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  openV2DeliveryJournal,
  V2_DELIVERY_JOURNAL_CRASH_STAGES,
  V2DeliveryJournalCrash,
} from './delivery-journal.mjs';
import { createV2InputRoleLayout } from './transaction-policy.mjs';
import { canonicalizeV2Evidence } from './vm-evidence.mjs';

const workerPath = join(
  dirname(fileURLToPath(import.meta.url)),
  'test-fixtures',
  'delivery-race-worker.mjs',
);
const carrierCount = 7;
const roleLayoutHash = createHash('sha256')
  .update(canonicalizeV2Evidence(createV2InputRoleLayout(carrierCount)))
  .digest('hex');
const rawTransactionSha256 = 'aa'.repeat(32);
const identity = Object.freeze({
  operationId: 'op-race',
  txid: '11'.repeat(32),
  metadataHash: '22'.repeat(32),
  evidenceHash: '33'.repeat(32),
  carrierCount,
  roleLayoutHash,
});

function temporaryJournal(t) {
  const parent = mkdtempSync(join(tmpdir(), 'shieldkit-v2-delivery-'));
  chmodSync(parent, 0o700);
  const path = join(parent, 'delivery.sqlite');
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  return { parent, path };
}

function nextMessage(child) {
  return new Promise((resolve, reject) => {
    child.once('message', resolve);
    child.once('error', reject);
    child.once('exit', (code) => {
      if (code !== null && code !== 0) {
        reject(new Error(`delivery race worker exited ${code}`));
      }
    });
  });
}

function submitted(journal, claimed) {
  return journal.markSubmitted({
    operationId: identity.operationId,
    txid: identity.txid,
    attemptToken: claimed.attemptToken,
    rawTransactionSha256,
  });
}

test('SQLite delivery journal atomically creates a durable first-send claim with private modes', (t) => {
  const { parent, path } = temporaryJournal(t);
  const journal = openV2DeliveryJournal(path);
  t.after(() => journal.close());
  const claimed = journal.claimOrCreate(identity);
  assert.equal(claimed.state, 'attempted');
  assert.equal(claimed.attemptCount, 1);
  assert.equal(claimed.carrierCount, identity.carrierCount);
  assert.equal(claimed.roleLayoutHash, identity.roleLayoutHash);
  assert.match(claimed.attemptToken, /^[0-9a-f-]{36}$/);
  assert.deepEqual(journal.pragmas(), {
    journalMode: 'wal',
    synchronous: 2,
    foreignKeys: 1,
    busyTimeout: 5000,
  });
  assert.equal(lstatSync(parent).mode & 0o777, 0o700);
  assert.equal(lstatSync(path).mode & 0o777, 0o600);
  for (const sidecar of [`${path}-wal`, `${path}-shm`]) {
    try {
      assert.equal(lstatSync(sidecar).mode & 0o777, 0o600);
    } catch (error) {
      assert.equal(error?.code, 'ENOENT');
    }
  }
  assert.throws(
    () => journal.claimOrCreate(identity),
    (error) => error?.code === 'SEND_ALREADY_CLAIMED',
  );
  for (const divergent of [
    { ...identity, metadataHash: '44'.repeat(32) },
    { ...identity, carrierCount: 10, roleLayoutHash: '55'.repeat(32) },
  ]) {
    assert.throws(
      () => journal.claimOrCreate(divergent),
      (error) => error?.code === 'DIVERGENT_DELIVERY_RECORD',
    );
  }
});

test('submitted RPC acknowledgement, authenticated observation, and local reconciliation bind the exact raw transaction', (t) => {
  const { path } = temporaryJournal(t);
  const journal = openV2DeliveryJournal(path);
  t.after(() => journal.close());
  const claimed = journal.claimOrCreate(identity);
  const rpcSubmitted = submitted(journal, claimed);
  assert.equal(rpcSubmitted.state, 'submitted');
  assert.equal(rpcSubmitted.submissionKind, 'rpc-accepted');
  assert.equal(rpcSubmitted.observedRawSha256, rawTransactionSha256);
  assert.equal(submitted(journal, claimed).state, 'submitted');
  assert.throws(
    () => journal.reconcileObserved({
      operationId: identity.operationId,
      txid: identity.txid,
      rawTransactionSha256: 'bb'.repeat(32),
    }),
    (error) => error?.code === 'DIVERGENT_DELIVERY_RECORD',
  );
  const local = journal.markLocallyReconciled({
    operationId: identity.operationId,
    txid: identity.txid,
    rawTransactionSha256,
  });
  assert.equal(local.state, 'locally_reconciled');
  assert.equal(local.locallyReconciledAtMs >= local.submittedAtMs, true);
  assert.equal(
    journal.markLocallyReconciled({
      operationId: identity.operationId,
      txid: identity.txid,
      rawTransactionSha256,
    }).state,
    'locally_reconciled',
  );
});

test('ambiguous send remains unresolved until an authenticated exact-byte observation', (t) => {
  const { path } = temporaryJournal(t);
  const journal = openV2DeliveryJournal(path);
  t.after(() => journal.close());
  const claimed = journal.claimOrCreate(identity);
  const indeterminate = journal.markIndeterminate({
    operationId: identity.operationId,
    attemptToken: claimed.attemptToken,
    reason: 'network connection closed after send request',
  });
  assert.equal(indeterminate.state, 'indeterminate');
  assert.equal(indeterminate.reason, 'network connection closed after send request');
  assert.throws(
    () => journal.claimOrCreate(identity),
    (error) => error?.code === 'SEND_ALREADY_CLAIMED',
  );
  const observed = journal.reconcileObserved({
    operationId: identity.operationId,
    txid: identity.txid,
    rawTransactionSha256,
  });
  assert.equal(observed.state, 'submitted');
  assert.equal(observed.submissionKind, 'authenticated-transaction-read');
  assert.equal(observed.observedRawSha256, rawTransactionSha256);
  assert.equal(
    journal.reconcileObserved({
      operationId: identity.operationId,
      txid: identity.txid,
      rawTransactionSha256,
    }).state,
    'submitted',
  );
  assert.throws(
    () => journal.reconcileObserved({
      operationId: identity.operationId,
      txid: identity.txid,
      rawTransactionSha256: 'cc'.repeat(32),
    }),
    (error) => error?.code === 'DIVERGENT_DELIVERY_RECORD',
  );
});

test('explicit exact-byte resubmission requires the current CAS token and increments attempt count', (t) => {
  const { path } = temporaryJournal(t);
  const journal = openV2DeliveryJournal(path);
  t.after(() => journal.close());
  const first = journal.claimOrCreate(identity);
  const indeterminate = journal.markIndeterminate({
    operationId: identity.operationId,
    attemptToken: first.attemptToken,
    reason: 'operator classified a prior send as ambiguous',
  });
  const second = journal.claimExactResubmission({
    identity,
    priorAttemptToken: indeterminate.attemptToken,
  });
  assert.equal(second.state, 'attempted');
  assert.equal(second.attemptCount, 2);
  assert.notEqual(second.attemptToken, first.attemptToken);
  assert.throws(
    () => journal.claimExactResubmission({ identity, priorAttemptToken: first.attemptToken }),
    (error) => error?.code === 'DELIVERY_STATE_MISMATCH',
  );
  assert.throws(
    () => journal.claimExactResubmission({
      identity: { ...identity, evidenceHash: '66'.repeat(32) },
      priorAttemptToken: second.attemptToken,
    }),
    (error) => error?.code === 'DIVERGENT_DELIVERY_RECORD',
  );
  assert.throws(
    () => journal.markSubmitted({
      operationId: identity.operationId,
      txid: identity.txid,
      attemptToken: first.attemptToken,
      rawTransactionSha256,
    }),
    (error) => error?.code === 'DELIVERY_STATE_MISMATCH',
  );
});

test('attempted and indeterminate records survive close/reopen without automatic resend', (t) => {
  const { path } = temporaryJournal(t);
  let journal = openV2DeliveryJournal(path);
  const claim = journal.claimOrCreate(identity);
  journal.close();
  journal = openV2DeliveryJournal(path);
  assert.equal(journal.record(identity.operationId).state, 'attempted');
  assert.throws(
    () => journal.claimOrCreate(identity),
    (error) => error?.code === 'SEND_ALREADY_CLAIMED',
  );
  const indeterminate = journal.markIndeterminate({
    operationId: identity.operationId,
    attemptToken: claim.attemptToken,
    reason: 'manual crash classification',
  });
  journal.close();
  journal = openV2DeliveryJournal(path);
  t.after(() => journal.close());
  assert.equal(journal.record(identity.operationId).state, 'indeterminate');
  assert.equal(journal.record(identity.operationId).attemptToken, indeterminate.attemptToken);
});

test('every delivery crash hook rolls back its exact uncommitted mutation', (t) => {
  for (const stage of V2_DELIVERY_JOURNAL_CRASH_STAGES) {
    const { path } = temporaryJournal(t);
    let journal = openV2DeliveryJournal(path);
    let expectedState = null;
    if (stage === 'delivery.claim-or-create.after_insert') {
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => journal.claimOrCreate(identity), V2DeliveryJournalCrash);
      journal.close();
      journal = openV2DeliveryJournal(path);
      assert.equal(journal.record(identity.operationId), null);
      journal.close();
      continue;
    }
    const first = journal.claimOrCreate(identity);
    if (stage === 'delivery.recovery-claim.after_update') {
      journal.markIndeterminate({
        operationId: identity.operationId,
        attemptToken: first.attemptToken,
        reason: 'prepare recovery crash hook',
      });
      expectedState = 'indeterminate';
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(
        () => journal.claimExactResubmission({ identity, priorAttemptToken: first.attemptToken }),
        V2DeliveryJournalCrash,
      );
    } else if (stage === 'delivery.submitted.after_update') {
      expectedState = 'attempted';
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(() => submitted(journal, first), V2DeliveryJournalCrash);
    } else if (stage === 'delivery.indeterminate.after_update') {
      expectedState = 'attempted';
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(
        () => journal.markIndeterminate({
          operationId: identity.operationId,
          attemptToken: first.attemptToken,
          reason: 'injected interruption',
        }),
        V2DeliveryJournalCrash,
      );
    } else if (stage === 'delivery.observed.after_update') {
      journal.markIndeterminate({
        operationId: identity.operationId,
        attemptToken: first.attemptToken,
        reason: 'prepare observation crash hook',
      });
      expectedState = 'indeterminate';
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(
        () => journal.reconcileObserved({
          operationId: identity.operationId,
          txid: identity.txid,
          rawTransactionSha256,
        }),
        V2DeliveryJournalCrash,
      );
    } else if (stage === 'delivery.locally-reconciled.after_update') {
      submitted(journal, first);
      expectedState = 'submitted';
      journal.close();
      journal = openV2DeliveryJournal(path, { crashAt: stage });
      assert.throws(
        () => journal.markLocallyReconciled({
          operationId: identity.operationId,
          txid: identity.txid,
          rawTransactionSha256,
        }),
        V2DeliveryJournalCrash,
      );
    } else {
      assert.fail(`uncovered crash stage ${stage}`);
    }
    journal.close();
    journal = openV2DeliveryJournal(path);
    assert.equal(journal.record(identity.operationId)?.state ?? null, expectedState);
    journal.close();
  }
});

test('schema v2 journals are refused rather than silently migrated', (t) => {
  const { path } = temporaryJournal(t);
  const database = new DatabaseSync(path);
  database.exec(`
    CREATE TABLE delivery_journal_metadata (
      singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      schema_version INTEGER NOT NULL CHECK(schema_version=2)
    ) STRICT;
    INSERT INTO delivery_journal_metadata(singleton,schema_version) VALUES(1,2);
  `);
  database.close();
  chmodSync(path, 0o600);
  assert.throws(() => openV2DeliveryJournal(path));
});

test('two processes racing a first send produce exactly one atomic claim', async (t) => {
  const { path } = temporaryJournal(t);
  // Initialize the schema before the race. The race under test is the first
  // atomic claim, not SQLite's one-time WAL/schema bootstrap.
  const setup = openV2DeliveryJournal(path);
  setup.close();
  const encodedIdentity = Buffer.from(JSON.stringify(identity), 'utf8').toString('base64url');
  const workers = [
    fork(workerPath, [path, encodedIdentity], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }),
    fork(workerPath, [path, encodedIdentity], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }),
  ];
  t.after(() => {
    for (const worker of workers) if (!worker.killed) worker.kill();
  });
  const ready = await Promise.all(workers.map((worker) => nextMessage(worker)));
  assert.ok(ready.every((message) => message.status === 'ready'));
  const outcomes = workers.map((worker) => nextMessage(worker));
  for (const worker of workers) worker.send('claim');
  const results = await Promise.all(outcomes);
  assert.equal(results.filter((result) => result.status === 'claimed').length, 1);
  assert.deepEqual(
    results.filter((result) => result.status === 'rejected').map((result) => result.code),
    ['SEND_ALREADY_CLAIMED'],
  );
  for (const worker of workers) if (worker.connected) worker.disconnect();
  await Promise.all(workers.map((worker) => new Promise((resolve, reject) => {
    if (worker.exitCode !== null) {
      if (worker.exitCode === 0) resolve();
      else reject(new Error(`delivery race worker exited ${worker.exitCode}`));
      return;
    }
    worker.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`delivery race worker exited ${code}`));
    });
    worker.once('error', reject);
  })));
  const reopened = openV2DeliveryJournal(path);
  t.after(() => reopened.close());
  const record = reopened.record(identity.operationId);
  assert.equal(record.state, 'attempted');
  assert.equal(record.attemptCount, 1);
});
