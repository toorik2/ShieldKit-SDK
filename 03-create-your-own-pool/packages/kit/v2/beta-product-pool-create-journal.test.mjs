import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  openV2BetaProductPoolCreateJournalForTest,
  V2BetaProductPoolCreateJournalError,
} from './beta-product-pool-create-journal.mjs';

const PROFILE = 'a'.repeat(64);
const INSTANCE = 'b'.repeat(64);
const SOURCE = 'c'.repeat(64);
const RAW = 'd'.repeat(64);
const GENESIS = 'e'.repeat(64);

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-pool-create-journal-'));
  chmodSync(directory, 0o700);
  return { directory, databasePath: join(directory, 'pool-create.sqlite') };
}

const binding = (overrides = {}) => ({
  operationId: `pool-create.${INSTANCE}`,
  profileId: PROFILE,
  instanceId: INSTANCE,
  sourceTransactionId: SOURCE,
  bootstrapRawSha256: RAW,
  fundingOutpointTransactionId: 'f'.repeat(64),
  fundingOutpointVout: 0,
  fundingLockingBytecodeSha256: '1'.repeat(64),
  ...overrides,
});

function open(databasePath, pid, startTicks, live = new Set()) {
  return openV2BetaProductPoolCreateJournalForTest(
    { databasePath },
    {
      owner: { pid, startTicks },
      ownerAlive: (candidatePid, candidateTicks) =>
        live.has(`${candidatePid}:${candidateTicks}`),
    },
  );
}

const rejects = (code) => (error) =>
  error instanceof V2BetaProductPoolCreateJournalError && error.code === code;

test('serializes one live creator and recovers a dead pre-send owner with send permission', () => {
  const subject = fixture();
  try {
    const live = new Set(['101:1001']);
    const first = open(subject.databasePath, 101, '1001', live);
    const claim = first.claimOrRecover(binding());
    assert.equal(claim.mode, 'send-allowed');
    assert.equal(claim.record.claimCount, 1);
    const second = open(subject.databasePath, 202, '2002', live);
    assert.throws(() => second.claimOrRecover(binding()), rejects('POOL_CREATE_JOURNAL_BUSY'));
    live.delete('101:1001');
    const recovered = second.claimOrRecover(binding());
    assert.equal(recovered.mode, 'send-allowed');
    assert.equal(recovered.record.claimCount, 2);
    assert.equal(lstatSync(subject.databasePath).mode & 0o777, 0o600);
    first.close(); second.close();
  } finally { rmSync(subject.directory, { recursive: true, force: true }); }
});

test('post-send recovery is reconciliation-only and cannot authorize another send', () => {
  const subject = fixture();
  try {
    const first = open(subject.databasePath, 301, '3001');
    const initial = first.claimOrRecover(binding());
    const attempted = first.markSendAttempt({ claim: initial, genesisTransactionId: GENESIS });
    assert.equal(attempted.state, 'send-attempted');
    first.close();
    const recoveredJournal = open(subject.databasePath, 302, '3002');
    const recovered = recoveredJournal.claimOrRecover(binding());
    assert.equal(recovered.mode, 'reconcile-only');
    assert.throws(
      () => recoveredJournal.markSendAttempt({ claim: recovered, genesisTransactionId: GENESIS }),
      rejects('POOL_CREATE_JOURNAL_RECONCILE_ONLY'),
    );
    assert.equal(
      recoveredJournal.markAccepted({ claim: recovered, genesisTransactionId: GENESIS }).state,
      'accepted-zero-conf',
    );
    assert.equal(
      recoveredJournal.markCommitted({ claim: recovered, genesisTransactionId: GENESIS }).state,
      'committed',
    );
    recoveredJournal.close();
    const finalJournal = open(subject.databasePath, 303, '3003');
    const completed = finalJournal.claimOrRecover(binding());
    assert.equal(completed.mode, 'completed');
    assert.equal(completed.record.genesisTransactionId, GENESIS);
    finalJournal.close();
  } finally { rmSync(subject.directory, { recursive: true, force: true }); }
});

test('safe pre-send release permits exact retry but never operation rebinding', () => {
  const subject = fixture();
  try {
    const first = open(subject.databasePath, 401, '4001');
    const claim = first.claimOrRecover(binding());
    assert.equal(first.releaseSafePreSend({ claim }).state, 'claimed-pre-send');
    const second = open(subject.databasePath, 402, '4002');
    const retried = second.claimOrRecover(binding());
    assert.equal(retried.mode, 'send-allowed');
    assert.equal(retried.record.claimCount, 2);
    assert.throws(
      () => second.claimOrRecover(binding({ bootstrapRawSha256: 'f'.repeat(64) })),
      rejects('POOL_CREATE_JOURNAL_BINDING_REUSE'),
    );
    assert.throws(
      () => second.claimOrRecover(binding({ fundingOutpointVout: 1 })),
      rejects('POOL_CREATE_JOURNAL_BINDING_REUSE'),
    );
    assert.throws(
      () => first.markSendAttempt({ claim, genesisTransactionId: GENESIS }),
      rejects('POOL_CREATE_JOURNAL_CLAIM_LOST'),
    );
    first.close(); second.close();
  } finally { rmSync(subject.directory, { recursive: true, force: true }); }
});

test('accepted crash recovery is commit-only and retains exact genesis binding', () => {
  const subject = fixture();
  try {
    const first = open(subject.databasePath, 501, '5001');
    const claim = first.claimOrRecover(binding());
    first.markSendAttempt({ claim, genesisTransactionId: GENESIS });
    first.markAccepted({ claim, genesisTransactionId: GENESIS });
    first.close();
    const second = open(subject.databasePath, 502, '5002');
    const recovered = second.claimOrRecover(binding());
    assert.equal(recovered.mode, 'commit-only');
    assert.throws(
      () => second.markCommitted({ claim: recovered, genesisTransactionId: '0'.repeat(64) }),
      rejects('POOL_CREATE_JOURNAL_BINDING_REUSE'),
    );
    assert.equal(second.markCommitted({ claim: recovered, genesisTransactionId: GENESIS }).state, 'committed');
    second.close();
  } finally { rmSync(subject.directory, { recursive: true, force: true }); }
});
