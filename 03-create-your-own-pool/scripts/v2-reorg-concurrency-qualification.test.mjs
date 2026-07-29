import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  parseV2ReorgConcurrencyQualificationArguments,
  runV2ReorgConcurrencyQualification,
  V2ReorgConcurrencyQualificationError,
} from './v2-reorg-concurrency-qualification.mjs';

test('reorg/concurrency qualification accepts only one explicit new evidence target', () => {
  assert.throws(
    () => parseV2ReorgConcurrencyQualificationArguments([]),
    V2ReorgConcurrencyQualificationError,
  );
  assert.throws(
    () => parseV2ReorgConcurrencyQualificationArguments(['--output', '--bad']),
    V2ReorgConcurrencyQualificationError,
  );
  assert.equal(
    parseV2ReorgConcurrencyQualificationArguments(['--output', 'evidence.json'], '/tmp/q06').output,
    '/tmp/q06/evidence.json',
  );
});

test('bounded Q-06 smoke uses the real store, rollback, reservation release, and recovery installer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'shieldkit-v2-q06-test-'));
  const output = join(directory, 'evidence.json');
  try {
    const evidence = runV2ReorgConcurrencyQualification({
      output,
      reorgDepths: [1],
      walletCounts: [2],
      deepReplayActions: 1,
    });
    assert.equal(evidence.schema, 'shieldkit-v2-direct-reorg-concurrency-qualification-v1');
    assert.equal(evidence.discrepancies.length, 0);
    assert.equal(evidence.reorgDepths[0].depth, 1);
    assert.equal(evidence.walletContention[0].wallets, 2);
    assert.equal(evidence.maliciousSelfTransfer.duplicateNullifierRejected, true);
    assert.equal(evidence.deepWipeReplay.authenticatedSnapshotInstalled, true);
    assert.ok(evidence.invariantCounts.noPrematureConfirmedCommit > 0);
    assert.equal(evidence.invariantCounts.conflictReservationRelease, 1);
    assert.equal(evidence.invariantCounts.rebaseReservationReacquire, 1);
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), evidence);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
