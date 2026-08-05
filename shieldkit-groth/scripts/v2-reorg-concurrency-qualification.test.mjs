import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  encodeV2CapturedRecoveryCorpusForTest,
  parseV2ReorgConcurrencyQualificationArguments,
  replayV2CapturedRecoveryCorpus,
  runV2ReorgConcurrencyQualification,
  verifyV2CapturedRecoveryCorpusForTest,
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
    parseV2ReorgConcurrencyQualificationArguments(
      ['--output', 'evidence.json', '--corpus-output', 'corpus.json'],
      '/tmp/q06',
    ).corpusOutput,
    '/tmp/q06/corpus.json',
  );
});

test('focused Q-06 run uses exact captured recovery events and deterministic sequential sibling scheduling', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'shieldkit-v2-q06-test-'));
  const output = join(directory, 'evidence.json');
  const corpusOutput = join(directory, 'corpus.json');
  try {
    const evidence = runV2ReorgConcurrencyQualification({
      output,
      corpusOutput,
      reorgDepths: [1],
      walletCounts: [2],
      deepReplayActions: 101,
    });
    assert.equal(evidence.schema, 'shieldkit-v2-direct-reorg-sequential-sibling-qualification-v2');
    assert.equal(evidence.discrepancies.length, 0);
    assert.equal(evidence.reorgDepths[0].depth, 1);
    assert.equal(evidence.sequentialSiblingConflicts[0].participants, 2);
    assert.equal(evidence.sequentialSiblingConflicts[0].deterministicSequentialSchedule, true);
    assert.equal(evidence.maliciousSelfTransfer.duplicateNullifierRejected, true);
    assert.equal(evidence.deepWipeReplay.authenticatedSnapshotInstalled, true);
    assert.equal(evidence.deepWipeReplay.crossedHundredActionBoundary, true);
    assert.equal(evidence.deepWipeReplay.rollbackHistoryCheckerMatched, true);
    assert.equal(evidence.deepWipeReplay.exactCapturedCorpusIngested, true);
    assert.match(evidence.deepWipeReplay.actionCorpusSha256, /^[0-9a-f]{64}$/u);
    assert.ok(evidence.deepWipeReplay.actionCorpusBytes > 0);
    assert.match(evidence.deepWipeReplay.terminalCanonicalSha256, /^[0-9a-f]{64}$/u);
    assert.equal(evidence.deepWipeReplay.actions, 101);
    assert.equal(evidence.reorgDepths[0].rollbackHistoryCheckerMatched, true);
    assert.equal(evidence.invariantCounts.canonicalTipUnchangedBeforeApplyConfirmed, 206);
    assert.equal(evidence.invariantCounts.reorgAncestorCanonicalTipMatched, 1);
    assert.equal(evidence.invariantCounts.siblingConflictFundingReleased, 1);
    assert.equal(evidence.invariantCounts.siblingRebaseFundingReacquired, 1);
    assert.equal(evidence.invariantCounts.deepWipeExactCapturedEventIngestions, 101);
    assert.match(evidence.limitations.at(-2), /no barrier, overlapping call, worker process, or concurrency evidence/u);
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.equal((await stat(corpusOutput)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(output, 'utf8')), evidence);
    const corpusBytes = await readFile(corpusOutput);
    assert.equal(corpusBytes.length, evidence.deepWipeReplay.actionCorpusBytes);
    assert.equal(
      createHash('sha256').update(corpusBytes).digest('hex'),
      evidence.deepWipeReplay.actionCorpusSha256,
    );
    const replay = replayV2CapturedRecoveryCorpus({
      bytes: corpusBytes,
      expectedSha256: evidence.deepWipeReplay.actionCorpusSha256,
      expectedActions: 101,
    });
    assert.equal(replay.terminalCanonicalSha256, evidence.deepWipeReplay.terminalCanonicalSha256);
    assert.equal(replay.exactCapturedEventIngestions, 101);
    const child = spawnSync(process.execPath, [
      fileURLToPath(new URL('./v2-reorg-concurrency-qualification.mjs', import.meta.url)),
      '--replay-corpus',
      corpusOutput,
      '--expected-sha256',
      evidence.deepWipeReplay.actionCorpusSha256,
      '--expected-actions',
      '101',
    ], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(
      JSON.parse(child.stdout).terminalCanonicalSha256,
      evidence.deepWipeReplay.terminalCanonicalSha256,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('captured recovery corpus gate rejects byte-level mutation before intake', () => {
  const corpus = encodeV2CapturedRecoveryCorpusForTest({ schema: 'shieldkit-v2-direct/captured-recovery-action-corpus/v1', events: [{}] });
  const digest = createHash('sha256').update(corpus).digest('hex');
  assert.equal(verifyV2CapturedRecoveryCorpusForTest(corpus, digest, 1), 1);
  const tampered = Buffer.from(corpus); tampered[tampered.length - 1] ^= 1;
  assert.throws(() => verifyV2CapturedRecoveryCorpusForTest(tampered, digest, 1), /digest changed before intake/u);
});
