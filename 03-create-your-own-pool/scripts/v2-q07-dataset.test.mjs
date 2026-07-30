import assert from 'node:assert/strict';
import {
  chmodSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  V2_Q07_BN254_FR_MODULUS,
  V2_Q07_DATASET_SCHEMA,
  V2Q07DatasetError,
  createQ07SingleHistoryKeyStream,
  verifyQ07SingleHistoryDataset,
  writeQ07SingleHistoryDataset,
} from './v2-q07-dataset.mjs';

const TEST_MAIN_COUNT = 4;

function fixture(t, name = 'q07-dataset-') {
  const directory = mkdtempSync(join(tmpdir(), name));
  chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const written = writeQ07SingleHistoryDataset({
    outputDirectory: directory,
    testOnlyMainCount: TEST_MAIN_COUNT,
  });
  return { directory, path: written.path, written };
}

function rewrite(path, transform) {
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line));
  writeFileSync(path, transform(lines).map((line) => JSON.stringify(line)).join('\n') + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
}

test('Q-07 writes and streaming-verifies a deterministic single history with a reserved warm sample', (t) => {
  const subject = fixture(t);
  const verified = verifyQ07SingleHistoryDataset({
    path: subject.path,
    testOnlyMainCount: TEST_MAIN_COUNT,
  });
  assert.equal(subject.written.schema, V2_Q07_DATASET_SCHEMA);
  assert.equal(verified.count, TEST_MAIN_COUNT + 1);
  assert.equal(verified.mainCount, TEST_MAIN_COUNT);
  assert.equal(verified.warmSampleOrdinal, TEST_MAIN_COUNT + 1);
  assert.equal(verified.qualifyingShape, false);
  assert.equal(verified.qualification, 'test-only-nonqualifying');
  assert.equal(verified.sha256, subject.written.sha256);
  assert.equal(verified.transcriptSha256, subject.written.transcriptSha256);
  assert.deepEqual(verified.edgeEvidence, {
    zeroOrdinal: 1,
    zeroKey: '0'.repeat(64),
    frMinusOneOrdinal: 2,
    frMinusOneKey: (V2_Q07_BN254_FR_MODULUS - 1n).toString(16).padStart(64, '0'),
  });
});

test('Q-07 stream is deterministic, globally unique, and reserves Fr edges at ordinals one and two', () => {
  const stream = createQ07SingleHistoryKeyStream({ testOnlyMainCount: TEST_MAIN_COUNT });
  const entries = [];
  for (let entry = stream.next(); entry !== null; entry = stream.next()) entries.push(entry);
  assert.equal(entries.length, TEST_MAIN_COUNT + 1);
  assert.deepEqual(entries.slice(0, 2), [
    { ordinal: 1, key: '0'.repeat(64) },
    { ordinal: 2, key: (V2_Q07_BN254_FR_MODULUS - 1n).toString(16).padStart(64, '0') },
  ]);
  assert.equal(new Set(entries.map((entry) => entry.key)).size, entries.length);
  assert.deepEqual(entries, (() => {
    const repeated = createQ07SingleHistoryKeyStream({ testOnlyMainCount: TEST_MAIN_COUNT });
    const result = [];
    for (let entry = repeated.next(); entry !== null; entry = repeated.next()) result.push(entry);
    return result;
  })());
});

test('Q-07 verifier rejects duplicate keys, ordinal gaps, noncanonical fields, shape changes, truncation, and extra records', (t) => {
  const cases = [
    ['duplicate', (lines) => { lines[1].key = lines[0].key; return lines; }, /key differs/u],
    ['ordinal-gap', (lines) => { lines[1].ordinal = 3; return lines; }, /ordinal is not the exact sequence/u],
    ['bad-fr', (lines) => { lines[2].key = V2_Q07_BN254_FR_MODULUS.toString(16).padStart(64, '0'); return lines; }, /not canonical BN254 Fr/u],
    ['shape', (lines) => { lines[2].extra = true; return lines; }, /missing or unknown properties/u],
  ];
  for (const [name, mutate, message] of cases) {
    const subject = fixture(t, `q07-${name}-`);
    rewrite(subject.path, mutate);
    assert.throws(
      () => verifyQ07SingleHistoryDataset({ path: subject.path, testOnlyMainCount: TEST_MAIN_COUNT }),
      message,
    );
  }
  const truncated = fixture(t, 'q07-truncated-');
  const bytes = readFileSync(truncated.path);
  writeFileSync(truncated.path, bytes.subarray(0, bytes.length - 1), { mode: 0o600 });
  assert.throws(
    () => verifyQ07SingleHistoryDataset({ path: truncated.path, testOnlyMainCount: TEST_MAIN_COUNT }),
    /must end with one newline/u,
  );
  const extra = fixture(t, 'q07-extra-');
  writeFileSync(extra.path, `${readFileSync(extra.path, 'utf8')}${JSON.stringify({ schema: V2_Q07_DATASET_SCHEMA, ordinal: 6, key: '0'.repeat(64) })}\n`, { mode: 0o600 });
  assert.throws(
    () => verifyQ07SingleHistoryDataset({ path: extra.path, testOnlyMainCount: TEST_MAIN_COUNT }),
    /extra line/u,
  );
});

test('Q-07 verifier rejects symlink and hardlink inputs', (t) => {
  const subject = fixture(t);
  const symlink = join(subject.directory, 'linked.ndjson');
  symlinkSync(subject.path, symlink);
  assert.throws(
    () => verifyQ07SingleHistoryDataset({ path: symlink, testOnlyMainCount: TEST_MAIN_COUNT }),
    V2Q07DatasetError,
  );
  const hardlink = join(subject.directory, 'hardlinked.ndjson');
  linkSync(subject.path, hardlink);
  assert.throws(
    () => verifyQ07SingleHistoryDataset({ path: hardlink, testOnlyMainCount: TEST_MAIN_COUNT }),
    /single-link/u,
  );
});
