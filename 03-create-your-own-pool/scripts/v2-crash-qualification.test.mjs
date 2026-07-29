import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  parseV2CrashQualificationArguments,
  runV2ExternalCrashCorpus,
  V2CrashQualificationError,
} from './v2-crash-qualification.mjs';

test('crash qualification command requires one new evidence output path', () => {
  assert.deepEqual(
    parseV2CrashQualificationArguments(['--output', 'evidence.json'], '/work'),
    { output: '/work/evidence.json' },
  );
  for (const argv of [[], ['--output'], ['--cases', '10000'], ['--output', '--bad']]) {
    assert.throws(
      () => parseV2CrashQualificationArguments(argv, '/work'),
      V2CrashQualificationError,
    );
  }
});

test('focused external crash corpus requires SIGKILL and fresh-process exact durable state checks', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-v2-q06-external-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  assert.throws(
    () => runV2ExternalCrashCorpus({ directory: 'relative-directory' }),
    /absolute normalized/u,
  );
  const nonempty = mkdtempSync(join(tmpdir(), 'shieldkit-v2-q06-nonempty-'));
  t.after(() => rmSync(nonempty, { recursive: true, force: true }));
  writeFileSync(join(nonempty, 'existing'), 'occupied');
  assert.throws(
    () => runV2ExternalCrashCorpus({ directory: nonempty }),
    /new empty directory/u,
  );
  const result = runV2ExternalCrashCorpus({ directory });
  assert.equal(result.schema, 'shieldkit-v2-direct-external-crash-corpus-v1');
  assert.equal(result.cases.length, 6);
  assert.deepEqual(
    result.cases.map((item) => item.signal),
    Array(6).fill('SIGKILL'),
  );
  assert.deepEqual(
    result.cases.map((item) => item.crashMode),
    [
      'sqlite-create-before',
      'sqlite-create-after',
      'sqlite-reserve-before',
      'sqlite-reserve-after',
      'delivery-submit-before',
      'delivery-submit-after',
    ],
  );
  assert.deepEqual(
    result.cases[3].invariants,
    ['canonical-unchanged', 'operation-state-exact', 'note-and-utxo-reservations-exact'],
  );
  assert.deepEqual(
    result.cases[5].invariants,
    ['delivery-state-exact', 'duplicate-send-claim-rejected'],
  );
  assert.match(result.limitations[0], /not power-loss or filesystem-fault semantics/);
});
