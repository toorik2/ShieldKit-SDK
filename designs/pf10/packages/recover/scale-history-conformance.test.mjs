import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { runScaleHistoryConformance, SCALE_HISTORY_SCHEMA } from './scale-history-conformance.mjs';

test('384 public deterministic transitions compare reference and portable recovery then reject provider faults', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-scale-history-'));
  try {
    const output = path.join(directory, 'vectors'); const result = await runScaleHistoryConformance({ transitions: 384, outputDirectory: output });
    assert.equal(result.schema, SCALE_HISTORY_SCHEMA); assert.equal(result.coverage.validCases, 384); assert.deepEqual(result.actionCounts, { deposit: 128, transfer: 128, withdrawal: 128 }); assert.equal(result.recoveredNotes, 256); assert.equal(result.recoveredUnspentNotes, 0);
    assert.deepEqual(result.faultInjection, { missing: 'TERMINAL_STATE_MISMATCH', duplicate: 'DUPLICATE_PACKET', reordered: 'HISTORY_DISCONTINUITY', truncated: 'TERMINAL_STATE_MISMATCH', equivocated: 'HISTORY_DISCONTINUITY' });
    assert.deepEqual(Object.keys(result.rollbackReplay), ['1', '2', '10', '100']); assert.equal(JSON.parse(await readFile(path.join(output, 'result.json'), 'utf8')).packetsSha256, result.packetsSha256);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
