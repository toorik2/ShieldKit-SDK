import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { REAL_ACTION_MUTATION_SCHEMA, runRealActionMutationMatrix } from './real-action-mutation-matrix.mjs';

test('all ten roles accept each real action and every mutation family rejects in Libauth BCH-2026 standard VM', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-real-action-mutations-'));
  try {
    const result = await runRealActionMutationMatrix({ outputDirectory: path.join(directory, 'result') });
    assert.equal(result.schema, REAL_ACTION_MUTATION_SCHEMA); assert.equal(result.totals.actions, 3); assert.equal(result.totals.baselineVmExecutions, 30); assert.equal(result.totals.falseAccepts, 0); assert.equal(result.totals.unexecuted, 0);
    for (const action of result.actions) { assert.equal(action.exactFee.exactOneSatPerByte, true); assert.ok(action.mutations.total > 70); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
