import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeRepositoryBaseline } from './baseline-envelope.mjs';

test('computes the frozen verifier baseline against source-recorded and G2 limits', async () => {
  const result = await analyzeRepositoryBaseline();
  assert.equal(result.baseline.allBytes, 54_949);
  assert.equal(result.baseline.wireBytes, 54_739);
  assert.equal(result.allBytesBudgetRemaining, 40_051);
  assert.equal(result.wireBudgetRemaining, 40_261);
  assert.equal(result.minimumRelayFeeSatoshis, 54_739);
  assert.equal(result.fixtureFeeShortfallSatoshis, 49_739);
  assert.equal(result.feeAsPercentOfOneNote, 0.54739);
  assert.deepEqual(result.unlockingViolations, [
    { inputIndex: 0, bytes: 9_853, overG2CeilingBytes: 353 },
    { inputIndex: 1, bytes: 9_848, overG2CeilingBytes: 348 },
    { inputIndex: 2, bytes: 9_877, overG2CeilingBytes: 377 },
  ]);
  assert.equal(result.baselineQualifiesForG2, false);
});

