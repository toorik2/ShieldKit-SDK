import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeRepositoryBaseline } from './baseline-envelope.mjs';

test('keeps PF6 as a fee reference under the frozen PF7/59KB/10KB policy', async () => {
  const result = await analyzeRepositoryBaseline();
  assert.equal(result.baseline.allBytes, 54_949);
  assert.equal(result.baseline.wireBytes, 54_739);
  assert.equal(result.feeReference.qualification, 'fee reference only; never the selected verifier or a G2 settlement candidate');
  assert.equal(result.selectedPolicy.candidate, 'bn254-onetx-pf7-sub62-r1');
  assert.equal(result.selectedPolicy.completeTransactionWireLimitBytes, 59_000);
  assert.equal(result.selectedPolicy.perInputUnlockingLimitBytes, 10_000);
  assert.equal(result.selectedPolicy.percentageHeadroomRequired, false);
  assert.equal(result.selectedPolicy.allBytesCap, null);
  assert.equal(result.wireReferenceDeltaToSelectedCap, 4_261);
  assert.equal(result.minimumRelayFeeSatoshis, 54_739);
  assert.equal(result.fixtureFeeShortfallSatoshis, 49_739);
  assert.equal(result.feeAsPercentOfOneNote, 0.54739);
  assert.deepEqual(result.unlockingViolations, []);
  assert.equal(result.maximumUnlockingBytes, 9_877);
  assert.equal(result.baselineQualifiesForG2, false);
  assert.deepEqual(result.baselineDisqualificationReasons, [
    'candidate mismatch: fee reference bn254-onetx-pf6-a3-r1, selected bn254-onetx-pf7-sub62-r1',
    'input-count mismatch: fee reference 6, selected 7',
    'verifier-only fixture omits the binding/state/transparent-fee settlement roles and canonical change output',
    'encoded fixture fee shortfall: 49739 satoshis at the recorded relay floor',
  ]);
});
