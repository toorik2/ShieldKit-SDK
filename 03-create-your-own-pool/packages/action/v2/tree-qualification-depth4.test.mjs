import assert from 'node:assert/strict';
import test from 'node:test';
import { runDepth4ExhaustiveQualification } from './tree-qualification-depth4.mjs';

test('depth-4 indexed-nullifier qualification exhausts the fixed canonical boundary corpus', () => {
  const evidence = runDepth4ExhaustiveQualification();
  assert.equal(evidence.status, 'completed-bounded-structural-campaign');
  assert.equal(evidence.exhaustiveDefinition.traces, 13_700);
  assert.equal(evidence.exhaustiveDefinition.treeInsertionTransitions, 13_699);
  assert.equal(evidence.exhaustiveDefinition.storeReplayInsertions, 82_201);
  assert.equal(evidence.failures.duplicateRejectionStates, 13_699);
  assert.equal(evidence.failures.boundaryAndEncodingRejections, 7);
  assert.equal(evidence.claims.exhaustiveOverBn254Field, false);
  assert.equal(evidence.claims.exhaustiveThroughFullDepth4Capacity, false);
  assert.equal(evidence.claims.independentHashOracle, false);
  assert.equal(evidence.claims.productionPoseidonHashBackend, false);
  assert.equal(evidence.claims.millionEntryCampaignRun, false);
  assert.match(evidence.evidenceDigestSha256, /^[0-9a-f]{64}$/);
});
