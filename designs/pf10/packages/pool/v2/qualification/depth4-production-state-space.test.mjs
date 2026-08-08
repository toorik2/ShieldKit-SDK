import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  Q04_DEPTH4_OCCUPANCY_STATES,
  runProductionDepth4StateSpace,
} from "./depth4-production-state-space.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(here, "../../../../../..");
const parameterSourcePath = resolve(
  workspace,
  "node_modules/circomlib/circuits/poseidon_constants.circom",
);

test("Q-04 depth-4 production Poseidon state-space agrees with the independent oracle", { timeout: 300_000 }, () => {
  const evidence = runProductionDepth4StateSpace({ parameterSourcePath });
  const expectedClassesByCount = Array.from(
    { length: 14 },
    (_, normalCount) => normalCount === 0 ? 1 : normalCount * (normalCount + 1),
  );
  const expectedSetupTransitionsByCount = expectedClassesByCount.map(
    (classes, normalCount) => classes * normalCount,
  );
  const expectedNonlocalPermutationClassesByCount = [
    0, 0, 0, 6, 20, 30, 42, 56, 72, 90, 110, 132, 156, 182,
  ];
  assert.equal(evidence.status, "pass");
  assert.equal(
    evidence.occupancy.statesChecked,
    Q04_DEPTH4_OCCUPANCY_STATES,
  );
  assert.equal(evidence.occupancy.subtreeHashComparisons, 66_144);
  assert.deepEqual(
    evidence.indexed.classBreakdown.map((entry) => entry.classes),
    expectedClassesByCount,
  );
  assert.deepEqual(
    evidence.indexed.classBreakdown.map((entry) => entry.setupTransitions),
    expectedSetupTransitionsByCount,
  );
  assert.equal(
    evidence.indexed.classes,
    expectedClassesByCount.reduce((total, classes) => total + classes, 0),
  );
  assert.equal(
    evidence.indexed.setupTransitions,
    expectedSetupTransitionsByCount.reduce(
      (total, transitions) => total + transitions,
      0,
    ),
  );
  assert.equal(evidence.indexed.targetTransitions, evidence.indexed.classes);
  assert.deepEqual(
    evidence.indexed.classBreakdown.map((entry) =>
      entry.nonlocalPermutationClasses
    ),
    expectedNonlocalPermutationClassesByCount,
  );
  assert.equal(
    evidence.indexed.nonlocalPermutationClasses,
    expectedNonlocalPermutationClassesByCount.reduce(
      (total, classes) => total + classes,
      0,
    ),
  );
  assert.equal(
    evidence.indexed.nonlocalPermutationTargetTransitions,
    evidence.indexed.nonlocalPermutationClasses,
  );
  assert.equal(evidence.indexed.nonlocalPermutationMismatches, 0);
  assert.equal(
    evidence.indexed.sqliteScheduleLanes,
    (evidence.indexed.classes * 2) +
      evidence.indexed.nonlocalPermutationClasses,
  );
  assert.equal(
    evidence.indexed.durableReopenChecks,
    evidence.indexed.sqliteScheduleLanes,
  );
  assert.equal(evidence.indexed.depth3.sqliteStates, 874);
  assert.equal(evidence.indexed.depth3.durableReopenChecks, 874);
  assert.equal(
    evidence.indexed.duplicateAttempts,
    evidence.indexed.targetTransitions,
  );
  const nonterminalClasses = evidence.indexed.classBreakdown
    .filter((entry) => entry.normalCount < 13)
    .reduce((total, entry) => total + entry.classes, 0);
  const terminalClasses = evidence.indexed.classBreakdown
    .filter((entry) => entry.normalCount === 13)
    .reduce((total, entry) => total + entry.classes, 0);
  assert.equal(
    evidence.indexed.semanticDuplicateRejections,
    nonterminalClasses,
  );
  assert.equal(
    evidence.indexed.terminalCapacityPrecedenceRejections,
    terminalClasses,
  );
  assert.equal(
    evidence.indexed.failClosedDuplicateAttempts,
    evidence.indexed.semanticDuplicateRejections +
      evidence.indexed.terminalCapacityPrecedenceRejections,
  );
  assert.equal(evidence.indexed.capacityRejected, true);
  assert.equal(evidence.hashes.discrepancies, 0);
  assert.equal(evidence.discrepancies, 0);
  assert.equal(
    evidence.claims.authenticatedOccupancyStateSpaceExhaustive,
    true,
  );
  assert.equal(
    evidence.claims.indexedControlSkeletonsEnumerated,
    true,
  );
  assert.equal(
    evidence.claims.indexedControlSkeletonsAreStateQuotient,
    false,
  );
  assert.equal(
    evidence.claims.pairedNumericEmbeddingsUseSharedSqlite,
    true,
  );
  assert.equal(
    evidence.claims.nonlocalRankPermutationsUseSharedSqlite,
    true,
  );
  assert.equal(evidence.claims.everySqliteLaneReopenedAndAudited, true);
  assert.equal(evidence.claims.sharedKernelSymbolicTemplatesChecked, true);
  assert.equal(evidence.claims.sharedKernelSymbolicFormalTheorem, false);
  assert.equal(evidence.claims.externalProofCheckerRequired, true);
  assert.equal(
    evidence.symbolic.verification.controlSkeletons,
    evidence.indexed.classes,
  );
  assert.equal(
    evidence.symbolic.verification
      .representedConcreteRankStateGapTransitions,
    "93928268313",
  );
  assert.equal(evidence.claims.terminalCapacityPrecedenceCovered, true);
  assert.equal(evidence.claims.exhaustiveOverBn254Field, false);
  assert.equal(evidence.claims.enumeratesAllFourteenKeyHistories, false);
  assert.equal(evidence.claims.enumeratesAllDepth4IndexedHistories, false);
  assert.match(evidence.evidenceDigestSha256, /^[0-9a-f]{64}$/);
});
