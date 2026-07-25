import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { readJson } from '../../../packages/contracts/src/index.mjs';
import { readBuildProfile } from '../src/build-profile.mjs';
import {
  MIXED_EXECUTOR_RANGES_6,
  MIXED_EXECUTOR_RANGES_7,
  MIXED_EXECUTOR_RANGES_GEN6_4,
  MIXED_GENESIS_RANGE_GEN6_4,
  MIXED_EXECUTOR_RANGES_GEN6_4_IDEAL,
  MIXED_GENESIS_RANGE_GEN6_4_IDEAL,
} from '../src/c7/composed-window-plan.mjs';
import { PAIRFOLD_6_IDENTITY, PAIRFOLD_7_IDENTITY } from '../src/c7/pairfold-identity.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const candidatesDir = join(here, '../candidates');

const shortlist = [
  {
    file: 'bn254-onetx-near-pf6-source-r1.json',
    construction: 'near-pf6',
    topology: 6,
    lean: 'candidateNearPf6',
    idealGen: 1,
    idealExec: [8, 8, 8, 7],
    // Deployable pure-pair: genHi=2 → genP=1, modes [14,16,16,16] pairs [7,8,8,8]
    deployableGen: 1,
    deployableExec: [7, 8, 8, 8],
    deployableGenesis: [0, 2],
    deployableRanges: [[2, 16], [16, 32], [32, 48], [48, 64]],
    fragments: 4,
  },
  {
    file: 'bn254-onetx-gen6-4exec-source-r1.json',
    construction: 'gen6-4exec',
    topology: 6,
    lean: 'candidateGen6FourExec',
    // Lean Ideal: genP=6 / 8+8+8+2 (density-blocked on current genesis path).
    idealGen: 6,
    idealExec: [8, 8, 8, 2],
    // Deployable gen-absorb probe: genHi=4 → genP=2, modes [14,16,16,14] pairs [7,8,8,7]
    deployableGen: 2,
    deployableExec: [7, 8, 8, 7],
    deployableGenesis: [0, 4],
    deployableRanges: [[4, 18], [18, 34], [34, 50], [50, 64]],
    fragments: 4,
  },
  {
    file: 'bn254-onetx-gen6-7in-source-r1.json',
    construction: 'gen6-7in',
    topology: 7,
    lean: 'candidateGen6SevenIn',
    idealGen: 6,
    idealExec: [8, 8, 6, 2, 2],
    deployableGen: 1,
    deployableExec: [6, 6, 6, 6, 7],
    deployableGenesis: [0, 1],
    deployableRanges: [[1, 14], [14, 26], [26, 38], [38, 50], [50, 64]],
    fragments: 5,
  },
];

test('shortlist manifests are distinct Ideal-aligned PairFold candidates with measured scores', () => {
  for (const item of shortlist) {
    const candidate = readJson(join(candidatesDir, item.file));
    assert.equal(candidate.lane, 'bn254-onetx');
    assert.equal(candidate.identity.construction, item.construction);
    assert.equal(candidate.identity.topology, item.topology);
    assert.equal(candidate.build.pairfoldTopology, item.topology === 6 ? 6 : 7);
    assert.equal(candidate.build.fixedG2Static, true);
    assert.equal(candidate.build.idealVariant, item.construction);
    assert.match(candidate.provenance.scope, new RegExp(item.lean));
    const profile = readBuildProfile(candidate.build.profile);
    assert.equal(profile.layout.windowSize, 13);
    assert.equal(profile.layout.stripedFragments, item.fragments);
    assert.equal(candidate.judge.expected.inputCount, item.topology);
    // Measured score/hash pins are required once a candidate has been rebuilt;
    // gen6-4exec may be mid-rebuild without pins while its schedule is fixed.
    if (candidate.judge.expected.score !== undefined) {
      assert.ok(
        candidate.judge.expected.score > 60000,
        `${item.construction} must pin a real measured score`,
      );
      assert.ok(candidate.judge.expected.artifactHashes?.result);
    }
  }
  assert.equal(new Set(shortlist.map((s) => s.construction)).size, 3);
});

test('exported Miller window tables encode PairFold-6, PairFold-7, and gen6-4exec plans', () => {
  assert.deepEqual(MIXED_EXECUTOR_RANGES_6, [
    [2, 16],
    [16, 32],
    [32, 48],
    [48, 64],
  ]);
  assert.deepEqual(MIXED_EXECUTOR_RANGES_7, [
    [1, 14],
    [14, 26],
    [26, 38],
    [38, 50],
    [50, 64],
  ]);
  // Deployable gen-absorb (density-feasible)
  assert.deepEqual([...MIXED_GENESIS_RANGE_GEN6_4], [0, 4]);
  assert.deepEqual(MIXED_EXECUTOR_RANGES_GEN6_4, [
    [4, 18],
    [18, 34],
    [34, 50],
    [50, 64],
  ]);
  // Aspirational Ideal genP=6 tables retained for research reference
  assert.deepEqual([...MIXED_GENESIS_RANGE_GEN6_4_IDEAL], [0, 12]);
  assert.deepEqual(MIXED_EXECUTOR_RANGES_GEN6_4_IDEAL, [
    [12, 28],
    [28, 44],
    [44, 60],
    [60, 64],
  ]);
  // full cover integrity for deployable gen6-4 plan
  assert.equal(MIXED_GENESIS_RANGE_GEN6_4[0], 0);
  assert.equal(MIXED_EXECUTOR_RANGES_GEN6_4.at(-1)[1], 64);
  let cursor = MIXED_GENESIS_RANGE_GEN6_4[1];
  for (const [lo, hi] of MIXED_EXECUTOR_RANGES_GEN6_4) {
    assert.equal(lo, cursor);
    cursor = hi;
  }
  // Mode lengths are pure-pair and distinct from stock PF6 [14,16,16,16]
  const modeLens = MIXED_EXECUTOR_RANGES_GEN6_4.map(([lo, hi]) => hi - lo);
  assert.deepEqual(modeLens, [14, 16, 16, 14]);
  assert.notDeepEqual(modeLens, MIXED_EXECUTOR_RANGES_6.map(([lo, hi]) => hi - lo));
  assert.equal(PAIRFOLD_6_IDENTITY.topology, 6);
  assert.equal(PAIRFOLD_7_IDENTITY.topology, 7);
  assert.equal(PAIRFOLD_6_IDENTITY.construction, 'pairfold');
});

test('Ideal and deployable gen/exec pair maps sum to 32 for each shortlist contract', () => {
  for (const item of shortlist) {
    const idealSum = item.idealGen + item.idealExec.reduce((a, b) => a + b, 0);
    assert.equal(idealSum, 32, `${item.construction} Ideal cover`);
    const depSum = item.deployableGen + item.deployableExec.reduce((a, b) => a + b, 0);
    assert.equal(depSum, 32, `${item.construction} deployable cover`);
  }
});

test('gen6-4exec deployable windows are distinct from near-pf6 (not a PF6 clone)', () => {
  const near = shortlist.find((s) => s.construction === 'near-pf6');
  const gen64 = shortlist.find((s) => s.construction === 'gen6-4exec');
  assert.ok(near && gen64);
  assert.notDeepEqual(gen64.deployableRanges, near.deployableRanges);
  assert.notDeepEqual(gen64.deployableGenesis, near.deployableGenesis);
  assert.notEqual(gen64.deployableGen, near.deployableGen);
  assert.deepEqual([...MIXED_GENESIS_RANGE_GEN6_4], gen64.deployableGenesis);
  assert.deepEqual(MIXED_EXECUTOR_RANGES_GEN6_4, gen64.deployableRanges);
});

test('gen6-4exec measured pins are distinct from near-pf6 (honest clone detector)', () => {
  const near = readJson(join(candidatesDir, 'bn254-onetx-near-pf6-source-r1.json'));
  const gen64 = readJson(join(candidatesDir, 'bn254-onetx-gen6-4exec-source-r1.json'));
  assert.notEqual(gen64.judge.expected.score, near.judge.expected.score);
  assert.notEqual(
    gen64.judge.expected.artifactHashes.result,
    near.judge.expected.artifactHashes.result,
  );
  assert.notEqual(
    gen64.judge.expected.artifactHashes.transaction,
    near.judge.expected.artifactHashes.transaction,
  );
  assert.ok(gen64.judge.expected.score > 60000);
  assert.match(gen64.provenance.scope, /gen-absorb|\[0,4\)/);
  assert.match(gen64.provenance.scope, /\[4,18\]/);
});
