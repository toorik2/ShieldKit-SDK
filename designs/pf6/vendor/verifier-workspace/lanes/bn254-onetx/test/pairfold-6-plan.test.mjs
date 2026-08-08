import assert from 'node:assert/strict';
import test from 'node:test';

test('PairFold-6 mixed ranges are four even-boundary executor spans', async () => {
  process.env.C7_PAIRFOLD_TOPOLOGY = '6';
  const plan = await import(new URL('../src/c7/composed-window-plan.mjs?pairfold6=2', import.meta.url).href);
  assert.deepEqual([...plan.MIXED_EXECUTOR_RANGES_6], [
    [2, 16],
    [16, 32],
    [32, 48],
    [48, 64],
  ]);
  assert.deepEqual([...plan.MIXED_GENESIS_RANGE], [0, 2]);
  assert.equal(plan.MIXED_EXECUTOR_RANGES.length, 4);
  assert.deepEqual([...plan.MIXED_EXECUTOR_RANGES], [...plan.MIXED_EXECUTOR_RANGES_6]);
  // PairFold-7 remains available for the five-executor route.
  assert.equal(plan.MIXED_EXECUTOR_RANGES_7.length, 5);
  assert.deepEqual([...plan.MIXED_EXECUTOR_RANGES_7], [
    [1, 14],
    [14, 26],
    [26, 38],
    [38, 50],
    [50, 64],
  ]);
});

test('PairFold-6 identity slug matches construction naming', async () => {
  const { PAIRFOLD_6_IDENTITY, PAIRFOLD_7_IDENTITY } = await import(new URL('../src/c7/pairfold-identity.mjs?pairfold6id=2', import.meta.url).href);
  assert.equal(PAIRFOLD_6_IDENTITY.topology, 6);
  assert.equal(PAIRFOLD_6_IDENTITY.slug, 'bn254-pairfold-6-p2shchain-pf1');
  assert.equal(PAIRFOLD_6_IDENTITY.construction, 'pairfold');
  assert.equal(PAIRFOLD_7_IDENTITY.topology, 7);
});
