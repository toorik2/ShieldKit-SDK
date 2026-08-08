import assert from 'node:assert/strict';
import test from 'node:test';

test('PairFold-8 mixed ranges are six executor spans covering [1,64)', async () => {
  process.env.C7_PAIRFOLD_TOPOLOGY = '8';
  delete process.env.C7_IDEAL_VARIANT;
  const plan = await import(new URL('../src/c7/composed-window-plan.mjs?pairfold8=1', import.meta.url).href);
  assert.deepEqual([...plan.MIXED_EXECUTOR_RANGES_8], [
    [1, 12],
    [12, 22],
    [22, 32],
    [32, 42],
    [42, 52],
    [52, 64],
  ]);
  assert.equal(plan.MIXED_EXECUTOR_RANGES.length, 6);
  assert.deepEqual([...plan.MIXED_EXECUTOR_RANGES], [...plan.MIXED_EXECUTOR_RANGES_8]);
  assert.deepEqual([...plan.MIXED_GENESIS_RANGE], [0, 1]);
  // Coverage: contiguous [1,64)
  const ranges = plan.MIXED_EXECUTOR_RANGES_8;
  assert.equal(ranges[0][0], 1);
  assert.equal(ranges.at(-1)[1], 64);
  for (let i = 1; i < ranges.length; i++) {
    assert.equal(ranges[i][0], ranges[i - 1][1], `gap/overlap at role ${i}`);
  }
});

test('PairFold-8 identity is topology 8 spike', async () => {
  const { PAIRFOLD_8_IDENTITY, PAIRFOLD_7_IDENTITY } = await import(
    new URL('../src/c7/pairfold-identity.mjs?pairfold8id=1', import.meta.url).href
  );
  assert.equal(PAIRFOLD_8_IDENTITY.topology, 8);
  assert.equal(PAIRFOLD_8_IDENTITY.revision, 'spike1');
  assert.equal(PAIRFOLD_8_IDENTITY.slug, 'bn254-pairfold-8-p2shchain-spike1');
  assert.equal(PAIRFOLD_7_IDENTITY.topology, 7);
});

test('build-adapter accepts pairfoldTopology 8 with stripedFragments 6', async () => {
  const { validateBuild } = await import(new URL('../src/build-adapter.mjs?pf8val=1', import.meta.url).href);
  const base = JSON.parse(
    await (await import('node:fs/promises')).readFile(
      new URL('../candidates/bn254-onetx-pairfold-8-spike-r1.json', import.meta.url),
      'utf8',
    ),
  );
  // validateBuild only checks structural fields on build
  assert.doesNotThrow(() => validateBuild(base.build));
  assert.throws(
    () => validateBuild({
      ...base.build,
      profile: {
        ...base.build.profile,
        layout: { ...base.build.profile.layout, stripedFragments: 5 },
      },
    }),
    /stripedFragments=6/,
  );
});
