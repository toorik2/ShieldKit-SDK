import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertV2BetaPoolCreateRuntimeWork,
  assertV2BetaWarmActionRuntimeWork,
  observeV2BetaActionRuntimeWork,
  observeV2BetaRuntimeWork,
  recordV2BetaRuntimeWork,
} from './beta-runtime-work-observer.mjs';

test('records only action-scoped allowlisted runtime work', async () => {
  assert.equal(recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' }), false);
  const observed = await observeV2BetaActionRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
    return 'ok';
  });
  assert.equal(observed.value, 'ok');
  assert.equal(assertV2BetaWarmActionRuntimeWork(observed.observation), observed.observation);
});

for (const type of ['cold-runtime-build', 'full-runtime-verification', 'compiler-child-spawn', 'instance-specialization']) {
  test(`fails closed when warm action records ${type}`, async () => {
    const observed = await observeV2BetaActionRuntimeWork(async () => {
      recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
      recordV2BetaRuntimeWork({ type });
    });
    assert.throws(() => assertV2BetaWarmActionRuntimeWork(observed.observation), { code: 'BETA_RUNTIME_WARM_WORK_FORBIDDEN' });
  });
}

test('pool create permits exactly one measured fixed-width instance relocation', async () => {
  const observed = await observeV2BetaRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'instance-specialization' });
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
  });
  assert.equal(
    assertV2BetaPoolCreateRuntimeWork(observed.observation, {
      linkedDuringCommand: true,
    }),
    observed.observation,
  );
});

test('cache-hit pool restart performs only one linked cache load and no relocation', async () => {
  const observed = await observeV2BetaRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
  });
  assert.equal(
    assertV2BetaPoolCreateRuntimeWork(observed.observation, {
      linkedDuringCommand: false,
    }),
    observed.observation,
  );
});

test('pool create rejects hidden builds, compilers, and relocation/cache claim mismatches', async () => {
  for (const type of ['cold-runtime-build', 'full-runtime-verification', 'compiler-child-spawn']) {
    const observed = await observeV2BetaRuntimeWork(async () => {
      recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
      recordV2BetaRuntimeWork({ type });
    });
    assert.throws(
      () => assertV2BetaPoolCreateRuntimeWork(observed.observation, {
        linkedDuringCommand: false,
      }),
      { code: 'BETA_POOL_CREATE_RUNTIME_WORK_FORBIDDEN' },
    );
  }
  const missingRelocation = await observeV2BetaRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
  });
  assert.throws(
    () => assertV2BetaPoolCreateRuntimeWork(missingRelocation.observation, {
      linkedDuringCommand: true,
    }),
    { code: 'BETA_POOL_CREATE_RUNTIME_WORK_FORBIDDEN' },
  );
  const reordered = await observeV2BetaRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
    recordV2BetaRuntimeWork({ type: 'instance-specialization' });
  });
  assert.throws(
    () => assertV2BetaPoolCreateRuntimeWork(reordered.observation, {
      linkedDuringCommand: true,
    }),
    { code: 'BETA_POOL_CREATE_RUNTIME_WORK_FORBIDDEN' },
  );
  const doubledCacheLoad = await observeV2BetaRuntimeWork(async () => {
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
    recordV2BetaRuntimeWork({ type: 'linked-runtime-cache-load' });
  });
  assert.throws(
    () => assertV2BetaPoolCreateRuntimeWork(doubledCacheLoad.observation, {
      linkedDuringCommand: false,
    }),
    { code: 'BETA_POOL_CREATE_RUNTIME_WORK_FORBIDDEN' },
  );
});
