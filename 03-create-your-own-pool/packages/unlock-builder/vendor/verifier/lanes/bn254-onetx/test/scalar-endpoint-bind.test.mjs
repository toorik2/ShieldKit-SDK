import assert from 'node:assert/strict';
import test from 'node:test';

/**
 * Unit tests for the scalar-endpoint bind helper used by C7_SCALAR_ENDPOINT.
 * Exercises the real exported function (not a reimplementation).
 */
test('scalarBindLimbs is deterministic weighted Fp fold', async () => {
  const { scalarBindLimbs, SCALAR_ENDPOINT_WEIGHT } = await import(
    new URL('../src/c7/composed-window-szmath.mjs?bindtest=1', import.meta.url).href
  );
  assert.equal(SCALAR_ENDPOINT_WEIGHT, 7n);
  const limbs = [1n, 2n, 3n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
  const a = scalarBindLimbs(limbs);
  const b = scalarBindLimbs(limbs);
  assert.equal(a, b);
  // 1 + 2*7 + 3*49 = 1+14+147 = 162
  assert.equal(a, 162n);
});

test('scalarBindLimbs changes when any limb changes', async () => {
  const { scalarBindLimbs } = await import(
    new URL('../src/c7/composed-window-szmath.mjs?bindtest=2', import.meta.url).href
  );
  const base = Array.from({ length: 12 }, (_, i) => BigInt(i + 1));
  const a = scalarBindLimbs(base);
  const tweaked = base.slice();
  tweaked[5] = tweaked[5] + 1n;
  const b = scalarBindLimbs(tweaked);
  assert.notEqual(a, b);
});
