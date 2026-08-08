import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';

import {
  BenchDataHomeError,
  cliDataHomeFromProduct,
  findProductDataHome,
  requireProductDataHome,
  resolveBenchDataHomeFromEnv,
} from './data-home.mjs';

function existsFromSet(paths) {
  const set = new Set(paths.map((p) => path.resolve(p)));
  return (p) => set.has(path.resolve(p));
}

test('findProductDataHome accepts nested product and outer root', () => {
  const outer = '/tmp/shieldkit-install-a';
  const product = path.join(outer, 'shieldkit', 'v2-beta-product');
  const exists = existsFromSet([
    path.join(product, 'session.json'),
  ]);

  assert.equal(findProductDataHome(product, { existsSync: exists }), product);
  assert.equal(findProductDataHome(outer, { existsSync: exists }), product);
  assert.equal(findProductDataHome(path.join(outer, 'shieldkit'), { existsSync: exists }), product);
  assert.equal(findProductDataHome('/tmp/missing', { existsSync: exists }), null);
  assert.equal(findProductDataHome('relative/path', { existsSync: exists }), null);
  assert.equal(findProductDataHome('', { existsSync: exists }), null);
});

test('cliDataHomeFromProduct maps nested product to outer root', () => {
  const outer = '/tmp/shieldkit-install-b';
  const product = path.join(outer, 'shieldkit', 'v2-beta-product');
  assert.equal(cliDataHomeFromProduct(product), outer);
  assert.equal(cliDataHomeFromProduct(outer), outer);
});

test('requireProductDataHome requires explicit path and validates session', () => {
  const outer = '/tmp/shieldkit-install-c';
  const product = path.join(outer, 'shieldkit', 'v2-beta-product');
  const exists = existsFromSet([path.join(product, 'session.json')]);

  assert.throws(
    () => requireProductDataHome(null, { existsSync: exists, env: {} }),
    (err) => err instanceof BenchDataHomeError && err.code === 'BENCH_DATA_HOME_REQUIRED',
  );
  assert.throws(
    () => requireProductDataHome('rel', { existsSync: exists, env: {} }),
    (err) => err instanceof BenchDataHomeError && err.code === 'BENCH_DATA_HOME_INVALID',
  );
  assert.throws(
    () => requireProductDataHome('/tmp/empty-home', { existsSync: exists, env: {} }),
    (err) => err instanceof BenchDataHomeError && err.code === 'BENCH_DATA_HOME_UNAVAILABLE',
  );

  assert.equal(
    requireProductDataHome(outer, { existsSync: exists, env: {} }),
    product,
  );
  assert.equal(
    requireProductDataHome(null, {
      existsSync: exists,
      env: { SHIELDKIT_BENCH_DATA_HOME: outer },
    }),
    product,
  );
});

test('resolveBenchDataHomeFromEnv has no hardcoded machine paths', () => {
  assert.equal(resolveBenchDataHomeFromEnv({}), null);
  assert.equal(
    resolveBenchDataHomeFromEnv({ SHIELDKIT_BENCH_DATA_HOME: '/abs/home' }),
    path.resolve('/abs/home'),
  );
});
