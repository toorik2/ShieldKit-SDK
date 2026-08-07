import assert from 'node:assert/strict';
import test from 'node:test';

import { buildDemoCatalog, isUnavailableDemoCatalog, verifyDemoCatalog } from './catalog.mjs';

test('no placeholder or unkeyed demo signature is presented as authentic', () => {
  const catalog = buildDemoCatalog();
  assert.equal(catalog.availability, 'unavailable');
  assert.deepEqual(catalog.entries, []);
  assert.equal(Object.hasOwn(catalog, 'signature'), false);
  assert.equal(isUnavailableDemoCatalog(catalog), true);
  assert.equal(verifyDemoCatalog(catalog), false);
  assert.equal(isUnavailableDemoCatalog({ ...catalog, signature: 'forged' }), false);
  assert.equal(verifyDemoCatalog({ ...catalog, signature: 'forged' }), false);
});
