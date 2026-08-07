import assert from 'node:assert/strict';
import test from 'node:test';

import {
  capabilitiesForDesign,
  catalogContentHash,
  listDesignsDataOnly,
  loadClosedCatalog,
  showDesign,
} from './designs.mjs';
import { isMutationAllowed } from '../contracts/capabilities.mjs';

test('design summaries do not mint protocol profile IDs', () => {
  const catalog = loadClosedCatalog();
  assert.equal(catalog.schema, 'shieldkit-closed-design-catalog/v2');
  assert.deepEqual(catalog.designs.map(({ id, profileId, profileStatus }) => ({ id, profileId, profileStatus })), [
    { id: 'pf10', profileId: null, profileStatus: 'unselected' },
    { id: 'pf6-a3-direct-v1', profileId: null, profileStatus: 'unfrozen' },
    { id: 'fri-stark-96kb', profileId: null, profileStatus: 'unfrozen' },
  ]);
  assert.match(catalogContentHash(), /^[0-9a-f]{64}$/);
});

test('closed catalog listing remains data-only and honest about profile authority', () => {
  const rows = listDesignsDataOnly();
  assert.equal(rows.length, 3);
  assert.equal(rows.every((row) => row.backendModuleLoaded === false), true);
  assert.equal(rows.find((row) => row.id === 'pf10').profileStatus, 'unselected');
  assert.equal(rows.find((row) => row.id === 'fri-stark-96kb').profileStatus, 'unfrozen');
});

test('Lab designs are blocked, not made runnable by --allow-lab', () => {
  for (const alias of ['pf6', 'fri']) {
    const design = showDesign(alias);
    const record = capabilitiesForDesign(design);
    assert.equal(record.overall, 'blocked');
    for (const verb of ['createPool', 'deposit', 'transfer', 'withdraw']) {
      assert.equal(record.guarantees[verb].status, 'blocked');
      assert.equal(isMutationAllowed(record, verb, { allowLab: true }), false);
    }
  }
  assert.equal(capabilitiesForDesign(showDesign('pf6')).guarantees.destinationBinding.status, 'blocked');
});

test('PF10 catalog support is beta family metadata, not an exact-profile qualification', () => {
  const record = capabilitiesForDesign(showDesign('pf10'));
  assert.equal(record.profileId, null);
  assert.equal(record.profileStatus, 'unselected');
  assert.equal(record.overall, 'experimental');
  assert.equal(record.mutationAuthority, 'none-design-family-only');
  assert.equal(isMutationAllowed(record, 'deposit', { allowLab: true }), false);
});
