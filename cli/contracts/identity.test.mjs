import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildIdentityFields,
  computeProfileId,
  resolveProfileIdentity,
  resolveAlias,
  assertOperationId,
  IdentityError,
} from './identity.mjs';
import { loadClosedCatalog } from '../registry/designs.mjs';

test('buildIdentityFields rejects tip as identity', () => {
  assert.throws(
    () => buildIdentityFields({
      backendId: 'pf10-v2-beta',
      profileId: 'ab'.repeat(32),
      tip: { height: 1 },
    }),
    (e) => e instanceof IdentityError && e.code === 'TIP_NOT_IDENTITY',
  );
});

test('design aliases resolve to honest family identity states', () => {
  const catalog = loadClosedCatalog();
  const pf10 = resolveAlias('pf10', catalog);
  assert.equal(pf10.id, 'pf10');
  assert.equal(pf10.profileId, null);
  assert.equal(pf10.profileStatus, 'unselected');
  const fri = resolveAlias('fri-96k', catalog);
  assert.equal(fri.id, 'fri-stark-96kb');
  assert.equal(fri.profileId, null);
  assert.equal(fri.profileStatus, 'unfrozen');
});

test('summary-shaped fields cannot mint an authoritative profile id', () => {
  assert.throws(
    () => computeProfileId({ proofSystem: 'Groth16', topology: 'PF10', roles: 10 }),
    (e) => e instanceof IdentityError && e.code === 'PROFILE_AUTHORITY_REQUIRED',
  );
  assert.throws(
    () => resolveProfileIdentity({ profileCore: { schema: 'backend-specific' } }),
    (e) => e instanceof IdentityError && e.code === 'PROFILE_AUTHORITY_REQUIRED',
  );
});

test('operation identity accepts bounded PF10 namespaces but never path syntax', () => {
  assert.equal(assertOperationId(`deposit.${'ab'.repeat(32)}`), `deposit.${'ab'.repeat(32)}`);
  assert.throws(() => assertOperationId('../../outside'), /safe identifier/);
  assert.throws(() => assertOperationId('a'.repeat(129)), /safe identifier/);
});

test('pinned identities and explicit unfrozen designs are distinguishable', () => {
  const pinned = resolveProfileIdentity({ profileId: 'cd'.repeat(32) });
  assert.deepEqual(pinned, { profileId: 'cd'.repeat(32), profileStatus: 'frozen' });
  assert.deepEqual(
    resolveProfileIdentity({ profileStatus: 'unfrozen' }),
    { profileId: null, profileStatus: 'unfrozen' },
  );
  assert.deepEqual(
    resolveProfileIdentity({ profileStatus: 'unselected' }),
    { profileId: null, profileStatus: 'unselected' },
  );
  assert.throws(
    () => resolveProfileIdentity({}),
    (e) => e instanceof IdentityError && e.code === 'PROFILE_AUTHORITY_REQUIRED',
  );
});
