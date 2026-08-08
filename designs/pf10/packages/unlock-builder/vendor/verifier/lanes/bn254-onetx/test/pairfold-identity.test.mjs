import assert from 'node:assert/strict';
import test from 'node:test';

import { PAIRFOLD_7_IDENTITY } from '../src/c7/pairfold-identity.mjs';

test('PairFold-7 keeps a policy-compliant stable construction identity', () => {
  assert.equal(PAIRFOLD_7_IDENTITY.humanName, 'BN254 PairFold-7');
  assert.equal(PAIRFOLD_7_IDENTITY.displayName, 'BN254 PairFold-7 — Authenticated P2SH Chain');
  assert.equal(PAIRFOLD_7_IDENTITY.slug, 'bn254-pairfold-7-p2shchain-pf1');
  assert.deepEqual(
    PAIRFOLD_7_IDENTITY.slug.split('-'),
    [PAIRFOLD_7_IDENTITY.curve, PAIRFOLD_7_IDENTITY.construction, String(PAIRFOLD_7_IDENTITY.topology), PAIRFOLD_7_IDENTITY.stateModel, PAIRFOLD_7_IDENTITY.revision],
  );
});
