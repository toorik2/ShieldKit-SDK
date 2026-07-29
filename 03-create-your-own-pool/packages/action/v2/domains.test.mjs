import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BN254_SCALAR_FIELD_MODULUS,
  deriveV2DomainSeparator,
  DOMAIN_DERIVATION_PREFIX,
  V2_DOMAIN_SEPARATORS,
  V2DomainError,
  verifyPinnedV2DomainSeparators,
} from './domains.mjs';

test('pins unique nonzero canonical BN254 domain separators', () => {
  assert.equal(DOMAIN_DERIVATION_PREFIX, 'ShieldKit/PoolActionV2Direct/domain/v1/');
  assert.equal(verifyPinnedV2DomainSeparators(), true);
  const values = Object.values(V2_DOMAIN_SEPARATORS).map(({ value }) => value);
  assert.equal(new Set(values).size, values.length);
  for (const value of values) {
    assert.ok(value > 0n);
    assert.ok(value < BN254_SCALAR_FIELD_MODULUS);
  }
});

test('derivation is deterministic and first-canonical-digest', () => {
  for (const [label, pinned] of Object.entries(V2_DOMAIN_SEPARATORS)) {
    assert.deepEqual(deriveV2DomainSeparator(label), pinned);
  }
});

test('rejects labels outside the frozen ASCII grammar', () => {
  for (const label of ['', 'address', ' ADDRESS', 'ADDRESS-', 'ÄDDRESS']) {
    assert.throws(() => deriveV2DomainSeparator(label), V2DomainError);
  }
});
