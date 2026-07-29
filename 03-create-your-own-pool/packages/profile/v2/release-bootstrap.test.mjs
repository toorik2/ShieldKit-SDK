/* The public release registry is intentionally empty until a reviewed final
 * V2 Direct profile is added to a ShieldKit release. */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  resolveV2FinalReleaseRoot,
  V2_FINAL_RELEASE_BOOTSTRAP_SHA256,
  V2FinalReleaseBootstrapError,
  verifyV2FinalReleaseProfileCore,
} from './release-bootstrap.mjs';

test('compiled final release registry is fail-closed before a final profile exists', () => {
  assert.match(V2_FINAL_RELEASE_BOOTSTRAP_SHA256, /^[0-9a-f]{64}$/u);
  assert.throws(
    () => resolveV2FinalReleaseRoot('final-chipnet'),
    /no approved V2 Direct final release roots/u,
  );
});

test('compiled final release registry rejects malformed caller root IDs', () => {
  assert.throws(
    () => resolveV2FinalReleaseRoot('../caller-root'),
    V2FinalReleaseBootstrapError,
  );
});

test('release profile verification accepts only a compiled root capability', () => {
  assert.throws(
    () => verifyV2FinalReleaseProfileCore(
      Object.freeze({}),
      Buffer.from('{}'),
      {},
    ),
    /not a final release root resolved by this ShieldKit build/u,
  );
});
