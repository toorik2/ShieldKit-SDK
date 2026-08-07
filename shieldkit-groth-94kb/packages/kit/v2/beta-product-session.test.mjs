import assert from 'node:assert/strict';
import test from 'node:test';

import {
  composeV2BetaProductSessionForTest,
  V2BetaProductSessionError,
} from './beta-product-session.mjs';

test('session composition rejects structural context lookalikes', async () => {
  await assert.rejects(
    composeV2BetaProductSessionForTest(Object.freeze({ close() {} }), async () => ({})),
    (error) => error instanceof V2BetaProductSessionError
      && error.code === 'BETA_SESSION_CONTEXT_REJECTED',
  );
});
