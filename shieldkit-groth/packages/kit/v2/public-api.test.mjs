import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createV2BetaChipnetActionLifecycle,
  createV2DirectActionLifecycle,
  recoverPool,
  V2ActionLifecycleError,
  V2RecoverPoolError,
} from '@shieldkit/kit/v2';

test('@shieldkit/kit/v2 exposes the validated durable lifecycle factory', async () => {
  await assert.rejects(
    createV2DirectActionLifecycle(undefined),
    (error) => error instanceof V2ActionLifecycleError
      && error.code === 'INVALID_LIFECYCLE_INPUT',
  );
  assert.equal(typeof createV2DirectActionLifecycle, 'function');
  assert.equal(typeof createV2BetaChipnetActionLifecycle, 'function');
});

test('@shieldkit/kit/v2 recovery cannot accept caller-authenticated history', async () => {
  let storeReads = 0;
  const base = {
    binding: {},
    chainClient: {},
    fundingWallets: [],
    genesis: {},
    recoverOwnedNote: null,
    recoveryScanner: {},
    store: {
      canonicalState() {
        storeReads += 1;
        throw new Error('must not read an untrusted recovery store');
      },
    },
  };
  await assert.rejects(
    recoverPool(base),
    (error) => error instanceof V2RecoverPoolError
      && /production pinned-TLS/.test(error.message),
  );
  assert.equal(storeReads, 0);
  await assert.rejects(
    recoverPool({
      ...base,
      binaryPath: '/caller/scanner',
    }),
    (error) => error instanceof V2RecoverPoolError
      && /unknown fields/.test(error.message),
  );
  assert.equal(storeReads, 0);
});
