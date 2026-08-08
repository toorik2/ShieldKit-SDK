import assert from 'node:assert/strict';
import test from 'node:test';

import * as poolV2 from '@shieldkit/pool/v2';

test('@shieldkit/pool/v2 exposes storage, not recovery trust decisions', () => {
  assert.equal(typeof poolV2.openV2DirectStore, 'function');
  assert.equal(Object.hasOwn(poolV2, 'recoverPool'), false);
  assert.equal(Object.hasOwn(poolV2, 'V2RecoverPoolError'), false);
});
