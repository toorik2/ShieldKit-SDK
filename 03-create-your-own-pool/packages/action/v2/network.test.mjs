import assert from 'node:assert/strict';
import test from 'node:test';

import {
  directV2NetworkIdFromName,
  directV2NetworkNameFromId,
  DIRECT_V2_NETWORK_CHIPNET,
  DIRECT_V2_NETWORK_MAINNET,
  isSupportedDirectV2NetworkId,
} from './network.mjs';

test('pins distinct V2 mainnet and Chipnet wire identifiers', () => {
  assert.equal(DIRECT_V2_NETWORK_MAINNET, 1);
  assert.equal(DIRECT_V2_NETWORK_CHIPNET, 2);
  assert.equal(directV2NetworkIdFromName('mainnet'), 1);
  assert.equal(directV2NetworkIdFromName('chipnet'), 2);
  assert.equal(directV2NetworkNameFromId(1), 'mainnet');
  assert.equal(directV2NetworkNameFromId(2), 'chipnet');
  for (const value of [0, 3, 255, -1, '2']) {
    assert.equal(isSupportedDirectV2NetworkId(value), false);
  }
});
