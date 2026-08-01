import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertV2Pf10AuthenticatedTemplateCapability,
  assertV2Pf10SpecializedRuntimeCapability,
  parseV2Pf10LinkBytecode,
  V2Pf10InstanceSpecializerError,
} from './pf10-instance-specializer.mjs';

test('PF10 linker retains exact data-push offsets rather than scanning byte substrings', () => {
  const parsed = parseV2Pf10LinkBytecode(Buffer.from([
    0x51, 0x02, 0xaa, 0xbb, 0x4c, 0x03, 0xcc, 0xdd, 0xee, 0x87,
  ]));
  assert.equal(parsed.length, 4);
  assert.equal(parsed[0].opcode, 0x51);
  assert.equal(parsed[1].dataOffset, 2);
  assert.deepEqual(parsed[1].data, Buffer.from('aabb', 'hex'));
  assert.equal(parsed[2].dataOffset, 6);
  assert.deepEqual(parsed[2].data, Buffer.from('ccddee', 'hex'));
});

test('PF10 linker rejects malformed push layouts before any specialization', () => {
  assert.throws(
    () => parseV2Pf10LinkBytecode(Buffer.from([0x4d, 0x02])),
    (error) => error instanceof V2Pf10InstanceSpecializerError
      && error.code === 'PF10_LINK_LAYOUT_DRIFT',
  );
  assert.throws(
    () => parseV2Pf10LinkBytecode(Buffer.from([0x03, 0x01])),
    (error) => error instanceof V2Pf10InstanceSpecializerError
      && error.code === 'PF10_LINK_LAYOUT_DRIFT',
  );
});

test('PF10 linker rejects structural capability lookalikes', () => {
  for (const assertion of [
    assertV2Pf10AuthenticatedTemplateCapability,
    assertV2Pf10SpecializedRuntimeCapability,
  ]) {
    assert.throws(
      () => assertion(Object.freeze({ schema: 'shieldkit-v2-direct-pf10-instance-specializer-v1' })),
      (error) => error instanceof V2Pf10InstanceSpecializerError
        && /CAPABILITY_INVALID$/u.test(error.code),
    );
  }
});
