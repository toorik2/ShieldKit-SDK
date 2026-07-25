import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

test('BCH-2026 standard VM accepts a 9,499-byte P2SH32 settlement-surface spend', () => {
  // This is a policy/VM surface probe, not a candidate verifier or covenant.
  // The redeem script consumes its witness and proves its exact byte length;
  // it intentionally has no OP_TRUE/mock verifier-acceptance path.
  const witness = new Uint8Array(9_488).fill(0x42);
  const redeemBytecode = Uint8Array.of(
    0x82, // OP_SIZE
    0x7c, // OP_SWAP
    0x75, // OP_DROP
    0x02, 0x10, 0x25, // minimally encoded 9,488
    0x9c, // OP_NUMEQUAL
  );
  const witnessPush = encodeDataPush(witness);
  const redeemPush = encodeDataPush(redeemBytecode);
  const unlockingBytecode = new Uint8Array(witnessPush.length + redeemPush.length);
  unlockingBytecode.set(witnessPush);
  unlockingBytecode.set(redeemPush, witnessPush.length);
  const lockingBytecode = encodeLockingBytecodeP2sh32(hash256(redeemBytecode));

  assert.equal(lockingBytecode.length, 35);
  assert.equal(unlockingBytecode.length, 9_499);

  const program = createTestAuthenticationProgramBch({
    lockingBytecode,
    unlockingBytecode,
    valueSatoshis: 1_000n,
  });
  const result = createVirtualMachineBch2026(true).evaluate(program);
  assert.equal(result.error, undefined);
  assert.equal(result.metrics.operationCost, 10_949);
});
