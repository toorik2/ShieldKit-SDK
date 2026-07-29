import assert from 'node:assert/strict';
import test from 'node:test';

import {
  encodeLockingBytecodeP2sh32,
} from '@bitauth/libauth';

import {
  deriveV2RollingBaseSats,
  DirectV2DustPolicyError,
  pinnedBchn2026DustThresholdSats,
  roundUpV2RollingBaseSats,
} from './dust-policy.mjs';

const p2sh32 = Buffer.from(
  encodeLockingBytecodeP2sh32(new Uint8Array(32).fill(0x42)),
);

test('pins BCHN 2026 token-aware dust and the doubled rounded V2 base', () => {
  assert.equal(p2sh32.length, 35);
  assert.equal(
    pinnedBchn2026DustThresholdSats({ lockingBytecode: p2sh32 }),
    576n,
  );
  assert.equal(
    deriveV2RollingBaseSats({ lockingBytecode: p2sh32 }),
    1_200n,
  );

  const stateOutput = {
    lockingBytecode: Buffer.alloc(88, 0x51),
    token: {
      category: new Uint8Array(32).fill(0x11),
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: new Uint8Array(128),
      },
    },
  };
  assert.equal(pinnedBchn2026DustThresholdSats(stateOutput), 1_224n);
  assert.equal(deriveV2RollingBaseSats(stateOutput), 2_500n);
});

test('rounding and malformed output behavior are exact', () => {
  assert.equal(roundUpV2RollingBaseSats(0n), 0n);
  assert.equal(roundUpV2RollingBaseSats(1_000n), 1_000n);
  assert.equal(roundUpV2RollingBaseSats(1_001n), 1_100n);
  assert.throws(
    () => roundUpV2RollingBaseSats(1),
    DirectV2DustPolicyError,
  );
  assert.throws(
    () => pinnedBchn2026DustThresholdSats({
      lockingBytecode: Buffer.alloc(0),
    }),
    DirectV2DustPolicyError,
  );
});
