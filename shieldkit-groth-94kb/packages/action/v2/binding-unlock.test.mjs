import assert from 'node:assert/strict';
import test from 'node:test';
import {
  encodeDataPush,
} from '@bitauth/libauth';

import {
  DirectV2BindingUnlockError,
  decodeDirectV2BindingUnlock,
  deriveDirectV2BindingP2sh32Lock,
  encodeDirectV2BindingUnlock,
  verifyDirectV2BindingP2sh32Lock,
} from './binding-unlock.mjs';

const packet = () => {
  const value = Buffer.alloc(552);
  value.write('SDA2', 0, 'ascii');
  return value;
};

const redeem = () => Buffer.concat([
  Buffer.alloc(256, 0x61),
  Buffer.from([0x75, 0x51]),
]);

const rejects = (operation, pattern) => assert.throws(
  operation,
  (error) =>
    error instanceof DirectV2BindingUnlockError
    && pattern.test(error.message),
);

test('binding unlock codec emits and decodes the canonical two-push layout', () => {
  const actionPacket = packet();
  const redeemScript = redeem();
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const unlockingBytecode = encodeDirectV2BindingUnlock({
    packet: actionPacket,
    redeemScript,
    sourceLockingBytecode,
  });
  assert.deepEqual(
    unlockingBytecode.subarray(0, 3),
    Buffer.from([0x4d, 0x28, 0x02]),
  );
  assert.deepEqual(
    unlockingBytecode.subarray(3, 555),
    actionPacket,
  );
  assert.deepEqual(
    unlockingBytecode.subarray(555),
    Buffer.from(encodeDataPush(redeemScript)),
  );
  assert.deepEqual(
    decodeDirectV2BindingUnlock({
      unlockingBytecode,
      sourceLockingBytecode,
      expectedPacket: actionPacket,
    }),
    {
      packet: actionPacket,
      redeemScript,
      sourceLockingBytecode,
    },
  );
  assert.deepEqual(
    verifyDirectV2BindingP2sh32Lock({
      redeemScript,
      sourceLockingBytecode,
    }),
    sourceLockingBytecode,
  );
});

test('binding unlock decoder rejects packet-only and trailing bytes', () => {
  const actionPacket = packet();
  const redeemScript = redeem();
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const canonical = encodeDirectV2BindingUnlock({
    packet: actionPacket,
    redeemScript,
    sourceLockingBytecode,
  });
  const prefix = canonical.subarray(0, 555);
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode: prefix,
      sourceLockingBytecode,
    }),
    /PUSHDATA2/,
  );
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode: Buffer.concat([
        canonical,
        Buffer.from([0]),
      ]),
      sourceLockingBytecode,
    }),
    /exactly one redeem push/,
  );
});

test('binding unlock decoder rejects a nonminimal redeem push', () => {
  const actionPacket = packet();
  const redeemScript = redeem();
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const nonminimal = Buffer.concat([
    Buffer.from([
      0x4d,
      0x28,
      0x02,
    ]),
    actionPacket,
    Buffer.from([
      0x4e,
      redeemScript.length & 0xff,
      (redeemScript.length >> 8) & 0xff,
      0,
      0,
    ]),
    redeemScript,
  ]);
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode: nonminimal,
      sourceLockingBytecode,
    }),
    /minimally pushed/,
  );
});

test('binding unlock codec authenticates the redeem against exact P2SH32', () => {
  const actionPacket = packet();
  const redeemScript = redeem();
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const unlockingBytecode = encodeDirectV2BindingUnlock({
    packet: actionPacket,
    redeemScript,
    sourceLockingBytecode,
  });
  const wrongRedeem = Buffer.from(redeemScript);
  wrongRedeem[0] ^= 1;
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode: Buffer.concat([
        unlockingBytecode.subarray(0, 555),
        Buffer.from(encodeDataPush(wrongRedeem)),
      ]),
      sourceLockingBytecode,
    }),
    /hash256/,
  );
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode,
      sourceLockingBytecode: Buffer.from([0x75, 0x51]),
    }),
    /P2SH32/,
  );
});

test('binding unlock codec binds exact SDA2 packet bytes', () => {
  const actionPacket = packet();
  const redeemScript = redeem();
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const unlockingBytecode = encodeDirectV2BindingUnlock({
    packet: actionPacket,
    redeemScript,
    sourceLockingBytecode,
  });
  const differentPacket = packet();
  differentPacket[100] = 1;
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode,
      sourceLockingBytecode,
      expectedPacket: differentPacket,
    }),
    /differs/,
  );
  const wrongMagic = packet();
  wrongMagic.write('SDC2', 0, 'ascii');
  rejects(
    () => encodeDirectV2BindingUnlock({
      packet: wrongMagic,
      redeemScript,
      sourceLockingBytecode,
    }),
    /SDA2/,
  );
});

test('binding unlock codec handles minimal numeric pushes and rejects invalid shapes', () => {
  const actionPacket = packet();
  const redeemScript = Buffer.from([1]);
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  const unlockingBytecode = encodeDirectV2BindingUnlock({
    packet: actionPacket,
    redeemScript,
    sourceLockingBytecode,
  });
  assert.equal(unlockingBytecode[555], 0x51);
  assert.deepEqual(
    decodeDirectV2BindingUnlock({
      unlockingBytecode,
      sourceLockingBytecode,
    }).redeemScript,
    redeemScript,
  );
  rejects(
    () => encodeDirectV2BindingUnlock({
      packet: actionPacket,
      redeemScript: Buffer.alloc(0),
      sourceLockingBytecode,
    }),
    /nonempty/,
  );
  rejects(
    () => decodeDirectV2BindingUnlock({
      unlockingBytecode,
      sourceLockingBytecode,
      unknown: true,
    }),
    /unknown/,
  );
});

test('binding unlock codec enforces the standard unlocking-bytecode limit', () => {
  const actionPacket = packet();
  const redeemScript = Buffer.alloc(9_500, 0x61);
  const sourceLockingBytecode =
    deriveDirectV2BindingP2sh32Lock(redeemScript);
  rejects(
    () => encodeDirectV2BindingUnlock({
      packet: actionPacket,
      redeemScript,
      sourceLockingBytecode,
    }),
    /exceeds 10000 bytes/,
  );
});
