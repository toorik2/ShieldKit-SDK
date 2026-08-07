import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { bn254 } from '@noble/curves/bn254.js';

import {
  BN254_BASE_FIELD,
  canonicalizeDirectV2Jacobian,
  computeDirectV2ExactMsm,
  createDirectV2MsmInitialState,
  decodeDirectV2MsmState,
  DIRECT_V2_MSM_STATE_BYTES,
  DIRECT_V2_MSM_WINDOWS,
  directV2PacketDigestPublicInputs,
  encodeDirectV2MsmState,
  parseDirectV2VerificationKeyJson,
} from './exact-msm.mjs';

const root = path.resolve(import.meta.dirname, '../../../..');
const verificationKeyPath = path.join(
  root,
  'shieldkit-groth',
  'packages',
  'prove',
  'test-fixtures',
  'two-public',
  'verification_key.json',
);

const point = ([x, y, z]) =>
  BigInt(z) === 0n
    ? bn254.G1.Point.ZERO
    : bn254.G1.Point.fromAffine({ x: BigInt(x), y: BigInt(y) });

const nobleExpected = (verificationKey, input0, input1) => {
  const [ic0, ic1, ic2] = verificationKey.IC.map(point);
  const multiply = (base, scalar) =>
    scalar === 0n ? bn254.G1.Point.ZERO : base.multiply(scalar);
  return ic0
    .add(multiply(ic1, input0))
    .add(multiply(ic2, input1));
};

const deterministicScalars = () => {
  let state = 0x243f6a8885a308d3n;
  const values = [];
  for (let index = 0; index < 128; index += 1) {
    state ^= state << 13n;
    state ^= state >> 7n;
    state ^= state << 17n;
    state &= (1n << 128n) - 1n;
    values.push(state);
  }
  return values;
};

test('fixed 128-bit Shamir windows are total and match independent BN254 MSM', async () => {
  const verificationKey = parseDirectV2VerificationKeyJson(
    await readFile(verificationKeyPath),
  );
  assert.deepEqual(DIRECT_V2_MSM_WINDOWS, [
    { start: 0, end: 38 },
    { start: 38, end: 75 },
    { start: 75, end: 112 },
    { start: 112, end: 128 },
  ]);
  const maximum = (1n << 128n) - 1n;
  const pairs = [
    [0n, 0n],
    [1n, 0n],
    [0n, 1n],
    [1n, 1n],
    [maximum, maximum],
  ];
  for (let bit = 0; bit < 128; bit += 1) {
    pairs.push([1n << BigInt(bit), 0n]);
    pairs.push([0n, 1n << BigInt(bit)]);
  }
  const random = deterministicScalars();
  for (let index = 0; index < random.length; index += 2) {
    pairs.push([random[index], random[index + 1]]);
  }

  for (const [input0, input1] of pairs) {
    const actual = computeDirectV2ExactMsm(
      verificationKey,
      input0,
      input1,
    );
    const expected = nobleExpected(verificationKey, input0, input1);
    if (expected.equals(bn254.G1.Point.ZERO)) {
      assert.equal(actual.output.infinity, true);
      assert.deepEqual(
        [actual.output.x, actual.output.y, actual.output.zInverse],
        [0n, 0n, 0n],
      );
    } else {
      const affine = expected.toAffine();
      assert.equal(actual.output.infinity, false);
      assert.deepEqual(
        [actual.output.x, actual.output.y],
        [affine.x, affine.y],
      );
      assert.equal(
        (actual.folded.z * actual.output.zInverse) % BN254_BASE_FIELD,
        1n,
      );
    }
    assert.equal(actual.states.length, 5);
  }
});

test('the exact 128-byte carried state round-trips and rejects aliases', () => {
  const initial = createDirectV2MsmInitialState(
    (1n << 128n) - 1n,
    0x1234n,
  );
  const encoded = encodeDirectV2MsmState(initial);
  assert.equal(encoded.length, DIRECT_V2_MSM_STATE_BYTES);
  assert.deepEqual(decodeDirectV2MsmState(encoded), initial);
  assert.throws(
    () => decodeDirectV2MsmState(encoded.subarray(1)),
    /exactly 128 bytes/,
  );
  const aliased = Buffer.from(encoded);
  aliased.fill(0xff, 0, 32);
  assert.throws(
    () => decodeDirectV2MsmState(aliased),
    /canonical BN254 base-field element/,
  );
  const noncanonicalIdentity = Buffer.from(encoded);
  noncanonicalIdentity[31] = 7;
  noncanonicalIdentity[63] = 9;
  assert.throws(
    () => decodeDirectV2MsmState(noncanonicalIdentity),
    /noncanonical identity encoding/,
  );
  assert.throws(
    () => createDirectV2MsmInitialState(1n << 128n, 0n),
    /unsigned 128-bit/,
  );
});

test('canonical infinity is unique and packet limbs use unsigned big-endian halves', () => {
  assert.throws(
    () => canonicalizeDirectV2Jacobian({ x: 7n, y: 9n, z: 0n }),
    /noncanonical identity encoding/,
  );
  const digest = Buffer.from(
    '80000000000000000000000000000001'
    + 'ffffffffffffffffffffffffffffffff',
    'hex',
  );
  assert.deepEqual(directV2PacketDigestPublicInputs(digest), [
    0x80000000000000000000000000000001n,
    (1n << 128n) - 1n,
  ]);
});
