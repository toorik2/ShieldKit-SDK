import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeDirectV2Address,
  DIRECT_V2_ADDRESS_BYTES,
  DIRECT_V2_ADDRESS_OFFSETS,
  encodeDirectV2Address,
} from './address.mjs';
import { BN254_SCALAR_FIELD_MODULUS } from './domains.mjs';
import { deriveDirectV2Address } from './notes.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const address = deriveDirectV2Address({
  networkId: 2,
  profileId: '11'.repeat(32),
  instanceId: '22'.repeat(32),
  spendSecret: fr(3),
  incomingViewSecret: fr(4),
});

test('pins and round-trips the exact 168-byte SKA2 address layout', () => {
  const encoded = encodeDirectV2Address(address);
  const golden = [
    '534b4132',
    '02',
    '000000',
    '11'.repeat(32),
    '22'.repeat(32),
    '957cfd431b63e4a96bf4f3ef71dfb4c19c31f98958f2944495ae95220e6fd621',
    'dc4f6bf477ec17e8f19442c6730e701caaa89050edc595280d3155e00beed782',
    '0dc9831817e6c520d9a38d14c88e91d930a1f33179ac917b52f39bb83e125bbd',
  ].join('');
  assert.equal(encoded.length, DIRECT_V2_ADDRESS_BYTES);
  assert.equal(encoded.toString('hex'), golden);
  assert.equal(encoded[DIRECT_V2_ADDRESS_OFFSETS.networkId], 2);
  assert.deepEqual(decodeDirectV2Address(encoded), address);
});

test('rejects lengths, headers, flags, point mutations, and authority drift', () => {
  const encoded = encodeDirectV2Address(address);
  for (const length of [167, 169]) {
    const malformed = Buffer.alloc(length);
    encoded.copy(malformed, 0, 0, Math.min(length, encoded.length));
    assert.throws(() => decodeDirectV2Address(malformed), /exactly 168 bytes/);
  }
  for (let offset = 0; offset < 4; offset += 1) {
    const malformed = Buffer.from(encoded);
    malformed[offset] ^= 1;
    assert.throws(() => decodeDirectV2Address(malformed), /magic/);
  }
  for (const offset of [5, 6, 7]) {
    const malformed = Buffer.from(encoded);
    malformed[offset] = 1;
    assert.throws(() => decodeDirectV2Address(malformed), /flags/);
  }
  const badNetwork = Buffer.from(encoded);
  badNetwork[4] = 99;
  assert.throws(() => decodeDirectV2Address(badNetwork), /network/);
  for (const offset of [8, 40, 72, 104, 136]) {
    const malformed = Buffer.from(encoded);
    malformed[offset] ^= 1;
    assert.throws(() => decodeDirectV2Address(malformed), /invalid|authority|point/);
  }
});

test('Q-05 rejects identity, non-subgroup, off-curve, and noncanonical public-key encodings', () => {
  const encoded = encodeDirectV2Address(address);
  const pointCases = Object.freeze([
    ['identity', Uint8Array.of(1, ...new Uint8Array(31))],
    ['non-subgroup', new Uint8Array(32)],
    ['off-curve', Uint8Array.of(2, ...new Uint8Array(31))],
    // The BN254 modulus in little-endian compressed-y form is noncanonical.
    ['noncanonical', Uint8Array.from(Buffer.from(
      fr(BN254_SCALAR_FIELD_MODULUS), 'hex',
    ).reverse())],
  ]);
  for (const [label, point] of pointCases) {
    const malformed = Buffer.from(encoded);
    Buffer.from(point).copy(malformed, DIRECT_V2_ADDRESS_OFFSETS.spendPublicKey);
    assert.throws(
      () => decodeDirectV2Address(malformed),
      /invalid|point|authority/,
      label,
    );
  }
});
