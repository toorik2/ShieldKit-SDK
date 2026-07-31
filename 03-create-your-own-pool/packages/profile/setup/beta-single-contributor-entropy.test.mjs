import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA,
  BetaSingleContributorEntropyError,
  deriveBetaSingleContributorEntropy,
} from './beta-single-contributor-entropy.mjs';

const hash = (character) => `sha256:${character.repeat(64)}`;
const request = Object.freeze({
  schema: 'shieldkit/v2-beta-single-contributor-contribution-request/v1',
  ceremonyId: 'shielded-action-v2-beta',
  sequence: '1',
  r1csSha256: hash('a'),
  ptauSha256: hash('b'),
  previousZkeySha256: hash('c'),
});
const dice = Buffer.from('123456'.repeat(16) + '1234', 'ascii');
const osRandomBytes = Buffer.from(Array.from({ length: 64 }, (_, index) => index));

function derive(overrides = {}) {
  return deriveBetaSingleContributorEntropy({ dice, osRandomBytes, request, ...overrides });
}

test('derives the frozen beta Phase-2 KAT without exposing source material', () => {
  const result = derive();
  assert.deepEqual({ ...result, prompt: result.promptBytes.toString('ascii') }, {
    schema: BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA,
    prompt: 'SKV2P2:c83afabd35f9ea6daa5f0e0e8bdaa6dd2341088d51c5cff9ce4504d7dfb00c9418327273e4b3cca396be039cb9d77eb0dad70e20a1c0d24f2fe934bcd2753707',
    entropyCommitment: 'sha256:77b5fef73ccdfd7306766440904f330f02f1b2b8e661f346dc3d5bcb45d4ec0c',
    requestSha256: 'sha256:93b3b0bb2caa07ec16ab9c45477755e0dabed9051e62757fd04e20586d4e266a',
    saltSha256: 'sha256:a687b7c62c460a5a7cc30d24c61e5289b6b65b06f07ea21bc9bde0c721346276',
  });
  assert.match(result.promptBytes.toString('ascii'), /^SKV2P2:[0-9a-f]{128}$/);
  assert.equal(Object.isFrozen(result), true);
});

test('binds every entropy source and canonical request field', () => {
  const baseline = derive();
  const reorderedRequest = {
    previousZkeySha256: request.previousZkeySha256,
    ceremonyId: request.ceremonyId,
    schema: request.schema,
    ptauSha256: request.ptauSha256,
    r1csSha256: request.r1csSha256,
    sequence: request.sequence,
  };
  const changedDiceBytes = Buffer.from(dice); changedDiceBytes[0] = 0x36;
  const changedDice = derive({ dice: changedDiceBytes });
  const changedOs = Buffer.from(osRandomBytes); changedOs[63] ^= 1;
  const changedRequest = { ...request, sequence: '2' };
  const fromChangedOs = derive({ osRandomBytes: changedOs });
  const fromChangedRequest = derive({ request: changedRequest });
  for (const candidate of [changedDice, fromChangedOs, fromChangedRequest]) {
    assert.notDeepEqual(candidate.promptBytes, baseline.promptBytes);
    assert.notEqual(candidate.entropyCommitment, baseline.entropyCommitment);
  }
  assert.notEqual(fromChangedRequest.requestSha256, baseline.requestSha256);
  assert.notEqual(fromChangedRequest.saltSha256, baseline.saltSha256);
  const reordered = derive({ request: reorderedRequest });
  assert.deepEqual(reordered, baseline);
  assert.deepEqual(reordered.promptBytes, baseline.promptBytes);
});

test('rejects malformed dice, OS randomness, request, and unknown input fields', () => {
  const malformed = [
    { dice: dice.slice(1) },
    { dice: Buffer.concat([dice.subarray(0, -1), Buffer.from('7')]) },
    { dice: Buffer.concat([dice.subarray(0, -1), Buffer.from('\n')]) },
    { osRandomBytes: Buffer.alloc(63) },
    { osRandomBytes: 'not bytes' },
    { request: { ...request, r1csSha256: hash('A') } },
    { request: { ...request, extra: true } },
  ];
  for (const value of malformed) {
    assert.throws(() => derive(value), BetaSingleContributorEntropyError);
  }
  assert.throws(
    () => deriveBetaSingleContributorEntropy({ dice, osRandomBytes, request, extra: true }),
    /unknown properties/,
  );
});

test('result and errors do not disclose raw dice or OS randomness', () => {
  const markerDice = Buffer.from('615243'.repeat(16) + '6152', 'ascii');
  const markerOs = Buffer.from('ab'.repeat(64), 'hex');
  const result = derive({ dice: markerDice, osRandomBytes: markerOs });
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(markerDice.toString('ascii')), false);
  assert.equal(serialized.includes(markerOs.toString('hex')), false);
  assert.deepEqual(Object.keys(result).sort(), [
    'entropyCommitment',
    'requestSha256',
    'saltSha256',
    'schema',
  ]);
  assert.throws(
    () => derive({ dice: Buffer.concat([markerDice.subarray(0, -1), Buffer.from('7')]) }),
    (error) => error instanceof BetaSingleContributorEntropyError
      && !String(error).includes(markerDice.toString('ascii'))
      && !String(error).includes(markerOs.toString('hex')),
  );
});
