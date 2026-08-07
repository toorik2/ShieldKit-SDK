import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS,
  BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS,
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA,
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
  BetaSingleContributorEntropyError,
  deriveBetaSingleContributorEntropy,
} from './beta-single-contributor-entropy.mjs';

const hash = (character) => `sha256:${character.repeat(64)}`;
const request = Object.freeze({
  schema: 'shieldkit/v2-beta-single-contributor-contribution-request/v2',
  ceremonyId: 'shielded-action-v2-beta',
  entropyPolicySha256: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
  implementationSha256: hash('d'),
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

test('derives the frozen v2 beta Phase-2 KAT without exposing source material', () => {
  const result = derive();
  assert.deepEqual({ ...result, prompt: result.promptBytes.toString('ascii') }, {
    schema: BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA,
    prompt: 'SKV2P2:10c7eb7797af53f51c44f97910bee1041d869e1eaa047dfae9ddc9cde6bc60a3cfe26744d80239e763a136478032fb9f103c095b8f4b1165b53b1bee4710a27c',
    entropyCommitment: 'sha256:6914543c38c4f5aac384833299819cb89d63c7288025f58467d22e58134cd001',
    requestSha256: 'sha256:36ddb67660923542a9f8b82852289beab4e3395ed583f0d66fc51df2d88eae41',
    saltSha256: 'sha256:b057f73aef55426ca85133320cf204282bcab448d026c4a3bf071985c2c06c42',
  });
  assert.match(result.promptBytes.toString('ascii'), /^SKV2P2:[0-9a-f]{128}$/);
  assert.equal(Object.isFrozen(result), true);
});

test('derives frozen KATs for 101 and 128 rolls and uses every entered roll', () => {
  const vectors = [
    {
      length: 101,
      prompt: 'SKV2P2:229297de81bc88406a893c06e2d044106ec239d71936f89ab3fe9f05ef3254c46dada16b41fa1ade0a2900ebf070b35758f3be10ae952dc9322ac27a63b67115',
      entropyCommitment: 'sha256:a021f81cdca5af77d616bc35524827c0ea6657d43cb944c70a55752f76d90b0a',
    },
    {
      length: 128,
      prompt: 'SKV2P2:145e53248912e12154b62a26e774735ebf198f7853d1e117c35d0ae052d3a675f76e6548ea07409ba5ade5638a647ad8f2e97167ae32fe61a99eca25c1a66534',
      entropyCommitment: 'sha256:9c4b5580acd47547c1e44b5c1bb1eaf7cedf450dd6f5838a0a778d9f851c3982',
    },
  ];
  const source = '123456'.repeat(22);
  for (const vector of vectors) {
    const rolls = Buffer.from(source.slice(0, vector.length), 'ascii');
    const result = derive({ dice: rolls });
    assert.equal(result.promptBytes.toString('ascii'), vector.prompt);
    assert.equal(result.entropyCommitment, vector.entropyCommitment);
    result.promptBytes.fill(0);
    rolls.fill(0);
  }
});

test('binds every entropy source and canonical request field', () => {
  const baseline = derive();
  const reorderedRequest = {
    previousZkeySha256: request.previousZkeySha256,
    entropyPolicySha256: request.entropyPolicySha256,
    implementationSha256: request.implementationSha256,
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

  const extraRoll = derive({ dice: Buffer.concat([dice, Buffer.from('6')]) });
  const maximumRolls = derive({
    dice: Buffer.alloc(BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS, 0x31),
  });
  assert.notDeepEqual(extraRoll.promptBytes, baseline.promptBytes);
  assert.notEqual(extraRoll.entropyCommitment, baseline.entropyCommitment);
  assert.match(maximumRolls.promptBytes.toString('ascii'), /^SKV2P2:[0-9a-f]{128}$/u);
});

test('rejects malformed dice, OS randomness, request, and unknown input fields', () => {
  const malformed = [
    { dice: Buffer.alloc(BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS - 1, 0x31) },
    { dice: Buffer.alloc(BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS + 1, 0x31) },
    { dice: Buffer.concat([dice.subarray(0, -1), Buffer.from('7')]) },
    { dice: Buffer.concat([Buffer.alloc(127, 0x31), Buffer.from('7')]) },
    { dice: Buffer.concat([dice.subarray(0, -1), Buffer.from('\n')]) },
    { osRandomBytes: Buffer.alloc(63) },
    { osRandomBytes: 'not bytes' },
    { request: { ...request, r1csSha256: hash('A') } },
    { request: { ...request, entropyPolicySha256: hash('e') } },
    { request: { ...request, implementationSha256: 'not-a-hash' } },
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
