import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  createExternalContributionRequest,
  signExternalContributionReceipt,
  verifyExternalContributionChain,
} from './external-contribution.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const r1csSha256 = digest('r1cs');
const ptauSha256 = digest('ptau');
const initialZkeySha256 = digest('initial');

function receipt({ sequence, previous, output, participant }) {
  const { privateKey } = generateKeyPairSync('ed25519');
  const request = createExternalContributionRequest({
    ceremonyId: 'shielded-action-v2',
    sequence,
    r1csSha256,
    ptauSha256,
    previousZkeySha256: previous,
  });
  return signExternalContributionReceipt({
    request,
    contributedZkeySha256: output,
    participantId: participant,
    participantPrivateKey: privateKey,
    entropyCommitment: digest(randomBytes(32)),
  });
}

test('two independently signed receipts form a hash-chained external transcript', () => {
  const firstHash = digest('participant-one-zkey');
  const secondHash = digest('participant-two-zkey');
  const receipts = [
    receipt({ sequence: 1, previous: initialZkeySha256, output: firstHash, participant: 'alice' }),
    receipt({ sequence: 2, previous: firstHash, output: secondHash, participant: 'bob' }),
  ];
  const transcript = verifyExternalContributionChain({
    ceremonyId: 'shielded-action-v2',
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    receipts,
  });
  assert.equal(transcript.mode, 'external-contribution-transcript');
  assert.equal(transcript.finalZkeySha256, secondHash);
  assert.match(transcript.qualification, /governance evidence/);
});

test('signature, chain, and unique-participant failures are rejected', () => {
  const firstHash = digest('one');
  const first = receipt({
    sequence: 1,
    previous: initialZkeySha256,
    output: firstHash,
    participant: 'alice',
  });
  const duplicate = { ...first, request: { ...first.request, sequence: '2', previousZkeySha256: firstHash } };
  assert.throws(() => verifyExternalContributionChain({
    ceremonyId: 'shielded-action-v2',
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    receipts: [first, duplicate],
  }), /signature is invalid/);
});
