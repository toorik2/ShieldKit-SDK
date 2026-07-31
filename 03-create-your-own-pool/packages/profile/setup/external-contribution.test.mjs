import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
  createBetaSingleContributorContributionRequest,
  createExternalContributionRequest,
  signBetaSingleContributorContributionReceipt,
  signExternalContributionReceipt,
  V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_TRANSCRIPT_SCHEMA,
  verifyBetaSingleContributorExternalReceiptChain,
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

function betaReceipt({ sequence, previous, output, participant }) {
  const { privateKey } = generateKeyPairSync('ed25519');
  const request = createBetaSingleContributorContributionRequest({
    ceremonyId: 'shielded-action-v2-beta',
    sequence,
    r1csSha256,
    ptauSha256,
    previousZkeySha256: previous,
  });
  return signBetaSingleContributorContributionReceipt({
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

test('BETA profile accepts exactly one receipt and makes no qualification claim', () => {
  const output = digest('beta-participant-zkey');
  const receipts = [betaReceipt({
    sequence: 1,
    previous: initialZkeySha256,
    output,
    participant: 'beta-alice',
  })];
  const transcript = verifyBetaSingleContributorExternalReceiptChain({
    ceremonyId: 'shielded-action-v2-beta',
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    receipts,
  });
  assert.equal(transcript.schema, V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_TRANSCRIPT_SCHEMA);
  assert.equal(transcript.status, 'beta-single-contributor-unqualified');
  assert.equal(transcript.profile, BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE);
  assert.equal(transcript.contributorCount, 1);
  assert.equal(transcript.betaProvingKeySha256, output);
  assert.equal(Object.hasOwn(transcript, 'finalZkeySha256'), false);
  assert.deepEqual(transcript.profile.claims, {
    b02Qualified: false,
    ceremonyQualified: false,
    d01Qualified: false,
    d02Qualified: false,
    finalKey: false,
    participantIndependenceEstablished: false,
    production: false,
    q01FinalReplayQualified: false,
    q02Qualified: false,
    q03Qualified: false,
    q07Qualified: false,
    q08Qualified: false,
    q09Qualified: false,
    releaseQualified: false,
  });
});

test('generic chains retain their two-contributor floor and BETA rejects zero or two', () => {
  const firstHash = digest('beta-first-zkey');
  const secondHash = digest('beta-second-zkey');
  const genericFirst = receipt({
    sequence: 1,
    previous: initialZkeySha256,
    output: firstHash,
    participant: 'beta-alice',
  });
  const first = betaReceipt({
    sequence: 1,
    previous: initialZkeySha256,
    output: firstHash,
    participant: 'beta-alice',
  });
  const second = betaReceipt({
    sequence: 2,
    previous: firstHash,
    output: secondHash,
    participant: 'beta-bob',
  });
  const input = {
    ceremonyId: 'shielded-action-v2-beta',
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
  };
  assert.throws(
    () => verifyExternalContributionChain({ ...input, receipts: [genericFirst] }),
    /at least 2 signed external receipts/u,
  );
  assert.throws(
    () => verifyBetaSingleContributorExternalReceiptChain({ ...input, receipts: [] }),
    /requires exactly one signed external receipt/u,
  );
  assert.throws(
    () => verifyBetaSingleContributorExternalReceiptChain({ ...input, receipts: [first, second] }),
    /requires exactly one signed external receipt/u,
  );
  assert.throws(
    () => verifyBetaSingleContributorExternalReceiptChain({ ...input, receipts: [genericFirst] }),
    /unsupported external contribution receipt/u,
  );
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
