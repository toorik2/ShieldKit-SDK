import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../load.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const DOMAIN = 'shieldkit/external-phase2-contribution/v1\0';

export class ExternalContributionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ExternalContributionError';
  }
}

const fail = (message) => {
  throw new ExternalContributionError(message);
};

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export function digestContributionFile(filePath) {
  return sha256(readFileSync(filePath));
}

function signingBytes(body) {
  return Buffer.concat([
    Buffer.from(DOMAIN, 'utf8'),
    Buffer.from(canonicalJson(body), 'utf8'),
  ]);
}

function validateRequest(request) {
  if (!request || request.schema !== 'shieldkit/external-contribution-request/v1') {
    fail('unsupported external contribution request');
  }
  if (!ID.test(request.ceremonyId) || !/^[1-9][0-9]*$/.test(request.sequence)) {
    fail('contribution request identity or sequence is invalid');
  }
  for (const field of ['r1csSha256', 'ptauSha256', 'previousZkeySha256']) {
    if (!HASH.test(request[field])) fail(`contribution request ${field} is invalid`);
  }
  return request;
}

/**
 * Coordinator-created request. The participant receives the request and previous zkey,
 * performs `snarkjs zkey contribute` in an independently controlled environment, and
 * returns the resulting zkey plus a signed receipt.
 */
export function createExternalContributionRequest({
  ceremonyId,
  sequence,
  r1csSha256,
  ptauSha256,
  previousZkeySha256,
}) {
  return Object.freeze(validateRequest({
    schema: 'shieldkit/external-contribution-request/v1',
    ceremonyId,
    sequence: String(sequence),
    r1csSha256,
    ptauSha256,
    previousZkeySha256,
  }));
}

function publicKeyDer(publicKey) {
  return createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
}

/**
 * Participant-side receipt signing. Entropy is deliberately absent from this API.
 */
export function signExternalContributionReceipt({
  request,
  contributedZkeySha256,
  participantId,
  participantPrivateKey,
  entropyCommitment,
}) {
  validateRequest(request);
  if (!HASH.test(contributedZkeySha256) || contributedZkeySha256 === request.previousZkeySha256) {
    fail('contributed zkey hash must be valid and differ from the input');
  }
  if (!HASH.test(entropyCommitment)) fail('entropy commitment is invalid');
  if (!ID.test(participantId)) fail('participantId is invalid');
  const privateKey = participantPrivateKey?.type === 'private'
    ? participantPrivateKey
    : createPrivateKey(participantPrivateKey);
  if (privateKey.asymmetricKeyType !== 'ed25519') fail('participant signing key must be Ed25519');
  const participantPublicKey = publicKeyDer(privateKey).toString('base64');
  const body = {
    schema: 'shieldkit/external-contribution-receipt/v1',
    request,
    contributedZkeySha256,
    entropyCommitment,
    participant: {
      id: participantId,
      publicKeySpkiBase64: participantPublicKey,
    },
  };
  const signature = sign(null, signingBytes(body), privateKey).toString('base64');
  return Object.freeze({ ...body, signature });
}

function verifyReceipt(receipt) {
  if (!receipt || receipt.schema !== 'shieldkit/external-contribution-receipt/v1') {
    fail('unsupported external contribution receipt');
  }
  validateRequest(receipt.request);
  if (!HASH.test(receipt.contributedZkeySha256) || !HASH.test(receipt.entropyCommitment)) {
    fail('receipt hashes are invalid');
  }
  if (!ID.test(receipt.participant?.id)
    || typeof receipt.participant.publicKeySpkiBase64 !== 'string') {
    fail('receipt participant identity is invalid');
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(receipt.participant.publicKeySpkiBase64, 'base64'),
      type: 'spki',
      format: 'der',
    });
  } catch {
    fail('receipt participant public key is invalid');
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') fail('receipt participant key must be Ed25519');
  const { signature, ...body } = receipt;
  if (typeof signature !== 'string'
    || !verify(null, signingBytes(body), publicKey, Buffer.from(signature, 'base64'))) {
    fail('receipt signature is invalid');
  }
  return receipt;
}

/**
 * Coordinator-side chain verification. Unique signed identities and hash chaining prove
 * transcript integrity; operational independence remains a governance assertion and is
 * intentionally not converted into a "production" label.
 */
export function verifyExternalContributionChain({
  ceremonyId,
  r1csSha256,
  ptauSha256,
  initialZkeySha256,
  receipts,
  minimumParticipants = 2,
}) {
  if (!ID.test(ceremonyId) || !HASH.test(r1csSha256)
    || !HASH.test(ptauSha256) || !HASH.test(initialZkeySha256)) {
    fail('external contribution chain identity is invalid');
  }
  if (!Number.isSafeInteger(minimumParticipants) || minimumParticipants < 2) {
    fail('minimumParticipants must be at least two');
  }
  if (!Array.isArray(receipts) || receipts.length < minimumParticipants) {
    fail(`at least ${minimumParticipants} signed external receipts are required`);
  }
  const participantKeys = new Set();
  const participantIds = new Set();
  let previous = initialZkeySha256;
  receipts.forEach((receipt, index) => {
    verifyReceipt(receipt);
    const request = receipt.request;
    if (request.ceremonyId !== ceremonyId
      || request.sequence !== String(index + 1)
      || request.r1csSha256 !== r1csSha256
      || request.ptauSha256 !== ptauSha256
      || request.previousZkeySha256 !== previous) {
      fail(`receipt ${index + 1} does not continue the requested contribution chain`);
    }
    if (participantIds.has(receipt.participant.id)
      || participantKeys.has(receipt.participant.publicKeySpkiBase64)) {
      fail('external participant identities and keys must be unique');
    }
    participantIds.add(receipt.participant.id);
    participantKeys.add(receipt.participant.publicKeySpkiBase64);
    previous = receipt.contributedZkeySha256;
  });
  const transcriptBody = {
    schema: 'shieldkit/external-contribution-transcript/v1',
    mode: 'external-contribution-transcript',
    ceremonyId,
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    finalZkeySha256: previous,
    qualification: 'transcript-integrity-only; participant independence requires external governance evidence',
    receipts,
  };
  return Object.freeze({
    ...transcriptBody,
    transcriptSha256: sha256(Buffer.from(canonicalJson(transcriptBody), 'utf8')),
  });
}
