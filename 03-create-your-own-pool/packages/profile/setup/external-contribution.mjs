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
const BETA_DOMAIN = 'shieldkit/v2/beta-single-contributor-receipt/v1\0';
const EXTERNAL_REQUEST_SCHEMA = 'shieldkit/external-contribution-request/v1';
const EXTERNAL_RECEIPT_SCHEMA = 'shieldkit/external-contribution-receipt/v1';

export const V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE_SCHEMA =
  'shieldkit/v2-beta-single-contributor-ceremony-profile/v1';
export const V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_TRANSCRIPT_SCHEMA =
  'shieldkit/v2-beta-single-contributor-ceremony-transcript/v1';
export const V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA =
  'shieldkit/v2-beta-single-contributor-contribution-request/v1';
export const V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_RECEIPT_SCHEMA =
  'shieldkit/v2-beta-single-contributor-contribution-receipt/v1';
export const BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE = Object.freeze({
  schema: V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE_SCHEMA,
  id: 'beta-single-contributor',
  mode: 'beta-single-contributor',
  contributorCount: 1,
  claims: Object.freeze({
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
  }),
});

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

function signingBytes(body, domain = DOMAIN) {
  return Buffer.concat([
    Buffer.from(domain, 'utf8'),
    Buffer.from(canonicalJson(body), 'utf8'),
  ]);
}

function validateRequest(request, schema = EXTERNAL_REQUEST_SCHEMA, exact = false) {
  if (!request || request.schema !== schema) {
    fail('unsupported external contribution request');
  }
  if (exact) {
    const actual = Object.keys(request).sort();
    const expected = [
      'ceremonyId', 'previousZkeySha256', 'ptauSha256', 'r1csSha256',
      'schema', 'sequence',
    ].sort();
    if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
      fail('beta contribution request has missing or unknown properties');
    }
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
    schema: EXTERNAL_REQUEST_SCHEMA,
    ceremonyId,
    sequence: String(sequence),
    r1csSha256,
    ptauSha256,
    previousZkeySha256,
  }));
}

/** Create the domain-separated, exactly-one-contributor BETA request. */
export function createBetaSingleContributorContributionRequest({
  ceremonyId,
  sequence,
  r1csSha256,
  ptauSha256,
  previousZkeySha256,
}) {
  return Object.freeze(validateRequest({
    schema: V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA,
    ceremonyId,
    sequence: String(sequence),
    r1csSha256,
    ptauSha256,
    previousZkeySha256,
  }, V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA, true));
}

function publicKeyDer(publicKey) {
  return createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
}

/**
 * Participant-side receipt signing. Entropy is deliberately absent from this API.
 */
function signContributionReceipt({
  request,
  contributedZkeySha256,
  participantId,
  participantPrivateKey,
  entropyCommitment,
}, {
  domain,
  receiptSchema,
  requestSchema,
  exactRequest = false,
}) {
  validateRequest(request, requestSchema, exactRequest);
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
    schema: receiptSchema,
    request,
    contributedZkeySha256,
    entropyCommitment,
    participant: {
      id: participantId,
      publicKeySpkiBase64: participantPublicKey,
    },
  };
  const signature = sign(null, signingBytes(body, domain), privateKey).toString('base64');
  return Object.freeze({ ...body, signature });
}

export function signExternalContributionReceipt(input) {
  return signContributionReceipt(input, {
    domain: DOMAIN,
    receiptSchema: EXTERNAL_RECEIPT_SCHEMA,
    requestSchema: EXTERNAL_REQUEST_SCHEMA,
  });
}

/** Sign a receipt which cannot be replayed as a generic/final contribution. */
export function signBetaSingleContributorContributionReceipt(input) {
  return signContributionReceipt(input, {
    domain: BETA_DOMAIN,
    receiptSchema: V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_RECEIPT_SCHEMA,
    requestSchema: V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA,
    exactRequest: true,
  });
}

function verifyReceipt(receipt, {
  domain,
  receiptSchema,
  requestSchema,
  exact = false,
}) {
  if (!receipt || receipt.schema !== receiptSchema) {
    fail('unsupported external contribution receipt');
  }
  if (exact) {
    const actual = Object.keys(receipt).sort();
    const expected = [
      'contributedZkeySha256', 'entropyCommitment', 'participant', 'request',
      'schema', 'signature',
    ].sort();
    if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
      fail('beta contribution receipt has missing or unknown properties');
    }
    const participantKeys = Object.keys(receipt.participant ?? {}).sort();
    if (participantKeys.length !== 2
      || participantKeys[0] !== 'id'
      || participantKeys[1] !== 'publicKeySpkiBase64') {
      fail('beta contribution receipt participant has missing or unknown properties');
    }
  }
  validateRequest(receipt.request, requestSchema, exact);
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
    || !verify(null, signingBytes(body, domain), publicKey, Buffer.from(signature, 'base64'))) {
    fail('receipt signature is invalid');
  }
  return receipt;
}

function verifyContributionChain({
  ceremonyId,
  r1csSha256,
  ptauSha256,
  initialZkeySha256,
  receipts,
}, {
  minimumParticipants,
  minimumParticipantFloor = 1,
  maximumParticipants = undefined,
  receiptCountError = `at least ${minimumParticipants} signed external receipts are required`,
  receiptVerifier,
}) {
  if (!ID.test(ceremonyId) || !HASH.test(r1csSha256)
    || !HASH.test(ptauSha256) || !HASH.test(initialZkeySha256)) {
    fail('external contribution chain identity is invalid');
  }
  if (!Number.isSafeInteger(minimumParticipants)
    || minimumParticipants < minimumParticipantFloor) {
    fail(minimumParticipantFloor === 2
      ? 'minimumParticipants must be at least two'
      : 'minimumParticipants must be a positive safe integer');
  }
  if (!Array.isArray(receipts)
    || receipts.length < minimumParticipants
    || (maximumParticipants !== undefined && receipts.length > maximumParticipants)) {
    fail(receiptCountError);
  }
  const participantKeys = new Set();
  const participantIds = new Set();
  let previous = initialZkeySha256;
  receipts.forEach((receipt, index) => {
    receiptVerifier(receipt);
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
  return Object.freeze({
    ceremonyId,
    outputZkeySha256: previous,
    initialZkeySha256,
    ptauSha256,
    r1csSha256,
    receipts,
  });
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
  const chain = verifyContributionChain({
    ceremonyId,
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    receipts,
  }, {
    minimumParticipants,
    minimumParticipantFloor: 2,
    receiptVerifier: (receipt) => verifyReceipt(receipt, {
      domain: DOMAIN,
      receiptSchema: EXTERNAL_RECEIPT_SCHEMA,
      requestSchema: EXTERNAL_REQUEST_SCHEMA,
    }),
  });
  const transcriptBody = {
    schema: 'shieldkit/external-contribution-transcript/v1',
    mode: 'external-contribution-transcript',
    ceremonyId: chain.ceremonyId,
    r1csSha256: chain.r1csSha256,
    ptauSha256: chain.ptauSha256,
    initialZkeySha256: chain.initialZkeySha256,
    finalZkeySha256: chain.outputZkeySha256,
    qualification: 'transcript-integrity-only; participant independence requires external governance evidence',
    receipts: chain.receipts,
  };
  return Object.freeze({
    ...transcriptBody,
    transcriptSha256: sha256(Buffer.from(canonicalJson(transcriptBody), 'utf8')),
  });
}

/**
 * BETA-only external receipt record. Exactly one signed contribution is useful
 * for bounded interoperability work, but cannot qualify a final key, D-01,
 * production, or release.
 */
export function verifyBetaSingleContributorExternalReceiptChain({
  ceremonyId,
  r1csSha256,
  ptauSha256,
  initialZkeySha256,
  receipts,
}) {
  const chain = verifyContributionChain({
    ceremonyId,
    r1csSha256,
    ptauSha256,
    initialZkeySha256,
    receipts,
  }, {
    minimumParticipants: 1,
    maximumParticipants: 1,
    receiptCountError: 'beta single-contributor ceremony requires exactly one signed external receipt',
    receiptVerifier: (receipt) => verifyReceipt(receipt, {
      domain: BETA_DOMAIN,
      receiptSchema: V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_RECEIPT_SCHEMA,
      requestSchema: V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA,
      exact: true,
    }),
  });
  const transcriptBody = {
    schema: V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_TRANSCRIPT_SCHEMA,
    profile: BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
    status: 'beta-single-contributor-unqualified',
    ceremonyId: chain.ceremonyId,
    r1csSha256: chain.r1csSha256,
    ptauSha256: chain.ptauSha256,
    initialZkeySha256: chain.initialZkeySha256,
    betaProvingKeySha256: chain.outputZkeySha256,
    contributorCount: 1,
    receipts: chain.receipts,
  };
  return Object.freeze({
    ...transcriptBody,
    transcriptSha256: sha256(Buffer.from(canonicalJson(transcriptBody), 'utf8')),
  });
}
