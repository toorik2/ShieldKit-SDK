/*
 * Q-08 action-lane replay.
 *
 * A clean-host action is accepted only when the exact raw transaction is
 * independently replayed by the pinned local Libauth evaluator and by every
 * manifest-authenticated external authority: maintainer verifier-bench,
 * BCHN mempool policy, BCHN mined inclusion, and LeanBCH.
 */
import {
  lstatSync,
  realpathSync,
} from 'node:fs';
import {
  isAbsolute,
  resolve,
} from 'node:path';

import {
  inspectV2LocalVmEvidence,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
} from '../packages/recover/raw-chain-recovery.mjs';
import {
  createV2LaneEvidencePrimitives,
} from './v2-lane-evidence-primitives.mjs';
import {
  verifyV2Q02AuthorityLaneEvidence,
} from './v2-q02-lane-evidence.mjs';

const HASH = /^[0-9a-f]{64}$/u;
const HEX = /^[0-9a-f]+$/u;
const ACTION_BY_STEP = Object.freeze({
  deposit: 'deposit',
  recoveredSpend: 'withdraw',
  transfer: 'transfer',
  withdraw: 'withdraw',
});

export const V2_Q08_ACTION_SUBJECT_SCHEMA =
  'shieldkit-v2-direct-q08-action-subject-v1';
export const V2_Q08_LANE_ENVELOPE_SCHEMA =
  'shieldkit-v2-direct-q08-lane-envelope-v1';
export const V2_Q08_LANE_ATTESTATION_DOMAIN =
  'shieldkit-v2-direct-q08-lane-attestation';
export const V2_Q08_LANE_ATTESTATION_VERSION = 1;
export const V2_Q08_LANE_DERIVATION_SCHEMA =
  'shieldkit-v2-direct-q08-lane-derivation-v1';
export const V2_Q08_MACHINE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-q08-machine-manifest-v1';
export const V2_Q08_VM_INPUT_SCHEMA =
  'shieldkit-v2-direct-q08-vm-run-input-v1';
export const V2_Q08_VM_OUTPUT_SCHEMA =
  'shieldkit-v2-direct-q08-per-input-run-v1';
export const V2_Q08_BCHN_MINED_INPUT_SCHEMA =
  'shieldkit-v2-direct-q08-bchn-mined-input-v1';
export const V2_Q08_BCHN_MINED_OUTPUT_SCHEMA =
  'shieldkit-v2-direct-q08-bchn-mined-result-v1';

export class V2Q08LaneEvidenceError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q08LaneEvidenceError';
  }
}

const fail = (message) => {
  throw new V2Q08LaneEvidenceError(message);
};

const {
  exact,
  hash,
  integer,
  relativeReference,
  sha256,
} = createV2LaneEvidencePrimitives({
  canonicalizeJcs,
  fail,
  parseRawTransaction: parseV2RawTransaction,
  parseSerializedSourceOutput,
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
});

function directEvidenceRoot(value) {
  if (
    typeof value !== 'string'
    || !isAbsolute(value)
    || resolve(value) !== value
  ) {
    fail('Q-08 lane evidence root must be an absolute normalized path');
  }
  const entry = lstatSync(value, { throwIfNoEntry: false });
  if (
    entry === undefined
    || !entry.isDirectory()
    || entry.isSymbolicLink()
    || realpathSync(value) !== value
  ) {
    fail('Q-08 lane evidence root must be one direct canonical directory');
  }
  return value;
}

function expectedAction(value) {
  exact(value, [
    'action',
    'carrierCount',
    'instanceId',
    'journeyStep',
    'profileId',
    'profileSha256',
    'rawTransactionHex',
    'spentNoteId',
    'transactionId',
  ], 'Q-08 expected action');
  if (
    !Object.hasOwn(ACTION_BY_STEP, value.journeyStep)
    || value.action !== ACTION_BY_STEP[value.journeyStep]
  ) {
    fail('Q-08 journey step and action are inconsistent');
  }
  hash(value.profileId, 'Q-08 expected action.profileId');
  hash(value.profileSha256, 'Q-08 expected action.profileSha256');
  hash(value.instanceId, 'Q-08 expected action.instanceId');
  hash(value.transactionId, 'Q-08 expected action.transactionId');
  integer(value.carrierCount, 1, 255, 'Q-08 expected action.carrierCount');
  if (
    typeof value.rawTransactionHex !== 'string'
    || value.rawTransactionHex.length === 0
    || value.rawTransactionHex.length % 2 !== 0
    || !HEX.test(value.rawTransactionHex)
  ) {
    fail('Q-08 expected action raw transaction must be lowercase even-length hex');
  }
  if (
    (value.journeyStep === 'recoveredSpend'
      && (typeof value.spentNoteId !== 'string'
        || !HASH.test(value.spentNoteId)))
    || (value.journeyStep !== 'recoveredSpend'
      && value.spentNoteId !== null)
  ) {
    fail('Q-08 expected action recovered-note binding is invalid');
  }
  let transaction;
  try {
    transaction = parseV2RawTransaction(value.rawTransactionHex);
  } catch (error) {
    fail(
      `Q-08 expected action transaction is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (transaction.txid !== value.transactionId) {
    fail('Q-08 expected action transaction ID does not bind its raw bytes');
  }
  return Object.freeze({
    ...value,
    rawTransactionSha256: sha256(transaction.bytes),
  });
}

function actionSubject(expected) {
  return Object.freeze({
    schema: V2_Q08_ACTION_SUBJECT_SCHEMA,
    action: expected.action,
    journeyStep: expected.journeyStep,
    rawTransactionSha256: expected.rawTransactionSha256,
    transactionId: expected.transactionId,
    spentNoteId: expected.spentNoteId,
  });
}

function verifyExternal({
  authorityContext,
  evidenceRoot,
  expected,
  reference,
  role,
  subject,
}) {
  const artifact = relativeReference(
    reference,
    evidenceRoot,
    `Q-08 ${role} lane envelope`,
  );
  const derived = verifyV2Q02AuthorityLaneEvidence({
    attestationDomain: V2_Q08_LANE_ATTESTATION_DOMAIN,
    attestationVersion: V2_Q08_LANE_ATTESTATION_VERSION,
    authorityContext,
    bchnMinedInputSchema: V2_Q08_BCHN_MINED_INPUT_SCHEMA,
    bchnMinedOutputSchema: V2_Q08_BCHN_MINED_OUTPUT_SCHEMA,
    envelopePath: artifact.filename,
    envelopeSchema: V2_Q08_LANE_ENVELOPE_SCHEMA,
    expectedRole: role,
    expectedSubject: subject,
    expectedTransaction: {
      expectation: 'accept',
      rawTransactionSha256: expected.rawTransactionSha256,
      transactionId: expected.transactionId,
    },
    machineManifestSchema: V2_Q08_MACHINE_MANIFEST_SCHEMA,
    subjectField: 'subject',
    vmInputSchema: V2_Q08_VM_INPUT_SCHEMA,
    vmOutputSchema: V2_Q08_VM_OUTPUT_SCHEMA,
  });
  if (
    derived.derivedOutcome !== 'accepted'
    || derived.envelopeSha256 !== artifact.sha256
  ) {
    fail(`Q-08 ${role} lane did not derive exact transaction acceptance`);
  }
  return derived;
}

function evidenceReference(value, label) {
  exact(value, ['path', 'sha256'], label);
  hash(value.sha256, `${label}.sha256`);
  if (
    typeof value.path !== 'string'
    || value.path.length === 0
    || isAbsolute(value.path)
    || value.path.split(/[\\/]/u).includes('..')
  ) {
    fail(`${label}.path must be a safe relative path`);
  }
  return Object.freeze({
    path: value.path,
    sha256: value.sha256,
  });
}

export function normalizeV2Q08LaneEvidenceReferences(value) {
  exact(value, [
    'bchn',
    'leanbch',
    'libauth',
    'maintainer',
  ], 'Q-08 action lane evidence');
  exact(value.bchn, ['mempool', 'mined'], 'Q-08 BCHN lane evidence');
  return Object.freeze({
    bchn: Object.freeze({
      mempool: evidenceReference(
        value.bchn.mempool,
        'Q-08 BCHN mempool evidence reference',
      ),
      mined: evidenceReference(
        value.bchn.mined,
        'Q-08 BCHN mined evidence reference',
      ),
    }),
    leanbch: evidenceReference(
      value.leanbch,
      'Q-08 LeanBCH evidence reference',
    ),
    libauth: evidenceReference(
      value.libauth,
      'Q-08 local Libauth evidence reference',
    ),
    maintainer: evidenceReference(
      value.maintainer,
      'Q-08 maintainer evidence reference',
    ),
  });
}

/**
 * Derive acceptance for one exact clean-host action. The returned value is an
 * evidence summary only; Q-08 qualification still requires the independently
 * signed host transcript pair.
 */
export function verifyV2Q08ActionLaneEvidence({
  authorityContext,
  evidenceRoot,
  expected: value,
  laneEvidence,
}) {
  const root = directEvidenceRoot(evidenceRoot);
  const expected = expectedAction(value);
  const references = normalizeV2Q08LaneEvidenceReferences(laneEvidence);

  const localArtifact = relativeReference(
    references.libauth,
    root,
    'Q-08 local Libauth VM evidence',
  );
  let local;
  try {
    local = inspectV2LocalVmEvidence(localArtifact.bytes);
  } catch (error) {
    fail(
      `Q-08 local Libauth VM evidence is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    local.transaction.rawTransactionHex !== expected.rawTransactionHex
    || local.transaction.txid !== expected.transactionId
    || local.instanceId !== expected.instanceId
    || local.carrierCount !== expected.carrierCount
    || local.tool.profileId !== expected.profileId
    || local.tool.profileSha256 !== expected.profileSha256
    || local.allInputsAccepted !== true
  ) {
    fail(
      'Q-08 local Libauth evidence does not bind the exact action, instance, carrier count, and profile',
    );
  }

  const subject = actionSubject(expected);
  const external = Object.freeze({
    maintainer: verifyExternal({
      authorityContext,
      evidenceRoot: root,
      expected,
      reference: references.maintainer,
      role: 'maintainer',
      subject,
    }),
    bchnMempool: verifyExternal({
      authorityContext,
      evidenceRoot: root,
      expected,
      reference: references.bchn.mempool,
      role: 'bchn-mempool',
      subject,
    }),
    bchnMined: verifyExternal({
      authorityContext,
      evidenceRoot: root,
      expected,
      reference: references.bchn.mined,
      role: 'bchn-mined',
      subject,
    }),
    leanbch: verifyExternal({
      authorityContext,
      evidenceRoot: root,
      expected,
      reference: references.leanbch,
      role: 'leanbch',
      subject,
    }),
  });
  const runIds = Object.values(external).map((entry) => entry.runId);
  if (new Set(runIds).size !== runIds.length) {
    fail('Q-08 external lane evidence must contain four distinct signed runs');
  }
  return Object.freeze({
    schema: V2_Q08_LANE_DERIVATION_SCHEMA,
    accepted: true,
    rawTransactionSha256: expected.rawTransactionSha256,
    transactionId: expected.transactionId,
    localVmEvidenceSha256: localArtifact.sha256,
    externalEnvelopeSha256: Object.freeze({
      maintainer: external.maintainer.envelopeSha256,
      bchnMempool: external.bchnMempool.envelopeSha256,
      bchnMined: external.bchnMined.envelopeSha256,
      leanbch: external.leanbch.envelopeSha256,
    }),
  });
}
