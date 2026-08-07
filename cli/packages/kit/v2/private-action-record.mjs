import { createHash } from 'node:crypto';

import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';
import {
  commitV2PrivateActionMaterial,
} from './private-action-commitment.mjs';

export const V2_PRIVATE_ACTION_RECORD_SCHEMA =
  'shieldkit-v2-private-action-record-v1';

const OPERATION_ID = /^v2op:[0-9a-f]{64}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{256}$/;
const ACTION_KINDS = new Set(['deposit', 'transfer', 'withdrawal']);
const MAX_RECORD_BYTES = 16 * 1024;
const OUTPUT_WITNESS_FIELDS = Object.freeze([
  'authority',
  'ephemeralScalar',
  'incomingViewPublicKey',
  'r',
  'rho',
  'rhoBlind',
  'spendPublicKey',
]);

export class V2PrivateActionRecordError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2PrivateActionRecordError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2PrivateActionRecordError(code, message, options);
};

function exact(value, fields, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('PRIVATE_ACTION_RECORD_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalBytes(value) {
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

function safeActionSequence(value, label) {
  if (
    !Number.isSafeInteger(value)
    || value < 0
    || value > 0x1_ffff_ffff
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `${label} must be a supported nonnegative action sequence`,
    );
  }
  return value;
}

function canonicalOutput(output) {
  if (output === null) return null;
  exact(output, ['public', 'witness'], 'private action output');
  exact(
    output.public,
    ['encryptedRecord', 'noteCommitment', 'outputNoteLeaf'],
    'private action output.public',
  );
  exact(
    output.witness,
    OUTPUT_WITNESS_FIELDS,
    'private action output.witness',
  );
  if (
    !(output.public.encryptedRecord instanceof Uint8Array)
    || output.public.encryptedRecord.length !== 128
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      'private action encrypted record must contain exactly 128 bytes',
    );
  }
  for (const [field, value] of Object.entries({
    noteCommitment: output.public.noteCommitment,
    outputNoteLeaf: output.public.outputNoteLeaf,
    ...output.witness,
  })) {
    if (typeof value !== 'string' || !HEX_32.test(value)) {
      fail(
        'PRIVATE_ACTION_RECORD_INVALID',
        `private action ${field} must be 32-byte lowercase hexadecimal`,
      );
    }
  }
  return Object.freeze({
    public: Object.freeze({
      encryptedRecordHex:
        Buffer.from(output.public.encryptedRecord).toString('hex'),
      noteCommitment: output.public.noteCommitment,
      outputNoteLeaf: output.public.outputNoteLeaf,
    }),
    witness: Object.freeze({ ...output.witness }),
  });
}

function runtimeOutput(output) {
  if (output === null) return null;
  exact(output, ['public', 'witness'], 'private action record output');
  exact(
    output.public,
    ['encryptedRecordHex', 'noteCommitment', 'outputNoteLeaf'],
    'private action record output.public',
  );
  exact(
    output.witness,
    OUTPUT_WITNESS_FIELDS,
    'private action record output.witness',
  );
  if (
    typeof output.public.encryptedRecordHex !== 'string'
    || !HEX_128.test(output.public.encryptedRecordHex)
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      'private action record encryptedRecordHex must encode exactly 128 bytes',
    );
  }
  const candidate = {
    public: {
      encryptedRecord:
        Buffer.from(output.public.encryptedRecordHex, 'hex'),
      noteCommitment: output.public.noteCommitment,
      outputNoteLeaf: output.public.outputNoteLeaf,
    },
    witness: { ...output.witness },
  };
  // Use the same strict field and hexadecimal validation as newly generated
  // runtime material before passing this object to the lifecycle.
  canonicalOutput(candidate);
  return Object.freeze({
    public: Object.freeze(candidate.public),
    witness: Object.freeze(candidate.witness),
  });
}

function operationIdentity(value, label) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `${label} must be a canonical V2 operation ID`,
    );
  }
  return value;
}

function actionKind(value, label) {
  if (typeof value !== 'string' || !ACTION_KINDS.has(value)) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `${label} must be deposit, transfer, or withdrawal`,
    );
  }
  return value;
}

function expectedCommitment(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `${label} must be 32-byte lowercase hexadecimal`,
    );
  }
  return value;
}

/**
 * Encode the only private material required to resume proving. The caller must
 * publish these bytes as a new 0600 file before atomically preparing the
 * corresponding store operation.
 */
export function encodeV2PrivateActionRecord(value) {
  exact(
    value,
    [
      'expectedActionSequence',
      'kind',
      'operationId',
      'output',
      'publicNullifier',
    ],
    'private action record input',
  );
  const operationId = operationIdentity(value.operationId, 'operationId');
  const expectedActionSequence = safeActionSequence(
    value.expectedActionSequence,
    'expectedActionSequence',
  );
  const kind = actionKind(value.kind, 'kind');
  const output = canonicalOutput(value.output);
  let commitment;
  try {
    commitment = commitV2PrivateActionMaterial({
      kind,
      output: value.output,
      publicNullifier: value.publicNullifier,
    });
  } catch (error) {
    fail(
      error?.code ?? 'PRIVATE_ACTION_RECORD_INVALID',
      error instanceof Error
        ? error.message
        : 'private action commitment failed',
      { cause: error },
    );
  }
  const core = {
    schema: V2_PRIVATE_ACTION_RECORD_SCHEMA,
    operationId,
    expectedActionSequence,
    kind,
    output,
    publicNullifier: value.publicNullifier,
    actionMaterialSha256: commitment.sha256.toString('hex'),
  };
  const record = Object.freeze({
    ...core,
    recordSha256: sha256(canonicalBytes(core)),
  });
  return Object.freeze({
    actionMaterialSha256: Buffer.from(commitment.sha256),
    bytes: canonicalBytes(record),
    record,
  });
}

/**
 * Decode canonical private material and bind it to one exact durable
 * operation. A record from another operation or pre-state is never reusable.
 */
export function decodeV2PrivateActionRecord(bytesValue, expected) {
  if (
    !(bytesValue instanceof Uint8Array)
    || bytesValue.length === 0
    || bytesValue.length > MAX_RECORD_BYTES
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      `private action record must contain 1-${MAX_RECORD_BYTES} bytes`,
    );
  }
  exact(
    expected,
    [
      'actionMaterialSha256',
      'expectedActionSequence',
      'kind',
      'operationId',
    ],
    'private action record expectation',
  );
  const expectedOperationId = operationIdentity(
    expected.operationId,
    'expected operationId',
  );
  const expectedSequence = safeActionSequence(
    expected.expectedActionSequence,
    'expected expectedActionSequence',
  );
  const expectedKind = actionKind(expected.kind, 'expected kind');
  const expectedActionMaterialSha256 = expectedCommitment(
    expected.actionMaterialSha256,
    'expected actionMaterialSha256',
  );
  const bytes = Buffer.from(bytesValue);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      'private action record is not valid JSON',
      { cause: error },
    );
  }
  exact(
    parsed,
    [
      'actionMaterialSha256',
      'expectedActionSequence',
      'kind',
      'operationId',
      'output',
      'publicNullifier',
      'recordSha256',
      'schema',
    ],
    'private action record',
  );
  const { recordSha256, ...core } = parsed;
  if (
    parsed.schema !== V2_PRIVATE_ACTION_RECORD_SCHEMA
    || !HEX_32.test(recordSha256)
    || sha256(canonicalBytes(core)) !== recordSha256
    || !bytes.equals(canonicalBytes(parsed))
    || parsed.operationId !== expectedOperationId
    || parsed.expectedActionSequence !== expectedSequence
    || parsed.kind !== expectedKind
    || parsed.actionMaterialSha256 !== expectedActionMaterialSha256
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_MISMATCH',
      'private action record identity, canonical bytes, or durable binding differs',
    );
  }
  const output = runtimeOutput(parsed.output);
  let commitment;
  try {
    commitment = commitV2PrivateActionMaterial({
      kind: parsed.kind,
      output,
      publicNullifier: parsed.publicNullifier,
    });
  } catch (error) {
    fail(
      error?.code ?? 'PRIVATE_ACTION_RECORD_INVALID',
      error instanceof Error
        ? error.message
        : 'private action commitment failed',
      { cause: error },
    );
  }
  if (commitment.sha256.toString('hex') !== expectedActionMaterialSha256) {
    fail(
      'PRIVATE_ACTION_RECORD_MISMATCH',
      'private action material does not match its durable commitment',
    );
  }
  return Object.freeze({
    actionMaterialSha256: Buffer.from(commitment.sha256),
    expectedActionSequence: parsed.expectedActionSequence,
    kind: parsed.kind,
    operationId: parsed.operationId,
    output,
    publicNullifier: parsed.publicNullifier,
    recordSha256,
  });
}
