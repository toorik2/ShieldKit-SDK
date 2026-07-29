import { createHash } from 'node:crypto';

import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';

const HEX_32 = /^[0-9a-f]{64}$/;
const ACTION_KINDS = new Set(['deposit', 'transfer', 'withdrawal']);
const OUTPUT_WITNESS_FIELDS = Object.freeze([
  'authority',
  'ephemeralScalar',
  'incomingViewPublicKey',
  'r',
  'rho',
  'rhoBlind',
  'spendPublicKey',
]);

export class V2PrivateActionCommitmentError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2PrivateActionCommitmentError';
    this.code = code;
  }
}

const fail = (message) => {
  throw new V2PrivateActionCommitmentError(
    'PRIVATE_ACTION_MISMATCH',
    message,
  );
};

function exact(value, fields, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be lowercase 32-byte hexadecimal`);
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(canonicalizeJcs(value), 'utf8');
}

/**
 * Commit to all private/public action material that may influence proving.
 * Operation identity and expected sequence are separately committed by the
 * private record and SQLite operation row.
 */
export function commitV2PrivateActionMaterial(value) {
  exact(
    value,
    ['kind', 'output', 'publicNullifier'],
    'private action material',
  );
  const { kind, output, publicNullifier } = value;
  if (!ACTION_KINDS.has(kind)) {
    fail(
      'private action material kind must be deposit, transfer, or withdrawal',
    );
  }
  const outputActive = kind === 'deposit' || kind === 'transfer';
  const spendActive = kind === 'transfer' || kind === 'withdrawal';
  if ((outputActive && output === null) || (!outputActive && output !== null)) {
    fail(`${kind} output construction presence is invalid`);
  }
  if (
    (spendActive && !HEX_32.test(publicNullifier))
    || (!spendActive && publicNullifier !== null)
  ) {
    fail(`${kind} public nullifier presence is invalid`);
  }
  let outputMaterial = null;
  if (output !== null) {
    exact(output, ['public', 'witness'], 'private output construction');
    exact(
      output.public,
      ['encryptedRecord', 'noteCommitment', 'outputNoteLeaf'],
      'private output construction.public',
    );
    exact(
      output.witness,
      OUTPUT_WITNESS_FIELDS,
      'private output construction.witness',
    );
    if (
      !(output.public.encryptedRecord instanceof Uint8Array)
      || output.public.encryptedRecord.length !== 128
    ) {
      fail('private output encryptedRecord must contain exactly 128 bytes');
    }
    for (const [name, entry] of Object.entries({
      noteCommitment: output.public.noteCommitment,
      outputNoteLeaf: output.public.outputNoteLeaf,
      ...output.witness,
    })) {
      hex32(entry, `private output construction ${name}`);
    }
    outputMaterial = {
      public: {
        noteCommitment: output.public.noteCommitment,
        outputNoteLeaf: output.public.outputNoteLeaf,
        encryptedRecordHex:
          Buffer.from(output.public.encryptedRecord).toString('hex'),
      },
      witness: { ...output.witness },
    };
  }
  const core = {
    schema: 'shieldkit-v2-private-action-commitment-v1',
    kind,
    output: outputMaterial,
    publicNullifier,
  };
  const bytes = canonicalBytes(core);
  return Object.freeze({
    bytes,
    sha256: createHash('sha256').update(bytes).digest(),
  });
}
