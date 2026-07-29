import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
} from '../../action/v2/notes.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  decodeV2PrivateActionRecord,
  encodeV2PrivateActionRecord,
  V2PrivateActionRecordError,
} from './private-action-record.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const PROFILE_ID = '11'.repeat(32);
const INSTANCE_ID = '22'.repeat(32);
const PUBLIC_NULLIFIER = '33'.repeat(32);
const SECRET_VALUES = [
  fr(3),
  fr(4),
  fr(5),
  fr(6),
  fr(7),
];

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const actionRecordError = (code) => (error) =>
  error instanceof V2PrivateActionRecordError && error.code === code;

function fixedRng() {
  let next = 5n;
  return {
    bytes(length) {
      assert.equal(length, 32);
      const bytes = Buffer.from(fr(next), 'hex');
      next += 1n;
      return Uint8Array.from(bytes);
    },
  };
}

function realOutput(sequence) {
  const address = deriveDirectV2Address({
    networkId: 2,
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    spendSecret: fr(3),
    incomingViewSecret: fr(4),
  });
  return constructDirectV2Output({
    address,
    postActionSequence: String(sequence + 1),
    rng: fixedRng(),
  });
}

function material(kind, sequence = 41) {
  return {
    operationId: `v2op:${(sequence + 1).toString(16).padStart(64, '0')}`,
    expectedActionSequence: sequence,
    kind,
    output: kind === 'withdrawal' ? null : realOutput(sequence),
    publicNullifier:
      kind === 'deposit' ? null : PUBLIC_NULLIFIER,
  };
}

function mutableMaterial(kind, sequence = 41) {
  const value = material(kind, sequence);
  if (value.output !== null) {
    value.output = {
      public: {
        ...value.output.public,
        encryptedRecord: Uint8Array.from(value.output.public.encryptedRecord),
      },
      witness: { ...value.output.witness },
    };
  }
  return value;
}

function expectation(encoded) {
  return {
    operationId: encoded.record.operationId,
    expectedActionSequence: encoded.record.expectedActionSequence,
    kind: encoded.record.kind,
    actionMaterialSha256: encoded.record.actionMaterialSha256,
  };
}

function cloneRecord(encoded) {
  return JSON.parse(Buffer.from(encoded.bytes).toString('utf8'));
}

function canonicalRecordBytes(record) {
  const { recordSha256: _discarded, ...core } = record;
  return Buffer.from(canonicalizeJcs({
    ...core,
    recordSha256: sha256(Buffer.from(canonicalizeJcs(core), 'utf8')),
  }), 'utf8');
}

function flipHex(value) {
  return `${value[0] === '0' ? '1' : '0'}${value.slice(1)}`;
}

function assertNoSecretLeak(callback, secrets = SECRET_VALUES) {
  assert.throws(callback, (error) => {
    assert(error instanceof V2PrivateActionRecordError);
    const message = String(error.message).toLowerCase();
    for (const secret of secrets) {
      assert(!message.includes(secret), `secret leaked in error: ${secret}`);
    }
    return true;
  });
}

test('private-action records round-trip real deposit, transfer, and withdrawal material with exact canonical bytes', () => {
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const input = material(kind);
    const encoded = encodeV2PrivateActionRecord(input);
    const repeated = encodeV2PrivateActionRecord(input);
    assert.deepEqual(encoded.bytes, repeated.bytes, `${kind} bytes are stable`);
    assert.deepEqual(encoded.record, repeated.record, `${kind} record is stable`);

    const decoded = decodeV2PrivateActionRecord(
      encoded.bytes,
      expectation(encoded),
    );
    assert.deepEqual(decoded.actionMaterialSha256, encoded.actionMaterialSha256);
    assert.equal(decoded.operationId, input.operationId);
    assert.equal(decoded.expectedActionSequence, input.expectedActionSequence);
    assert.equal(decoded.kind, input.kind);
    assert.equal(decoded.publicNullifier, input.publicNullifier);
    if (input.output === null) {
      assert.equal(decoded.output, null);
    } else {
      assert.deepEqual(
        Buffer.from(decoded.output.public.encryptedRecord),
        Buffer.from(input.output.public.encryptedRecord),
      );
      assert.deepEqual(decoded.output.witness, input.output.witness);
    }

    const reencoded = encodeV2PrivateActionRecord({
      operationId: decoded.operationId,
      expectedActionSequence: decoded.expectedActionSequence,
      kind: decoded.kind,
      output: decoded.output,
      publicNullifier: decoded.publicNullifier,
    });
    assert.deepEqual(reencoded.bytes, encoded.bytes, `${kind} decode/re-encode is stable`);
  }
});

test('private-action records bind one operation id, kind, action sequence, and durable material hash', () => {
  const encoded = encodeV2PrivateActionRecord(material('transfer'));
  const expected = expectation(encoded);
  const mutations = [
    ['operationId', { ...expected, operationId: `v2op:${'aa'.repeat(32)}` }],
    ['expectedActionSequence', { ...expected, expectedActionSequence: expected.expectedActionSequence + 1 }],
    ['kind', { ...expected, kind: 'deposit' }],
    ['actionMaterialSha256', { ...expected, actionMaterialSha256: '44'.repeat(32) }],
  ];
  for (const [label, other] of mutations) {
    assert.throws(
      () => decodeV2PrivateActionRecord(encoded.bytes, other),
      actionRecordError('PRIVATE_ACTION_RECORD_MISMATCH'),
      label,
    );
  }
});

test('private-action records reject every real secret and public material mutation after a self-consistent record rehash', () => {
  for (const kind of ['deposit', 'transfer']) {
    const encoded = encodeV2PrivateActionRecord(material(kind));
    const paths = [
      ['output.public.encryptedRecordHex', (record) => record.output.public.encryptedRecordHex],
      ['output.public.noteCommitment', (record) => record.output.public.noteCommitment],
      ['output.public.outputNoteLeaf', (record) => record.output.public.outputNoteLeaf],
      ...Object.keys(encoded.record.output.witness).map((field) => [
        `output.witness.${field}`,
        (record) => record.output.witness[field],
      ]),
    ];
    if (kind === 'transfer') {
      paths.push(['publicNullifier', (record) => record.publicNullifier]);
    }
    for (const [label, select] of paths) {
      const record = cloneRecord(encoded);
      const current = select(record);
      if (label.startsWith('output.public.')) {
        const field = label.slice('output.public.'.length);
        record.output.public[field] = flipHex(current);
      } else if (label.startsWith('output.witness.')) {
        const field = label.slice('output.witness.'.length);
        record.output.witness[field] = flipHex(current);
      } else {
        record.publicNullifier = flipHex(current);
      }
      assert.throws(
        () => decodeV2PrivateActionRecord(canonicalRecordBytes(record), expectation(encoded)),
        actionRecordError('PRIVATE_ACTION_RECORD_MISMATCH'),
        `${kind} ${label}`,
      );
    }
  }

  const withdrawal = encodeV2PrivateActionRecord(material('withdrawal'));
  const record = cloneRecord(withdrawal);
  record.publicNullifier = flipHex(record.publicNullifier);
  assert.throws(
    () => decodeV2PrivateActionRecord(canonicalRecordBytes(record), expectation(withdrawal)),
    actionRecordError('PRIVATE_ACTION_RECORD_MISMATCH'),
  );
});

test('private-action records reject missing and unknown properties at every record shape', () => {
  const input = material('deposit');
  const encoded = encodeV2PrivateActionRecord(input);
  const malformedInputs = [
    { ...input, unexpected: true },
    (() => { const { output, ...rest } = input; return rest; })(),
    { ...input, output: { ...input.output, unexpected: true } },
    { ...input, output: { public: input.output.public } },
    { ...input, output: { ...input.output, public: { ...input.output.public, unexpected: true } } },
    { ...input, output: { ...input.output, witness: { ...input.output.witness, unexpected: true } } },
  ];
  for (const candidate of malformedInputs) {
    assertNoSecretLeak(
      () => encodeV2PrivateActionRecord(candidate),
      Object.values(input.output.witness),
    );
  }

  for (const mutate of [
    (record) => { record.unexpected = true; },
    (record) => { delete record.output; },
    (record) => { record.output.unexpected = true; },
    (record) => { delete record.output.public.noteCommitment; },
    (record) => { record.output.witness.unexpected = true; },
    (record) => { delete record.output.witness.rho; },
  ]) {
    const record = cloneRecord(encoded);
    mutate(record);
    assertNoSecretLeak(
      () => decodeV2PrivateActionRecord(
        canonicalRecordBytes(record),
        expectation(encoded),
      ),
      Object.values(input.output.witness),
    );
  }
});

test('private-action records reject wrong lengths and uppercase hexadecimal without exposing secrets', () => {
  const input = material('transfer');
  const encoded = encodeV2PrivateActionRecord(input);
  const publicAndSecretFields = [
    ['public', 'noteCommitment'],
    ['public', 'outputNoteLeaf'],
    ...Object.keys(input.output.witness).map((field) => ['witness', field]),
  ];
  for (const [section, field] of publicAndSecretFields) {
    const short = mutableMaterial('transfer');
    short.output[section][field] = short.output[section][field].slice(0, -2);
    assertNoSecretLeak(
      () => encodeV2PrivateActionRecord(short),
      Object.values(input.output.witness),
    );

    const upper = mutableMaterial('transfer');
    upper.output[section][field] = `A${upper.output[section][field].slice(1)}`;
    assertNoSecretLeak(
      () => encodeV2PrivateActionRecord(upper),
      Object.values(input.output.witness),
    );
  }
  const shortRecord = cloneRecord(encoded);
  shortRecord.output.public.encryptedRecordHex =
    shortRecord.output.public.encryptedRecordHex.slice(0, -2);
  assertNoSecretLeak(
    () => decodeV2PrivateActionRecord(
      canonicalRecordBytes(shortRecord),
      expectation(encoded),
    ),
    Object.values(input.output.witness),
  );
  const uppercaseRecord = cloneRecord(encoded);
  uppercaseRecord.output.public.encryptedRecordHex =
    `A${uppercaseRecord.output.public.encryptedRecordHex.slice(1)}`;
  assertNoSecretLeak(
    () => decodeV2PrivateActionRecord(
      canonicalRecordBytes(uppercaseRecord),
      expectation(encoded),
    ),
    Object.values(input.output.witness),
  );

  assertNoSecretLeak(() => encodeV2PrivateActionRecord({
    ...input,
    operationId: `v2op:${'A'.repeat(64)}`,
  }));
  assertNoSecretLeak(() => decodeV2PrivateActionRecord(encoded.bytes, {
    ...expectation(encoded),
    actionMaterialSha256: 'A'.repeat(64),
  }));
});

test('private-action records reject malformed or noncanonical JSON without leaking secret material', () => {
  const encoded = encodeV2PrivateActionRecord(material('deposit'));
  const canonical = Buffer.from(encoded.bytes).toString('utf8');
  const reordered = JSON.stringify({
    recordSha256: encoded.record.recordSha256,
    schema: encoded.record.schema,
    publicNullifier: encoded.record.publicNullifier,
    output: encoded.record.output,
    actionMaterialSha256: encoded.record.actionMaterialSha256,
    kind: encoded.record.kind,
    expectedActionSequence: encoded.record.expectedActionSequence,
    operationId: encoded.record.operationId,
  });
  const candidates = [
    Buffer.from('{not-json', 'utf8'),
    Buffer.from(` ${canonical}`, 'utf8'),
    Buffer.from(reordered, 'utf8'),
    Buffer.from(`{\"operationId\":\"${encoded.record.operationId}\",\"operationId\":\"${encoded.record.operationId}\"}`, 'utf8'),
    Buffer.alloc(16 * 1024 + 1),
  ];
  for (const bytes of candidates) {
    assertNoSecretLeak(
      () => decodeV2PrivateActionRecord(bytes, expectation(encoded)),
      Object.values(encoded.record.output.witness),
    );
  }
});
