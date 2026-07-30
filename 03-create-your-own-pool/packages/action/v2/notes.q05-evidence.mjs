#!/usr/bin/env node
// Local-only Q-05 negative corpus. This intentionally emits counts and limits,
// never private scalars, witnesses, records, or ciphertext bytes.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { BABYJUB_SUBGROUP_ORDER } from '../../recover/portable-core.mjs';

import {
  decodeDirectV2Address,
  encodeDirectV2Address,
} from './address.mjs';
import { BN254_SCALAR_FIELD_MODULUS } from './domains.mjs';
import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
} from './notes.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const profileId = '11'.repeat(32);
const instanceId = '22'.repeat(32);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const checkLabels = [];
const checks = Object.create(null);

function checked(category, label, action) {
  action();
  checkLabels.push(`${category}:${label}`);
  checks[category] = (checks[category] ?? 0) + 1;
}

function canarySecret(label) {
  // Keep the sentinel-derived scalar in memory only. Its bytes are never
  // serialized by this script or placed in its report.
  const digest = createHash('sha256').update(`ShieldKit/V2/Q-05/${label}`).digest();
  const value = Buffer.alloc(32);
  digest.copy(value, 16, 16);
  digest.fill(0);
  const encoded = value.toString('hex');
  value.fill(0);
  return encoded;
}

function fixedRng(values = [5n, 6n, 7n]) {
  const remaining = [...values];
  return Object.freeze({
    bytes(length) {
      assert.equal(length, 32);
      if (remaining.length === 0) throw new Error('deterministic source exhausted');
      return Uint8Array.from(Buffer.from(fr(remaining.shift()), 'hex'));
    },
  });
}

function rejects(action, label) {
  // Field parsing can fail before the note API wraps an error; all corpus
  // cases must still reject without emitting the supplied input.
  assert.throws(action, Error, label);
}

const spendSecret = canarySecret('spend');
const incomingViewSecret = canarySecret('incoming-view');
const address = deriveDirectV2Address({
  networkId: 2,
  profileId,
  instanceId,
  spendSecret,
  incomingViewSecret,
});
const account = Object.freeze({ address, spendSecret, incomingViewSecret });
const output = constructDirectV2Output({
  address,
  postActionSequence: '1',
  rng: fixedRng(),
});
checked('canonicalNonzeroSecretCases', 'derive-valid-address', () => {
  assert.equal(address.spendPublicKey.length, 64);
  assert.equal(address.incomingViewPublicKey.length, 64);
});

for (const [label, secret] of [
  ['zero', fr(0)],
  ['babyjub-subgroup-order', fr(BABYJUB_SUBGROUP_ORDER)],
  ['bn254-scalar-field-modulus', fr(BN254_SCALAR_FIELD_MODULUS)],
]) {
  checked('invalidSpendSecretCases', label, () => rejects(() => deriveDirectV2Address({
      networkId: 2,
      profileId,
      instanceId,
      spendSecret: secret,
      incomingViewSecret,
    }), 'invalid spend secret'));
}

for (const [label, secret] of [
  ['zero', fr(0)],
  ['babyjub-subgroup-order', fr(BABYJUB_SUBGROUP_ORDER)],
  ['bn254-scalar-field-modulus', fr(BN254_SCALAR_FIELD_MODULUS)],
]) {
  checked('invalidIncomingViewSecretCases', label, () => rejects(() => deriveDirectV2Address({
      networkId: 2,
      profileId,
      instanceId,
      spendSecret,
      incomingViewSecret: secret,
    }), 'invalid incoming-view secret'));
}

for (const [index, point] of [
  Uint8Array.of(1, ...new Uint8Array(31)), new Uint8Array(32),
  Uint8Array.of(2, ...new Uint8Array(31)), Uint8Array.from(Buffer.from(fr(BN254_SCALAR_FIELD_MODULUS), 'hex').reverse()),
].entries()) {
  checked('invalidPointCases', `point-${index}`, () => {
    const encoded = Buffer.from(encodeDirectV2Address(address));
    Buffer.from(point).copy(encoded, 72);
    assert.throws(() => decodeDirectV2Address(encoded), /invalid|point|authority/);
  });
}

for (const length of [0, 1, 127, 129]) {
  checked('malformedRecordLengthCases', `length-${length}`, () => rejects(() => recoverDirectV2Output({
      account, outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: new Uint8Array(length),
    }), 'malformed record length'));
}

for (const offset of [32, 64, 96]) {
  checked('invalidRecordFieldCases', `field-${offset}`, () => {
    const malformed = new Uint8Array(output.public.encryptedRecord);
    malformed.fill(0xff, offset, offset + 32);
    rejects(() => recoverDirectV2Output({ account, outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: malformed }), 'noncanonical record field');
  });
}

for (let offset = 0; offset < output.public.encryptedRecord.length; offset += 1) {
  checked('authenticatedRecordByteMutations', `byte-${offset}`, () => {
    const malformed = new Uint8Array(output.public.encryptedRecord);
    malformed[offset] ^= 1;
    rejects(() => recoverDirectV2Output({ account, outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: malformed }), `authenticated byte ${offset}`);
  });
}

const foreignSpendSecret = canarySecret('foreign-spend');
const foreignIncomingViewSecret = canarySecret('foreign-incoming-view');
const foreignAddress = deriveDirectV2Address({
  networkId: 2,
  profileId,
  instanceId,
  spendSecret: foreignSpendSecret,
  incomingViewSecret: foreignIncomingViewSecret,
});
const foreignOutput = constructDirectV2Output({
  address: foreignAddress,
  postActionSequence: '1',
  rng: fixedRng(),
});
checked('wrongRecipientCases', 'foreign-address-output', () => rejects(() => recoverDirectV2Output({
    account, outputNoteLeaf: foreignOutput.public.outputNoteLeaf, encryptedRecord: foreignOutput.public.encryptedRecord,
  }), 'wrong recipient'));

const faerie = new Uint8Array(output.public.encryptedRecord);
faerie.fill(0, 0, 32);
checked('zeroEphemeralPointRecordCases', 'zero-ephemeral-point', () => rejects(() => recoverDirectV2Output({
    account, outputNoteLeaf: output.public.outputNoteLeaf, encryptedRecord: faerie,
  }), 'Faerie-style malformed output'));

const reused = constructDirectV2Output({ address, postActionSequence: '1', rng: fixedRng() });
checked('reuseVisibleEqualityChecks', 'note-commitment', () => assert.equal(reused.public.noteCommitment, output.public.noteCommitment));
checked('reuseVisibleEqualityChecks', 'output-leaf', () => assert.equal(reused.public.outputNoteLeaf, output.public.outputNoteLeaf));
checked('reuseVisibleEqualityChecks', 'encrypted-record', () => assert.deepEqual(reused.public.encryptedRecord, output.public.encryptedRecord));

const report = {
  schema: 'shieldkit-v2-q05-crypto-safety-report/v3',
  deterministic: true,
  scope: 'local JS address/note/record negative corpus',
  totalChecks: 0,
  passed: checks,
  transcript: { format: 'shieldkit-v2-q05-executed-check-labels/v1', labels: checkLabels, sha256: '' },
  limits: [
    'local deterministic test evidence only; not an independent audit',
    'no global spent-randomness registry exists at this address/note API boundary',
    'reuse is detectable here only when identical public outputs are compared',
    'the serialized JSON report intentionally excludes canary scalar strings, witnesses, and ciphertext bytes',
    'the serialized-JSON canary check does not establish process-memory zeroization or general stdout/stderr non-emission',
    'this does not qualify a circuit, profile, transaction, or release',
  ],
};
// Finalize this check before serialization so the assertion covers the exact
// JSON line emitted below, including its final counts and transcript digest.
checkLabels.push('serializedJsonCanaryNonEmissionChecks:report-excludes-secret-canaries');
checks.serializedJsonCanaryNonEmissionChecks = 1;
report.totalChecks = checkLabels.length;
report.transcript.sha256 = digest(JSON.stringify(report.transcript.labels));
const serialized = JSON.stringify(report);
for (const secret of [spendSecret, incomingViewSecret, foreignSpendSecret, foreignIncomingViewSecret]) {
  assert.equal(serialized.includes(secret), false, 'secret canary appeared in serialized JSON report');
}

console.log(serialized);
