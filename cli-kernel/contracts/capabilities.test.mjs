import assert from 'node:assert/strict';
import test from 'node:test';

import {
  MUTATION_SAFETY_GUARANTEES,
  buildCapabilityRecord,
  isMutationAllowed,
  mutationBlockReason,
} from './capabilities.mjs';

const profileId = '11'.repeat(32);
const evidence = `sha256:${'22'.repeat(32)}`;

function admittedRecord({ overall = 'qualified', verbStatus = 'qualified', blockers = [] } = {}) {
  const guarantees = Object.fromEntries(MUTATION_SAFETY_GUARANTEES.map((key) => [key, {
    status: 'qualified',
    evidence: [evidence],
  }]));
  guarantees.deposit = { status: verbStatus, evidence: verbStatus === 'qualified' ? [evidence] : [] };
  return buildCapabilityRecord({
    designId: 'test-design',
    profileId,
    profileStatus: 'frozen',
    network: 'bch-chipnet',
    overall,
    guarantees,
    blockers,
  });
}

test('design-family records never authorize mutation, even with Lab acknowledgement', () => {
  const record = buildCapabilityRecord({
    designId: 'unfrozen-design',
    profileId: null,
    profileStatus: 'unfrozen',
    network: 'bch-chipnet',
    overall: 'experimental',
    guarantees: {
      deposit: { status: 'experimental' },
    },
  });
  assert.equal(isMutationAllowed(record, 'deposit', { allowLab: true }), false);
  assert.match(mutationBlockReason(record, 'deposit', { allowLab: true }), /exact frozen profile/);
});

test('mutation requires every safety guarantee to be qualified and evidence-bound', () => {
  const admitted = admittedRecord();
  assert.equal(isMutationAllowed(admitted, 'deposit'), true);
  assert.equal(mutationBlockReason(admitted, 'deposit'), null);

  const guarantees = { ...admitted.guarantees };
  guarantees.exactReadback = { status: 'experimental', evidence: [], blockers: [] };
  const incomplete = buildCapabilityRecord({
    designId: 'test-design',
    profileId,
    profileStatus: 'frozen',
    network: 'bch-chipnet',
    overall: 'experimental',
    guarantees,
  });
  assert.equal(isMutationAllowed(incomplete, 'deposit', { allowLab: true }), false);
  assert.match(mutationBlockReason(incomplete, 'deposit', { allowLab: true }), /exactReadback/);
});

test('Lab acknowledgement may unlock only the verb, never the safety prerequisites', () => {
  const experimental = admittedRecord({ overall: 'experimental', verbStatus: 'experimental' });
  assert.equal(isMutationAllowed(experimental, 'deposit'), false);
  assert.equal(isMutationAllowed(experimental, 'deposit', { allowLab: true }), true);
});

test('qualified claims reject opaque evidence labels and unresolved blockers', () => {
  assert.throws(() => buildCapabilityRecord({
    designId: 'test-design',
    profileId,
    profileStatus: 'frozen',
    network: 'bch-chipnet',
    guarantees: {
      deposit: { status: 'qualified', evidence: ['looks-good'] },
    },
  }), /sha256/);
  assert.throws(() => admittedRecord({ blockers: ['still blocked'] }), /cannot retain blockers/);
  assert.throws(() => buildCapabilityRecord({
    designId: 'test-design',
    profileId: null,
    profileStatus: 'unfrozen',
    network: 'bch-chipnet',
    guarantees: { madeUpGuarantee: { status: 'blocked' } },
  }), /unknown capability guarantee/);
});
