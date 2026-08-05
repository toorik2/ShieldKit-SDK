import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  assertV2Pf10InstanceSpecializationByteEquality,
  compareV2Pf10InstanceSpecializationRuntimes,
  snapshotV2Pf10InstanceSpecializationRuntime,
  V2Pf10InstanceSpecializationSpikeError,
  V2_PF10_INSTANCE_SPECIALIZATION_SPIKE_SCHEMA,
} from './pf10-instance-specialization-spike.mjs';

const hash = (label) => createHash('sha256').update(label).digest('hex');
const bytes = (label) => Buffer.from(hash(label), 'hex');
const program = (label) => Object.freeze({
  hashes: Object.freeze({
    source: hash(`${label}:source`),
    raw: hash(`${label}:raw`),
    redeem: hash(`${label}:redeem`),
    lock: hash(`${label}:lock`),
  }),
});

function runtime(instanceId) {
  const changed = (label) => `${instanceId}:${label}`;
  return Object.freeze({
    instanceId,
    runtimeMaterial: Object.freeze({ materialSha256: hash(changed('material')) }),
    structural: Object.freeze({
      bindingRedeem: bytes(changed('binding-redeem')),
      bindingLock: bytes(changed('binding-lock')),
      stateHelper: bytes(changed('state-helper')),
      stateUnlock: bytes(changed('state-unlock')),
      stateLock: bytes(changed('state-lock')),
      verifierLocks: Object.freeze(Array.from({ length: 10 }, (_, index) =>
        bytes(changed(`verifier-lock:${index}`)))),
    }),
    programs: Object.freeze({
      terminal: program(changed('terminal')),
      executor: program(changed('executor')),
      exactFinal: program(changed('exact-final')),
      miller: program(changed('miller')),
      fused: program(changed('fused')),
      exactMsm: Object.freeze(Array.from({ length: 3 }, (_, index) =>
        program(changed(`exact-msm:${index}`)))),
    }),
    fixedTables: Object.freeze({
      remoteBlobSha256: hash('fixed:remote-blob'),
      terminalTableHash256: hash('fixed:terminal-table'),
      carrierPadsSha256: Object.freeze(Array.from({ length: 3 }, (_, index) =>
        hash(`fixed:carrier:${index}`))),
      roleTableHash256: Object.freeze(Array.from({ length: 5 }, (_, index) =>
        hash(`fixed:role:${index}`))),
    }),
  });
}

test('instance specialization spike classifies emitted-byte divergence as a hard stop', () => {
  const left = runtime('11'.repeat(32));
  const right = runtime('22'.repeat(32));
  const snapshot = snapshotV2Pf10InstanceSpecializationRuntime(left);
  assert.equal(snapshot.schema, V2_PF10_INSTANCE_SPECIALIZATION_SPIKE_SCHEMA);
  assert.equal(Object.keys(snapshot.changing).length, 46);
  assert.equal(Object.keys(snapshot.reusable).length, 10);

  const comparison = compareV2Pf10InstanceSpecializationRuntimes(left, right);
  assert.equal(comparison.status, 'byte-divergence-no-specialization');
  assert.equal(comparison.specializationPermitted, false);
  assert.equal(comparison.changedPaths.length, 46);
  assert.deepEqual(comparison.unchangedPaths, []);
  assert.equal(comparison.reusableEqualPaths.length, 10);
  assert.throws(
    () => assertV2Pf10InstanceSpecializationByteEquality(left, right),
    (error) => error instanceof V2Pf10InstanceSpecializationSpikeError
      && error.code === 'PF10_INSTANCE_SPECIALIZATION_BYTE_DIVERGENCE',
  );
});

test('instance specialization spike rejects incomplete runtime observations', () => {
  const incomplete = structuredClone(runtime('11'.repeat(32)));
  incomplete.structural.verifierLocks.pop();
  assert.throws(
    () => snapshotV2Pf10InstanceSpecializationRuntime(incomplete),
    (error) => error instanceof V2Pf10InstanceSpecializationSpikeError
      && error.code === 'PF10_INSTANCE_SPECIALIZATION_RUNTIME_INVALID',
  );
  assert.throws(
    () => compareV2Pf10InstanceSpecializationRuntimes(
      runtime('11'.repeat(32)),
      runtime('11'.repeat(32)),
    ),
    (error) => error instanceof V2Pf10InstanceSpecializationSpikeError
      && error.code === 'PF10_INSTANCE_SPECIALIZATION_IDS_NOT_DISTINCT',
  );
});
