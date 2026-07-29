import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BCH_HARD_POLICY_CEILINGS,
  EXTERNAL_RELEASE_GATES,
  externalReleaseGateBoundary,
  parseExternalReleaseGateArguments,
} from './external-release-gate.mjs';

test('every external release command remains an explicit fail-closed boundary', () => {
  assert.deepEqual(BCH_HARD_POLICY_CEILINGS, {
    serializedTransactionBytes: 100_000,
    everyInputUnlockingBytecodeBytes: 10_000,
    everyVmResourcePercent: 100,
  });
  assert.deepEqual(Object.keys(EXTERNAL_RELEASE_GATES), [
    'bchn',
    'chipnet',
    'final-ceremony-and-audits',
  ]);
  for (const gate of Object.keys(EXTERNAL_RELEASE_GATES)) {
    const result = externalReleaseGateBoundary(gate);
    assert.equal(result.status, 'blocked-external-evidence-required');
    assert.equal(result.releaseQualified, false);
    assert.equal(result.portableCiCanSatisfy, false);
    assert.equal(result.hardPolicyCeilings, BCH_HARD_POLICY_CEILINGS);
    assert.equal(result.narrowerMargins, 'non-blocking-risk-telemetry-only');
    assert.ok(result.planGates.length > 0);
    assert.ok(result.requirements.length > 0);
    assert.ok(result.expectedArtifacts.length > 0);
  }
});

test('unknown or incomplete external gate requests fail closed', () => {
  assert.throws(() => parseExternalReleaseGateArguments([]), /usage/);
  assert.throws(
    () => parseExternalReleaseGateArguments(['--gate', 'invented']),
    /unknown external release gate/,
  );
  assert.throws(() => externalReleaseGateBoundary('invented'), /unknown external release gate/);
});

test('the external gate CLI reports structured blockers and exits nonzero', () => {
  const childEnvironment = { ...process.env };
  delete childEnvironment.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL('./external-release-gate.mjs', import.meta.url)),
    '--gate',
    'bchn',
  ], {
    encoding: 'utf8',
    env: childEnvironment,
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const report = JSON.parse(result.stderr);
  assert.equal(report.gate, 'bchn');
  assert.equal(report.releaseQualified, false);
});
