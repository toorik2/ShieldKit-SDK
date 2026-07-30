#!/usr/bin/env node
import { pathToFileURL } from 'node:url';

export class ExternalReleaseGateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ExternalReleaseGateError';
  }
}

export const BCH_HARD_POLICY_CEILINGS = Object.freeze({
  serializedTransactionBytes: 100_000,
  everyInputUnlockingBytecodeBytes: 10_000,
  everyVmResourcePercent: 100,
});

export const EXTERNAL_RELEASE_GATES = Object.freeze({
  bchn: Object.freeze({
    planGates: Object.freeze(['B-02-final']),
    requirements: Object.freeze([
      'latest unmodified verifier benchmark, Libauth, BCHN testmempoolaccept, mined BCHN, and LeanBCH must accept the same final deposit, transfer, and withdrawal transactions',
      'every transaction byte, unlocking byte, VM resource, and hash iteration must be measured',
      'test:external:verifier-source must run after the omitted full verifier packages/build and packages/contracts source snapshot is restored',
    ]),
    expectedArtifacts: Object.freeze([
      'artifacts/v2-direct/<profileId>/verification/maintainer.json',
      'artifacts/v2-direct/<profileId>/verification/libauth.json',
      'artifacts/v2-direct/<profileId>/verification/bchn-mempool.json',
      'artifacts/v2-direct/<profileId>/verification/bchn-mined.json',
      'artifacts/v2-direct/<profileId>/verification/leanbch.json',
      'artifacts/v2-direct/<profileId>/verification/measurements.json',
    ]),
  }),
  chipnet: Object.freeze({
    planGates: Object.freeze(['Q-08', 'Q-09']),
    requirements: Object.freeze([
      'two clean hosts must verify final signed artifacts and complete deposit, transfer, withdrawal, erase, recovery, and recovered-note spend',
      'a 30-day Chipnet soak must record at least 1,000 matching V2 Direct settlements and the required 32-live-note playground campaigns',
      'the existing e2e:standalone and e2e:multiuser-blank development scripts are not V2 Direct Q-08/Q-09 evidence',
    ]),
    expectedArtifacts: Object.freeze([
      'artifacts/v2-direct/<profileId>/qualification/clean-host-a.json',
      'artifacts/v2-direct/<profileId>/qualification/clean-host-b.json',
      'artifacts/v2-direct/<profileId>/chipnet/instance.json',
      'artifacts/v2-direct/<profileId>/chipnet/settlements.json',
      'artifacts/v2-direct/<profileId>/chipnet/soak.json',
      'artifacts/v2-direct/<profileId>/chipnet/playground.json',
    ]),
  }),
  'final-ceremony-and-audits': Object.freeze({
    planGates: Object.freeze(['D-01', 'D-02']),
    requirements: Object.freeze([
      'the frozen final circuit needs at least five independent phase-2 contributors and a public beacon',
      'two clean machines must verify the transcript and two independent clean hosts must reproduce matching final artifacts',
      'all four independent audit scopes need signed reports and blocker-complete closure',
      'local development ceremony tests cannot substitute for the final ceremony or independent audits',
    ]),
    expectedArtifacts: Object.freeze([
      'artifacts/v2-direct/<profileId>/ceremony/transcript.json',
      'artifacts/v2-direct/<profileId>/ceremony/beacon.json',
      'artifacts/v2-direct/<profileId>/ceremony/contributors.json',
      'artifacts/v2-direct/<profileId>/ceremony/verify-host-a.json',
      'artifacts/v2-direct/<profileId>/ceremony/verify-host-b.json',
      'artifacts/v2-direct/<profileId>/ceremony/repro-host-a.json',
      'artifacts/v2-direct/<profileId>/ceremony/repro-host-b.json',
      'artifacts/v2-direct/<profileId>/qualification/audit-closure.json',
    ]),
  }),
});

function fail(message) {
  throw new ExternalReleaseGateError(message);
}

export function parseExternalReleaseGateArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--gate') {
    fail('usage: node external-release-gate.mjs --gate bchn|chipnet|final-ceremony-and-audits');
  }
  if (!Object.hasOwn(EXTERNAL_RELEASE_GATES, argv[1])) {
    fail(`unknown external release gate: ${argv[1]}`);
  }
  return argv[1];
}

export function externalReleaseGateBoundary(gate) {
  const definition = EXTERNAL_RELEASE_GATES[gate];
  if (definition === undefined) fail(`unknown external release gate: ${gate}`);
  return Object.freeze({
    schema: 'shieldkit-v2-direct-external-release-boundary-v1',
    gate,
    status: 'blocked-external-evidence-required',
    releaseQualified: false,
    portableCiCanSatisfy: false,
    hardPolicyCeilings: BCH_HARD_POLICY_CEILINGS,
    narrowerMargins: 'non-blocking-risk-telemetry-only',
    ...definition,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = externalReleaseGateBoundary(
      parseExternalReleaseGateArguments(process.argv.slice(2)),
    );
    process.stderr.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`external release gate failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
