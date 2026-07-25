import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  EvidenceValidationError,
  createEvidenceValidator,
  validateEvidenceFile,
} from './validate-evidence.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '../..');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function fixtureRecord(mutator) {
  const directory = await mkdtemp(path.join(repositoryRoot, '.tmp-evidence-'));
  const artifactRelative = path.relative(
    repositoryRoot,
    path.join(directory, 'artifact.txt'),
  );
  const artifactBytes = Buffer.from('evidence fixture\n');
  await writeFile(path.join(directory, 'artifact.txt'), artifactBytes);
  const record = {
    schema: 'shield.cash/evidence/v1',
    id: 'test.evidence-record',
    gate: 'G1',
    candidate: 'test-only',
    claim: 'Conformance validator test fixture.',
    source: {
      repository: repositoryRoot,
      commit: '0000000000000000000000000000000000000000',
      dirtyPaths: [],
    },
    environment: {
      observedAt: '2026-07-23T00:00:00Z',
      hardware: {},
      software: {},
    },
    commands: ['test fixture'],
    artifacts: [{
      path: artifactRelative,
      sha256: digest(artifactBytes),
      bytes: artifactBytes.length,
    }],
    tests: [{
      name: 'fixture',
      expected: true,
      observed: true,
      pass: true,
    }],
    verdict: 'PASS',
    limitations: ['Non-protocol test fixture.'],
  };
  if (mutator) await mutator(record, directory);
  const filename = path.join(directory, 'observation.json');
  await writeFile(filename, `${JSON.stringify(record, null, 2)}\n`);
  return { directory, filename };
}

test('accepts a schema-valid record with matching local artifact bytes', async () => {
  const validateSchema = await createEvidenceValidator();
  const { directory, filename } = await fixtureRecord();
  try {
    const record = await validateEvidenceFile(filename, validateSchema);
    assert.equal(record.verdict, 'PASS');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects artifact hash drift', async () => {
  const validateSchema = await createEvidenceValidator();
  const { directory, filename } = await fixtureRecord((record) => {
    record.artifacts[0].sha256 = '0'.repeat(64);
  });
  try {
    await assert.rejects(
      () => validateEvidenceFile(filename, validateSchema),
      EvidenceValidationError,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects a PASS record containing a failing test', async () => {
  const validateSchema = await createEvidenceValidator();
  const { directory, filename } = await fixtureRecord((record) => {
    record.tests[0].pass = false;
  });
  try {
    await assert.rejects(
      () => validateEvidenceFile(filename, validateSchema),
      /PASS record contains 1 failing test/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('validates immutable source artifacts at their recorded commit after the workspace advances', async () => {
  const filename = path.join(
    repositoryRoot,
    'evidence/G2/preparation-review/observation.json',
  );
  const record = JSON.parse(await readFile(filename, 'utf8'));
  const historical = record.artifacts.find(
    (artifact) => artifact.path
      === 'packages/action/settlement.mjs',
  );
  assert.notEqual(historical, undefined);
  const current = await readFile(path.join(repositoryRoot, historical.path));
  assert.notEqual(digest(current), historical.sha256);
  const validateSchema = await createEvidenceValidator();
  const validated = await validateEvidenceFile(filename, validateSchema);
  assert.equal(validated.source.commit, record.source.commit);
});
