import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  V2_Q07_FIXED_DEPTH_COUNTER_KEYS,
  V2_Q07_OPERATION_KINDS,
  V2_Q07_PERFORMANCE_SCHEMA,
  V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS,
  V2Q07PerformanceHarnessError,
  createQ07ReferenceMachineManifest,
  emptyQ07FixedDepthOperationCounts,
  measureQ07Operation,
  runQ07SmallFixtureHarness,
} from './v2-q07-performance-harness.mjs';

function q04Counts(overrides = {}) {
  return { ...emptyQ07FixedDepthOperationCounts(), ...overrides };
}

test('Q-07 small harness emits each non-interchangeable operation and makes no qualification claim', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-q07-small-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const databasePath = join(directory, 'pool.sqlite');
  const setup = new DatabaseSync(databasePath);
  setup.exec('CREATE TABLE sample (value INTEGER NOT NULL); INSERT INTO sample VALUES (7);');
  setup.close();
  const workload = (counts = q04Counts()) => ({
    historyActions: 3,
    run: async () => ({ fixedDepthOperationCounts: counts }),
  });
  const manifest = await runQ07SmallFixtureHarness({
    fixtureId: 'q07-three-action-fixture',
    workloads: {
      'bottom-up-snapshot-authentication': workload(),
      'raw-fallback': workload(),
      'suffix-replay': workload(),
      'warm-fixed-depth-update': workload(q04Counts({
        productionLeafHashCalls: 2,
        productionMutationNodeHashCalls: 128,
        productionTotalAdapterNodeReads: 64,
      })),
      'cold-sqlite-io': {
        historyActions: 3,
        coldIoMode: 'reopened-handle-no-cache-eviction',
        storePaths: [databasePath],
        run: async () => {
          const reopened = new DatabaseSync(databasePath, { readOnly: true });
          assert.equal(reopened.prepare('SELECT value FROM sample').get().value, 7);
          reopened.close();
          return { fixedDepthOperationCounts: q04Counts() };
        },
      },
    },
  });
  assert.equal(manifest.schema, V2_Q07_PERFORMANCE_SCHEMA);
  assert.deepEqual(manifest.operations.map((operation) => operation.kind), V2_Q07_OPERATION_KINDS);
  assert.deepEqual(manifest.claims, {
    q04Campaign: 'not-run',
    q07PerformanceTargets: 'not-qualified',
    publishedReferenceMachine: 'not-attested',
    required100kRecovery: 'not-run',
  });
  assert.equal(manifest.fixture.maximumHistoryActions, V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS);
  const cold = manifest.operations.at(-1);
  assert.equal(cold.coldIoMode, 'reopened-handle-no-cache-eviction');
  assert.equal(cold.storeSize.available, true);
  assert.ok(cold.storeSize.bytes > 0);
  assert.ok(manifest.operations.every(
    (operation) => operation.peakRss.qualifiesOperationPeak === false,
  ));
  assert.deepEqual(Object.keys(cold.fixedDepthOperationCounts), V2_Q07_FIXED_DEPTH_COUNTER_KEYS);
  assert.ok(manifest.operations.every((operation) => Number.isFinite(operation.wallMs) && operation.wallMs >= 0));
  await assert.rejects(
    runQ07SmallFixtureHarness({
      fixtureId: 'q07-bad-counter-shape',
      workloads: Object.fromEntries(V2_Q07_OPERATION_KINDS.map((kind) => [kind, {
        historyActions: 1,
        ...(kind === 'cold-sqlite-io' ? { coldIoMode: 'fresh-process' } : {}),
        run: async () => ({ fixedDepthOperationCounts: { leafHashes: 1 } }),
      }])),
    }),
    /unexpected keys/u,
  );
});

test('Q-07 rejects omitted operation kinds, unbounded fixture sizes, and fabricated counter shapes', async () => {
  await assert.rejects(
    runQ07SmallFixtureHarness({
      fixtureId: 'q07-incomplete',
      workloads: {},
    }),
    V2Q07PerformanceHarnessError,
  );
  await assert.rejects(
    runQ07SmallFixtureHarness({
      fixtureId: 'q07-large-fixture',
      workloads: Object.fromEntries(V2_Q07_OPERATION_KINDS.map((kind) => [kind, {
        historyActions: V2_Q07_SMALL_FIXTURE_MAX_HISTORY_ACTIONS + 1,
        ...(kind === 'cold-sqlite-io' ? { coldIoMode: 'fresh-process' } : {}),
        run: async () => ({ fixedDepthOperationCounts: q04Counts() }),
      }])),
    }),
    V2Q07PerformanceHarnessError,
  );
  await assert.rejects(
    measureQ07Operation({
      kind: 'suffix-replay',
      historyActions: 1,
      run: async () => ({ fixedDepthOperationCounts: { leafHashes: 1 } }),
    }),
    /unexpected keys/u,
  );
});

test('Q-07 captures a hash-bound but unattested local reference-machine manifest', () => {
  const referenceMachine = createQ07ReferenceMachineManifest();
  assert.equal(referenceMachine.attestation, 'local-unattested');
  assert.equal(referenceMachine.schema, 'shieldkit-v2-direct/q07-reference-machine-manifest/v1');
  assert.match(referenceMachine.sha256, /^[0-9a-f]{64}$/);
  assert.ok(referenceMachine.hardware.logicalCores > 0);
});
