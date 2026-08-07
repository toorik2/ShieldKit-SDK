import assert from 'node:assert/strict';
import test from 'node:test';

import { SpanRecorder, spansFromProductTimings } from './span-recorder.mjs';
import { criticalPath, wallEnvelopeMs } from './critical-path.mjs';

test('SpanRecorder parentage, parallel siblings, and failed attempt retention', async () => {
  const rec = new SpanRecorder({ design: 'pf10', profile: 't' });
  const cmd = rec.start('command');
  const intent = rec.start('intent', { parentId: cmd });
  // Parallel branches under intent
  const proof = rec.start('proof', { parentId: intent, attempt: 1 });
  const mat = rec.start('materialize', { parentId: intent, attempt: 1 });
  // First proof attempt fails (visible)
  rec.end(proof, { status: 'failed', reason: 'synthetic unit failure' });
  const proof2 = rec.start('proof', { parentId: intent, attempt: 2 });
  rec.end(proof2, { status: 'executed' });
  rec.end(mat, { status: 'executed' });
  rec.end(intent, { status: 'executed' });
  rec.end(cmd, { status: 'executed' });
  const spans = rec.finalize();
  // command, intent, proof@1(failed), proof@2, materialize
  assert.equal(spans.length, 5);
  const failed = spans.find((s) => s.name === 'proof' && s.attempt === 1);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.reason, 'synthetic unit failure');
  const parents = new Set(spans.map((s) => s.parentId));
  assert.ok(parents.has(intent));
  // Parallel: materialize and proof share parent
  const kids = spans.filter((s) => s.parentId === intent);
  assert.ok(kids.length >= 2);

  const crit = criticalPath(spans);
  assert.ok(typeof crit.criticalPathMs === 'number' && crit.criticalPathMs >= 0);
  assert.ok(Array.isArray(crit.pathNames) && crit.pathNames.includes('command'));
  assert.ok(wallEnvelopeMs(spans) >= 0);
});

test('criticalPath does not sum fully overlapping parallel siblings', () => {
  // Two overlapping children under root
  const spans = [
    {
      id: 'r', parentId: null, name: 'root', attempt: 1, status: 'executed',
      startOffsetMs: 0, endOffsetMs: 100, durationMs: 100,
    },
    {
      id: 'a', parentId: 'r', name: 'a', attempt: 1, status: 'executed',
      startOffsetMs: 0, endOffsetMs: 80, durationMs: 80,
    },
    {
      id: 'b', parentId: 'r', name: 'b', attempt: 1, status: 'executed',
      startOffsetMs: 10, endOffsetMs: 90, durationMs: 80,
    },
  ];
  const crit = criticalPath(spans);
  // Parallel group → max(80,80)=80, not 160
  assert.equal(crit.criticalPathMs, 80);
});

test('criticalPath sums sequential non-overlapping children', () => {
  const spans = [
    {
      id: 'r', parentId: null, name: 'root', attempt: 1, status: 'executed',
      startOffsetMs: 0, endOffsetMs: 100, durationMs: 100,
    },
    {
      id: 'a', parentId: 'r', name: 'a', attempt: 1, status: 'executed',
      startOffsetMs: 0, endOffsetMs: 40, durationMs: 40,
    },
    {
      id: 'b', parentId: 'r', name: 'b', attempt: 1, status: 'executed',
      startOffsetMs: 40, endOffsetMs: 100, durationMs: 60,
    },
  ];
  const crit = criticalPath(spans);
  assert.equal(crit.criticalPathMs, 100);
});

test('spansFromProductTimings builds nested DAG from real helper', () => {
  const spans = spansFromProductTimings({
    timingsMs: {
      stateRead: 10,
      fundingRead: 5,
      proofGeneration: 1000,
      witnessAssembly: 50,
      signingAndVm: 20,
      admission: 30,
      commit: 5,
      total: 1120,
    },
    design: 'pf10',
  });
  assert.ok(spans.some((s) => s.name === 'proof'));
  assert.ok(spans.some((s) => s.name === 'admission'));
  const crit = criticalPath(spans);
  assert.ok(crit.criticalPathMs > 0);
});
