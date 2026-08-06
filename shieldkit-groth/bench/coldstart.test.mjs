import assert from 'node:assert/strict';
import test from 'node:test';

import {
  COLDSTART_SCHEMA,
  COLDSTART_STEPS,
  buildColdstartReport,
  formatColdstartTable,
} from './coldstart.mjs';

test('coldstart report and table include clone/build ladder', () => {
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'clone'));
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'npm_ci'));
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'artifact_install'));
  const report = buildColdstartReport({
    design: 't',
    commit: 'a'.repeat(40),
    steps: [
      { id: 'clone', ms: 12_000, bytes: 50_000_000, ok: true, detail: 'git clone' },
      { id: 'npm_ci', ms: 45_000, bytes: 280_000_000, ok: true },
      { id: 'first_prove_cold', ms: 4000, ok: true },
      { id: 'second_prove_warm', ms: 3200, ok: true },
      { id: 'disk_footprint', bytes: 2_000_000_000, ok: true },
    ],
    totals: { timedMs: 61_000, diskBytes: 2_000_000_000 },
  });
  assert.equal(report.schema, COLDSTART_SCHEMA);
  const table = formatColdstartTable(report);
  assert.match(table, /Download \/ clone repo/);
  assert.match(table, /Install JS deps/);
  assert.match(table, /First prove/);
  assert.match(table, /Disk footprint/);
  assert.match(table, /Also consider/);
});
