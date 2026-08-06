import assert from 'node:assert/strict';
import test from 'node:test';

import {
  COLDSTART_SCHEMA,
  COLDSTART_STEPS,
  MACHINE_COLDSTART_FAIRNESS,
  buildColdstartReport,
  formatColdstartTable,
} from './coldstart.mjs';

test('coldstart report and table include clone/build ladder', () => {
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'clone'));
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'npm_ci'));
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'cdn_download'));
  assert.ok(COLDSTART_STEPS.some((s) => s.id === 'artifact_install'));
  assert.equal(COLDSTART_STEPS.find((s) => s.id === 'cdn_download').n, 3);
  const report = buildColdstartReport({
    design: 't',
    commit: 'a'.repeat(40),
    steps: [
      { id: 'clone', ms: 12_000, bytes: 50_000_000, ok: true, detail: 'git clone' },
      { id: 'npm_ci', ms: 45_000, bytes: 280_000_000, ok: true },
      { id: 'cdn_download', ms: 22_000, bytes: 197_212_683, ok: true, detail: 'HTTPS pin tar' },
      { id: 'first_prove_cold', ms: 4000, ok: true },
      { id: 'second_prove_warm', ms: 3200, ok: true },
      { id: 'disk_footprint', bytes: 2_000_000_000, ok: true },
    ],
    totals: { timedMs: 83_000, diskBytes: 2_000_000_000 },
  });
  assert.equal(report.schema, COLDSTART_SCHEMA);
  const table = formatColdstartTable(report);
  assert.match(table, /Download \/ clone repo/);
  assert.match(table, /Install JS deps/);
  assert.match(table, /CDN download pin artifacts/);
  assert.match(table, /First prove/);
  assert.match(table, /Disk footprint/);
  assert.match(table, /Also consider/);
});

test('machine cold-start fairness includes timed CDN + empty install', () => {
  // Even without an explicit fairness array, machine mode injects the lines.
  const report = buildColdstartReport({
    design: 't',
    commit: 'b'.repeat(40),
    mode: 'machine-cold-start',
    steps: [
      { id: 'cdn_download', ms: 25_000, bytes: 197_212_683, ok: true },
      { id: 'artifact_install', ms: 120_000, bytes: 1.4e9, ok: true },
    ],
    totals: { timedMs: 145_000, diskBytes: 1.4e9 },
  });
  const table = formatColdstartTable(report);
  assert.match(table, /Machine cold-start story/);
  assert.match(table, /CDN pin download/);
  assert.match(table, /Fairness note \(in the output\):/);
  assert.match(table, /CDN download is timed/);
  assert.match(table, /Native prover is timed separately/);
  assert.match(table, /Product artifact install is timed separately/);
  assert.equal(report.fairness.length, MACHINE_COLDSTART_FAIRNESS.length);
  assert.ok(MACHINE_COLDSTART_FAIRNESS[0].includes('CDN download is timed'));
  assert.ok(MACHINE_COLDSTART_FAIRNESS.some((line) => line.includes('Native prover is timed separately')));
});
