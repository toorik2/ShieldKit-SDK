import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SCORECARD_SCHEMA,
  UNLOCK_BUDGET_BYTES,
  buildScorecard,
  compareScorecards,
  formatCompareTableFromCards,
  percentile,
  unlockMargin,
  validateScorecard,
} from './scorecard.mjs';

const COMMIT = 'a'.repeat(40);

test('percentile and unlockMargin drive real helpers', () => {
  assert.equal(percentile([10, 20, 30, 40], 0.5), 20);
  assert.equal(percentile([10, 20, 30, 40], 0.95), 40);
  assert.equal(unlockMargin(10_000), 0);
  assert.equal(unlockMargin(9_500), 500);
  assert.equal(unlockMargin(null), null);
});

test('buildScorecard + validateScorecard reject bad unlock arithmetic', () => {
  const ok = buildScorecard({
    design: 't',
    commit: COMMIT,
    story: 'S0',
    N: 1,
    ok: true,
    first_try: true,
    prove_ms_p50: 100,
    prove_ms_p95: 100,
    total_ms_p95: 120,
    max_unlock_bytes: 10_000,
    notes: 'unit',
  });
  assert.equal(ok.schema, SCORECARD_SCHEMA);
  assert.equal(ok.unlock_margin, 0);
  assert.equal(ok.commit.length, 40);

  assert.throws(
    () => validateScorecard({
      ...ok,
      unlock_margin: 1,
    }),
    /unlock_margin/,
  );
  assert.throws(
    () => buildScorecard({
      design: 't',
      commit: COMMIT,
      story: 'S0',
      N: 1,
      ok: true,
      first_try: false,
      notes: 'bad',
    }),
    /first_try/,
  );
  assert.equal(UNLOCK_BUDGET_BYTES, 10_000);
});

test('compareScorecards and format table use real modules', () => {
  const a = buildScorecard({
    design: 'left',
    commit: COMMIT,
    story: 'S0',
    N: 1,
    ok: true,
    first_try: true,
    prove_ms_p95: 1000,
    max_unlock_bytes: 10_000,
    notes: '',
  });
  const b = buildScorecard({
    design: 'right',
    commit: 'b'.repeat(40),
    story: 'S0',
    N: 1,
    ok: true,
    first_try: true,
    prove_ms_p95: 800,
    max_unlock_bytes: 9_500,
    notes: '',
  });
  const cmp = compareScorecards(a, b);
  assert.equal(cmp.deltas.prove_ms_p95, -200);
  assert.equal(cmp.deltas.unlock_margin, 500);
  const table = formatCompareTableFromCards(a, b);
  assert.match(table, /prove_ms_p95/);
  assert.match(table, /left/);
  assert.match(table, /right/);
  assert.match(table, /ok/);
});
