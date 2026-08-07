/**
 * Component microbenchmark scorecard for S0/S1/S2 (isolated prove/scaling).
 * Pure validation + builders — no prove/RPC I/O.
 *
 * NOT the primary end-to-end action benchmark.
 * Primary action traces use shieldkit-action-benchmark-run/v2 (see bench/action/).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

/** @deprecated name retained as alias — prefer COMPONENT_SCORECARD_SCHEMA */
export const SCORECARD_SCHEMA = 'shieldkit-component-bench-scorecard-v1';
export const COMPONENT_SCORECARD_SCHEMA = SCORECARD_SCHEMA;
/** Historical schema id — rejected for new primary claims */
export const LEGACY_SCORECARD_SCHEMA = 'shieldkit-bench-scorecard-v1';
export const UNLOCK_BUDGET_BYTES = 10_000;
export const DESIGN_PF10_BASELINE = 'pf10-baseline';

const GIT_SHA = /^[0-9a-f]{40}$/u;
const STORIES = new Set(['S0', 'S1', 'S2']);

export class BenchScorecardError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BenchScorecardError';
  }
}

const fail = (message) => {
  throw new BenchScorecardError(message);
};

function finiteNonNeg(value, label) {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail(`${label} must be a finite number >= 0 or null`);
  }
  return value;
}

function optionalInt(value, label) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a safe integer >= 0 or null`);
  }
  return value;
}

/** Percentile in [0,1] on a non-empty number array (nearest-rank). */
export function percentile(values, probability) {
  if (!Array.isArray(values) || values.length === 0) {
    fail('percentile requires a non-empty values array');
  }
  if (typeof probability !== 'number' || !(probability > 0) || probability > 1) {
    fail('percentile probability must be in (0, 1]');
  }
  const sorted = [...values].map((v, i) => {
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
      fail(`percentile values[${i}] must be finite >= 0`);
    }
    return v;
  }).sort((a, b) => a - b);
  const index = Math.ceil(sorted.length * probability) - 1;
  return sorted[Math.max(0, index)];
}

export function unlockMargin(maxUnlockBytes) {
  if (maxUnlockBytes === null || maxUnlockBytes === undefined) return null;
  if (!Number.isSafeInteger(maxUnlockBytes) || maxUnlockBytes < 0) {
    fail('max_unlock_bytes must be a safe integer >= 0 or null');
  }
  return UNLOCK_BUDGET_BYTES - maxUnlockBytes;
}

export function resolveGitCommit(cwd = path.resolve(import.meta.dirname, '../..')) {
  try {
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd,
      encoding: 'utf8',
    }).trim();
    if (!GIT_SHA.test(commit)) fail('git rev-parse HEAD did not return a 40-char lowercase sha');
    return commit;
  } catch (error) {
    fail(`cannot resolve git commit: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Build a scorecard object. Applies unlock_margin arithmetic when max unlock is set.
 */
export function buildScorecard({
  design,
  commit,
  story,
  N,
  ok,
  first_try: firstTry,
  prove_ms_p50: proveP50 = null,
  prove_ms_p95: proveP95 = null,
  total_ms_p95: totalP95 = null,
  tx_bytes: txBytes = null,
  max_unlock_bytes: maxUnlock = null,
  notes = '',
} = {}) {
  const card = Object.freeze({
    schema: SCORECARD_SCHEMA,
    design: typeof design === 'string' ? design : fail('design must be a string'),
    commit: typeof commit === 'string' ? commit : fail('commit must be a string'),
    story: typeof story === 'string' ? story : fail('story must be a string'),
    N: optionalInt(N, 'N') ?? fail('N is required'),
    ok: ok === true,
    first_try: firstTry === true,
    prove_ms_p50: finiteNonNeg(proveP50, 'prove_ms_p50'),
    prove_ms_p95: finiteNonNeg(proveP95, 'prove_ms_p95'),
    total_ms_p95: finiteNonNeg(totalP95, 'total_ms_p95'),
    tx_bytes: optionalInt(txBytes, 'tx_bytes'),
    max_unlock_bytes: optionalInt(maxUnlock, 'max_unlock_bytes'),
    unlock_margin: unlockMargin(maxUnlock ?? null),
    notes: typeof notes === 'string' ? notes : fail('notes must be a string'),
  });
  return validateScorecard(card);
}

/** Validate scorecard shape and unlock_margin arithmetic. Returns frozen copy. */
export function validateScorecard(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('scorecard must be a plain object');
  }
  const required = [
    'schema', 'design', 'commit', 'story', 'N', 'ok', 'first_try',
    'prove_ms_p50', 'prove_ms_p95', 'total_ms_p95', 'tx_bytes',
    'max_unlock_bytes', 'unlock_margin', 'notes',
  ];
  const keys = Object.keys(value).sort();
  const expected = [...required].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    fail('scorecard has missing or unknown properties');
  }
  if (value.schema !== SCORECARD_SCHEMA) fail(`schema must be ${SCORECARD_SCHEMA}`);
  if (typeof value.design !== 'string' || value.design.length === 0) fail('design must be non-empty string');
  if (typeof value.commit !== 'string' || !GIT_SHA.test(value.commit)) {
    fail('commit must be full 40-char lowercase git sha');
  }
  if (!STORIES.has(value.story)) fail('story must be S0, S1, or S2');
  if (!Number.isSafeInteger(value.N) || value.N < 0) fail('N must be a safe integer >= 0');
  if (typeof value.ok !== 'boolean') fail('ok must be boolean');
  if (typeof value.first_try !== 'boolean') fail('first_try must be boolean');
  if (value.ok === true && value.first_try !== true) {
    fail('successful scorecard requires first_try: true');
  }
  finiteNonNeg(value.prove_ms_p50, 'prove_ms_p50');
  finiteNonNeg(value.prove_ms_p95, 'prove_ms_p95');
  finiteNonNeg(value.total_ms_p95, 'total_ms_p95');
  optionalInt(value.tx_bytes, 'tx_bytes');
  optionalInt(value.max_unlock_bytes, 'max_unlock_bytes');
  if (value.max_unlock_bytes !== null) {
    const expectedMargin = UNLOCK_BUDGET_BYTES - value.max_unlock_bytes;
    if (value.unlock_margin !== expectedMargin) {
      fail(`unlock_margin must equal ${UNLOCK_BUDGET_BYTES} - max_unlock_bytes`);
    }
  } else if (value.unlock_margin !== null) {
    fail('unlock_margin must be null when max_unlock_bytes is null');
  }
  if (typeof value.notes !== 'string') fail('notes must be a string');
  return Object.freeze({ ...value });
}

/** Compare two validated scorecards; returns plain object of deltas. */
export function compareScorecards(left, right) {
  const a = validateScorecard(left);
  const b = validateScorecard(right);
  const numDelta = (x, y) => {
    if (x === null || y === null) return null;
    return y - x;
  };
  return Object.freeze({
    schema: 'shieldkit-component-bench-compare-v1',
    left: Object.freeze({ design: a.design, commit: a.commit, story: a.story, ok: a.ok }),
    right: Object.freeze({ design: b.design, commit: b.commit, story: b.story, ok: b.ok }),
    deltas: Object.freeze({
      prove_ms_p95: numDelta(a.prove_ms_p95, b.prove_ms_p95),
      unlock_margin: numDelta(a.unlock_margin, b.unlock_margin),
      tx_bytes: numDelta(a.tx_bytes, b.tx_bytes),
      total_ms_p95: numDelta(a.total_ms_p95, b.total_ms_p95),
    }),
  });
}

export function formatCompareTableFromCards(left, right) {
  const a = validateScorecard(left);
  const b = validateScorecard(right);
  const comparison = compareScorecards(a, b);
  const d = comparison.deltas;
  const cell = (v) => (v === null || v === undefined ? 'null' : String(v));
  const row = (label, L, R, D) =>
    `${label.padEnd(16)} ${cell(L).padStart(14)} ${cell(R).padStart(14)} ${cell(D).padStart(12)}`;
  return [
    'ShieldKit bench compare',
    row('field', 'left', 'right', 'delta(R-L)'),
    row('design', a.design, b.design, ''),
    row('commit', a.commit, b.commit, ''),
    row('story', a.story, b.story, ''),
    row('ok', a.ok, b.ok, ''),
    row('prove_ms_p95', a.prove_ms_p95, b.prove_ms_p95, d.prove_ms_p95),
    row('unlock_margin', a.unlock_margin, b.unlock_margin, d.unlock_margin),
    row('max_unlock', a.max_unlock_bytes, b.max_unlock_bytes,
      a.max_unlock_bytes === null || b.max_unlock_bytes === null
        ? null
        : b.max_unlock_bytes - a.max_unlock_bytes),
    row('tx_bytes', a.tx_bytes, b.tx_bytes, d.tx_bytes),
  ].join('\n');
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
