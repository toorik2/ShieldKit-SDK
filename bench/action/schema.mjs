/**
 * shieldkit-action-benchmark-run/v2 and campaign-summary schemas + validators.
 * Pure — no RPC/prove I/O.
 */

import { createHash } from 'node:crypto';
import { isOutcomeClass, buildOutcome, OUTCOME_CLASSES } from './outcomes.mjs';
import { criticalPath, wallEnvelopeMs } from './critical-path.mjs';
import { SPAN_STATUSES } from './span-recorder.mjs';

export const RUN_SCHEMA = 'shieldkit-action-benchmark-run/v2';
export const CAMPAIGN_SUMMARY_SCHEMA = 'shieldkit-action-benchmark-campaign-summary/v1';

export const CACHE_MODES = Object.freeze([
  'warm-resident',
  'cold-installed',
  'readiness',
]);

export const ACTION_KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
export const DESIGNS = Object.freeze(['pf10', 'pf6', 'fri']);

const GIT_SHA = /^[0-9a-f]{40}$/;
const TXID = /^[0-9a-f]{64}$/;
const CACHE_SET = new Set(CACHE_MODES);
const ACTION_SET = new Set(ACTION_KINDS);
const DESIGN_SET = new Set(DESIGNS);
const SPAN_STATUS_SET = new Set(SPAN_STATUSES);

export class RunSchemaError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RunSchemaError';
  }
}

const fail = (message) => {
  throw new RunSchemaError(message);
};

function finiteNonNeg(value, label) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail(`${label} must be finite >= 0 or null`);
  }
  return value;
}

function optionalInt(value, label) {
  if (value === null || value === undefined) return null;
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a safe integer >= 0 or null`);
  }
  return value;
}

function validateSpan(span, index) {
  if (span === null || typeof span !== 'object' || Array.isArray(span)) {
    fail(`spans[${index}] must be an object`);
  }
  if (typeof span.id !== 'string' || span.id.length === 0) fail(`spans[${index}].id required`);
  if (!(span.parentId === null || typeof span.parentId === 'string')) {
    fail(`spans[${index}].parentId must be string or null`);
  }
  if (typeof span.name !== 'string' || span.name.length === 0) fail(`spans[${index}].name required`);
  if (!Number.isSafeInteger(span.attempt) || span.attempt < 1) {
    fail(`spans[${index}].attempt must be integer >= 1`);
  }
  if (!SPAN_STATUS_SET.has(span.status)) {
    fail(`spans[${index}].status invalid`);
  }
  if (typeof span.startOffsetMs !== 'number' || !Number.isFinite(span.startOffsetMs)) {
    fail(`spans[${index}].startOffsetMs invalid`);
  }
  if (typeof span.endOffsetMs !== 'number' || !Number.isFinite(span.endOffsetMs)) {
    fail(`spans[${index}].endOffsetMs invalid`);
  }
  if (span.endOffsetMs < span.startOffsetMs) {
    fail(`spans[${index}] end before start`);
  }
  // Reject estimated-size placeholders in meta
  if (span.meta && typeof span.meta === 'object') {
    for (const [k, v] of Object.entries(span.meta)) {
      if (/estimat/i.test(k) || (typeof v === 'string' && /estimat/i.test(v))) {
        fail(`spans[${index}].meta must not contain estimated placeholders (${k})`);
      }
    }
  }
}

/**
 * Validate and freeze a run record.
 */
export function validateRunRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('run record must be a plain object');
  }
  if (value.schema !== RUN_SCHEMA) fail(`schema must be ${RUN_SCHEMA}`);
  if (typeof value.runId !== 'string' || value.runId.length === 0) fail('runId required');
  if (typeof value.campaignId !== 'string' || value.campaignId.length === 0) fail('campaignId required');
  if (!DESIGN_SET.has(value.design)) fail(`design must be one of ${DESIGNS.join(', ')}`);
  if (typeof value.profile !== 'string' || value.profile.length === 0) fail('profile required');
  if (typeof value.commit !== 'string' || !GIT_SHA.test(value.commit)) {
    fail('commit must be full 40-char lowercase git sha');
  }
  if (!ACTION_SET.has(value.action)) fail(`action must be one of ${ACTION_KINDS.join(', ')}`);
  if (!CACHE_SET.has(value.cacheMode)) fail(`cacheMode must be one of ${CACHE_MODES.join(', ')}`);
  if (value.boundary !== 'intent' && value.boundary !== 'command') {
    // both starts are recorded; primary comparison boundary is intent
    fail('boundary must be intent or command (primary comparison is intent)');
  }

  if (!Array.isArray(value.spans) || value.spans.length === 0) fail('spans must be a non-empty array');
  const ids = new Set();
  for (let i = 0; i < value.spans.length; i += 1) {
    validateSpan(value.spans[i], i);
    if (ids.has(value.spans[i].id)) fail(`duplicate span id at ${i}`);
    ids.add(value.spans[i].id);
  }
  for (let i = 0; i < value.spans.length; i += 1) {
    const p = value.spans[i].parentId;
    if (p !== null && !ids.has(p)) fail(`spans[${i}] unknown parentId`);
  }

  // Critical path must be present and consistent with spans
  if (value.criticalPath === null || typeof value.criticalPath !== 'object') {
    fail('criticalPath object required');
  }
  if (typeof value.criticalPath.criticalPathMs !== 'number'
    || !Number.isFinite(value.criticalPath.criticalPathMs)
    || value.criticalPath.criticalPathMs < 0) {
    fail('criticalPath.criticalPathMs invalid');
  }

  if (!value.outcome || !isOutcomeClass(value.outcome.class)) {
    fail(`outcome.class must be one of ${OUTCOME_CLASSES.join(', ')}`);
  }

  // Acceptance evidence
  const acc = value.acceptance;
  if (acc === null || typeof acc !== 'object') fail('acceptance object required');
  if (typeof acc.tmaIsAcceptance !== 'boolean' || acc.tmaIsAcceptance !== false) {
    fail('acceptance.tmaIsAcceptance must be false (TMA is never acceptance)');
  }
  if (value.outcome.class === 'accepted' || value.outcome.class === 'accepted_commit_failed') {
    if (acc.accepted !== true || acc.mempoolObserved !== true) {
      fail('accepted outcomes require mempoolObserved acceptance evidence');
    }
    if (typeof acc.txid !== 'string' || !TXID.test(acc.txid)) {
      fail('accepted outcomes require full 64-char txid');
    }
    if (acc.acceptanceMethod !== 'mempool_membership') {
      fail('acceptanceMethod must be mempool_membership');
    }
    if (!acc.readback || acc.readback.match !== true) {
      fail('accepted outcomes require exact readback match');
    }
  }

  // Exact metrics — no estimated placeholders
  const m = value.metrics;
  if (m === null || typeof m !== 'object') fail('metrics object required');
  if (m.txBytesEstimated === true || m.estimated === true) {
    fail('metrics must not use estimated sizes');
  }
  optionalInt(m.txBytes, 'metrics.txBytes');
  optionalInt(m.maxUnlockBytes, 'metrics.maxUnlockBytes');
  optionalInt(m.feeSats, 'metrics.feeSats');
  finiteNonNeg(m.peakRssBytes, 'metrics.peakRssBytes');
  finiteNonNeg(m.cpuSeconds, 'metrics.cpuSeconds');

  // first-try: product policy — multi-retry greenwash forbidden at record level
  // Attempts may be >1 only if production path truly retried and each attempt is in spans.
  if (value.firstTry !== true && value.firstTry !== false) fail('firstTry boolean required');
  if (value.outcome.class === 'accepted' && value.firstTry !== true) {
    fail('accepted rows require firstTry: true (no multi-retry greenwash)');
  }

  if (!value.environment || typeof value.environment !== 'object') fail('environment required');
  if (!value.provenance || typeof value.provenance !== 'object') fail('provenance required');
  if (typeof value.provenance.recordSha256 !== 'string'
    || !/^[0-9a-f]{64}$/.test(value.provenance.recordSha256)) {
    fail('provenance.recordSha256 must be 64-char hex');
  }

  return Object.freeze(deepFreeze(value));
}

function deepFreeze(o) {
  if (o === null || typeof o !== 'object') return o;
  if (Object.isFrozen(o)) return o;
  for (const v of Object.values(o)) deepFreeze(v);
  return Object.freeze(o);
}

/**
 * Build a complete run record (computes critical path + content hash).
 */
export function buildRunRecord({
  runId,
  campaignId,
  design,
  profile,
  commit,
  action,
  cacheMode = 'warm-resident',
  boundary = 'intent',
  spans,
  outcome,
  acceptance,
  metrics = {},
  environment = {},
  workload = {},
  preState = {},
  firstTry = true,
  notes = '',
  wallStartedAt = null,
  wallEndedAt = null,
} = {}) {
  if (!Array.isArray(spans)) fail('spans array required');
  if (metrics?.txBytesEstimated === true || metrics?.estimated === true) {
    fail('metrics must not use estimated sizes');
  }
  const crit = criticalPath(spans);
  const envelope = wallEnvelopeMs(spans);
  const outcomeObj = outcome?.class ? outcome : buildOutcome(outcome ?? { class: 'design_failure' });

  const body = {
    schema: RUN_SCHEMA,
    runId,
    campaignId,
    design,
    profile,
    commit,
    action,
    cacheMode,
    boundary,
    firstTry: firstTry === true,
    spans: spans.map((s) => ({ ...s })),
    criticalPath: {
      criticalPathMs: crit.criticalPathMs,
      pathNames: [...crit.pathNames],
      wallEnvelopeMs: envelope,
    },
    outcome: outcomeObj,
    acceptance: acceptance ?? {
      accepted: false,
      acceptanceMethod: null,
      txid: null,
      mempoolObserved: false,
      tmaIsAcceptance: false,
      readback: null,
    },
    metrics: {
      txBytes: metrics.txBytes ?? null,
      maxUnlockBytes: metrics.maxUnlockBytes ?? null,
      feeSats: metrics.feeSats ?? null,
      feeRateSatPerByte: metrics.feeRateSatPerByte ?? null,
      peakRssBytes: metrics.peakRssBytes ?? null,
      cpuSeconds: metrics.cpuSeconds ?? null,
      inputCount: metrics.inputCount ?? null,
      outputCount: metrics.outputCount ?? null,
      verifierRoleCount: metrics.verifierRoleCount ?? null,
      // never estimated
      txBytesEstimated: false,
      estimated: false,
      ...Object.fromEntries(
        Object.entries(metrics).filter(([k]) => !['txBytesEstimated', 'estimated'].includes(k)),
      ),
    },
    environment: {
      host: environment.host ?? null,
      nodeVersion: environment.nodeVersion ?? process.version,
      platform: environment.platform ?? process.platform,
      cpus: environment.cpus ?? null,
      ...environment,
    },
    workload: { ...workload },
    preState: { ...preState },
    notes: typeof notes === 'string' ? notes : '',
    wallStartedAt,
    wallEndedAt,
    provenance: {
      recordSha256: '0'.repeat(64), // filled below
      plan: 'BENCHMARK_PLAN.md',
      schema: RUN_SCHEMA,
    },
  };

  // Hash without provenance.recordSha256
  const forHash = { ...body, provenance: { ...body.provenance, recordSha256: null } };
  const recordSha256 = createHash('sha256')
    .update(stableStringify(forHash))
    .digest('hex');
  body.provenance.recordSha256 = recordSha256;

  return validateRunRecord(body);
}

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

/**
 * Campaign summary over validated runs. No global scalar winner.
 */
export function buildCampaignSummary({
  campaignId,
  runs,
  cacheMode = null,
  notes = '',
} = {}) {
  if (!Array.isArray(runs) || runs.length === 0) fail('campaign requires non-empty runs');
  const validated = runs.map((r) => (r.schema === RUN_SCHEMA ? validateRunRecord(r) : r));

  // Group design × action
  const cells = new Map();
  for (const r of validated) {
    if (cacheMode && r.cacheMode !== cacheMode) continue;
    const key = `${r.design}::${r.action}::${r.cacheMode}`;
    if (!cells.has(key)) {
      cells.set(key, {
        design: r.design,
        action: r.action,
        cacheMode: r.cacheMode,
        runs: [],
      });
    }
    cells.get(key).runs.push(r);
  }

  const rows = [];
  for (const cell of cells.values()) {
    const attempted = cell.runs.length;
    const acceptedRuns = cell.runs.filter(
      (r) => r.outcome.class === 'accepted' || r.outcome.class === 'accepted_commit_failed',
    );
    const accepted = acceptedRuns.length;
    const latencies = acceptedRuns
      .map((r) => r.outcome.intentToAcceptedMs)
      .filter((v) => typeof v === 'number');
    const cpu = cell.runs.map((r) => r.metrics.cpuSeconds).filter((v) => typeof v === 'number');
    const mem = cell.runs.map((r) => r.metrics.peakRssBytes).filter((v) => typeof v === 'number');
    const tx = acceptedRuns.map((r) => r.metrics.txBytes).filter((v) => typeof v === 'number');
    const unlock = acceptedRuns.map((r) => r.metrics.maxUnlockBytes).filter((v) => typeof v === 'number');
    const fee = acceptedRuns.map((r) => r.metrics.feeSats).filter((v) => typeof v === 'number');

    rows.push(Object.freeze({
      design: cell.design,
      action: cell.action,
      cacheMode: cell.cacheMode,
      accepted,
      attempted,
      reliability: attempted === 0 ? null : accepted / attempted,
      intentToAcceptedMs_p50: percentile(latencies, 0.5),
      intentToAcceptedMs_p95: percentile(latencies, 0.95),
      cpuSeconds_p50: percentile(cpu, 0.5),
      peakRssBytes_p50: percentile(mem, 0.5),
      txBytes_p50: percentile(tx, 0.5),
      maxUnlockBytes_p50: percentile(unlock, 0.5),
      feeSats_p50: percentile(fee, 0.5),
      runIds: Object.freeze(cell.runs.map((r) => r.runId)),
      recordHashes: Object.freeze(cell.runs.map((r) => r.provenance.recordSha256)),
    }));
  }

  // Pareto surface — multi-objective, no winner
  const pareto = rows.map((r) => Object.freeze({
    design: r.design,
    action: r.action,
    cacheMode: r.cacheMode,
    objectives: Object.freeze({
      latencyP50Ms: r.intentToAcceptedMs_p50,
      cpuSeconds: r.cpuSeconds_p50,
      peakRssBytes: r.peakRssBytes_p50,
      txBytes: r.txBytes_p50,
      maxUnlockBytes: r.maxUnlockBytes_p50,
      feeSats: r.feeSats_p50,
      reliability: r.reliability,
    }),
  }));

  const summary = {
    schema: CAMPAIGN_SUMMARY_SCHEMA,
    campaignId,
    generatedAt: new Date().toISOString(),
    notes,
    // Explicit: no global scalar ranking
    globalWinner: null,
    ranking: 'none',
    reliabilityFirst: true,
    warmColdSeparated: true,
    rows: Object.freeze(rows),
    pareto: Object.freeze(pareto),
    panels: Object.freeze({
      warm: Object.freeze(rows.filter((r) => r.cacheMode === 'warm-resident')),
      cold: Object.freeze(rows.filter((r) => r.cacheMode === 'cold-installed')),
      readiness: Object.freeze(rows.filter((r) => r.cacheMode === 'readiness')),
    }),
  };
  return Object.freeze(summary);
}

export function percentile(values, p) {
  if (!Array.isArray(values) || values.length === 0) return null;
  const sorted = [...values].filter((v) => typeof v === 'number' && Number.isFinite(v)).sort((a, b) => a - b);
  if (sorted.length === 0) return null;
  const index = Math.ceil(sorted.length * p) - 1;
  return sorted[Math.max(0, index)];
}

export function formatCampaignReport(summary) {
  const lines = [];
  lines.push('ShieldKit action benchmark campaign summary');
  lines.push(`schema=${summary.schema} campaign=${summary.campaignId}`);
  lines.push('globalWinner=none (Pareto surface only; reliability gate first)');
  lines.push('');
  lines.push('design × action (reliability + p50 latency + resources)');
  lines.push(
    [
      'design'.padEnd(8),
      'action'.padEnd(12),
      'cache'.padEnd(14),
      'acc/att'.padStart(8),
      'p50ms'.padStart(10),
      'txB'.padStart(8),
      'unlock'.padStart(8),
      'fee'.padStart(8),
    ].join(' '),
  );
  for (const r of summary.rows) {
    lines.push([
      String(r.design).padEnd(8),
      String(r.action).padEnd(12),
      String(r.cacheMode).padEnd(14),
      `${r.accepted}/${r.attempted}`.padStart(8),
      (r.intentToAcceptedMs_p50 === null ? 'n/a' : String(Math.round(r.intentToAcceptedMs_p50))).padStart(10),
      (r.txBytes_p50 === null ? 'n/a' : String(r.txBytes_p50)).padStart(8),
      (r.maxUnlockBytes_p50 === null ? 'n/a' : String(r.maxUnlockBytes_p50)).padStart(8),
      (r.feeSats_p50 === null ? 'n/a' : String(r.feeSats_p50)).padStart(8),
    ].join(' '));
  }
  lines.push('');
  lines.push('Pareto objectives (no scalar score): latency, cpu, memory, txBytes, maxUnlock, fee, reliability');
  if (summary.panels.warm.length && summary.panels.cold.length) {
    lines.push('panels: warm-resident and cold-installed are reported separately (not conflated)');
  }
  return lines.join('\n');
}
