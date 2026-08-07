/**
 * Shared monotonic span recorder for action benchmark traces.
 * Preserves parentage, attempts, parallel branches, and resource counters.
 */

import { performance } from 'node:perf_hooks';
import { createHash, randomUUID } from 'node:crypto';

export const SPAN_STATUSES = Object.freeze([
  'executed',
  'not_applicable',
  'unavailable',
  'failed',
]);

const STATUS_SET = new Set(SPAN_STATUSES);

function nowMs() {
  return performance.now();
}

function requireStatus(status) {
  if (!STATUS_SET.has(status)) {
    throw new Error(`span status must be one of: ${SPAN_STATUSES.join(', ')}`);
  }
  return status;
}

/**
 * @typedef {object} SpanOpen
 * @property {string} id
 * @property {string|null} parentId
 * @property {string} name
 * @property {number} attempt
 * @property {number} startOffsetMs
 * @property {object} meta
 */

export class SpanRecorder {
  /**
   * @param {{ originMs?: number, design?: string, profile?: string }} [opts]
   */
  constructor(opts = {}) {
    this.originMs = typeof opts.originMs === 'number' ? opts.originMs : nowMs();
    this.design = opts.design ?? null;
    this.profile = opts.profile ?? null;
    /** @type {Map<string, object>} */
    this._spans = new Map();
    /** @type {Map<string, SpanOpen>} */
    this._open = new Map();
  }

  /** Absolute wall clock epoch for provenance only (not used for span math). */
  wallNow() {
    return Date.now();
  }

  offsetNow() {
    return nowMs() - this.originMs;
  }

  /**
   * Open a child span. Parallel siblings share the same parentId.
   * @param {string} name
   * @param {{ parentId?: string|null, attempt?: number, meta?: object, id?: string }} [opts]
   */
  start(name, opts = {}) {
    if (typeof name !== 'string' || name.length === 0) {
      throw new Error('span name must be a non-empty string');
    }
    const id = typeof opts.id === 'string' && opts.id.length > 0
      ? opts.id
      : randomUUID();
    if (this._open.has(id) || this._spans.has(id)) {
      throw new Error(`span id already in use: ${id}`);
    }
    const parentId = opts.parentId === undefined ? null : opts.parentId;
    if (parentId !== null) {
      if (!this._open.has(parentId) && !this._spans.has(parentId)) {
        throw new Error(`unknown parent span: ${parentId}`);
      }
    }
    const attempt = opts.attempt === undefined ? 1 : opts.attempt;
    if (!Number.isSafeInteger(attempt) || attempt < 1) {
      throw new Error('attempt must be a safe integer >= 1');
    }
    const open = {
      id,
      parentId,
      name,
      attempt,
      startOffsetMs: this.offsetNow(),
      meta: opts.meta && typeof opts.meta === 'object' ? { ...opts.meta } : {},
    };
    this._open.set(id, open);
    return id;
  }

  /**
   * Close a span.
   * @param {string} id
   * @param {{ status?: string, reason?: string|null, resources?: object, endOffsetMs?: number }} [opts]
   */
  end(id, opts = {}) {
    const open = this._open.get(id);
    if (!open) throw new Error(`span not open: ${id}`);
    const status = requireStatus(opts.status ?? 'executed');
    const endOffsetMs = typeof opts.endOffsetMs === 'number'
      ? opts.endOffsetMs
      : this.offsetNow();
    if (endOffsetMs < open.startOffsetMs) {
      throw new Error('span endOffsetMs must be >= startOffsetMs');
    }
    const span = Object.freeze({
      id: open.id,
      parentId: open.parentId,
      name: open.name,
      attempt: open.attempt,
      status,
      reason: opts.reason === undefined || opts.reason === null
        ? null
        : String(opts.reason),
      startOffsetMs: open.startOffsetMs,
      endOffsetMs,
      durationMs: endOffsetMs - open.startOffsetMs,
      design: this.design,
      profile: this.profile,
      meta: Object.freeze({ ...open.meta }),
      resources: Object.freeze({
        wallMs: endOffsetMs - open.startOffsetMs,
        userCpuMs: null,
        systemCpuMs: null,
        peakRssBytes: null,
        ...(opts.resources && typeof opts.resources === 'object' ? opts.resources : {}),
      }),
    });
    this._open.delete(id);
    this._spans.set(id, span);
    return span;
  }

  /**
   * Record a fully closed span (e.g. from product timingsMs without live hooks).
   */
  recordClosed({
    name,
    parentId = null,
    attempt = 1,
    startOffsetMs,
    endOffsetMs,
    status = 'executed',
    reason = null,
    meta = {},
    resources = {},
    id = null,
  }) {
    if (typeof startOffsetMs !== 'number' || typeof endOffsetMs !== 'number') {
      throw new Error('startOffsetMs and endOffsetMs required');
    }
    if (endOffsetMs < startOffsetMs) {
      throw new Error('endOffsetMs must be >= startOffsetMs');
    }
    const spanId = id || randomUUID();
    if (this._spans.has(spanId) || this._open.has(spanId)) {
      throw new Error(`span id already in use: ${spanId}`);
    }
    if (parentId !== null && !this._spans.has(parentId) && !this._open.has(parentId)) {
      // Allow recording children after parents if parent already closed.
      // parentId may reference a span already in _spans only.
      if (!this._spans.has(parentId)) {
        throw new Error(`unknown parent span: ${parentId}`);
      }
    }
    const span = Object.freeze({
      id: spanId,
      parentId,
      name,
      attempt,
      status: requireStatus(status),
      reason: reason === null ? null : String(reason),
      startOffsetMs,
      endOffsetMs,
      durationMs: endOffsetMs - startOffsetMs,
      design: this.design,
      profile: this.profile,
      meta: Object.freeze({ ...meta }),
      resources: Object.freeze({
        wallMs: endOffsetMs - startOffsetMs,
        userCpuMs: null,
        systemCpuMs: null,
        peakRssBytes: null,
        ...resources,
      }),
    });
    this._spans.set(spanId, span);
    return span;
  }

  /** Run async work inside a span; failure marks status=failed. */
  async measure(name, fn, opts = {}) {
    const id = this.start(name, opts);
    try {
      const result = await fn(id);
      this.end(id, { status: 'executed' });
      return result;
    } catch (error) {
      this.end(id, {
        status: 'failed',
        reason: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  openCount() {
    return this._open.size;
  }

  /** Freeze the completed span list. Fails if any span still open. */
  finalize() {
    if (this._open.size > 0) {
      const names = [...this._open.values()].map((s) => s.name).join(', ');
      throw new Error(`cannot finalize with open spans: ${names}`);
    }
    return Object.freeze([...this._spans.values()].map((s) => Object.freeze({ ...s })));
  }

  /** Snapshot including open spans as incomplete (for failure evidence). */
  snapshot({ forceCloseOpen = true, openStatus = 'failed', openReason = 'recorder snapshot with open span' } = {}) {
    if (forceCloseOpen) {
      for (const id of [...this._open.keys()]) {
        this.end(id, { status: openStatus, reason: openReason });
      }
    }
    return this.finalize();
  }
}

/**
 * Build a coarse span DAG from product timingsMs maps (PF10 seed).
 * Nested sequential stages under intent; does not invent parallel work.
 */
export function spansFromProductTimings({
  timingsMs = {},
  commandStartOffsetMs = 0,
  intentStartOffsetMs = 0,
  design = null,
  profile = null,
} = {}) {
  const rec = new SpanRecorder({ design, profile, originMs: 0 });
  // Use absolute offsets relative to command start = 0 via originMs 0 and nowMs override
  // We build closed spans with explicit offsets.
  const command = rec.recordClosed({
    name: 'command',
    parentId: null,
    startOffsetMs: commandStartOffsetMs,
    endOffsetMs: commandStartOffsetMs + (num(timingsMs.total) ?? num(timingsMs.commandTotal) ?? sumKnown(timingsMs) ?? 0),
    meta: { source: 'product-timingsMs' },
  });
  const intentEnd = intentStartOffsetMs + (num(timingsMs.total) ?? 0);
  const intent = rec.recordClosed({
    name: 'intent',
    parentId: command.id,
    startOffsetMs: intentStartOffsetMs,
    endOffsetMs: Math.max(intentEnd, intentStartOffsetMs),
  });

  let cursor = intentStartOffsetMs;
  const stages = [
    ['snapshot', ['stateRead', 'fundingRead']],
    ['transition', ['treeAndPreparation']],
    ['proof', ['witnessCalculation', 'proofGeneration', 'proofVerification', 'proofTotal']],
    ['materialize', ['witnessAssembly']],
    ['transaction', ['signingAndVm']],
    ['local_validation', ['localVm']],
    ['admission', ['admission']],
    ['post_accept', ['commit']],
  ];

  for (const [stageName, keys] of stages) {
    const parts = keys
      .map((k) => ({ key: k, ms: num(timingsMs[k]) }))
      .filter((p) => p.ms !== null);
    if (parts.length === 0) {
      rec.recordClosed({
        name: stageName,
        parentId: intent.id,
        startOffsetMs: cursor,
        endOffsetMs: cursor,
        status: 'unavailable',
        reason: 'not present in product timingsMs',
      });
      continue;
    }
    // Sequential children; wall of stage = sum of available keys (product already sequential)
    const stageStart = cursor;
    let stageMs = 0;
    for (const p of parts) stageMs += p.ms;
    const stage = rec.recordClosed({
      name: stageName,
      parentId: intent.id,
      startOffsetMs: stageStart,
      endOffsetMs: stageStart + stageMs,
    });
    let childCursor = stageStart;
    for (const p of parts) {
      rec.recordClosed({
        name: p.key,
        parentId: stage.id,
        startOffsetMs: childCursor,
        endOffsetMs: childCursor + p.ms,
      });
      childCursor += p.ms;
    }
    cursor = stageStart + stageMs;
  }

  return rec.finalize();
}

function num(v) {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v;
  return null;
}

function sumKnown(timingsMs) {
  let s = 0;
  let any = false;
  for (const v of Object.values(timingsMs)) {
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0) {
      s += v;
      any = true;
    }
  }
  return any ? s : null;
}

export function hashSpans(spans) {
  const canonical = JSON.stringify(spans.map((s) => ({
    id: s.id,
    parentId: s.parentId,
    name: s.name,
    attempt: s.attempt,
    status: s.status,
    startOffsetMs: s.startOffsetMs,
    endOffsetMs: s.endOffsetMs,
  })));
  return createHash('sha256').update(canonical).digest('hex');
}
