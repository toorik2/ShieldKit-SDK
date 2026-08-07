/**
 * Lifecycle observer / span hooks for benchmarks.
 * Real stages only — no parallel send path.
 */

import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';

export const LIFECYCLE_STAGES = Object.freeze([
  'preparation',
  'proof',
  'assembly',
  'whole_transaction_validation',
  'durable_staging',
  'admission',
  'exact_readback',
  'local_commit',
]);

/**
 * Create an observer that records stage spans (compatible with action-bench hooks).
 */
export function createLifecycleObserver({ onSpan = null } = {}) {
  const spans = [];
  const open = new Map();
  const origin = performance.now();

  function start(stage, meta = {}) {
    if (!LIFECYCLE_STAGES.includes(stage) && stage !== 'command' && stage !== 'intent') {
      // allow extension stages but mark unknown
    }
    const id = randomUUID();
    open.set(id, {
      id,
      stage,
      startOffsetMs: performance.now() - origin,
      meta,
    });
    return id;
  }

  function end(id, { status = 'executed', reason = null, meta = {} } = {}) {
    const o = open.get(id);
    if (!o) throw new Error(`unknown span ${id}`);
    open.delete(id);
    const endOffsetMs = performance.now() - origin;
    const span = Object.freeze({
      id: o.id,
      stage: o.stage,
      name: o.stage,
      startOffsetMs: o.startOffsetMs,
      endOffsetMs,
      durationMs: endOffsetMs - o.startOffsetMs,
      status,
      reason,
      meta: Object.freeze({ ...o.meta, ...meta }),
    });
    spans.push(span);
    if (typeof onSpan === 'function') onSpan(span);
    return span;
  }

  async function measure(stage, fn, meta = {}) {
    const id = start(stage, meta);
    try {
      const result = await fn();
      end(id, { status: 'executed' });
      return result;
    } catch (error) {
      end(id, {
        status: 'failed',
        reason: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  return {
    start,
    end,
    measure,
    spans: () => Object.freeze([...spans]),
    stages: LIFECYCLE_STAGES,
  };
}
