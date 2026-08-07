/**
 * Critical-path wall time over a span DAG.
 * Parallel (overlapping) siblings contribute max, not sum.
 */

/**
 * @param {Array<{ id: string, parentId: string|null, startOffsetMs: number, endOffsetMs: number, status?: string }>} spans
 * @returns {{ criticalPathMs: number, path: string[], pathNames: string[] }}
 */
export function criticalPath(spans) {
  if (!Array.isArray(spans)) throw new Error('spans must be an array');
  if (spans.length === 0) {
    return Object.freeze({ criticalPathMs: 0, path: Object.freeze([]), pathNames: Object.freeze([]) });
  }

  const byId = new Map();
  const children = new Map();
  for (const s of spans) {
    if (!s || typeof s.id !== 'string') throw new Error('each span requires string id');
    if (byId.has(s.id)) throw new Error(`duplicate span id: ${s.id}`);
    byId.set(s.id, s);
    children.set(s.id, []);
  }
  const roots = [];
  for (const s of spans) {
    if (s.parentId === null || s.parentId === undefined) {
      roots.push(s.id);
    } else {
      if (!byId.has(s.parentId)) {
        throw new Error(`orphan span ${s.id}: unknown parent ${s.parentId}`);
      }
      children.get(s.parentId).push(s.id);
    }
  }
  if (roots.length === 0) throw new Error('span DAG has no root');

  /** longest path length (ms) ending at node, via exclusive child contributions */
  const memo = new Map();
  const pred = new Map();

  function nodeExclusive(id) {
    const s = byId.get(id);
    // Prefer own duration; fall back to end-start.
    const dur = typeof s.durationMs === 'number'
      ? s.durationMs
      : s.endOffsetMs - s.startOffsetMs;
    return Number.isFinite(dur) && dur >= 0 ? dur : 0;
  }

  /**
   * Critical path length through the subtree rooted at id.
   * Children that overlap in time are parallel: use max of each parallel group.
   * Non-overlapping children are sequential (sorted by start).
   *
   * Simpler plan-aligned rule used here:
   * - For a node, look at direct children.
   * - Partition children into concurrent groups by overlap.
   * - Critical child contribution = sum over sequential groups of max(group paths).
   * - Total for node = nodeExclusive only if no children; else max(nodeExclusive,
   *   span of children critical path). Actually wall critical path through a
   *   hierarchical trace is: max over root-to-leaf of sum of exclusive segments
   *   along path, but exclusive segments must not double-count nesting.
   *
   * Correct nested rule: critical path ms of a node = max(
   *   exclusive self if leaf,
   *   max over children of (criticalPath(child)) when children parallel,
   *   sum when sequential.
   * ) — but parent duration already includes children wall if recorded as wall
   * envelope. Plan: "calculate the critical path rather than summing overlapping".
   *
   * We compute: for each root, criticalPath = end of last activity on critical
   * chain using dependency: children are independent if their intervals overlap;
   * otherwise ordered by startOffsetMs.
   */
  function crit(id) {
    if (memo.has(id)) return memo.get(id);
    const kids = children.get(id);
    if (kids.length === 0) {
      const v = nodeExclusive(id);
      memo.set(id, v);
      pred.set(id, null);
      return v;
    }
    // Sort children by start
    const ordered = [...kids].sort(
      (a, b) => byId.get(a).startOffsetMs - byId.get(b).startOffsetMs
        || byId.get(a).endOffsetMs - byId.get(b).endOffsetMs,
    );
    // Greedy sequential groups: if next overlaps current group max end, parallel
    const groups = [];
    let group = [ordered[0]];
    let groupEnd = byId.get(ordered[0]).endOffsetMs;
    for (let i = 1; i < ordered.length; i += 1) {
      const c = ordered[i];
      const s = byId.get(c);
      if (s.startOffsetMs < groupEnd) {
        group.push(c);
        groupEnd = Math.max(groupEnd, s.endOffsetMs);
      } else {
        groups.push(group);
        group = [c];
        groupEnd = s.endOffsetMs;
      }
    }
    groups.push(group);

    let total = 0;
    const groupPicks = [];
    for (const g of groups) {
      let best = -1;
      let bestId = g[0];
      for (const cid of g) {
        const v = crit(cid);
        if (v > best) {
          best = v;
          bestId = cid;
        }
      }
      total += best;
      groupPicks.push(bestId);
    }
    // Chain: first pick is predecessor link for reconstruction of one path
    pred.set(id, groupPicks[groupPicks.length - 1]);
    // Store full chain of picks for path reconstruction
    memo.set(id, total);
    memo.set(`${id}__picks`, groupPicks);
    return total;
  }

  let bestRoot = roots[0];
  let bestVal = -1;
  for (const r of roots) {
    const v = crit(r);
    if (v > bestVal) {
      bestVal = v;
      bestRoot = r;
    }
  }

  // Reconstruct path names via picks
  const path = [];
  const pathNames = [];
  function walk(id) {
    path.push(id);
    pathNames.push(byId.get(id).name);
    const picks = memo.get(`${id}__picks`);
    if (Array.isArray(picks)) {
      for (const p of picks) walk(p);
    }
  }
  walk(bestRoot);

  return Object.freeze({
    criticalPathMs: bestVal,
    path: Object.freeze(path),
    pathNames: Object.freeze(pathNames),
  });
}

/**
 * Wall envelope of a span set (max end − min start), independent of nesting.
 */
export function wallEnvelopeMs(spans) {
  if (!Array.isArray(spans) || spans.length === 0) return 0;
  let min = Infinity;
  let max = -Infinity;
  for (const s of spans) {
    if (s.startOffsetMs < min) min = s.startOffsetMs;
    if (s.endOffsetMs > max) max = s.endOffsetMs;
  }
  return max - min;
}
