import { measure, flush, compileCount, N, OP_BUDGET } from './_optgap_measure.mjs';

const FORCED = new Set([345]);           // forced final cut
const BUDGET = OP_BUDGET;                 // TRUE consensus budget 8,032,800 (not the shrunk 8,011,838)

function chunkCost(lo, hi) {
  const m = measure(lo, hi);
  return (m.feasible && Number.isFinite(m.realWorstOp) && m.realWorstOp <= BUDGET) ? m.realBytes : Infinity;
}
function totalBytes(cuts) {
  let t = 0; for (let i = 0; i+1 < cuts.length; i++) { const c = chunkCost(cuts[i], cuts[i+1]); if (!Number.isFinite(c)) return Infinity; t += c; } return t;
}
// local boundary search, single-boundary moves ±k, true-budget feasibility
function localSearch(cuts0, k) {
  let cuts = cuts0.slice(); let improved = true, sweeps = 0, moves = 0;
  while (improved && sweeps < 200) {
    improved = false; sweeps++;
    for (let bi = 1; bi + 1 < cuts.length; bi++) {
      const lo = cuts[bi-1], mid = cuts[bi], hi = cuts[bi+1];
      const base = chunkCost(lo, mid) + chunkCost(mid, hi);
      if (!Number.isFinite(base)) continue;
      let bestDelta = 0, bestMid = mid;
      for (let d = -k; d <= k; d++) {
        if (d === 0) continue;
        const nm = mid + d;
        if (nm <= lo || nm >= hi) continue;
        if (FORCED.has(mid) || FORCED.has(nm)) continue;
        let crosses = false;
        for (const f of FORCED) if (f > lo && f < hi && (f > Math.min(mid,nm) && f <= Math.max(mid,nm))) crosses = true;
        if (crosses) continue;
        const cand = chunkCost(lo, nm) + chunkCost(nm, hi);
        const delta = cand - base;
        if (delta < bestDelta - 1e-9) { bestDelta = delta; bestMid = nm; }
      }
      if (bestMid !== mid) { cuts[bi] = bestMid; improved = true; moves++; }
    }
  }
  return { cuts, total: totalBytes(cuts), sweeps, moves };
}

const toolCuts = [0,18,36,52,71,88,105,123,138,155,173,189,207,225,242,260,276,293,311,328,345,348];
const dpCuts   = [0,18,36,53,71,89,106,123,138,155,173,190,207,225,242,259,277,294,311,328,345,348];

const t0 = Date.now();
console.log('baseline tool total:', totalBytes(toolCuts));
for (const k of [2,3]) {
  const r = localSearch(toolCuts, k);
  console.log(`localSearch from tool k=${k}: total ${r.total} sweeps ${r.sweeps} moves ${r.moves}`);
  console.log('  cuts', JSON.stringify(r.cuts));
  flush();
}
for (const k of [2,3]) {
  const r = localSearch(dpCuts, k);
  console.log(`localSearch from DP k=${k}: total ${r.total} sweeps ${r.sweeps} moves ${r.moves}`);
  console.log('  cuts', JSON.stringify(r.cuts));
  flush();
}
flush();
console.log('compiles this run:', compileCount(), 'ms', Date.now()-t0);
