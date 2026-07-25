import { readFileSync } from 'node:fs';
import { N, OP_BUDGET } from './_optgap_measure.mjs';
const CACHE = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/_optgap_cache.json','utf8'));
const BUDGET = OP_BUDGET; // TRUE consensus budget
function cost(lo, hi) {
  const m = CACHE[`${lo},${hi}`];
  if (!m || !m.feasible || !(m.realWorstOp <= BUDGET)) return Infinity;
  return m.realBytes;
}
// Exact interval DP: dp[j] = min bytes to cover [0,j). Global optimum given additive chunk costs.
const dp = new Array(N+1).fill(Infinity);
const back = new Array(N+1).fill(-1);
dp[0] = 0;
for (let j = 1; j <= N; j++) {
  for (let lo = Math.max(0, j - 22); lo < j; lo++) {
    if (dp[lo] === Infinity) continue;
    const c = cost(lo, j);
    if (!Number.isFinite(c)) continue;
    if (dp[lo] + c < dp[j]) { dp[j] = dp[lo] + c; back[j] = lo; }
  }
}
if (dp[N] === Infinity) { console.log('DP: no feasible partition found in measured band'); process.exit(0); }
// reconstruct
const cuts = [N]; let j = N; while (j > 0) { j = back[j]; cuts.push(j); }
cuts.reverse();
let maxOp = 0; const rows = [];
for (let i = 0; i+1 < cuts.length; i++) { const m = CACHE[`${cuts[i]},${cuts[i+1]}`]; maxOp = Math.max(maxOp, m.realWorstOp); rows.push({lo:cuts[i],hi:cuts[i+1],bytes:m.realBytes,op:m.realWorstOp}); }
console.log('EXACT DP (true budget) global optimum');
console.log('  chunks:', cuts.length-1);
console.log('  totalRealBytes:', dp[N]);
console.log('  maxRealWorstOp:', maxOp, 'slack', BUDGET-maxOp);
console.log('  cuts:', JSON.stringify(cuts));
console.log('  tool total: 195306  => improvement:', 195306 - dp[N], 'bytes');
console.log('  per-chunk:'); for (const r of rows) console.log('   ', JSON.stringify(r));
