import { measure, flush, compileCount, N, OP_BUDGET } from './_optgap_measure.mjs';
// Measure the interval band needed for an exact real-bytes interval DP.
// For each lo, scan hi upward; stop when infeasible (op monotone in hi). Band [minW, maxW].
const t0 = Date.now();
const MINW = 11, MAXW = 22;
let feasCount = 0, infeasCount = 0;
for (let lo = 0; lo <= N; lo++) {
  // tail region: also measure small widths (down to 1) so the forced-final arrangement is fully covered
  const lowW = (lo >= N - 14) ? 1 : MINW;
  for (let w = lowW; w <= MAXW; w++) {
    const hi = lo + w;
    if (hi > N) break;
    const m = measure(lo, hi);
    if (m.feasible) feasCount++; else infeasCount++;
    // op monotone increasing in hi: once infeasible due to op>budget (not compile err), larger hi also infeasible
    if (!m.feasible && m.realWorstOp !== undefined && m.realWorstOp > OP_BUDGET && w >= MINW && lo < N - 14) break;
  }
  if (lo % 20 === 0) { flush(); process.stdout.write(`lo=${lo} feas=${feasCount} infeas=${infeasCount} compiles=${compileCount()} ms=${Date.now()-t0}\n`); }
}
flush();
console.log('DONE measband: feas', feasCount, 'infeas', infeasCount, 'newCompiles', compileCount(), 'ms', Date.now()-t0);
