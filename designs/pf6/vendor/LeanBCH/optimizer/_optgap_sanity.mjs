import { measure, evalPartition, flush, compileCount, N, OP_BUDGET } from './_optgap_measure.mjs';
const toolCuts = [0,18,36,52,71,88,105,123,138,155,173,189,207,225,242,260,276,293,311,328,345,348];
const t0 = Date.now();
const r = evalPartition(toolCuts, OP_BUDGET);
console.log('N =', N, 'OP_BUDGET =', OP_BUDGET);
console.log('tool plan: chunks', toolCuts.length-1, 'totalRealBytes', r.totalRealBytes, 'maxRealWorstOp', r.maxRealWorstOp, 'feasible', r.feasible);
console.log('slack to consensus budget:', OP_BUDGET - r.maxRealWorstOp);
flush();
console.log('compiles:', compileCount(), 'ms', Date.now()-t0);
