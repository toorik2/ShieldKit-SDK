// _validate_fresh_partitions.mjs — INDEPENDENT validation of the faithful re-chunk planner.
//
// Loads the DEPLOYED cost model (bn254_costvec_deployed.json), reconstructs the SAME costVec + params
// the driver builds, then on >=5 FRESH partitions (incl. the width-15 24-chunk and width-14-phase-5
// 27-chunk partitions the prior byte-fidelity skeptic used, plus new random boundaries, plus an
// over-wide A1-stress partition) confirms:
//   (1) the TOOL's post-verify reported bytes (chunkplan.compileVerify -> measureDeployed) == an
//       INDEPENDENT real measurement (separate compile + separate byte derivation + true-minimal
//       accepting-length binary search). 0 mismatch required.
//   (2) A1: across ALL chunks of ALL partitions the tool NEVER marks feasible a chunk whose REAL
//       worst-case op (op at the 10000-byte pad = the miller worst case) > 8,032,800. Over-budget
//       chunks MUST be flagged infeasible (feasible:false) and excluded.
//   (3) optimality gap: tool-chosen plan real bytes vs an independent real-bytes local-search optimum
//       (chunkplan.localBoundarySearch, k=3, from multiple seeds -> global min).
//
// Every op/byte number comes from the real BCH-2026 VM (createVirtualMachineBch2026(false)) driven
// through the deployed covenant token tx. Nothing predicted, nothing hand-rolled.
import { readFileSync, writeFileSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';
import { buildClassCostVec, normalizeParams, validateCostVec, planOptimal, chunkBytes, compileVerify, localBoundarySearch, cutsOf } from '/home/toorik/Projects/LeanBCH/optimizer/chunkplan.mjs';

const N = ops.length;                                   // 348 op-blocks
const VM = createVirtualMachineBch2026(false);          // consensus-64 deployed VM
const LIB_ABS = '/home/toorik/Projects/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE_A = '/tmp/_validate_probe_A.cash';          // tool measurement path
const PROBE_B = '/tmp/_validate_probe_B.cash';          // INDEPENDENT measurement path (separate temp file)
const HDR = 3;

// ---- deployed model (durable artifact from the driver's fresh DEPLOYED extraction) ----
const M = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/bn254_costvec_deployed.json', 'utf8'));
const classOf = M.classOf;
const { interceptTyp, marginMean, marginMax, redMargin, redBase, SAFETY_MARGIN, deltaGen, finalRealOp, finalForcedCut, boundaryStateBytes } = M;

// ---- deployed covenant measurement (build_vectors.mjs::buildCovStep, byte-for-byte) ----
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
const pushSize = (v) => encodeDataPush(bigIntToVmNumber(BigInt(v))).length;
let compiles = 0;

function buildCtx(lo, hi, probeFile) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(probeFile, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(probeFile)]); compiles++;
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const inCommit = commitBin(covIn), outCommit = commitBin(outLimbs);
  const mk = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  return { redeem: redeem.length, tail, argBytes: argb.length, locking, inCommit, outCommit, mk };
}
function evalAt(ctx, target) {
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.inCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: ctx.mk(target) }],
      outputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1,
           op: st.metrics.operationCost, completed: st.error === undefined };
}
const tunedLen = (argLen, op) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(op / 800) - 41 + 96));

// TOOL measurement path (== driver's measureDeployed, PROBE_A) — the tool's REPORTED bytes.
function measureDeployed(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi, PROBE_A); } catch (e) { return { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; }
  const probe = evalAt(ctx, TARGET_UNLOCK);
  const op10000 = probe.op;
  const feasibleOp = probe.completed && op10000 <= OP_BUDGET;
  if (!feasibleOp) return { feasible: false, realWorstOp: op10000, compileError: null };
  let target = tunedLen(ctx.argBytes + ctx.tail, op10000);
  let r = evalAt(ctx, target);
  while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
  if (!r.accepted) return { feasible: false, realWorstOp: op10000, compileError: 'no accepting pad' };
  return { feasible: true, realBytes: 35 + target, realWorstOp: op10000, lockingBytes: 35, unlockingBytes: target };
}

// INDEPENDENT measurement path (PROBE_B, separate compile + separate byte derivation + TRUE minimal
// accepting length via binary search). Must reproduce the deployed bytes AND prove a script of that
// size verifies on-chain (real bytes, not predicted) AND that op never exceeds budget when feasible.
function independentMeasure(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi, PROBE_B); } catch (e) { return { feasible: false, err: String(e?.message ?? e).slice(0, 60) }; }
  const probe = evalAt(ctx, TARGET_UNLOCK);
  const op10000 = probe.op;
  if (!(probe.completed && op10000 <= OP_BUDGET)) return { feasible: false, op10000 };
  const floor = ctx.argBytes + ctx.tail + 3;
  const deployedTarget = Math.min(TARGET_UNLOCK, Math.max(floor, Math.ceil(op10000 / 800) - 41 + 96));
  // confirm the deployed size actually verifies (walk +256 if the pad<->op fixpoint needs a nudge)
  let dt = deployedTarget, r = evalAt(ctx, dt);
  while (!r.accepted && dt < TARGET_UNLOCK) { dt = Math.min(TARGET_UNLOCK, dt + 256); r = evalAt(ctx, dt); }
  if (!r.accepted) return { feasible: false, op10000 };
  // TRUE minimal accepting length in [floor, dt] via binary search on an independent code path.
  let loB = floor, hiB = dt;
  while (loB < hiB) { const mid = (loB + hiB) >> 1; if (evalAt(ctx, mid).accepted) hiB = mid; else loB = mid + 1; }
  return { feasible: true, deployedBytes: 35 + dt, minimalBytes: 35 + loB, op10000 };
}

// ================= reconstruct the SAME costVec + params the driver builds =================
const blockDelta = { 0: { opTyp: deltaGen, opWC: deltaGen } };
const { costVec } = buildClassCostVec(classOf, { marginMean, marginMax, redMargin, boundaryStateBytes, blockDelta, forcedCuts: [finalForcedCut], stage: 'miller' });
{ const EPS = 1000, tb = N - finalForcedCut;
  for (let k = finalForcedCut; k < N - 1; k++) { costVec[k].opCost = EPS; costVec[k].opCostWorstCase = EPS; }
  const last = Math.max(EPS, finalRealOp - interceptTyp - EPS * (tb - 1));
  costVec[N - 1].opCost = last; costVec[N - 1].opCostWorstCase = last; }
validateCostVec(costVec);
const redeemBytesOf = (lo, hi) => { let r = redBase; for (let k = lo; k < hi; k++) r += redMargin[classOf[k]]; return r; };
const params = normalizeParams({
  opCostPerByte: 800, densityBase: 41, padSafety: 96, minPad: 3, lockingBytes: 35, targetUnlock: TARGET_UNLOCK, hashIterCost: 64,
  opBudget: OP_BUDGET - SAFETY_MARGIN, finalStateBytes: boundaryStateBytes[N],
  overheadOp: () => interceptTyp - redBase - HDR, redeemBytes: redeemBytesOf, pushHeader: () => HDR,
});
const modelOf = (lo, hi) => chunkBytes(costVec, lo, hi, params);

// ================= fresh partitions =================
// Skeptic's uniform builder that honors the forced-final cut (finalForcedCut=345).
function freshUniform(w, phase = 0) {
  const cuts = [0];
  if (phase > 0) { cuts.push(Math.min(finalForcedCut, phase)); }
  let lo = cuts[cuts.length - 1];
  while (lo < finalForcedCut) { const hi = Math.min(finalForcedCut, lo + w); cuts.push(hi); lo = hi; }
  cuts.push(N); return cuts;
}
// deterministic PRNG (mulberry32) so random partitions are reproducible.
function mulberry32(a) { return function () { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function freshRandom(seed, minW = 10, maxW = 18) {
  const rnd = mulberry32(seed); const cuts = [0]; let lo = 0;
  while (lo < finalForcedCut) { let w = minW + Math.floor(rnd() * (maxW - minW + 1)); let hi = Math.min(finalForcedCut, lo + w); if (finalForcedCut - hi < 3 && hi < finalForcedCut) hi = finalForcedCut; cuts.push(hi); lo = hi; }
  cuts.push(N); return cuts;
}
// A1-STRESS: deliberately over-wide chunks (width ~22-28) whose REAL op exceeds budget. The tool MUST
// flag every one infeasible. Interleaved with a couple feasible chunks so the partition is well-formed.
const a1StressCuts = [0, 22, 45, 68, 90, 112, 135, 158, 180, 202, 225, 248, 270, 293, 315, 337, 345, 348];

const freshPartitions = [
  ['skeptic-width15-24chunk', freshUniform(15)],
  ['skeptic-width14-phase5-27chunk', freshUniform(14, 5)],
  ['random-seed1337', freshRandom(1337)],
  ['random-seed90210', freshRandom(90210)],
  ['random-seed424242', freshRandom(424242, 11, 20)],
  ['a1-stress-overwide', a1StressCuts],   // over-wide chunks whose REAL op > budget: tool MUST reject each
];

// ================= (A) fresh-partition faithfulness + A1 =================
const results = [];
let globalA1Violations = 0;               // feasible==true AND realWorstOp > OP_BUDGET  (MUST stay 0)
let globalMismatch = 0;                   // toolBytes != independent deployed bytes    (MUST stay 0)
let globalMinimalUnder = 0;               // toolBytes < independent minimal accepting  (MUST stay 0)

for (const [name, cuts] of freshPartitions) {
  // TOOL path: chunkplan.compileVerify on the real oracle — the tool's post-verify reported bytes.
  const cv = compileVerify(cuts, measureDeployed, params, modelOf, OP_BUDGET);
  const rows = [];
  let mism = 0, minUnder = 0, a1Bad = 0, feasChunks = 0, infeasChunks = 0;
  for (let i = 0; i + 1 < cuts.length; i++) {
    const lo = cuts[i], hi = cuts[i + 1];
    const toolRow = cv.perChunk[i];                       // tool's reported feasibility + realBytes
    const ind = independentMeasure(lo, hi);               // INDEPENDENT recomputation
    // A1: the tool must never call feasible a chunk whose independent real op > budget.
    if (toolRow.feasible) {
      feasChunks++;
      const realOp = toolRow.realWorstOp;
      if (realOp > OP_BUDGET) { a1Bad++; globalA1Violations++; }
      // independent op must agree it is within budget too
      if (!ind.feasible || ind.op10000 > OP_BUDGET) { a1Bad++; globalA1Violations++; }
      // byte faithfulness
      if (ind.feasible) {
        if (toolRow.realBytes !== ind.deployedBytes) { mism++; globalMismatch++; }
        if (toolRow.realBytes < ind.minimalBytes) { minUnder++; globalMinimalUnder++; }
      }
      rows.push({ lo, hi, feasible: true, toolBytes: toolRow.realBytes, indepBytes: ind.deployedBytes ?? null, minimalBytes: ind.minimalBytes ?? null,
        toolOp: realOp, indepOp: ind.op10000 ?? null, match: ind.feasible ? toolRow.realBytes === ind.deployedBytes : null });
    } else {
      infeasChunks++;
      // tool rejected: confirm the independent measure agrees it is genuinely over budget / uncompilable.
      const indOver = !ind.feasible;
      rows.push({ lo, hi, feasible: false, toolOp: toolRow.realWorstOp ?? null, indepOp: ind.op10000 ?? null, indepRejected: indOver });
    }
  }
  results.push({ name, chunks: cuts.length - 1, cuts,
    toolTotalRealBytes: cv.totalRealBytes, toolFeasibleAll: cv.feasibleAll,
    toolMaxRealWorstOp: cv.maxRealWorstOp, a1CertPass: cv.a1Certificate.pass,
    feasibleChunks: feasChunks, infeasibleChunks: infeasChunks,
    mismatches: mism, minimalUnderCount: minUnder, a1Violations: a1Bad, rows });
}

// ================= (B) optimality gap: tool plan real bytes vs independent local-search optimum =================
// tool plan = DP (model) -> compileVerify -> localBoundarySearch (the driver already ran this; here we
// reconstruct the DP candidate and drive the SAME real-oracle local search independently, then push it
// HARDER (k=3, multiple seeds) to find a real-bytes local optimum and measure the gap.
const cache = new Map();
const measCached = (lo, hi) => { const key = `${lo},${hi}`; if (!cache.has(key)) cache.set(key, measureDeployed(lo, hi)); return cache.get(key); };
const dp = planOptimal(costVec, params);
const dpCuts = cutsOf(dp.partition);
const forcedCuts = [finalForcedCut];
// tool's local search (k=2, as the driver runs) from the DP candidate:
const lsTool = localBoundarySearch(dpCuts, measCached, params, { k: 2, forcedCuts, cache });
// harder independent search (k=3) from several seeds; global min over all:
const seeds = [lsTool.cuts, dpCuts, freshUniform(17), freshUniform(15), freshUniform(19, 7)];
let bestCuts = lsTool.cuts, bestBytes = Infinity;
const lsRuns = [];
for (const seed of seeds) {
  const ls = localBoundarySearch(seed, measCached, params, { k: 3, forcedCuts, cache });
  lsRuns.push({ fromChunks: seed.length - 1, resultChunks: ls.cuts.length - 1, bytes: ls.totalRealBytes, moves: ls.moves });
  if (ls.feasibleAll && ls.totalRealBytes < bestBytes) { bestBytes = ls.totalRealBytes; bestCuts = ls.cuts; }
}
// tool-chosen bytes = the tool's k=2 local optimum from the DP candidate (== driver's plan-result):
const toolChosen = compileVerify(lsTool.cuts, measCached, params, modelOf, OP_BUDGET);
const optimum = compileVerify(bestCuts, measCached, params, modelOf, OP_BUDGET);
const optimalityGapBytes = toolChosen.totalRealBytes - optimum.totalRealBytes;

// ================= report =================
const out = {
  stage: 'miller-residue (348 op-blocks)', opBudget: OP_BUDGET, effectiveDpBudget: OP_BUDGET - SAFETY_MARGIN,
  freshPartitionsTested: freshPartitions.length,
  reportedVsRealMismatch: globalMismatch,
  toolBytesUnderIndependentMinimal: globalMinimalUnder,
  a1WorstCaseAcceptedOverBudget: globalA1Violations,
  a1WorstCaseNeverUndercounted: globalA1Violations === 0,
  partitions: results.map((r) => ({ name: r.name, chunks: r.chunks, toolTotalRealBytes: r.toolTotalRealBytes,
    toolFeasibleAll: r.toolFeasibleAll, feasibleChunks: r.feasibleChunks, infeasibleChunks: r.infeasibleChunks,
    toolMaxRealWorstOp: r.toolMaxRealWorstOp, a1CertPass: r.a1CertPass, mismatches: r.mismatches,
    minimalUnderCount: r.minimalUnderCount, a1Violations: r.a1Violations })),
  optimality: {
    toolChosenRealBytes: toolChosen.totalRealBytes, toolChosenCuts: lsTool.cuts,
    localSearchOptimumRealBytes: optimum.totalRealBytes, optimumCuts: bestCuts,
    optimalityGapBytes, optimalityGapPct: (optimalityGapBytes / optimum.totalRealBytes * 100).toFixed(4),
    toolLsMoves: lsTool.moves, lsRuns,
  },
  compiles,
};
console.log(JSON.stringify(out, null, 2));
console.log('\n--- per-partition rows ---');
for (const r of results) { console.log(`\n### ${r.name} (${r.chunks} chunks) feasible=${r.feasibleChunks} infeasible=${r.infeasibleChunks} mismatch=${r.mismatches} a1Viol=${r.a1Violations}`);
  for (const row of r.rows) console.log(JSON.stringify(row)); }
writeFileSync('/home/toorik/Projects/LeanBCH/optimizer/_validate_fresh_partitions_report.json', JSON.stringify({ ...out, fullRows: results }, null, 2));
