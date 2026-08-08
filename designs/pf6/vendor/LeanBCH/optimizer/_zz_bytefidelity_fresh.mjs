// _zz_bytefidelity_fresh.mjs — ADVERSARIAL byte-fidelity-fresh verification of chunkplan.
//
// Lens: On BRAND-NEW partitions (not used in build or validate), does the tool's REPORTED bytes
// == a real compiled measurement? Confirm (a) the tool's compileVerify/localBoundarySearch actually
// COMPILE (re-verify) rather than trusting the model, and (b) no reported number is a model prediction.
//
// Method: reconstruct the tool's params+costVec from the PERSISTED deployed model (no re-extract),
// use chunkplan's REAL compileVerify / localBoundarySearch / plan, feed them the tool's real-compile
// oracle (measureDeployed, byte-for-byte the adapter), and cross-check every reported byte total on
// FRESH partitions against a GENUINELY INDEPENDENT recompile: a SEPARATE temp file, a SEPARATE byte
// derivation, and a TRUE-MINIMAL accepting-length binary search. Refuted if any reported byte total
// diverges from a real compile, or if the search/verify is found to trust the model.

import { writeFileSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';
import { buildClassCostVec, normalizeParams, validateCostVec, chunkBytes, compileVerify, localBoundarySearch, plan, cutsOf } from '/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/chunkplan.mjs';

const N = ops.length;
const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const HDR = 3;
const cls = (o) => (o.t === 'dl' || o.t === 'al') ? o.t + (o.j === 0 ? '0' : 'B') : o.t;
const classOf = ops.map(cls);

const M = JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/bn254_costvec_deployed.json', 'utf8'));
const { interceptTyp, marginMean, marginMax, redMargin, redBase, SAFETY_MARGIN, deltaGen, finalRealOp, finalForcedCut, boundaryStateBytes } = M;

// ---------- shared context builder (byte-for-byte the adapter buildCovStep convention) ----------
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

function buildCtx(lo, hi, probeFile) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(probeFile, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(probeFile)]);   // DEPLOYED (rescheduleStacks ON)
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const floor = argb.length + tail + 3;
  const inCommit = commitBin(covIn), outCommit = commitBin(outLimbs);
  const mk = (target) => Uint8Array.from([...padBytes(target - argb.length - tail), ...argb, ...rpush]);
  return { redeem: redeem.length, tail, argBytes: argb.length, floor, locking, inCommit, outCommit, mk };
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

// ---------- TOOL oracle: exactly the adapter measureDeployed (compileVerify path) ----------
// Cached by (lo,hi) — deterministic; the tool itself caches via measCached in plan(). We count the
// number of ACTUAL compiles (cache misses) so we can prove local search triggers real compiles.
let toolCompiles = 0;
const TCACHE = new Map();
function toolMeasure(lo, hi) {
  const key = `${lo},${hi}`; if (TCACHE.has(key)) return TCACHE.get(key);
  toolCompiles++;
  let out;
  let ctx; try { ctx = buildCtx(lo, hi, '/tmp/_zz_tool.cash'); } catch (e) { out = { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; TCACHE.set(key, out); return out; }
  const probe = evalAt(ctx, TARGET_UNLOCK);
  const op10000 = probe.op;
  const feasibleOp = probe.completed && op10000 <= OP_BUDGET;
  if (!feasibleOp) { out = { feasible: false, realWorstOp: op10000, compileError: null }; TCACHE.set(key, out); return out; }
  let target = tunedLen(ctx.argBytes + ctx.tail, op10000);
  let r = evalAt(ctx, target);
  while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
  if (!r.accepted) { out = { feasible: false, realWorstOp: op10000, compileError: 'no accepting pad' }; TCACHE.set(key, out); return out; }
  out = { feasible: true, realBytes: 35 + target, realWorstOp: op10000, lockingBytes: 35, unlockingBytes: target };
  TCACHE.set(key, out); return out;
}

// ---------- INDEPENDENT oracle: SEPARATE temp file, SEPARATE derivation ----------
// `withMinimal` also computes the TRUE-MINIMAL accepting length via a downward accept walk (capped),
// a stricter/independent notion of "real bytes". Compile ~800ms dominates; each descent eval ~30ms.
let indepCompiles = 0;
function indepMeasure(lo, hi, withMinimal = false) {
  indepCompiles++;
  let ctx; try { ctx = buildCtx(lo, hi, '/tmp/_zz_indep.cash'); } catch (e) { return { feasible: false, err: String(e?.message ?? e).slice(0, 60) }; }
  const probe = evalAt(ctx, TARGET_UNLOCK);
  if (!(probe.completed && probe.op <= OP_BUDGET)) return { feasible: false, op10000: probe.op };
  // independent deployed-tunedLen derivation (recomputed from scratch, own accept-walk)
  let target = Math.min(TARGET_UNLOCK, Math.max(ctx.argBytes + ctx.tail + 3, Math.ceil(probe.op / 800) - 41 + 96));
  let r = evalAt(ctx, target);
  while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
  if (!r.accepted) return { feasible: false, op10000: probe.op, err: 'no accepting pad (indep)' };
  const deployedBytes = 35 + target;
  let minimalBytes = deployedBytes;
  if (withMinimal) {
    let Lmin = target, guard = 0;
    while (Lmin > ctx.floor && guard++ < 400 && evalAt(ctx, Lmin - 1).accepted) Lmin--;
    minimalBytes = 35 + Lmin;
  }
  return { feasible: true, deployedBytes, minimalBytes, op10000: probe.op };
}

// ---------- reconstruct tool params + costVec from the persisted deployed model ----------
const blockDelta = { 0: { opTyp: deltaGen, opWC: deltaGen } };
const { costVec } = buildClassCostVec(classOf, { marginMean, marginMax, redMargin, boundaryStateBytes, blockDelta, forcedCuts: [finalForcedCut], stage: 'miller' });
{ // overwrite forced-final region exactly like the adapter
  const EPS = 1000, tb = N - finalForcedCut;
  for (let k = finalForcedCut; k < N - 1; k++) { costVec[k].opCost = EPS; costVec[k].opCostWorstCase = EPS; }
  const last = Math.max(EPS, finalRealOp - interceptTyp - EPS * (tb - 1));
  costVec[N - 1].opCost = last; costVec[N - 1].opCostWorstCase = last;
}
validateCostVec(costVec);
const redeemBytesOf = (lo, hi) => { let r = redBase; for (let k = lo; k < hi; k++) r += redMargin[classOf[k]]; return r; };
const params = normalizeParams({
  opCostPerByte: 800, densityBase: 41, padSafety: 96, minPad: 3, lockingBytes: 35, targetUnlock: TARGET_UNLOCK, hashIterCost: 64,
  opBudget: OP_BUDGET - SAFETY_MARGIN, finalStateBytes: boundaryStateBytes[N],
  overheadOp: () => interceptTyp - redBase - HDR, redeemBytes: redeemBytesOf, pushHeader: () => HDR,
});
const modelOf = (lo, hi) => chunkBytes(costVec, lo, hi, params);

// ---------- FRESH partition builders (widths/phases NEVER used in build [17,19@7] or validate [15,17,19,14@5, rnd 1337/90210/424242, a1-stress]) ----------
function freshUniform(w, phase = 0) {
  const cuts = [0];
  if (phase > 0) { let hi = Math.min(finalForcedCut, phase); while (hi > 1 && !toolMeasure(0, hi).feasible) hi--; cuts.push(hi); }
  let lo = cuts[cuts.length - 1];
  while (lo < finalForcedCut) { let hi = Math.min(finalForcedCut, lo + w); while (hi > lo + 1 && !toolMeasure(lo, hi).feasible) hi--; cuts.push(hi); lo = hi; }
  cuts.push(N); return cuts;
}
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function freshRandom(seed) {
  const rnd = mulberry32(seed); const cuts = [0]; let lo = 0;
  while (lo < finalForcedCut) {
    let w = 8 + Math.floor(rnd() * 14);            // width 8..21
    let hi = Math.min(finalForcedCut, lo + w);
    while (hi > lo + 1 && !toolMeasure(lo, hi).feasible) hi--;
    cuts.push(hi); lo = hi;
  }
  cuts.push(N); return cuts;
}

const FRESH = [
  ['fresh-width13', freshUniform(13)],
  ['fresh-width21', freshUniform(21)],           // width>feasible => builder shrinks each chunk (fresh cuts)
  ['fresh-width18-phase11', freshUniform(18, 11)],
  ['fresh-random-e271828', freshRandom(271828)],
  ['fresh-random-phi161803', freshRandom(161803)],
];

// ==================================================================================================
// TEST A — tool REPORTED bytes (chunkplan.compileVerify) vs INDEPENDENT recompile, on FRESH partitions
// ==================================================================================================
const results = { partitions: [], anyMismatch: false, anyUnderMinimal: false, anyOverBudget: false, totalIndepCompiles: 0 };
for (const [name, cuts] of FRESH) {
  // THE TOOL: this is exactly what plan() calls to produce reported real bytes.
  const cv = compileVerify(cuts, toolMeasure, params, modelOf, OP_BUDGET);
  let indepTotal = 0, mism = 0, underMin = 0, over = 0, feasAll = true, maxOp = 0;
  const rowsBad = []; const minimalSpotChecks = [];
  let spotDone = 0;
  for (const row of cv.perChunk) {
    const { lo, hi } = row;
    const wantMin = spotDone < 1 && row.feasible;   // one true-minimal spot-check per partition
    const ind = indepMeasure(lo, hi, wantMin);
    if (!row.feasible || !ind.feasible) {
      // both must agree on feasibility; if the tool says feasible but indep can't compile-accept => divergence
      if (row.feasible !== !!ind.feasible) { mism++; rowsBad.push({ lo, hi, kind: 'feasibility-divergence', toolFeasible: row.feasible, indepFeasible: !!ind.feasible }); feasAll = false; }
      continue;
    }
    maxOp = Math.max(maxOp, ind.op10000);
    if (ind.op10000 > OP_BUDGET) { over++; }
    indepTotal += ind.deployedBytes;
    if (row.realBytes !== ind.deployedBytes) { mism++; rowsBad.push({ lo, hi, toolReported: row.realBytes, indepDeployed: ind.deployedBytes, diff: row.realBytes - ind.deployedBytes }); }
    if (wantMin) {
      spotDone++;
      const under = row.realBytes < ind.minimalBytes;
      if (under) { underMin++; rowsBad.push({ lo, hi, kind: 'under-true-minimal', toolReported: row.realBytes, indepMinimal: ind.minimalBytes }); }
      minimalSpotChecks.push({ lo, hi, toolReported: row.realBytes, trueMinimal: ind.minimalBytes, toolGeMinimal: row.realBytes >= ind.minimalBytes, padOverMinimal: row.realBytes - ind.minimalBytes });
    }
  }
  const toolTotal = cv.totalRealBytes;
  const rec = {
    name, chunks: cuts.length - 1,
    toolReportedTotalBytes: Number.isFinite(toolTotal) ? toolTotal : 'INFEASIBLE',
    independentDeployedTotalBytes: indepTotal, minimalSpotChecks,
    perChunkMismatches: mism, toolUnderTrueMinimal: underMin, overBudgetChunks: over,
    maxRealOp: maxOp, a1SlackAtMax: OP_BUDGET - maxOp,
    totalsEqual: Number.isFinite(toolTotal) && toolTotal === indepTotal,
    a1CertPass: cv.a1Certificate.pass,
    modelNeverUnderCountsWorstOp: cv.modelGap ? cv.modelGap.modelNeverUnderCountsWorstOp : null,
    worstOpWorstUnder: cv.modelGap ? cv.modelGap.worstOpWorstUnder : null,
    badRows: rowsBad,
  };
  results.partitions.push(rec);
  if (mism > 0 || !rec.totalsEqual) results.anyMismatch = true;
  if (underMin > 0) results.anyUnderMinimal = true;
  if (over > 0) results.anyOverBudget = true;
  console.error(`[A] ${name}: chunks=${rec.chunks} toolTotal=${rec.toolReportedTotalBytes} indep=${indepTotal} equal=${rec.totalsEqual} mism=${mism} underMin=${underMin} over=${over} maxOp=${maxOp}`);
}

// ==================================================================================================
// TEST B — does localBoundarySearch RE-VERIFY (compile) rather than trust the model?
//   1) run it on a fresh seed with a compile-COUNTING oracle => confirm it compiles during search,
//   2) confirm its returned cuts' tool-reported bytes == an independent recompile,
//   3) confirm the reported bytes equal a fresh compileVerify (no stale/model number leaks).
// ==================================================================================================
const bSeed = freshUniform(16, 3);   // fresh seed width-16 phase-3 (unused width)
const compilesBefore = toolCompiles;
const cacheB = new Map();
const measCachedB = (lo, hi) => { const key = `${lo},${hi}`; if (!cacheB.has(key)) cacheB.set(key, toolMeasure(lo, hi)); return cacheB.get(key); };
const lsB = localBoundarySearch(bSeed, measCachedB, params, { k: 2, forcedCuts: [finalForcedCut], cache: cacheB });
const compilesDuringB = toolCompiles - compilesBefore;
// re-verify the returned cuts freshly + independently
const cvB = compileVerify(lsB.cuts, toolMeasure, params, modelOf, OP_BUDGET);
let indepB = 0, mismB = 0;
for (const row of cvB.perChunk) { if (!row.feasible) continue; const ind = indepMeasure(row.lo, row.hi); indepB += ind.deployedBytes; if (row.realBytes !== ind.deployedBytes) mismB++; }
const testB = {
  seedCuts: bSeed, seedChunks: bSeed.length - 1,
  compilesDuringLocalSearch: compilesDuringB,
  lsMoves: lsB.moves, lsSweeps: lsB.sweeps,
  lsReturnedTotalRealBytes: lsB.totalRealBytes,
  freshCompileVerifyTotal: cvB.totalRealBytes,
  lsMatchesFreshVerify: lsB.totalRealBytes === cvB.totalRealBytes,
  independentRecompileTotal: indepB,
  toolVsIndependentMismatches: mismB,
  reportedEqualsIndependent: cvB.totalRealBytes === indepB,
};
console.error(`[B] localSearch: compilesDuringSearch=${compilesDuringB} moves=${lsB.moves} lsTotal=${lsB.totalRealBytes} freshVerify=${cvB.totalRealBytes} indep=${indepB} mism=${mismB}`);

// ==================================================================================================
// TEST C — ADVERSARIAL model-trust probe. Feed a SYNTHETIC oracle whose realBytes deliberately
//   DISAGREE with the chunkBytes MODEL prediction. If the tool trusted the model, its reported total
//   and its search decisions would follow the model; instead they must follow the synthetic oracle.
//   This proves reported bytes come from the oracle (a compile in production), never the model.
// ==================================================================================================
// synthetic oracle over a tiny 6-block toy: realBytes convex, minimised at interior cut a=4;
// model (chunkBytes) would predict something else entirely (large op-pad numbers).
const N7 = 6;
const realBytesFn = (lo, hi) => { const w = hi - lo; return 1000 + (w - 3) * (w - 3) * 50 + lo * 3; };
let synthCompiles = 0;
const synthMeas = (lo, hi) => { synthCompiles++; return { feasible: true, realBytes: realBytesFn(lo, hi), realWorstOp: 1_000_000 + (hi - lo) * 100_000, lockingBytes: 35, unlockingBytes: realBytesFn(lo, hi) - 35 }; };
const p7 = normalizeParams({ opBudget: OP_BUDGET, overheadOp: () => 0, redeemBytes: () => 10, finalStateBytes: 10, opCostPerByte: 800, densityBase: 41, padSafety: 96, minPad: 3 });
// a bogus modelOf that returns absurd bytes; if the tool used it, reported bytes would be absurd.
const bogusModelOf = (lo, hi) => ({ bytes: 999999, op: 1, opWorstCase: 1 });
const cvC = compileVerify([0, 2, N7], synthMeas, p7, bogusModelOf, OP_BUDGET);
const handC = realBytesFn(0, 2) + realBytesFn(2, N7);
const lsC = localBoundarySearch([0, 2, N7], synthMeas, p7, { k: 2, forcedCuts: [] });
let bestA = 1, bestTot = Infinity; for (let a = 1; a < N7; a++) { const t = realBytesFn(0, a) + realBytesFn(a, N7); if (t < bestTot) { bestTot = t; bestA = a; } }
const testC = {
  compileVerifyReportedTotal: cvC.totalRealBytes,
  handComputedFromOracle: handC,
  compileVerifyUsesOracleNotModel: cvC.totalRealBytes === handC,
  reportedNotEqualBogusModel: cvC.totalRealBytes !== 999999 * 2,
  localSearchFoundCuts: lsC.cuts,
  localSearchTotal: lsC.totalRealBytes,
  realBytesOptimum: bestTot, realBytesOptimumCutA: bestA,
  localSearchReachedRealOptimum: lsC.totalRealBytes === bestTot,
  synthCompilesMade: synthCompiles,
};
console.error(`[C] adversarial: cvUsesOracle=${testC.compileVerifyUsesOracleNotModel} lsOptimum=${testC.localSearchReachedRealOptimum} (found ${lsC.totalRealBytes} vs opt ${bestTot})`);

// ==================================================================================================
// TEST D — full plan() end-to-end on the reconstructed model: confirm plan's REPORTED total ==
//   a fresh independent recompile of plan.cuts (the headline number the tool ships).
// ==================================================================================================
const planRes = plan(costVec, params, toolMeasure, { k: 2, requireA1: true, consensusOpBudget: OP_BUDGET });
let indepPlan = 0, mismPlan = 0, overPlan = 0, maxOpPlan = 0;
for (const row of planRes.perChunk) { if (!row.feasible) continue; const ind = indepMeasure(row.lo, row.hi); indepPlan += ind.deployedBytes; if (row.realBytes !== ind.deployedBytes) mismPlan++; if (ind.op10000 > OP_BUDGET) overPlan++; maxOpPlan = Math.max(maxOpPlan, ind.op10000); }
const testD = {
  planCuts: planRes.cuts, chunkCount: planRes.chunkCount,
  planReportedTotalRealBytes: planRes.totalRealBytes,
  independentRecompileTotal: indepPlan,
  reportedEqualsIndependent: planRes.totalRealBytes === indepPlan,
  perChunkMismatches: mismPlan, overBudgetChunks: overPlan, maxRealOp: maxOpPlan,
  planMaxRealWorstOp: planRes.maxRealWorstOp, a1CertPass: planRes.a1Certificate.pass,
};
console.error(`[D] plan(): reported=${planRes.totalRealBytes} indep=${indepPlan} equal=${testD.reportedEqualsIndependent} mism=${mismPlan} over=${overPlan}`);

results.totalIndepCompiles = indepCompiles;
const summary = {
  lens: 'byte-fidelity-fresh',
  testA_freshPartitions: results,
  testB_localSearchReVerifies: testB,
  testC_adversarialModelTrust: testC,
  testD_planEndToEnd: testD,
  verdict: {
    anyReportedByteTotalDivergesFromRealCompile: results.anyMismatch || !testB.reportedEqualsIndependent || !testC.compileVerifyUsesOracleNotModel || !testD.reportedEqualsIndependent,
    anyToolBytesUnderTrueMinimal: results.anyUnderMinimal,
    anyFeasibleChunkOverBudget: results.anyOverBudget || testD.overBudgetChunks > 0,
    localSearchReVerifiesNotModel: testB.compilesDuringLocalSearch > 0 && testC.localSearchReachedRealOptimum,
    compileVerifyUsesOracleNotModel: testC.compileVerifyUsesOracleNotModel,
  },
  toolCompiles, indepCompiles,
};
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_zz_bytefidelity_fresh_report.json', JSON.stringify(summary, null, 2));
console.log(JSON.stringify(summary.verdict, null, 2));
console.error(`\nDONE. toolCompiles=${toolCompiles} indepCompiles=${indepCompiles}`);
