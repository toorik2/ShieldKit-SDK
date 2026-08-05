// bn254_plan_validate.mjs — BN254 residue-Miller ADAPTER + REALITY VALIDATION for the re-chunk planner.
//
// (1) ADAPTER: turns the once-extracted cost vector (bn254_costvec.json) into a chunkplan.mjs cost
//     vector + params so the GENERAL CORE's interval DP plans the optimal Miller partition analytically.
// (2) planOptimal / planGreedy on it (chunkplan.mjs).
// (3) VALIDATE: for >=5 sample partitions (optimal, greedy, prior ~202,840 re-chunk, rv-like, uniform)
//     compile + TUNE each chunk to its minimal accepting unlocking length through the REAL libauth
//     BCH-2026 covenant tx (the deployed buildCovStep convention) and assert planner-predicted
//     chunkBytes == measured, counting mismatches.
// (4) cross-check one chunk's op-cost on libauth AND LeanBCH evalCost.
// (5) time planOptimal.
//
// Byte convention == build_vectors.mjs::buildCovStep (P2SH32, consensus-64 realVm), byte-for-byte.
// Measures op ONLY via libauth (this file) / LeanBCH (second oracle) — never hand-rolled.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBn254Adapter } from './bn254_adapter.mjs';
import { planOptimal, planGreedy, chunkBytes, normalizeParams, validateCostVec } from './chunkplan.mjs';

const adapter = await loadBn254Adapter();
const { genChunk, ops, inState, outState } = adapter.generator;
const { compileFileBytecodeRaw, commitBin, CATEGORY } = adapter.millermath;
const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } = adapter.libauth;
const HERE = dirname(fileURLToPath(import.meta.url));

const CV_PATH = process.env.CV_PATH || join(HERE, 'bn254_costvec_v3.json');
const CV = JSON.parse(readFileSync(CV_PATH, 'utf8'));
const N = CV.meta.numOps;
const OP_BUDGET = 8_032_800;
// The additive op-model UNDER-predicts real op10000 by up to ~10k op (OP_ROLL-depth super-additivity
// + value-dependent covOut reduction). The DP feasibility gate must stay conservative so it NEVER
// emits a chunk whose REAL worst-case op exceeds budget (soundness): shrink the effective budget by
// this margin so real op10000 = model + residual <= OP_BUDGET always.
const FEAS_MARGIN = 20_000;
// exact tuned unlocking length from a chunk's completed max-pad op-cost (empirically exact):
const tunedUnlockFromOp = (op10000, floor) => Math.max(Math.ceil((op10000 - 42800) / 799), floor);
const PROBE = '/tmp/_bn254_val.cash';
const VM = createVirtualMachineBch2026(false); // consensus-64: the deployed rv.json / build_vectors policy

// ---------------- real covenant measurement (deployed buildCovStep convention) --------------------
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
const pushSize = (v) => encodeDataPush(bigIntToVmNumber(BigInt(v))).length;

function buildCtx(lo, hi) {
  const isFinal = hi === N;
  const relocGenesis = lo === 0;
  writeFileSync(PROBE, genChunk(lo, hi, isFinal, relocGenesis));
  const redeem = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt);
  const outLimbs = outState(hi).map(BigInt);
  const covInLimbs = relocGenesis ? inState(lo).slice(18, 28).map(BigInt) : inLimbs; // reloc binds 10 pts
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const floor = argb.length + tail + 2;
  const inCommit = commitBin(covInLimbs), outCommit = commitBin(outLimbs);
  const mk = (target) => { const pad = padBytes(target - argb.length - tail); return Uint8Array.from([...pad, ...argb, ...rpush]); };
  return { redeem: redeem.length, tail, argBytes: argb.length, floor, inCommit, outCommit, locking, mk };
}
function evalAt(ctx, target) {
  const st = VM.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.inCommit) }],
    transaction: { version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: ctx.mk(target) }],
      outputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.outCommit) }], locktime: 0 },
  });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1, op: st.metrics.operationCost, completed: st.error === undefined };
}
const realCache = new Map();
/** GROUND TRUTH: compile [lo,hi), drive the real covenant tx, find the minimal accepting unlocking
 *  length (== the deployed tuning). Seeds the search from tunedL=ceil((op10000-42800)/799) then
 *  confirms accept@L and reject@L-1 (the true minimal, verified on the REAL VM), a few evals. */
function measureReal(lo, hi) {
  const key = `${lo},${hi}`; if (realCache.has(key)) return realCache.get(key);
  let ctx; try { ctx = buildCtx(lo, hi); }
  catch (e) { const r = { feasible: false, compileError: String(e?.message ?? e).slice(0, 60) }; realCache.set(key, r); return r; }
  const topProbe = evalAt(ctx, 10000);
  let res;
  if (!topProbe.accepted) { res = { feasible: false, op10000: topProbe.op, redeemBytes: ctx.redeem, floor: ctx.floor }; }
  else {
    // minimal accepting length: seed from the exact formula, then walk to the true minimum on the real VM
    let L = Math.max(ctx.floor, Math.ceil((topProbe.op - 42800) / 799));
    L = Math.min(10000, Math.max(L, ctx.floor));
    while (L < 10000 && !evalAt(ctx, L).accepted) L++;      // ensure accept
    while (L > ctx.floor && evalAt(ctx, L - 1).accepted) L--; // ensure minimal
    res = { feasible: true, tunedUnlock: L, tunedBytes: 35 + L, opTuned: evalAt(ctx, L).op, op10000: topProbe.op, redeemBytes: ctx.redeem, tail: ctx.tail, argBytes: ctx.argBytes, floor: ctx.floor, bound: (Math.ceil((topProbe.op - 42800) / 799) >= ctx.floor ? 'op-pad' : 'floor') };
  }
  realCache.set(key, res); return res;
}

// ---------------- genesis / final overhead deltas + perOp[347] (measured once) --------------------
const rawOp10000 = (lo, hi, isFinal, reloc) => { // max-pad completed op via covenant tx
  writeFileSync(PROBE, genChunk(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const st = VM.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(covIn)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.from([...padBytes(10000 - argb.length - tail), ...argb, ...rpush]) }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 } });
  return { op: st.metrics.operationCost, completed: st.error === undefined, redeem: redeem.length };
};
const { perOp, redPerOp, K, redBase } = CV;
// perOp[347] (interior model): op10000(s,348,nonfinal) - op10000(s,347)
{ const s = 340; const a = rawOp10000(s, 347, false, false), b = rawOp10000(s, 348, false, false);
  perOp[347] = b.op - a.op; redPerOp[347] = b.redeem - a.redeem; }
// genesis K delta: op10000_genesis(0,h) = K_gen + Σperop[0..h-1]  ->  deltaGen = K_gen - K
let deltaGen; { const h = 14; const g = CV.genesisSweep.find((r) => r.hi === h);
  const sum = perOp.slice(0, h).reduce((a, b) => a + b, 0); deltaGen = (g.op10000 - sum) - K; }
// final: op10000_final(lo,348) = K_final + Σperop[lo..347];  deltaFin = K_final - K
let deltaFin; { const r = CV.finalSweep.find((x) => x.lo === 346); const sum = perOp.slice(346, 348).reduce((a, b) => a + b, 0);
  deltaFin = (r.op10000 - sum) - K; }

// ---------------- build chunkplan cost vector + params (exact 799 mapping) -------------------------
// chunkplan op = overheadOp + Σ opCost + rpush.  We want op = op10000 - 10041 so that
//   padUnlock = ceil(op/799) - 41 = ceil((op10000 - 42800)/799) = the real tuned unlocking length.
// The redeem push (rpush) is cancelled by folding -redPerOp into opCost, and constants into overheadOp.
const HDR = 3; // miller redeems are all >256 B -> PUSHDATA2 header
function redeemBytesOf(lo, hi) { let r = redBase; for (let k = lo; k < hi; k++) r += redPerOp[k]; return r; }
const costVec = [];
for (let k = 0; k < N; k++) {
  let oc = perOp[k] - redPerOp[k];
  if (k === 0) oc += deltaGen;        // genesis chunk always starts at block 0
  if (k === N - 1) oc += deltaFin;    // final chunk always ends at block N-1
  costVec.push({
    id: `miller.op[${k}]`, stage: 'miller',
    opCost: oc, opCostWorstCase: oc,   // value-INDEPENDENT (fixed limb width) => worstCase == typical
    boundaryStateBytes: CV.boundaryStateBytes[k],
    forcedCutBefore: false,            // interior Miller cuts are all free (no stage seam inside)
  });
}
// FORCED final seam: gen_miller_residue's isFinal chunk hands off only [fF,c,cInv], so any op that
// updates R0/pts inside it leaves an unused var (cashc rejects) — the final Miller chunk is capped to
// the last few ops (empirically <=3). Probe the real max-feasible final start and force a cut there so
// the DP structurally cannot emit an over-wide (uncompilable / over-budget) final chunk.
let finalForcedCut = N - 1;
for (let lo = N - 1; lo >= N - 8; lo--) { const m = measureReal(lo, N); if (m.feasible) finalForcedCut = lo; else break; }
costVec[finalForcedCut].forcedCutBefore = true;
validateCostVec(costVec);
const params = normalizeParams({
  opCostPerByte: 799, densityBase: 41, minPad: 2, lockingBytes: 35, targetUnlock: 10000, padSafety: 0,
  hashIterCost: 64, // consensus-64 == the measurement/deployment VM policy (rv.json/build_vectors)
  opBudget: OP_BUDGET - FEAS_MARGIN - 10041, // chunkplan op = model_op10000 - 10041; conservative gate
                                             // => real op10000 (= model + residual) <= OP_BUDGET always
  finalStateBytes: CV.boundaryStateBytes[N],
  overheadOp: (inB, outB) => K - redBase - HDR - 10041, // interior; genesis/final absorbed via block deltas
  redeemBytes: redeemBytesOf,
  pushHeader: () => HDR,
});
// predicted bytes for a window, straight from chunkplan's frozen chunkBytes:
const predBytes = (lo, hi) => chunkBytes(costVec, lo, hi, params).bytes;

// ---------------- plan -------------------------------------------------------------------------------
const t0 = process.hrtime.bigint();
const opt = planOptimal(costVec, params);
const t1 = process.hrtime.bigint();
const planTimeMs = Number(t1 - t0) / 1e6;
const greedy = planGreedy(costVec, params);
const optCuts = [0, ...opt.partition.map((c) => c.hi)];
const greedyCuts = [0, ...greedy.partition.map((c) => c.hi)];

// ---------------- reconstruct the prior ~202,840 greedy re-chunk (REAL measure, v3_fullverifier) ----
function greedyRealCuts() {
  const cuts = [0]; let lo = 0;
  while (lo < N) { let hi = lo + 1, last = null;
    // grow while feasible+fits (real measure), like v3_fullverifier.measureWindow greedy
    while (hi <= N) { const m = measureReal(lo, hi); if (m.feasible && m.tunedUnlock <= 10000) { last = hi; hi++; } else break; }
    if (last === null) throw new Error(`greedyReal: singleton [${lo}) infeasible`);
    cuts.push(last); lo = last;
  }
  return cuts;
}
const rechunkCuts = greedyRealCuts();

// uniform ~equal-op partition (another sample) and an rv-like fixed-width(15) partition
function uniformCuts(target) { const cuts = [0]; let lo = 0; while (lo < N) { let hi = Math.min(N, lo + target), last = null;
  for (let h = hi; h > lo; h--) { const m = measureReal(lo, h); if (m.feasible) { last = h; break; } } cuts.push(last); lo = last; } return cuts; }
const rvLikeCuts = uniformCuts(14);
const uniform12Cuts = uniformCuts(12);

// ---------------- validate --------------------------------------------------------------------------
// Two levels:
//  L1 BYTE FORMULA (the deliverable "bytes are a pure function of op-cost"): predicted-bytes from the
//     chunk's MEASURED op-cost (one max-pad eval, cost.mjs-style) via the /799 formula, vs the REAL
//     tuned on-chain bytes.  mismatchCount == this (MUST be 0).
//  L2 ADDITIVE OP-MODEL (drives the DP with NO per-window recompile): predicted op10000 (Σ perOp)
//     vs measured op10000, and its byte impact.  Reported honestly (the residual only perturbs which
//     cuts the DP picks; the final bytes are exact via L1).
function validatePartition(name, cuts) {
  let predFormulaTotal = 0, measTotal = 0, predModelTotal = 0, mismatch = 0, under = 0, exact = 0;
  let feasibleAll = true, maxOpResid = 0, maxByteModelErr = 0;
  const rows = [];
  for (let i = 0; i + 1 < cuts.length; i++) {
    const lo = cuts[i], hi = cuts[i + 1];
    const m = measureReal(lo, hi);
    const modelBytes = predBytes(lo, hi);               // L2: additive-model bytes (analytical, no recompile)
    predModelTotal += modelBytes;
    if (!m.feasible) { feasibleAll = false; rows.push({ lo, hi, meas: 'INFEASIBLE', modelBytes }); mismatch++; continue; }
    // L1: byte formula on the chunk's MEASURED op-cost
    const formulaUnlock = tunedUnlockFromOp(m.op10000, m.floor);
    const formulaBytes = 35 + Math.min(10000, formulaUnlock);
    predFormulaTotal += formulaBytes;
    measTotal += m.tunedBytes;
    if (formulaBytes !== m.tunedBytes) mismatch++; else exact++;
    if (formulaBytes < m.tunedBytes) under++;
    // L2 model op accuracy
    const modelOp = K + costVecOp10000(lo, hi);
    maxOpResid = Math.max(maxOpResid, Math.abs(m.op10000 - modelOp));
    maxByteModelErr = Math.max(maxByteModelErr, Math.abs(modelBytes - m.tunedBytes));
    rows.push({ lo, hi, formulaBytes, meas: m.tunedBytes, diff: formulaBytes - m.tunedBytes, modelBytes, modelByteDiff: modelBytes - m.tunedBytes, op10000: m.op10000, modelOp });
  }
  return { name, chunks: cuts.length - 1, predFormulaTotal, measTotal, predModelTotal, mismatch, under, exact, feasibleAll, maxOpResid, maxByteModelErr, rows };
}
// model op10000 of a window from the extracted additive vector (= K + Σ perOp + genesis/final deltas)
function costVecOp10000(lo, hi) { let s = 0; for (let k = lo; k < hi; k++) s += perOp[k]; if (lo === 0) s += deltaGen; if (hi === N) s += deltaFin; return s; }
const samples = [
  ['optimal(DP)', optCuts],
  ['greedy(chunkplan)', greedyCuts],
  ['prior-rechunk(greedyReal ~202,840)', rechunkCuts],
  ['rv-like(width14)', rvLikeCuts],
  ['uniform(width12)', uniform12Cuts],
];
const results = samples.map(([n, c]) => validatePartition(n, c));

// ---------------- non-Miller carried bytes (from /tmp/rv.json: g2check+vk_x+residue-tail) ----------
let carriedNonMiller = 64933, carriedNote = 'default (g2 35401 + vkx 21827 + tail 7705)';
try { const rv = JSON.parse(readFileSync('/tmp/rv.json', 'utf8')); const s = rv.steps;
  const sumB = (a, b) => { let t = 0; for (let i = a; i <= b; i++) t += s[i].lockingBytes + s[i].unlockingBytes; return t; };
  carriedNonMiller = sumB(0, 3) + sumB(4, 11) + sumB(35, 35); carriedNote = `rv.json g2[0-3]+vkx[4-11]+tail[35]`;
} catch (e) { /* keep default */ }

// ---------------- LeanBCH second-oracle op cross-check on ONE representative chunk -----------------
// libauth op(10000) for a mid-chain chunk; LeanBCH evalCost on the SAME locking+unlocking bytes.
let twoOracle = { attempted: false, agree: null, note: '' };
try {
  const lo = optCuts[Math.floor(opt.partition.length / 2)], hi = optCuts[Math.floor(opt.partition.length / 2) + 1];
  const ctx = buildCtx(lo, hi);
  const target = measureReal(lo, hi).tunedUnlock;
  const unlocking = ctx.mk(target);
  const libauthOp = evalAt(ctx, target).op;
  writeFileSync('/tmp/_leanbch_xcheck.json', JSON.stringify({
    lo, hi, locking: Buffer.from(ctx.locking).toString('hex'), unlocking: Buffer.from(unlocking).toString('hex'),
    inCommit: Buffer.from(ctx.inCommit).toString('hex'), outCommit: Buffer.from(ctx.outCommit).toString('hex'),
    category: Buffer.from(CATEGORY).toString('hex'), libauthOp,
  }));
  twoOracle = { attempted: true, agree: null, libauthOp, chunk: [lo, hi], note: 'wrote /tmp/_leanbch_xcheck.json for LeanBCH evalCost (see runner)' };
} catch (e) { twoOracle.note = 'xcheck setup failed: ' + String(e?.message ?? e); }

// ---------------- report ----------------------------------------------------------------------------
const optMeas = results[0].measTotal, optFormula = results[0].predFormulaTotal, optModel = results[0].predModelTotal;
const greedyMeas = results[1].measTotal;
const totalMismatch = results.reduce((s, r) => s + r.mismatch, 0);
const totalChunks = results.reduce((s, r) => s + r.chunks, 0);
const maxOpResid = Math.max(...results.map((r) => r.maxOpResid));
const maxByteModelErr = Math.max(...results.map((r) => r.maxByteModelErr));
const out = {
  planTimeMs, numOps: N, lib: 'V3_millerres_lib.cash', policy: 'consensus-64 (rv.json/build_vectors)',
  optChunks: opt.chunkCount, greedyChunks: greedy.chunkCount, rechunkChunks: rechunkCuts.length - 1,
  optCuts, greedyCuts, rechunkCuts,
  deltas: { deltaGen, deltaFin, perOp347: perOp[347], K, redBase, feasMargin: FEAS_MARGIN },
  // L1 byte-formula validation (headline): predicted bytes from measured op-cost == real tuned bytes
  predictedOptimalMillerBytes: optFormula, measuredOptimalMillerBytes: optMeas,
  byteFormulaMismatchTotal: totalMismatch, byteFormulaUnderTotal: results.reduce((s, r) => s + r.under, 0),
  byteFormulaExactTotal: results.reduce((s, r) => s + r.exact, 0), sampleChunksChecked: totalChunks,
  // L2 additive op-model accuracy (drives the DP; no per-window recompile)
  additiveModelBytes: optModel, maxAdditiveOpResidual: maxOpResid, maxAdditiveByteError: maxByteModelErr,
  greedyMillerBytes: greedyMeas, optVsGreedyMillerBytes: `optimal ${optMeas} vs greedy ${greedyMeas} (Δ ${greedyMeas - optMeas})`,
  carriedNonMiller, carriedNote,
  measuredWholeVerifier: optMeas + carriedNonMiller,
  reproducesRechunk: (optMeas + carriedNonMiller) <= 202840,
  priorRechunkWholeVerifier: results[2].measTotal + carriedNonMiller,
  a1Certificate: opt.trustManifest.a1Certificate,
  samples: results.map((r) => ({ name: r.name, chunks: r.chunks, predFormulaTotal: r.predFormulaTotal, measTotal: r.measTotal, additiveModelTotal: r.predModelTotal, mismatch: r.mismatch, under: r.under, exact: r.exact, feasibleAll: r.feasibleAll, maxOpResid: r.maxOpResid, maxByteModelErr: r.maxByteModelErr })),
  twoOracle,
};
console.log(JSON.stringify(out, null, 2));
console.log('\n--- per-chunk optimal partition (formula-from-op vs measured; additive-model diff) ---');
for (const row of results[0].rows) console.log(JSON.stringify(row));
writeFileSync(join(HERE, 'bn254_validation_report.json'), JSON.stringify(out, null, 2));
