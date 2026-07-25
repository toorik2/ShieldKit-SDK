// verify_fresh_byte_fidelity.mjs — INDEPENDENT adversarial byte-fidelity on FRESH partitions.
// Widths/phases NOT used by the build (12/14/greedy/opt) nor prior verifier (13/16):
//   (A) uniform width 15, (B) width-14 PHASE-SHIFTED by 5 (boundaries {5,19,33,...}).
// For each fresh chunk we compare:
//   PLANNER-NATIVE  = chunkplan.chunkBytes(costVec,lo,hi,params).bytes  (pure analytical, what the DP consumes)
//   REAL            = true minimal accepting tuned bytes on the libauth BCH-2026 covenant token tx
//   FORMULA-ON-OP   = 35 + max(floor, ceil((op_measured-42800)/799))    (L1: needs a real max-pad eval)
// Refuted iff PLANNER-NATIVE != REAL for any fresh chunk.
import { readFileSync } from 'node:fs';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBn254Adapter, rewriteGeneratedLazyImport } from './bn254_adapter.mjs';
import { chunkBytes, planOptimal, normalizeParams, validateCostVec } from './chunkplan.mjs';

const adapter = await loadBn254Adapter();
const { genChunk, inState, outState } = adapter.generator;
const { compileFileBytecodeRaw, commitBin, CATEGORY } = adapter.millermath;
const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } = adapter.libauth;
const HERE = dirname(fileURLToPath(import.meta.url));

const CV = JSON.parse(readFileSync(join(HERE, 'bn254_costvec_v3.json'), 'utf8'));
const N = CV.meta.numOps;
const OP_BUDGET = 8_032_800, FEAS_MARGIN = 20_000;
const PROBE = '/tmp/_bn254_ff.cash';
const VM = createVirtualMachineBch2026(false);
const gen = (lo, hi, isFinal, reloc) => rewriteGeneratedLazyImport(genChunk(lo, hi, isFinal, reloc), adapter);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

function buildCtx(lo, hi) {
  const isFinal = hi === N, relocGenesis = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, relocGenesis));
  const redeem = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covInLimbs = relocGenesis ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const floor = argb.length + tail + 2;
  return { redeem: redeem.length, tail, argBytes: argb.length, floor, inCommit: commitBin(covInLimbs), outCommit: commitBin(outLimbs), locking,
    mk: (t) => Uint8Array.from([...padBytes(t - argb.length - tail), ...argb, ...rpush]) };
}
function evalAt(ctx, target) {
  const st = VM.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.inCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: ctx.mk(target) }],
      outputs: [{ lockingBytecode: ctx.locking, valueSatoshis: 1000n, token: tok(ctx.outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1, op: st.metrics.operationCost };
}
const cache = new Map();
function measureReal(lo, hi) {
  const key = `${lo},${hi}`; if (cache.has(key)) return cache.get(key);
  let ctx, r; try { ctx = buildCtx(lo, hi); } catch (e) { r = { feasible: false, compileError: String(e?.message ?? e).slice(0, 70) }; cache.set(key, r); return r; }
  const top = evalAt(ctx, 10000);
  if (!top.accepted) { r = { feasible: false, op10000: top.op, floor: ctx.floor }; cache.set(key, r); return r; }
  let L = Math.min(10000, Math.max(ctx.floor, Math.ceil((top.op - 42800) / 799)));
  while (L < 10000 && !evalAt(ctx, L).accepted) L++;
  while (L > ctx.floor && evalAt(ctx, L - 1).accepted) L--;
  r = { feasible: true, tunedUnlock: L, tunedBytes: 35 + L, op10000: top.op, floor: ctx.floor };
  cache.set(key, r); return r;
}

// ---- param build IDENTICAL to bn254_plan_validate.mjs adapter (with LIVE deltas) ----
const rawOp10000 = (lo, hi, isFinal, reloc) => {
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]);
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const st = VM.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(covIn)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.from([...padBytes(10000 - argb.length - tail), ...argb, ...rpush]) }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 } });
  return { op: st.metrics.operationCost, redeem: redeem.length };
};
const { perOp, redPerOp, K, redBase } = CV;
{ const s = 340; const a = rawOp10000(s, 347, false, false), b = rawOp10000(s, 348, false, false); perOp[347] = b.op - a.op; redPerOp[347] = b.redeem - a.redeem; }
let deltaGen; { const h = 14; const g = CV.genesisSweep.find((r) => r.hi === h); deltaGen = (g.op10000 - perOp.slice(0, h).reduce((a, b) => a + b, 0)) - K; }
let deltaFin; { const r = CV.finalSweep.find((x) => x.lo === 346); deltaFin = (r.op10000 - perOp.slice(346, 348).reduce((a, b) => a + b, 0)) - K; }
const HDR = 3;
const redeemBytesOf = (lo, hi) => { let r = redBase; for (let k = lo; k < hi; k++) r += redPerOp[k]; return r; };
const costVec = [];
for (let k = 0; k < N; k++) { let oc = perOp[k] - redPerOp[k]; if (k === 0) oc += deltaGen; if (k === N - 1) oc += deltaFin;
  costVec.push({ id: `m[${k}]`, stage: 'miller', opCost: oc, opCostWorstCase: oc, boundaryStateBytes: CV.boundaryStateBytes[k], forcedCutBefore: false }); }
let finalForcedCut = N - 1;
for (let lo = N - 1; lo >= N - 8; lo--) { if (measureReal(lo, N).feasible) finalForcedCut = lo; else break; }
costVec[finalForcedCut].forcedCutBefore = true;
validateCostVec(costVec);
const params = normalizeParams({ opCostPerByte: 799, densityBase: 41, minPad: 2, lockingBytes: 35, targetUnlock: 10000, padSafety: 0, hashIterCost: 64,
  opBudget: OP_BUDGET - FEAS_MARGIN - 10041, finalStateBytes: CV.boundaryStateBytes[N],
  overheadOp: () => K - redBase - HDR - 10041, redeemBytes: redeemBytesOf, pushHeader: () => HDR });
const NATIVE = (lo, hi) => chunkBytes(costVec, lo, hi, params).bytes;   // planner's analytical prediction

// ---- fresh partitions (feasibility-backed-off, forced final chunk) ----
function freshUniform(w, phase = 0) {
  const cuts = [];
  if (phase > 0) { // lead chunk covers [0,phase) feasibly
    let hi = Math.min(finalForcedCut, phase);
    while (hi > 1 && !measureReal(0, hi).feasible) hi--;
    cuts.push(0, hi);
  } else cuts.push(0);
  let lo = cuts[cuts.length - 1];
  while (lo < finalForcedCut) {
    let hi = Math.min(finalForcedCut, lo + w);
    while (hi > lo + 1 && !measureReal(lo, hi).feasible) hi--;
    if (hi <= lo) throw new Error(`stuck ${lo}`);
    cuts.push(hi); lo = hi;
  }
  cuts.push(N);
  return cuts;
}
function validate(name, cuts) {
  let nativeTot = 0, realTot = 0, l1Tot = 0, nativeMis = 0, l1Mis = 0, maxNativeErr = 0, feas = true, worstNativeUnder = 0;
  const rows = [];
  for (let i = 0; i + 1 < cuts.length; i++) {
    const lo = cuts[i], hi = cuts[i + 1];
    const m = measureReal(lo, hi);
    const nb = NATIVE(lo, hi);
    if (!m.feasible) { feas = false; rows.push({ lo, hi, real: 'INFEASIBLE', native: nb }); continue; }
    const l1b = 35 + Math.min(10000, Math.max(m.floor, Math.ceil((m.op10000 - 42800) / 799)));
    nativeTot += nb; realTot += m.tunedBytes; l1Tot += l1b;
    if (nb !== m.tunedBytes) nativeMis++;
    if (l1b !== m.tunedBytes) l1Mis++;
    const err = nb - m.tunedBytes;
    maxNativeErr = Math.max(maxNativeErr, Math.abs(err));
    worstNativeUnder = Math.min(worstNativeUnder, err);
    rows.push({ lo, hi, real: m.tunedBytes, native: nb, nativeDiff: err, l1: l1b, l1Diff: l1b - m.tunedBytes });
  }
  return { name, chunks: cuts.length - 1, cuts, feasibleAll: feas, nativeTot, realTot, l1Tot, nativeMismatch: nativeMis, l1Mismatch: l1Mis, maxNativeErr, worstNativeUnder, rows };
}

const FRESH = [
  ['fresh-uniform-15', freshUniform(15)],
  ['fresh-width14-phase5', freshUniform(14, 5)],
];
const results = FRESH.map(([n, c]) => validate(n, c));

// planOptimal native vs reality on ITS OWN returned partition
const opt = planOptimal(costVec, params);
const optCuts = [0, ...opt.partition.map((c) => c.hi)];
let optRealTot = 0, optFeasible = true, optFeasChunks = 0, optTotalChunks = 0;
for (let i = 0; i + 1 < optCuts.length; i++) { const m = measureReal(optCuts[i], optCuts[i + 1]); optTotalChunks++;
  if (!m.feasible) { optFeasible = false; continue; } optFeasChunks++; optRealTot += m.tunedBytes; }

const report = {
  env: { deltaGen, deltaFin, perOp347: perOp[347], stored_perOp347: CV.perOp[347], finalForcedCut,
    driftNote: 'live-measured deltas vs the cached costvec; concurrent regen may make cached perOp stale' },
  planOptimal_native: { chunks: opt.chunkCount, cuts: optCuts, nativeTotalBytes: opt.totalBytes,
    realFeasibleChunks: optFeasChunks, totalChunks: optTotalChunks, feasibleAll: optFeasible,
    realMeasuredTotalOfFeasible: optRealTot,
    a1MaxWorstCaseOp: opt.trustManifest.a1Certificate.maxWorstCaseChunkOp, a1Pass: opt.trustManifest.a1Certificate.pass },
  freshPartitions: results.map((r) => ({ name: r.name, chunks: r.chunks, feasibleAll: r.feasibleAll,
    NATIVE_total: r.nativeTot, REAL_total: r.realTot, L1_total: r.l1Tot,
    NATIVE_mismatch: r.nativeMismatch, L1_mismatch: r.l1Mismatch,
    NATIVE_vs_real: r.nativeTot - r.realTot, maxNativeByteErr: r.maxNativeErr, worstNativeUnder: r.worstNativeUnder })),
};
console.log(JSON.stringify(report, null, 2));
console.log('\n--- fresh-uniform-15 per-chunk (real | native planner chunkBytes | l1 formula-on-op) ---');
for (const row of results[0].rows) console.log(JSON.stringify(row));
writeFileSync(join(HERE, 'verify_fresh_byte_fidelity_report.json'), JSON.stringify({ report, rows15: results[0].rows, rowsPhase5: results[1].rows }, null, 2));
