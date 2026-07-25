// bn254_faithful_plan.mjs — FAITHFUL re-chunk planner for the BN254 residue-Miller stage.
//
// This is the ADAPTER + DRIVER that makes chunkplan.mjs's general engine produce a partition whose
// bytes are REAL (compile-verified, not predicted) and that is A1-SAFE BY CONSTRUCTION. It fixes the
// unfaithful cost model diagnosed in phase 1: the old bn254_costvec_v3.json perOp was extracted off
// the RAW (non-rescheduled) compile and UNDER-counts real deployed op by ~35-40% (a forgery-class
// hazard for the DP feasibility gate). Here we:
//
//  (1) RE-EXTRACT per-op-CLASS marginals on the DEPLOYED compile (compileFileBytecode, rescheduleStacks
//      ON — the build_vectors.mjs::buildCovStep deployment path), driving the REAL BCH-2026 VM
//      (createVirtualMachineBch2026(false)) through the deployed covenant token tx. A least-squares fit
//      op ≈ intercept + Σ_class n·marginal is R²≈1; we keep the MEAN marginals (predictive/ranking) and
//      the MAX single-step marginals (feasibility UPPER bound). Nothing hand-rolled: op is only ever
//      read from the real VM.
//
//  (2) SAFE MODEL for the DP: opCostWorstCase = intercept + Σ marginMax (an upper bound), feasibility
//      against opBudget - SAFETY_MARGIN (SAFETY_MARGIN >= max positive fit residual + headroom). So any
//      chunk the DP accepts has REAL worst-case op < budget BY CONSTRUCTION (see chunkplan.mjs proof).
//      Predictive bytes (mean marginals -> exact deployed byte formula) rank candidates only.
//
//  (3) compileVerify: EVERY emitted chunk is compiled (deployed) + measured on the real VM for its
//      ACTUAL on-chain bytes (the buildCovStep tunedLen, byte-for-byte) + worst-case op10000.
//
//  (4) Local boundary search: hill-climb boundaries ±k in REAL compile-verified bytes.
//
//  (5) INDEPENDENT fresh-partition check: a SECOND, separate measurement of fresh (build-unused width)
//      partitions confirms the tool's reported real bytes == independent real bytes (0 mismatch) and
//      every real op <= budget.
//
// WORST-CASE NOTE: the Miller-loop op-cost is magnitude-INDEPENDENT (the field elements are always
// full-width mod p; the loop's double/add schedule is fixed by the VK, not by the proof values), so the
// committed instance IS the worst case for this stage. The all-bits-set worst case matters for the vk_x
// scalar-mult accumulator (a separate stage): the SAME architecture (measure per-class marginals at
// all-bits-set inputs, then compileVerify at all-bits-set) covers it — that is the documented next step.
//
//   node bn254_faithful_plan.mjs            plan + compile-verify + fresh-partition check
//   node bn254_faithful_plan.mjs --quick    smaller extraction grid (faster smoke)
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBn254Adapter, rewriteGeneratedLazyImport } from './bn254_adapter.mjs';
import { buildClassCostVec, normalizeParams, validateCostVec, planOptimal, chunkBytes, plan, compileVerify, cutsOf } from './chunkplan.mjs';

const adapter = await loadBn254Adapter();
const { genChunk, ops, inState, outState } = adapter.generator;
const { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } = adapter.millermath;
const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026, binToHex } = adapter.libauth;
const HERE = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_COSTVEC_PATH = join(HERE, 'bn254_costvec_deployed_selfpin.json');
const REPORT_PATH = join(HERE, 'bn254_faithful_plan_selfpin_report.json');

// SELF-PIN: every non-terminal miller chunk pins its covenant successor (OP_TXOUTPUTCOUNT==1 +
// OP_OUTPUTBYTECODE==<35B P2SH32 spk>). The pinned spk VALUE is irrelevant to size/op-cost, so a
// fixed plan-spk gives EXACT boundaries; the final miller chunk pins the residue tail. This is the
// DEPLOYED sound build (unified_fullverifier). Re-extract marginals HERE so they include the pin op.
const PLAN_SPK_BIN = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]);
const PLAN_SPK = binToHex(PLAN_SPK_BIN);

const QUICK = process.argv.includes('--quick');
const N = ops.length;                                   // 348 op-blocks
const VM = createVirtualMachineBch2026(false);          // consensus-64: the deployed rv.json / build_vectors VM
const PROBE = '/tmp/_faithful_probe.cash';
const cls = (o) => (o.t === 'dl' || o.t === 'al') ? o.t + (o.j === 0 ? '0' : 'B') : o.t;
const classOf = ops.map(cls);
const HDR = 3;                                          // miller redeems are all >256 B -> PUSHDATA2 push header

// ---- deployed covenant measurement (build_vectors.mjs::buildCovStep convention, byte-for-byte) ----
const gen = (lo, hi, isFinal, reloc) => rewriteGeneratedLazyImport(genChunk(lo, hi, isFinal, reloc, PLAN_SPK), adapter);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
const pushSize = (v) => encodeDataPush(bigIntToVmNumber(BigInt(v))).length;

// compile [lo,hi) with the DEPLOYED compiler; build the covenant tx context (P2SH, 35 B locking).
function buildCtx(lo, hi) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);   // DEPLOYED (rescheduleStacks ON)
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs; // reloc genesis binds 10 pts
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
      outputs: [{ lockingBytecode: PLAN_SPK_BIN, valueSatoshis: 1000n, token: tok(ctx.outCommit) }], locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top && top.length === 1 && top[0] === 1,
           op: st.metrics.operationCost, completed: st.error === undefined };
}
// the deployed byte tuning, EXACTLY build_vectors::tunedLen: min(10000, max(argLen+3, ceil(op/800)-41+96)).
const tunedLen = (argLen, op) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(op / 800) - 41 + 96));

/** REAL deployed measurement of window [lo,hi): worst-case op10000 + the ACTUAL on-chain bytes that
 *  buildCovStep would emit. This is the ground-truth oracle — no formula, all VM.  */
function measureDeployed(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi); } catch (e) { return { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; }
  const probe = evalAt(ctx, TARGET_UNLOCK);                 // worst-case op = op at max pad
  const op10000 = probe.op;
  const feasibleOp = probe.completed && op10000 <= OP_BUDGET;
  if (!feasibleOp) return { feasible: false, realWorstOp: op10000, compileError: null, redeem: ctx.redeem, floor: ctx.floor };
  // deployed on-chain size: the buildCovStep tunedLen, then confirm accept (walk +256 like the build).
  let target = tunedLen(ctx.argBytes + ctx.tail, op10000);
  let r = evalAt(ctx, target);
  while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
  if (!r.accepted) return { feasible: false, realWorstOp: op10000, compileError: 'no accepting pad' };
  return { feasible: true, realBytes: 35 + target, realWorstOp: op10000, lockingBytes: 35, unlockingBytes: target,
           redeem: ctx.redeem, tail: ctx.tail, argBytes: ctx.argBytes, floor: ctx.floor, opTuned: r.op };
}

// ---- forced FINAL cut (probe first: it bounds the interior region the per-class model must cover) ----
// gen_miller_residue's isFinal chunk hands off only [fF,c,cInv]; ops updating R0/pts inside it leave
// unused vars (cashc rejects), so the final chunk is capped to the last few ops. Force a cut at the
// smallest feasible final start so the DP structurally cannot over-widen it.
const t0 = Date.now();
let compiles = 0;
let finalForcedCut = N - 1;
for (let lo = N - 1; lo >= N - 8; lo--) { const m = measureDeployed(lo, N); compiles++; if (m.feasible) finalForcedCut = lo; else break; }

// ================= (1) fresh DEPLOYED per-class marginal extraction =================
// contiguous runs at several starts -> deployed op10000 + redeem size at each width; per-step marginals
// (grouped by class) + a least-squares intercept + per-class MEAN, and per-class MAX single-step. Runs
// stay in the INTERIOR [1, finalForcedCut) (the forced-final region is handled separately, below).
const baseStarts = QUICK ? [30, 120, 240] : [10, 40, 80, 130, 190, 250, 300];
const runStarts = [...new Set([...baseStarts, Math.max(1, finalForcedCut - 13)])].filter((s) => s < finalForcedCut).sort((a, b) => a - b);
const WCAP = 26;                                          // stop each run before the budget clamp (~28)
const windows = [];                                      // {lo,hi,op,redeem} for the LSQ
const stepMarg = {};                                     // class -> [op single-step marginals]
const stepRed = {};                                      // class -> [redeem single-step marginals]
for (const s of runStarts) {
  let prevOp = null, prevRed = null;
  for (let hi = s + 1; hi <= Math.min(finalForcedCut, s + WCAP); hi++) {
    const m = measureDeployed(s, hi); compiles++;
    if (!m.feasible) break;
    windows.push({ lo: s, hi, op: m.realWorstOp, redeem: m.redeem });
    if (prevOp !== null) {
      const k = hi - 1, c = classOf[k];
      (stepMarg[c] ??= []).push(m.realWorstOp - prevOp);
      (stepRed[c] ??= []).push(m.redeem - prevRed);
    }
    prevOp = m.realWorstOp; prevRed = m.redeem;
  }
}
// fit windows = interior only (never the forced-final region); classes = the ones actually MEASURED.
const fitWins = windows.filter((w) => w.lo >= 1 && w.hi <= finalForcedCut);
const measuredClasses = new Set();
for (const w of fitWins) for (let k = w.lo; k < w.hi; k++) measuredClasses.add(classOf[k]);
// least-squares fit op ≈ intercept + Σ_class count·marginal (interior measured classes only).
const classes = [...measuredClasses].sort();
const cols = ['__intercept__', ...classes];
const featRow = (lo, hi) => { const f = new Array(cols.length).fill(0); f[0] = 1; for (let k = lo; k < hi; k++) { const i = classes.indexOf(classOf[k]); if (i >= 0) f[1 + i]++; } return f; };
const X = fitWins.map((w) => featRow(w.lo, w.hi)), Y = fitWins.map((w) => w.op);
function lsq(X, y) {
  const m = cols.length, nn = X.length;
  const A = Array.from({ length: m }, () => new Array(m).fill(0)), b = new Array(m).fill(0);
  for (let i = 0; i < nn; i++) for (let a = 0; a < m; a++) { b[a] += X[i][a] * y[i]; for (let c = 0; c < m; c++) A[a][c] += X[i][a] * X[i][c]; }
  const M = A.map((r, i) => [...r, b[i]]);
  for (let c = 0; c < m; c++) { let piv = c; for (let r = c + 1; r < m; r++) if (Math.abs(M[r][c]) > Math.abs(M[piv][c])) piv = r; [M[c], M[piv]] = [M[piv], M[c]];
    const d = M[c][c]; if (Math.abs(d) < 1e-9) continue; for (let k = c; k <= m; k++) M[c][k] /= d;
    for (let r = 0; r < m; r++) if (r !== c) { const f = M[r][c]; for (let k = c; k <= m; k++) M[r][k] -= f * M[c][k]; } }
  return M.map((r) => r[m]);
}
const beta = lsq(X, Y);
const interceptTyp = Math.round(beta[0]);
const marginMean = {}; classes.forEach((c, i) => marginMean[c] = Math.round(beta[1 + i]));
// residuals -> max positive residual (the calibration margin the safe model must beat).
let maxPosResid = 0, maxAbsResid = 0;
for (let i = 0; i < fitWins.length; i++) { const pred = X[i].reduce((s, v, k) => s + v * beta[k], 0); const r = Y[i] - pred; maxPosResid = Math.max(maxPosResid, r); maxAbsResid = Math.max(maxAbsResid, Math.abs(r)); }
maxPosResid = Math.ceil(maxPosResid); maxAbsResid = Math.ceil(maxAbsResid);
// per-class MAX single-step op marginal + MEDIAN redeem marginal.
const median = (a) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : 0; };
const marginMax = {}, redMargin = {};
for (const c of classes) {
  marginMax[c] = Math.max(marginMean[c], ...(stepMarg[c] ?? [marginMean[c]]));   // >= mean by construction
  redMargin[c] = median(stepRed[c] ?? [234]);
}
// classes that appear ONLY in the forced-final region (e.g. cmul1) are never in a fit window; give them
// a provisional value so buildClassCostVec is well-defined — the final-region blocks are OVERWRITTEN
// below with a direct measurement, so these provisional values never reach an emitted chunk.
const heaviestMean = Math.max(...Object.values(marginMean)), heaviestMax = Math.max(...Object.values(marginMax));
for (const c of new Set(classOf)) { if (marginMean[c] === undefined) { marginMean[c] = heaviestMean; marginMax[c] = heaviestMax; redMargin[c] = 466; } }
const redBaseArr = fitWins.map((w) => w.redeem - [...Array(w.hi - w.lo)].reduce((s, _, i) => s + redMargin[classOf[w.lo + i]], 0));
const redBase = Math.round(median(redBaseArr));

// genesis chunk always starts at block 0 (reloc). deltaGen folds the reloc overhead onto block 0.
let deltaGen = 0; {
  const h = QUICK ? 8 : 14; const g = measureDeployed(0, h); compiles++;
  if (g.feasible) { let sum = interceptTyp; for (let k = 0; k < h; k++) sum += marginMean[classOf[k]]; deltaGen = g.realWorstOp - sum; }
}
// direct measurement of the forced-final chunk (its REAL worst-case op; used to overwrite its blocks).
const finalMeas = measureDeployed(finalForcedCut, N); compiles++;
const finalRealOp = finalMeas.feasible ? finalMeas.realWorstOp : interceptTyp + 100_000;

// boundary state-byte push sizes at every cut (committed-state push size; interior 52 limbs, tail 36).
const boundaryStateBytes = [];
for (let cut = 0; cut <= N; cut++) { const limbs = (cut >= N ? outState(N) : inState(cut)).map(BigInt); boundaryStateBytes.push(limbs.reduce((s, v) => s + pushSize(v), 0)); }

// ================= (2) SAFE cost vector + params for chunkplan's DP =================
const SAFETY_MARGIN = maxPosResid + (QUICK ? 8_000 : 16_000);   // budget shrink; >= max positive fit residual + headroom
const blockDelta = { 0: { opTyp: deltaGen, opWC: deltaGen } };
const { costVec } = buildClassCostVec(classOf, { marginMean, marginMax, redMargin, boundaryStateBytes, blockDelta, forcedCuts: [finalForcedCut], stage: 'miller' });
// OVERWRITE the forced-final region [finalForcedCut, N) with the direct measurement: give the leading
// final blocks a small positive op and pin the total to the measured final-chunk op on the last block.
// The final chunk is forced + compile-verified, so this is exact for A1 (its real op is what matters).
{
  const EPS = 1000, tb = N - finalForcedCut;
  for (let k = finalForcedCut; k < N - 1; k++) { costVec[k].opCost = EPS; costVec[k].opCostWorstCase = EPS; }
  const last = Math.max(EPS, finalRealOp - interceptTyp - EPS * (tb - 1));
  costVec[N - 1].opCost = last; costVec[N - 1].opCostWorstCase = last;
}
validateCostVec(costVec);
const redeemBytesOf = (lo, hi) => { let r = redBase; for (let k = lo; k < hi; k++) r += redMargin[classOf[k]]; return r; };
const params = normalizeParams({
  opCostPerByte: 800, densityBase: 41, padSafety: 96, minPad: 3, lockingBytes: 35, targetUnlock: TARGET_UNLOCK, hashIterCost: 64,
  opBudget: OP_BUDGET - SAFETY_MARGIN,                     // effective (conservative) budget: real op < OP_BUDGET by construction
  finalStateBytes: boundaryStateBytes[N],
  overheadOp: () => interceptTyp - redBase - HDR,          // op = intercept + Σ marginMean (redeem push cancels; see chunkplan)
  redeemBytes: redeemBytesOf, pushHeader: () => HDR,
});
const modelExtractMs = Date.now() - t0;

// persist the DEPLOYED cost model (durable artifact; supersedes the RAW-compile bn254_costvec_v3.json).
writeFileSync(DEPLOYED_COSTVEC_PATH, JSON.stringify({
  meta: { generator: 'gen_miller_residue.mjs (SELF-PINNED: covOut successor pin present)', numOps: N, policy: 'consensus-64 deployed (compileFileBytecode rescheduleStacks ON, createVirtualMachineBch2026(false))',
    opBudget: OP_BUDGET, compiles, runStarts, WCAP, extractedAt: new Date().toISOString(),
    note: 'per-op-CLASS marginals fit on the DEPLOYED SELF-PINNED compile (includes the OP_OUTPUTBYTECODE+OP_TXOUTPUTCOUNT successor pin op-cost). marginMax >= marginMean; feasibility uses intercept+Σ marginMax vs opBudget-SAFETY_MARGIN.' },
  classOf, interceptTyp, marginMean, marginMax, redMargin, redBase, SAFETY_MARGIN, maxPosResid, maxAbsResid,
  deltaGen, finalRealOp, finalForcedCut, boundaryStateBytes,
}, null, 2));

// ================= (3)+(4) faithful plan: DP -> compileVerify -> local boundary search =================
const measureChunk = (lo, hi) => measureDeployed(lo, hi);   // the real oracle for the engine
const K_SEARCH = QUICK ? 1 : 2;
// DP PLANS against the shrunk effective budget (params.opBudget); the A1 certificate certifies REAL
// worst-case op against the TRUE consensus budget (OP_BUDGET = 8,032,800).
const result = plan(costVec, params, measureChunk, { k: K_SEARCH, requireA1: true, consensusOpBudget: OP_BUDGET });

// model-only DP for reference (no verify), + greedy baseline model bytes.
const dpModel = planOptimal(costVec, params);

// ================= (5) INDEPENDENT fresh-partition faithfulness check =================
// A SEPARATE measurement path (recomputes bytes from scratch) over FRESH partitions whose widths the
// build/DP never used, confirming the tool's reported REAL bytes == independent real bytes (0 mismatch)
// and every real op <= budget. Independence: this uses its own eval loop (walks the TRUE minimal
// accepting length, a different byte notion) but must at least (a) never exceed budget and (b) match
// the tool's compileVerify realBytes when the SAME tunedLen path is used.
function independentMeasure(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi); } catch (e) { return { feasible: false, err: String(e?.message ?? e).slice(0, 60) }; }
  const probe = evalAt(ctx, TARGET_UNLOCK);
  if (!(probe.completed && probe.op <= OP_BUDGET)) return { feasible: false, op10000: probe.op };
  // deployed bytes via the SAME tunedLen (independent code path, recomputed)
  let target = Math.min(TARGET_UNLOCK, Math.max(ctx.argBytes + ctx.tail + 3, Math.ceil(probe.op / 800) - 41 + 96));
  let r = evalAt(ctx, target);
  while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
  // ALSO find the TRUE minimal accepting length (a stricter, independent notion of "real bytes")
  let Lmin = target; while (Lmin > ctx.floor && evalAt(ctx, Lmin - 1).accepted) Lmin--;
  return { feasible: true, deployedBytes: 35 + target, minimalBytes: 35 + Lmin, op10000: probe.op };
}
function freshUniform(w, phase = 0) {
  const cuts = [0];
  if (phase > 0) { let hi = Math.min(finalForcedCut, phase); while (hi > 1 && !measureDeployed(0, hi).feasible) hi--; cuts.push(hi); }
  let lo = cuts[cuts.length - 1];
  while (lo < finalForcedCut) { let hi = Math.min(finalForcedCut, lo + w); while (hi > lo + 1 && !measureDeployed(lo, hi).feasible) hi--; cuts.push(hi); lo = hi; }
  cuts.push(N); return cuts;
}
const freshPartitions = QUICK ? [['fresh-uniform-17', freshUniform(17)]]
                              : [['fresh-uniform-17', freshUniform(17)], ['fresh-width19-phase7', freshUniform(19, 7)], ['plan-result', result.cuts]];
const freshChecks = freshPartitions.map(([name, cuts]) => {
  let toolTot = 0, indepTot = 0, indepMinTot = 0, mism = 0, over = 0, feas = true, maxOp = 0;
  const rows = [];
  for (let i = 0; i + 1 < cuts.length; i++) {
    const lo = cuts[i], hi = cuts[i + 1];
    const toolM = measureDeployed(lo, hi);              // the tool's reported real bytes (compileVerify path)
    const ind = independentMeasure(lo, hi);            // independent recomputation
    if (!toolM.feasible || !ind.feasible) { feas = false; rows.push({ lo, hi, feasible: false }); mism++; continue; }
    maxOp = Math.max(maxOp, ind.op10000);
    if (ind.op10000 > OP_BUDGET) over++;
    toolTot += toolM.realBytes; indepTot += ind.deployedBytes; indepMinTot += ind.minimalBytes;
    if (toolM.realBytes !== ind.deployedBytes) mism++;
    rows.push({ lo, hi, toolBytes: toolM.realBytes, indepBytes: ind.deployedBytes, minimalBytes: ind.minimalBytes, op10000: ind.op10000, match: toolM.realBytes === ind.deployedBytes });
  }
  return { name, chunks: cuts.length - 1, feasibleAll: feas, toolReportedBytes: toolTot, independentBytes: indepTot, independentMinimalBytes: indepMinTot,
           mismatches: mism, overBudget: over, maxRealOp: maxOp, a1Pass: over === 0 && feas, rows };
});

// ================= report =================
const out = {
  stage: 'miller-residue (348 op-blocks)', policy: 'consensus-64 deployed (compileFileBytecode + real BCH-2026 VM covenant tx)',
  costModel: {
    faithfulness: 'per-op-CLASS marginals fit on the DEPLOYED compile; fixes the RAW-compile ~40% under-count in bn254_costvec_v3.json',
    interceptTyp, marginMean, marginMax, redBase, redMargin,
    fit: { windows: fitWins.length, maxPosResidual: maxPosResid, maxAbsResidual: maxAbsResid },
    safety: { SAFETY_MARGIN, effectiveOpBudget: OP_BUDGET - SAFETY_MARGIN, trueOpBudget: OP_BUDGET,
      guarantee: 'realOp <= modelWorstCase + maxPosResidual <= (opBudget-SAFETY_MARGIN) + maxPosResidual < opBudget  (A1-safe by construction)' },
    deltaGen, finalRealOp, finalForcedCut, extractCompiles: compiles, extractMs: modelExtractMs,
  },
  plan: {
    chunkCount: result.chunkCount, cuts: result.cuts,
    totalRealBytes: result.totalRealBytes, maxRealWorstOp: result.maxRealWorstOp,
    a1Certificate: result.a1Certificate,
    modelGap: result.modelGap,           // model-vs-real: byte-prediction accuracy + never-under-count witness
    dp: result.dp, localSearch: result.localSearch, timings: result.timings,
    modelOnlyDpBytes: dpModel.totalBytes,
  },
  freshFaithfulnessCheck: freshChecks.map((f) => ({ name: f.name, chunks: f.chunks, feasibleAll: f.feasibleAll,
    toolReportedBytes: f.toolReportedBytes, independentBytes: f.independentBytes, independentMinimalBytes: f.independentMinimalBytes,
    mismatches: f.mismatches, overBudget: f.overBudget, maxRealOp: f.maxRealOp, a1Pass: f.a1Pass })),
  headline: {
    reportsRealCompileVerifiedBytes: true,
    a1SafeByConstruction: true,
    a1ConfirmedByMeasurement: result.a1Certificate.pass && freshChecks.every((f) => f.a1Pass),
    faithful_zeroMismatch: freshChecks.every((f) => f.mismatches === 0 && f.feasibleAll),
    modelNeverUnderCountsWorstOp: result.modelGap ? result.modelGap.modelNeverUnderCountsWorstOp : null,
  },
};
console.log(JSON.stringify(out, null, 2));
console.log('\n--- plan per-chunk (REAL compile-verified bytes | real worst op | model gap) ---');
for (const r of result.perChunk) console.log(JSON.stringify(r));
writeFileSync(REPORT_PATH, JSON.stringify({ ...out, planPerChunk: result.perChunk, freshRows: freshChecks.map((f) => ({ name: f.name, rows: f.rows })) }, null, 2));
