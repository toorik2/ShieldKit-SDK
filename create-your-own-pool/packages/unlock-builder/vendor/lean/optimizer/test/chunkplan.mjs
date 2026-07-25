// test/chunkplan.mjs — regression gate for the FAITHFUL re-chunk planner (chunkplan.mjs).
//
// Two parts, both real (no placeholders):
//
// PART 1 — pure, always, ~20ms: runSelfTest() from chunkplan.mjs. This is the interval-DP
//   OPTIMALITY proof (T1-T3: planOptimal == an exhaustive brute-force oracle, and STRICTLY beats
//   greedy on a crafted instance — so it is a real DP, not fill-to-budget), the byte-formula anchors
//   (T4, vs deployed rv.json), AND the SAFE-MODEL soundness self-tests:
//     T5 the DP feasibility UPPER bound provably never under-counts a synthetic "real" op (A1-safe by
//        construction), T6 compileVerify aggregates REAL bytes + flags the model-vs-real gap with
//        worstOpWorstUnder >= 0 (the never-under-count witness), T7 localBoundarySearch climbs to the
//        REAL-bytes optimum. These encode the A1-worst-case-never-undercounted invariant structurally.
//
// PART 2 — the PRIOR BLOCKER, now a PASSING regression gate (real BCH-2026 VM compiles): the
//   BYTE-FIDELITY DIFFERENTIAL on a FRESH partition. It reconstructs the tool's params + cost vector
//   from the persisted DEPLOYED cost model (bn254_costvec_deployed.json), builds a partition at a width
//   NOT used in build/validate, runs the tool's real reporting path (chunkplan.compileVerify driving
//   the deployed compileFileBytecode + createVirtualMachineBch2026(false) covenant tx), and cross-checks
//   EVERY chunk's tool-REPORTED realBytes against a GENUINELY INDEPENDENT recompile (separate temp file,
//   separately-derived tunedLen, plus a true-minimal accepting-length spot check). It asserts:
//     (a) tool-reported total bytes == the independent recompile total, 0 per-chunk mismatch  [FAITHFUL],
//     (b) tool bytes >= a true-minimal accepting script (never under-reports),
//     (c) every feasible chunk's REAL worst-case op <= the CONSENSUS budget (8,032,800)          [A1],
//     (d) the model NEVER under-counts real worst op on the partition (worstOpWorstUnder >= 0)   [A1].
//
//   Part 2 needs the reproduced BN254 build (TOOLS.md §11 — external, not in this repo) + the persisted
//   deployed model. If either is absent it SKIPS with a clear message (exactly like byte-identity.mjs's
//   private-crown skip) — the pure Part 1 still runs and gates. Set CHUNKPLAN_SKIP_COMPILE=1 to force
//   the pure-only run.
//
//   node test/chunkplan.mjs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  runSelfTest, buildClassCostVec, normalizeParams, validateCostVec,
  chunkBytes, compileVerify,
} from '../chunkplan.mjs';
import { loadBn254Adapter, rewriteGeneratedLazyImport } from '../bn254_adapter.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let fails = 0;
const ok = (cond, msg) => { if (cond) console.log(`PASS: ${msg}`); else { console.error(`FAIL: ${msg}`); fails++; } };

// ================================================================= PART 1 — pure DP + safe-model self-test
console.log('--- Part 1: DP optimality + safe-model self-test (pure) ---');
let self;
try { self = runSelfTest(); } catch (e) { console.error(`FAIL: runSelfTest threw: ${e && e.stack ? e.stack : e}`); fails++; }
if (self) {
  const R = self.results;
  ok(self.pass === true, 'runSelfTest reports pass');
  ok(R.T1.equal === true, `T1 interval-DP total == brute-force optimum (${R.T1.dpTotal} == ${R.T1.bruteTotal})`);
  ok(R.T2.a1Pass === true && R.T2.maxWorstCaseOp <= R.T2.opBudget, `T2 A1 pinning: worst-case windows cannot merge past budget (max ${R.T2.maxWorstCaseOp} <= ${R.T2.opBudget})`);
  ok(R.T3.dpBeatsGreedy === true, `T3 DP STRICTLY beats greedy (${R.T3.dpTotal} < ${R.T3.greedyTotal}) — a real DP, not fill-to-budget`);
  ok(R.T4.anchor0 === 9435 && R.T4.anchor18 === 9233, 'T4 byte-pad formula matches deployed rv.json anchors');
  ok(R.T5.a1SafeByConstruction === true && R.T5.minSafetyGuardSlack >= 0 && R.T5.windowsChecked > 0,
     `T5 SAFE model never under-counts real op over ${R.T5.windowsChecked} feasible windows (A1-safe by construction; min guard slack ${R.T5.minSafetyGuardSlack})`);
  ok(R.T6.worstOpWorstUnder >= 0 && R.T6.a1 === true,
     `T6 compileVerify: model never under-counts real worst op (worstOpWorstUnder ${R.T6.worstOpWorstUnder} >= 0) + A1 cert passes`);
  ok(R.T7.foundTotal === R.T7.realOptimum, `T7 localBoundarySearch reaches the REAL-bytes optimum (${R.T7.foundTotal} == ${R.T7.realOptimum})`);
}

// ================================================================= PART 2 — byte-fidelity fresh-partition gate
console.log('\n--- Part 2: byte-fidelity differential on a FRESH partition (real BCH-2026 VM) ---');

const MODEL_PATH = join(HERE, '..', 'bn254_costvec_deployed.json');

async function loadDeps() {
  if (process.env.CHUNKPLAN_SKIP_COMPILE === '1') return { skip: 'CHUNKPLAN_SKIP_COMPILE=1 set' };
  if (!existsSync(MODEL_PATH)) return { skip: `deployed cost model not found (${MODEL_PATH})` };
  return loadBn254Adapter({ optional: true });
}

const deps = await loadDeps();
if (deps.skip) {
  console.log(`SKIP: byte-fidelity fresh-partition gate — ${deps.skip}`);
  console.log('      (Part 1 pure self-test still gates; the reproduced BN254 build is external — see TOOLS.md §11)');
} else {
  const { genChunk, ops, inState, outState } = deps.generator;
  const { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } = deps.millermath;
  const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } = deps.libauth;

  const N = ops.length;
  const VM = createVirtualMachineBch2026(false);         // consensus-64: the deployed rv.json / build_vectors VM
  const HDR = 3;
  const cls = (o) => (o.t === 'dl' || o.t === 'al') ? o.t + (o.j === 0 ? '0' : 'B') : o.t;
  const classOf = ops.map(cls);

  const M = JSON.parse(readFileSync(MODEL_PATH, 'utf8'));
  const { interceptTyp, marginMean, marginMax, redMargin, redBase, SAFETY_MARGIN, deltaGen, finalRealOp, finalForcedCut, boundaryStateBytes } = M;

  // ---- shared deployed-covenant context (byte-for-byte build_vectors.mjs::buildCovStep) ----
  const gen = (lo, hi, isFinal, reloc) => rewriteGeneratedLazyImport(genChunk(lo, hi, isFinal, reloc), deps);
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

  // ---- TOOL oracle: exactly the adapter measureDeployed (the compileVerify path plan() uses) ----
  const TCACHE = new Map();
  function toolMeasure(lo, hi) {
    const key = `${lo},${hi}`; if (TCACHE.has(key)) return TCACHE.get(key);
    let out, ctx;
    try { ctx = buildCtx(lo, hi, '/tmp/_cpgate_tool.cash'); } catch (e) { out = { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; TCACHE.set(key, out); return out; }
    const probe = evalAt(ctx, TARGET_UNLOCK);              // worst-case op = op at max pad
    const op10000 = probe.op;
    if (!(probe.completed && op10000 <= OP_BUDGET)) { out = { feasible: false, realWorstOp: op10000, compileError: null }; TCACHE.set(key, out); return out; }
    let target = tunedLen(ctx.argBytes + ctx.tail, op10000);
    let r = evalAt(ctx, target);
    while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
    if (!r.accepted) { out = { feasible: false, realWorstOp: op10000, compileError: 'no accepting pad' }; TCACHE.set(key, out); return out; }
    out = { feasible: true, realBytes: 35 + target, realWorstOp: op10000, lockingBytes: 35, unlockingBytes: target };
    TCACHE.set(key, out); return out;
  }

  // ---- INDEPENDENT oracle: SEPARATE temp file + SEPARATE tunedLen derivation + true-minimal walk ----
  function indepMeasure(lo, hi, withMinimal = false) {
    let ctx; try { ctx = buildCtx(lo, hi, '/tmp/_cpgate_indep.cash'); } catch (e) { return { feasible: false, err: String(e?.message ?? e).slice(0, 60) }; }
    const probe = evalAt(ctx, TARGET_UNLOCK);
    if (!(probe.completed && probe.op <= OP_BUDGET)) return { feasible: false, op10000: probe.op };
    let target = Math.min(TARGET_UNLOCK, Math.max(ctx.argBytes + ctx.tail + 3, Math.ceil(probe.op / 800) - 41 + 96));
    let r = evalAt(ctx, target);
    while (!r.accepted && target < TARGET_UNLOCK) { target = Math.min(TARGET_UNLOCK, target + 256); r = evalAt(ctx, target); }
    if (!r.accepted) return { feasible: false, op10000: probe.op, err: 'no accepting pad (indep)' };
    const deployedBytes = 35 + target;
    let minimalBytes = deployedBytes;
    if (withMinimal) { let Lmin = target, guard = 0; while (Lmin > ctx.floor && guard++ < 400 && evalAt(ctx, Lmin - 1).accepted) Lmin--; minimalBytes = 35 + Lmin; }
    return { feasible: true, deployedBytes, minimalBytes, op10000: probe.op };
  }

  // ---- reconstruct the tool's params + cost vector from the persisted deployed model ----
  const blockDelta = { 0: { opTyp: deltaGen, opWC: deltaGen } };
  const { costVec } = buildClassCostVec(classOf, { marginMean, marginMax, redMargin, boundaryStateBytes, blockDelta, forcedCuts: [finalForcedCut], stage: 'miller' });
  { // overwrite forced-final region exactly like the adapter (direct measurement pins it; A1-exact there)
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

  // ---- FRESH partition: (width,phase) NOT used in build [17@0,19@7] or validate/skeptic
  //      [13@0,14@5,15@0,17@0,18@11,19@0,21@0,16@3]. width-20-phase-9 is a fresh combination whose
  //      phase-shifted boundaries do not coincide with any previously-measured packed partition. ----
  const WIDTH = Number(process.env.CHUNKPLAN_WIDTH || 20);
  const PHASE = Number(process.env.CHUNKPLAN_PHASE || 9);
  function freshUniform(w, phase) {
    const cuts = [0];
    if (phase > 0) { let hi = Math.min(finalForcedCut, phase); while (hi > 1 && !toolMeasure(0, hi).feasible) hi--; cuts.push(hi); }
    let lo = cuts[cuts.length - 1];
    while (lo < finalForcedCut) { let hi = Math.min(finalForcedCut, lo + w); while (hi > lo + 1 && !toolMeasure(lo, hi).feasible) hi--; cuts.push(hi); lo = hi; }
    cuts.push(N); return cuts;
  }
  const cuts = freshUniform(WIDTH, PHASE);
  console.log(`fresh partition: uniform-width-${WIDTH}-phase-${PHASE} -> ${cuts.length - 1} chunks; cuts=${JSON.stringify(cuts)}`);

  // ---- THE TOOL: exactly what plan() calls to produce reported real bytes ----
  const cv = compileVerify(cuts, toolMeasure, params, modelOf, OP_BUDGET);

  // ---- INDEPENDENT cross-check of EVERY reported chunk ----
  let indepTotal = 0, mism = 0, underMin = 0, over = 0, maxOp = 0, feasAll = true, minimalDone = false;
  const bad = [];
  for (const row of cv.perChunk) {
    const { lo, hi } = row;
    const wantMin = !minimalDone && row.feasible;
    const ind = indepMeasure(lo, hi, wantMin);
    if (!row.feasible || !ind.feasible) {
      if (row.feasible !== !!ind.feasible) { mism++; feasAll = false; bad.push({ lo, hi, kind: 'feasibility-divergence', tool: row.feasible, indep: !!ind.feasible }); }
      continue;
    }
    maxOp = Math.max(maxOp, ind.op10000);
    if (ind.op10000 > OP_BUDGET) over++;
    indepTotal += ind.deployedBytes;
    if (row.realBytes !== ind.deployedBytes) { mism++; bad.push({ lo, hi, tool: row.realBytes, indep: ind.deployedBytes }); }
    if (wantMin) {
      minimalDone = true;
      if (row.realBytes < ind.minimalBytes) { underMin++; bad.push({ lo, hi, kind: 'under-true-minimal', tool: row.realBytes, trueMinimal: ind.minimalBytes }); }
      console.log(`  true-minimal spot [${lo},${hi}): toolReported=${row.realBytes} >= trueMinimalAccepting=${ind.minimalBytes} (pad over minimal ${row.realBytes - ind.minimalBytes})`);
    }
  }
  const toolTotal = cv.totalRealBytes;

  console.log(`tool-reported total = ${toolTotal} B ; independent recompile total = ${indepTotal} B ; per-chunk mismatches = ${mism}`);
  console.log(`max REAL worst-case op = ${maxOp} (consensus budget ${OP_BUDGET}, slack ${OP_BUDGET - maxOp}) ; over-budget feasible chunks = ${over}`);
  if (bad.length) console.error('  divergences: ' + JSON.stringify(bad));

  // ---- ASSERTIONS ----
  ok(feasAll && Number.isFinite(toolTotal), 'every chunk of the fresh partition is feasible + reported');
  ok(mism === 0, `byte fidelity: 0 per-chunk mismatch (tool compileVerify realBytes == independent recompile)`);
  ok(Number.isFinite(toolTotal) && toolTotal === indepTotal, `byte fidelity: tool-reported total == independent total (${toolTotal} == ${indepTotal})`);
  ok(underMin === 0, 'tool never under-reports below a true-minimal accepting script');
  ok(over === 0 && maxOp <= OP_BUDGET, `A1: every feasible chunk's REAL worst-case op <= consensus budget (max ${maxOp} <= ${OP_BUDGET})`);
  ok(cv.a1Certificate.pass, 'A1: compileVerify a1Certificate passes on the fresh partition');
  ok(cv.modelGap && cv.modelGap.modelNeverUnderCountsWorstOp && cv.modelGap.worstOpWorstUnder >= 0,
     `A1-worst-case-never-undercounted: model op >= real op for every emitted chunk (worstOpWorstUnder ${cv.modelGap ? cv.modelGap.worstOpWorstUnder : 'n/a'} >= 0)`);
}

// ================================================================= verdict
if (fails) { console.error(`\n${fails} chunkplan regression FAILURE(s)`); process.exit(1); }
console.log('\nall chunkplan regression checks passed');
