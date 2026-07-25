// verify_fresh_smoke.mjs — adversarial byte-fidelity smoke test (ONE fresh window).
// Replicates the adapter's cost-vec + params EXACTLY, then measures real bytes for a
// fresh interior window and compares (L1) formula-on-measured-op and (L2) the pure
// additive planner prediction chunkBytes(...).bytes against reality. Times the machinery.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBn254Adapter, rewriteGeneratedLazyImport } from './bn254_adapter.mjs';
import { chunkBytes, normalizeParams, validateCostVec } from './chunkplan.mjs';

const adapter = await loadBn254Adapter();
const { genChunk, ops, inState, outState } = adapter.generator;
const { compileFileBytecodeRaw, commitBin, CATEGORY } = adapter.millermath;
const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } = adapter.libauth;
const HERE = dirname(fileURLToPath(import.meta.url));

const CV = JSON.parse(readFileSync(join(HERE, 'bn254_costvec_v3.json'), 'utf8'));
const N = CV.meta.numOps;
const OP_BUDGET = 8_032_800;
const FEAS_MARGIN = 20_000;
const tunedUnlockFromOp = (op10000, floor) => Math.max(Math.ceil((op10000 - 42800) / 799), floor);
const PROBE = '/tmp/_bn254_smoke.cash';
const VM = createVirtualMachineBch2026(false);

// concurrent build emits a pairing-anchored relative import; rewrite to the real lib abs path so a
// /tmp PROBE resolves it (identical bytecode: verified 5019B redeem via abs==relFromTmp on [10,23)).
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
  const inLimbs = inState(lo).map(BigInt);
  const outLimbs = outState(hi).map(BigInt);
  const covInLimbs = relocGenesis ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
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
function measureReal(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi); } catch (e) { return { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; }
  const topProbe = evalAt(ctx, 10000);
  if (!topProbe.accepted) return { feasible: false, op10000: topProbe.op, redeemBytes: ctx.redeem, floor: ctx.floor };
  let L = Math.max(ctx.floor, Math.ceil((topProbe.op - 42800) / 799));
  L = Math.min(10000, Math.max(L, ctx.floor));
  while (L < 10000 && !evalAt(ctx, L).accepted) L++;
  while (L > ctx.floor && evalAt(ctx, L - 1).accepted) L--;
  return { feasible: true, tunedUnlock: L, tunedBytes: 35 + L, op10000: topProbe.op, redeemBytes: ctx.redeem, tail: ctx.tail, argBytes: ctx.argBytes, floor: ctx.floor };
}

// ------- replicate adapter param build (deltas measured once) -------
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
  return { op: st.metrics.operationCost, completed: st.error === undefined, redeem: redeem.length };
};
const { perOp, redPerOp, K, redBase } = CV;
{ const s = 340; const a = rawOp10000(s, 347, false, false), b = rawOp10000(s, 348, false, false); perOp[347] = b.op - a.op; redPerOp[347] = b.redeem - a.redeem; }
let deltaGen; { const h = 14; const g = CV.genesisSweep.find((r) => r.hi === h); const sum = perOp.slice(0, h).reduce((a, b) => a + b, 0); deltaGen = (g.op10000 - sum) - K; }
let deltaFin; { const r = CV.finalSweep.find((x) => x.lo === 346); const sum = perOp.slice(346, 348).reduce((a, b) => a + b, 0); deltaFin = (r.op10000 - sum) - K; }
const HDR = 3;
function redeemBytesOf(lo, hi) { let r = redBase; for (let k = lo; k < hi; k++) r += redPerOp[k]; return r; }
const costVec = [];
for (let k = 0; k < N; k++) { let oc = perOp[k] - redPerOp[k]; if (k === 0) oc += deltaGen; if (k === N - 1) oc += deltaFin;
  costVec.push({ id: `miller.op[${k}]`, stage: 'miller', opCost: oc, opCostWorstCase: oc, boundaryStateBytes: CV.boundaryStateBytes[k], forcedCutBefore: false }); }
validateCostVec(costVec);
const params = normalizeParams({ opCostPerByte: 799, densityBase: 41, minPad: 2, lockingBytes: 35, targetUnlock: 10000, padSafety: 0, hashIterCost: 64,
  opBudget: OP_BUDGET - FEAS_MARGIN - 10041, finalStateBytes: CV.boundaryStateBytes[N],
  overheadOp: (inB, outB) => K - redBase - HDR - 10041, redeemBytes: redeemBytesOf, pushHeader: () => HDR });
const predBytesL2 = (lo, hi) => chunkBytes(costVec, lo, hi, params).bytes;

// ------- fresh window test -------
const wins = [[10, 23], [7, 19], [40, 55]];
console.log('deltaGen', deltaGen, 'deltaFin', deltaFin, 'perOp347', perOp[347]);
for (const [lo, hi] of wins) {
  const t0 = process.hrtime.bigint();
  const m = measureReal(lo, hi);
  const t1 = process.hrtime.bigint();
  if (!m.feasible) { console.log(`[${lo},${hi}) INFEASIBLE`, m); continue; }
  const l1 = 35 + Math.min(10000, tunedUnlockFromOp(m.op10000, m.floor));
  const l2 = predBytesL2(lo, hi);
  console.log(JSON.stringify({ lo, hi, real: m.tunedBytes, L1_formula: l1, L2_additive: l2,
    L1diff: l1 - m.tunedBytes, L2diff: l2 - m.tunedBytes, op10000: m.op10000, floor: m.floor, ms: Number(t1 - t0) / 1e6 }));
}
