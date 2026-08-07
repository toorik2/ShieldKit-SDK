// _characterize_additive.mjs — REAL-MEASUREMENT characterization of WHY the additive op-model is
// unfaithful for the chunkplan DP. Compiles + measures (real BCH-2026 VM) miller/residue windows
// across diverse widths & start positions, in BOTH compile modes (raw = plain cashc, resched =
// deployed rescheduleStacks), and compares real op10000 to the stored additive model K + Σ perOp.
//
// Outputs: per-window rows + aggregate stats (op under-count sign/magnitude, byte consequence,
// reschedule effect, correlation with width, per-step real marginal vs stored perOp).
import { writeFileSync, readFileSync } from 'node:fs';
import { genChunk, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, compileFileBytecodeRaw, commitBin, CATEGORY } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

const CV = JSON.parse(readFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/bn254_costvec_v3.json', 'utf8'));
const { perOp, K, boundaryStateBytes, classOf } = CV;
const N = CV.meta.numOps;
const OP_BUDGET = 8_032_800;
const VM = createVirtualMachineBch2026(false);
const PROBE = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_measure_probe.cash';
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

// on-chain byte formula (matches meta.tunedFormula): bytes = 35 + max(argFloor, ceil((op-42800)/799))
function bytesFromOp(op, argBytes, tail) {
  const floor = argBytes + tail + 2;
  const pad = Math.max(0, Math.ceil((op - 42800) / 799));
  return 35 + Math.min(10000, Math.max(floor, pad));
}

function measure(lo, hi, compileFn) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  let redeem;
  try { redeem = Uint8Array.from([...compileFn(PROBE)]); }
  catch (e) { return { err: String(e?.message ?? e).slice(0, 60) }; }
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const padTot = 10000 - argb.length - tail;
  if (padTot < 2) return { err: 'args+redeem>10000', redeem: redeem.length, tail, argBytes: argb.length };
  const unlocking = Uint8Array.from([...padBytes(padTot), ...argb, ...rpush]);
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(covIn)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 } });
  return { op10000: st.metrics.operationCost, redeem: redeem.length, tail, argBytes: argb.length,
           completed: st.error === undefined, err: st.error ? String(st.error).slice(0, 40) : null };
}

const additiveOp = (lo, hi) => K + perOp.slice(lo, hi).reduce((a, b) => a + (b ?? 0), 0);
const rows = [];
let nCompiles = 0;
function record(lo, hi, tag) {
  const raw = measure(lo, hi, compileFileBytecodeRaw); nCompiles++;
  const res = measure(lo, hi, compileFileBytecode); nCompiles++;
  if (raw.err || res.err) { rows.push({ tag, lo, hi, width: hi - lo, err: raw.err || res.err }); return null; }
  const add = additiveOp(lo, hi);
  const bReal = bytesFromOp(res.op10000, res.argBytes, res.tail);
  const bRaw = bytesFromOp(raw.op10000, raw.argBytes, raw.tail);
  const bAdd = bytesFromOp(add, res.argBytes, res.tail);
  const row = {
    tag, lo, hi, width: hi - lo, nInternalBoundaries: hi - lo - 1,
    stateBytesLo: boundaryStateBytes[lo],
    op_raw: raw.op10000, op_resched: res.op10000, additive: add,
    underCount_vs_raw: raw.op10000 - add,       // >0 = additive under-counts raw real
    underCount_vs_resched: res.op10000 - add,   // >0 = additive under-counts DEPLOYED real (A1-critical)
    reschedEffect: res.op10000 - raw.op10000,   // <0 = reschedule reduces op
    bytes_raw: bRaw, bytes_resched: bReal, bytes_additive: bAdd,
    byteUnderCount_vs_resched: bReal - bAdd,    // >0 = additive under-sizes deployed bytes
    redeem_raw: raw.redeem, redeem_resched: res.redeem,
    op_resched_over_budget: res.op10000 > OP_BUDGET,
    op_raw_over_budget: raw.op10000 > OP_BUDGET,
  };
  rows.push(row); return row;
}

// ---- A. width sweeps at several fixed lo (super-additivity + start-dependence) ----
const SWEEP_LO = [20, 50, 100, 200, 300];
const SWEEP_W = [2, 4, 6, 8, 10, 12, 14, 16];
for (const lo of SWEEP_LO) for (const w of SWEEP_W) { const hi = lo + w; if (hi <= N - 1) record(lo, hi, `sweep@${lo}`); }

// ---- B. reconciliation: on-anchor [20,33) vs off-anchor same width ----
for (const [lo, hi] of [[20, 33], [23, 36], [7, 20], [100, 113], [103, 116]]) record(lo, hi, 'recon13');

// ---- C. per-step real marginal vs stored perOp, contiguous at lo=50 (does perOp match reality?) ----
const stepRows = [];
{ let prevRaw = null, prevRes = null;
  for (let hi = 51; hi <= 66; hi++) {
    const raw = measure(50, hi, compileFileBytecodeRaw); nCompiles++;
    const res = measure(50, hi, compileFileBytecode); nCompiles++;
    if (raw.err || res.err) break;
    const k = hi - 1;
    if (prevRaw !== null) stepRows.push({ k, class: classOf?.[k],
      realMarginal_raw: raw.op10000 - prevRaw, realMarginal_resched: res.op10000 - prevRes, storedPerOp: perOp[k] });
    prevRaw = raw.op10000; prevRes = res.op10000; }
}

// ---- aggregate stats ----
const good = rows.filter((r) => !r.err);
const med = (a) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : NaN; };
const stat = (sel) => { const a = good.map(sel); return { min: Math.min(...a), median: med(a), max: Math.max(...a), mean: Math.round(a.reduce((x, y) => x + y, 0) / a.length) }; };
// correlation of underCount_vs_resched with width
function corr(xs, ys) { const n = xs.length, mx = xs.reduce((a, b) => a + b, 0) / n, my = ys.reduce((a, b) => a + b, 0) / n;
  let sxy = 0, sxx = 0, syy = 0; for (let i = 0; i < n; i++) { const dx = xs[i] - mx, dy = ys[i] - my; sxy += dx * dy; sxx += dx * dx; syy += dy * dy; }
  return sxy / Math.sqrt(sxx * syy); }
const widthArr = good.map((r) => r.width);
const summary = {
  nCompiles, nWindows: good.length, nErr: rows.length - good.length, opBudget: OP_BUDGET,
  underCount_vs_resched: stat((r) => r.underCount_vs_resched),
  underCount_vs_raw: stat((r) => r.underCount_vs_raw),
  reschedEffect: stat((r) => r.reschedEffect),
  byteUnderCount_vs_resched: stat((r) => r.byteUnderCount_vs_resched),
  corr_underCountResched_width: +corr(widthArr, good.map((r) => r.underCount_vs_resched)).toFixed(3),
  corr_reschedEffect_width: +corr(widthArr, good.map((r) => r.reschedEffect)).toFixed(3),
  perStepUnderCount_median: med(good.map((r) => r.width > 0 ? r.underCount_vs_resched / r.width : 0)).toFixed(0),
  raw_always_ge_resched: good.every((r) => r.op_raw >= r.op_resched),
  additive_always_underCounts_resched: good.every((r) => r.underCount_vs_resched > 0),
  additive_always_underCounts_raw: good.every((r) => r.underCount_vs_raw > 0),
  maxWidthMeasured: Math.max(...widthArr),
};
const out = { summary, stepRows, rows };
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_characterize_additive_report.json', JSON.stringify(out, null, 2));
console.log(JSON.stringify(summary, null, 2));
console.log('\n--- per-step real marginal (raw|resched) vs stored perOp, contiguous @lo=50 ---');
for (const s of stepRows) console.log(`k=${s.k} cls=${s.class} realMargRaw=${s.realMarginal_raw} realMargResched=${s.realMarginal_resched} storedPerOp=${s.storedPerOp}`);
