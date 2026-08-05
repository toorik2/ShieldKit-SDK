// _a1_busterprobe.mjs — demonstrate the A1 budget-buster: grow a window until REAL rescheduled op
// exceeds the 8,032,800 budget (VM aborts at pad=10000), and show the additive model still says
// feasible (additive op << budget). This is the forgery-class hazard the DP must never emit.
import { writeFileSync, readFileSync } from 'node:fs';
import { genChunk, inState, outState } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, compileFileBytecodeRaw, commitBin, CATEGORY } from '/home/toorik/Projects/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

const CV = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/bn254_costvec_v3.json', 'utf8'));
const { perOp, K } = CV;
const N = CV.meta.numOps, OP_BUDGET = 8_032_800;
const VM = createVirtualMachineBch2026(false);
const PROBE = '/home/toorik/Projects/verifier.cash/build/chunked/pairing/_measure_probe.cash';
const LIB_ABS = '/home/toorik/Projects/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

function measure(lo, hi, compileFn) {
  writeFileSync(PROBE, gen(lo, hi, hi === N, lo === 0));
  let redeem; try { redeem = Uint8Array.from([...compileFn(PROBE)]); } catch (e) { return { err: String(e?.message ?? e).slice(0, 50) }; }
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = (lo === 0) ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const padTot = 10000 - argb.length - tail;
  if (padTot < 2) return { err: 'args+redeem>10000', redeem: redeem.length };
  const st = VM.evaluate({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(covIn)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: Uint8Array.from([...padBytes(padTot), ...argb, ...rpush]) }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 } });
  return { op10000: st.metrics.operationCost, redeem: redeem.length, completed: st.error === undefined };
}
const additiveOp = (lo, hi) => K + perOp.slice(lo, hi).reduce((a, b) => a + (b ?? 0), 0);

const out = [];
for (const lo of [20, 200, 300]) {
  let lastFeasibleAdditiveButRealOverBudget = null;
  for (let w = 15; w <= 26; w++) {
    const hi = lo + w; if (hi > N - 1) break;
    const res = measure(lo, hi, compileFileBytecode);
    if (res.err) { out.push({ lo, w, err: res.err }); break; }
    const add = additiveOp(lo, hi);
    const realFeasible = res.completed && res.op10000 <= OP_BUDGET;   // VM completed at pad 10000
    const additiveFeasible = add <= OP_BUDGET;                        // what the DP would decide
    const row = { lo, w, op_resched: res.op10000, completed: res.completed, additive: add,
      realFeasible, additiveFeasible,
      A1_UNSOUND: additiveFeasible && !realFeasible };  // DP admits, but real busts budget
    out.push(row);
    if (row.A1_UNSOUND) lastFeasibleAdditiveButRealOverBudget = row;
    if (!res.completed && res.op10000 >= OP_BUDGET) { /* keep going a couple to show margin */ }
  }
}
writeFileSync('/home/toorik/Projects/LeanBCH/optimizer/_a1_busterprobe_report.json', JSON.stringify(out, null, 2));
for (const r of out) console.log(JSON.stringify(r));
const busters = out.filter((r) => r.A1_UNSOUND);
console.log(`\nA1-UNSOUND windows (additive says feasible, REAL op > budget): ${busters.length}`);
for (const b of busters) console.log(`  lo=${b.lo} w=${b.w}: additive=${b.additive} (<=budget) but REAL op_resched=${b.op_resched} > ${OP_BUDGET} (over by ${b.op_resched - OP_BUDGET}); additive under-counts by ${b.op_resched - b.additive}`);
