// _optgap_measure.mjs — independent real-compile oracle for the optimality-gap probe.
// Replicates bn254_faithful_plan.mjs::measureDeployed EXACTLY (deployed compile + real BCH-2026 VM,
// deployed tunedLen bytes). Adds a disk cache so repeated searches are cheap.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

export const N = ops.length;
export { OP_BUDGET, TARGET_UNLOCK };
const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = '/tmp/_optgap_probe.cash';

const gen = (lo, hi, isFinal, reloc) => genChunk(lo, hi, isFinal, reloc).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

function buildCtx(lo, hi) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc));
  const redeem = Uint8Array.from([...compileFileBytecode(PROBE)]);
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

function measureDeployedRaw(lo, hi) {
  let ctx; try { ctx = buildCtx(lo, hi); } catch (e) { return { feasible: false, compileError: String(e?.message ?? e).slice(0, 80) }; }
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

// disk cache
const CACHE_FILE = '/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_optgap_cache.json';
let CACHE = {};
if (existsSync(CACHE_FILE)) { try { CACHE = JSON.parse(readFileSync(CACHE_FILE, 'utf8')); } catch { CACHE = {}; } }
let dirty = 0, compiles = 0;
export function measure(lo, hi) {
  const key = `${lo},${hi}`;
  if (CACHE[key]) return CACHE[key];
  const m = measureDeployedRaw(lo, hi);
  compiles++;
  CACHE[key] = m; dirty++;
  if (dirty >= 20) { writeFileSync(CACHE_FILE, JSON.stringify(CACHE)); dirty = 0; }
  return m;
}
export function flush() { if (dirty) { writeFileSync(CACHE_FILE, JSON.stringify(CACHE)); dirty = 0; } }
export function compileCount() { return compiles; }

// evaluate a full partition (cuts array): total real bytes + max real worst op + feasibility under a budget
export function evalPartition(cuts, budget = OP_BUDGET) {
  let total = 0, maxOp = 0, feasible = true; const rows = [];
  for (let i = 0; i + 1 < cuts.length; i++) {
    const lo = cuts[i], hi = cuts[i + 1];
    const m = measure(lo, hi);
    if (!m.feasible || m.realWorstOp > budget) { feasible = false; rows.push({ lo, hi, feasible: false, realWorstOp: m.realWorstOp ?? null }); continue; }
    total += m.realBytes; maxOp = Math.max(maxOp, m.realWorstOp);
    rows.push({ lo, hi, realBytes: m.realBytes, realWorstOp: m.realWorstOp });
  }
  return { cuts, totalRealBytes: feasible ? total : Infinity, maxRealWorstOp: maxOp, feasible, rows };
}
