// bn254_extract.mjs — ONE-TIME BN254 residue-Miller cost-vector extraction (ADAPTER, read-only
// from a compatible external verifier.cash build). Emits optimizer/bn254_costvec.json:
//   - perOp[k]      : exact op(10000) [max-pad, VM-completed] contribution of op-block k, via
//                     nested-window DIFFERENCING (op10000(s,k+1)-op10000(s,k)=perOp[k], start-independent).
//   - redPerOp[k]   : exact redeem-bytecode-size contribution of op-block k (same differencing).
//   - K, redBase    : covenant overhead intercepts (interior 52-limb state).
//   - genesis/final : the two special forced chunks, measured directly for a width sweep.
//   - stage seams, budget, and the byte-model constants.
//
// WHY op(10000): near the floor pad the VM aborts at the op-budget mid-run, so the reported op is
// clamped ~budget; the TRUE completed op is only readable at max pad. The tuned on-chain unlocking
// length is then EXACTLY  tunedL = ceil((op(10000) - 42800)/799)  (empirically exact +/-1, the pad
// self-push fixpoint), and a window is FEASIBLE iff op(10000) <= OP_BUDGET (8,032,800). Both are
// pure functions of the (additive) op(10000), which is what we extract here.
//
// Measures op ONLY via the real libauth BCH-2026 VM driven through a synthetic token covenant tx
// (build_vectors.mjs::evalCov convention), byte-for-byte the deployed buildCovStep P2SH counter.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBn254Adapter } from './bn254_adapter.mjs';

const adapter = await loadBn254Adapter();
const { genChunk, ops, inState, outState } = adapter.generator;
const { compileFileBytecodeRaw, commitBin, CATEGORY } = adapter.millermath;
const { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } = adapter.libauth;
const HERE = dirname(fileURLToPath(import.meta.url));

const OUT = process.env.COSTVEC_OUT || join(HERE, 'bn254_costvec.json');
const PROBE = '/tmp/_bn254_extract.cash';
const VM = createVirtualMachineBch2026(false); // consensus-64 policy (rv.json / build_vectors realVm)
const OP_BUDGET = (41 + 10000) * 800;          // 8,032,800

const pushInt = (n) => encodeDataPush(bigIntToVmNumber(n));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

// Compile window [lo,hi) as P2SH redeem, drive the covenant tx at MAX pad, read completed op(10000).
function measMaxPad(lo, hi, isFinal, relocGenesis = false) {
  writeFileSync(PROBE, genChunk(lo, hi, isFinal, relocGenesis));
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecodeRaw(PROBE)]); }
  catch (e) { return { err: String(e?.message ?? e).slice(0, 80) }; }
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = (relocGenesis ? genesisCovInLimbs(lo) : inState(lo)).map(BigInt);
  const outLimbs = outState(hi).map(BigInt);
  const argLimbs = inState(lo).map(BigInt); // unlocking always pushes the full incoming state limbs
  const argb = Uint8Array.from([...argLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const padTot = 10000 - argb.length - tail;
  if (padTot < 2) return { err: 'args+redeem exceed 10000', redeem: redeem.length, tail, argBytes: argb.length };
  const unlocking = Uint8Array.from([...padBytes(padTot), ...argb, ...rpush]);
  const st = VM.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(inLimbs)) }],
    transaction: { version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 },
  });
  return { op10000: st.metrics.operationCost, redeem: redeem.length, tail, argBytes: argb.length,
           completed: st.error === undefined, err: null };
}
// reloc genesis covIn binds ONLY the 10 runtime point limbs (ptL): reconstruct them from inState.
// inState layout: f(12) R0(6) ptL(10) c(12) cInv(12)  -> ptL is indices [18,28).
function genesisCovInLimbs(lo) { return inState(lo).slice(18, 28); }

const cls = (o) => (o.t === 'dl' || o.t === 'al') ? o.t + (o.j === 0 ? '0' : 'B') : o.t;
const N = ops.length;
console.error(`extracting ${N} op-blocks (consensus-64), OP_BUDGET=${OP_BUDGET}`);

// ---- per-op op(10000) + redeem-size via nested-window differencing --------------------------------
const perOp = new Array(N).fill(null);
const redPerOp = new Array(N).fill(null);
const seen = new Array(N).fill(0);
let compiles = 0;
// sequential overlapping runs; extend each while the VM COMPLETES at max pad (only completed runs
// give the true op; the abort-clamped ones are skipped). Overlap re-measures for a cross-check.
let start = 0;
while (start < N - 1) {
  let prevOp = null, prevRed = null, w = 0, lastGood = start;
  for (let hi = start + 1; hi <= N - 1; hi++) {
    const r = measMaxPad(start, hi, false);
    compiles++;
    if (r.err || !r.completed) break; // window no longer feasible/complete -> stop this run
    if (prevOp !== null) {
      const k = hi - 1, po = r.op10000 - prevOp, pr = r.redeem - prevRed;
      if (perOp[k] === null) { perOp[k] = po; redPerOp[k] = pr; }
      seen[k]++;
    }
    prevOp = r.op10000; prevRed = r.redeem; lastGood = hi; w = hi - start;
    if (w >= 24) break; // cap window width (V3 lib feasibility ceiling ~28 ops)
  }
  // advance start; keep a 2-op overlap so every interior k gets covered by some run
  start = Math.max(lastGood - 1, start + 1);
  if (w === 0) start = start + 1; // couldn't even do 2 ops (shouldn't happen interior)
}
const missing = perOp.map((v, k) => v === null ? k : -1).filter((k) => k >= 1);
console.error(`per-op differencing done: ${compiles} compiles, missing k (excl 0): ${missing.length ? missing.join(',') : 'none'}`);

// ---- intercepts K (op) and redBase (redeem) for interior windows, + perOp[0] ----------------------
// op10000(s,s+1) = K + perOp[s]; pick an interior anchor s with a known perOp[s].
function anchorIntercept(s) {
  const r = measMaxPad(s, s + 1, false); compiles++;
  return { op1: r.op10000, red1: r.redeem };
}
let K = null, redBase = null;
for (let s = 5; s < N - 2 && K === null; s++) {
  if (perOp[s] !== null && redPerOp[s] !== null) { const a = anchorIntercept(s); K = a.op1 - perOp[s]; redBase = a.red1 - redPerOp[s]; }
}
// perOp[0] = op10000(0,1) - K   (non-reloc interior model for op 0; genesis handled separately)
{ const r0 = measMaxPad(0, 1, false); compiles++; perOp[0] = r0.op10000 - K; redPerOp[0] = r0.redeem - redBase; }

// fill any residual missing interior perOp by a direct short-window difference
for (const k of perOp.map((v, i) => v === null ? i : -1).filter((i) => i >= 1)) {
  const s = Math.max(0, k - 6);
  const a = measMaxPad(s, k, false), b = measMaxPad(s, k + 1, false); compiles += 2;
  if (!a.err && !b.err && a.completed && b.completed) { perOp[k] = b.op10000 - a.op10000; redPerOp[k] = b.redeem - a.redeem; }
}

// ---- genesis (reloc) + final chunks: measured op(10000) for a width sweep ---------------------------
// genesis is chunk 0 [0,h) with relocGenesis covIn (10 pts); final is [lo,N) isFinal (36-limb handoff).
function widthSweep(kind) {
  const rows = [];
  if (kind === 'genesis') {
    for (let hi = 2; hi <= 30; hi++) { const r = measMaxPad(0, hi, false, true); compiles++;
      rows.push({ hi, op10000: r.op10000 ?? null, redeem: r.redeem ?? null, tail: r.tail ?? null, argBytes: r.argBytes ?? null, completed: !!r.completed, err: r.err }); if (r.err || !r.completed) break; }
  } else {
    for (let lo = N - 2; lo >= N - 30; lo--) { const r = measMaxPad(lo, N, true); compiles++;
      rows.push({ lo, op10000: r.op10000 ?? null, redeem: r.redeem ?? null, tail: r.tail ?? null, argBytes: r.argBytes ?? null, completed: !!r.completed, err: r.err }); if (r.err || !r.completed) break; }
  }
  return rows;
}
const genesisSweep = widthSweep('genesis');
const finalSweep = widthSweep('final');

// ---- boundary state bytes at each cut (committed-state push size) -----------------------------------
// interior cut commits the 52-limb state; the vk_x->miller seam (cut 0) is the reloc genesis (10 pts);
// the miller->tail seam (cut N) hands off 36 limbs. push size: 33B per full-width limb, 1B for 0/1.
const pushSize = (v) => { const b = bigIntToVmNumber(BigInt(v)); return encodeDataPush(b).length; };
function stateBytesAt(cut) {
  const limbs = cut >= N ? outState(N).map(BigInt) : inState(cut).map(BigInt);
  return limbs.reduce((s, v) => s + pushSize(v), 0);
}
const boundaryStateBytes = [];
for (let cut = 0; cut <= N; cut++) boundaryStateBytes.push(stateBytesAt(cut));

const out = {
  meta: { generator: 'gen_miller_residue.mjs', numOps: N, policy: 'consensus-64 (createVirtualMachineBch2026(false), rv.json/build_vectors realVm)',
          opBudget: OP_BUDGET, tunedFormula: 'tunedL = ceil((op10000 - 42800)/799); bytes = 35 + max(tunedL, argBytes+tail+2)',
          feasible: 'op10000 <= opBudget', compiles, extractedAt: new Date().toISOString() },
  classOf: ops.map(cls),
  perOp, redPerOp, K, redBase,
  boundaryStateBytes,
  argBytesInterior: 1652,
  genesisSweep, finalSweep,
};
writeFileSync(OUT, JSON.stringify(out));
console.error(`wrote ${OUT}: perOp[${N}], K=${K}, redBase=${redBase}, ${compiles} total compiles`);
// quick self-consistency: predict op10000 of a few interior windows vs a fresh measure
let maxErr = 0;
for (const [lo, hi] of [[20, 33], [100, 113], [200, 214], [260, 273]]) {
  const pred = K + perOp.slice(lo, hi).reduce((a, b) => a + b, 0);
  const real = measMaxPad(lo, hi, false).op10000; compiles++;
  maxErr = Math.max(maxErr, Math.abs(pred - real));
  console.error(`  check [${lo},${hi}) predOp=${pred} realOp=${real} err=${pred - real}`);
}
console.error(`additivity max abs op-error on held-out windows: ${maxErr} (=> ~${(maxErr / 799).toFixed(2)} bytes)`);
