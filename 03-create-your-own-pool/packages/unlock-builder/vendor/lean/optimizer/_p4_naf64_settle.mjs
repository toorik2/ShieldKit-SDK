// P4 NAF length-64 settle — FORK-FREE.
// Reconstructs the miller op-list STRUCTURE (cashc-independent), finds the minimal-weight
// length-64 signed encoding of 6x+2 via DP, and re-runs the DEPLOYED chunkplan DP on both
// the shipped (65-step) and shortened (64-step) cost vectors to read the repacked byte delta.
import { readFileSync } from 'node:fs';
import { buildClassCostVec, normalizeParams, planOptimal } from '/home/toorik/Projects/LeanBCH/optimizer/chunkplan.mjs';

const BN_X = 4965661367192848881n;
const SIX = 6n * BN_X + 2n;                          // 29793968203157093288
const TARGET_UNLOCK = 10000, OP_BUDGET = (41 + 10000) * 800; // 8,032,800
const HDR = 3;

// ---- shipped NAF (verbatim from _millermath.mjs L50) ----
const naf = (a) => { const r = []; for (; a > 1n; a >>= 1n) { if ((a & 1n) === 0n) r.unshift(0); else if ((a & 3n) === 3n) { r.unshift(-1); a += 1n; } else r.unshift(1); } return r; };
const ATE_NAF = naf(SIX);

// ---- reconstruct the FUSED miller op-list CLASS sequence from an encoding ----
// Mirrors millerBatchOps({skipPairs:{1}}) + millerFusedOps: per NAF step k -> [sqr,(cf if digit),
// dl0,(al0 if digit), dlB,(alB), dlB,(alB)]; then 3x pp; then cmul1. Class map = faithful_plan `cls`.
function classSeq(enc) {
  const seq = [];
  for (let k = 0; k < enc.length; k++) {
    const digit = enc[k];
    seq.push('sqr');
    if (digit !== 0) seq.push('cf');
    // pair j=0 (both proof): dl0 [+ al0]; pairs j=2,3 (VK Q baked) -> class 'B': dlB [+ alB]
    seq.push('dl0'); if (digit !== 0) seq.push('al0');
    seq.push('dlB'); if (digit !== 0) seq.push('alB');
    seq.push('dlB'); if (digit !== 0) seq.push('alB');
  }
  seq.push('pp', 'pp', 'pp', 'cmul1');
  return seq;
}

// ---- validate: shipped classSeq == deployed json.classOf ----
const J = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/bn254_costvec_deployed_selfpin.json', 'utf8'));
const shippedSeq = classSeq(ATE_NAF);
const matchShipped = JSON.stringify(shippedSeq) === JSON.stringify(J.classOf);
console.log('=== op-list structure validation ===');
console.log('ATE_NAF length (shipped loop steps):', ATE_NAF.length, '| nonzeros:', ATE_NAF.filter(x => x).length);
console.log('reconstructed classSeq length:', shippedSeq.length, '| json.classOf length:', J.classOf.length);
console.log('reconstructed classSeq EXACTLY == deployed json.classOf ?', matchShipped);
if (!matchShipped) { for (let i = 0; i < Math.max(shippedSeq.length, J.classOf.length); i++) if (shippedSeq[i] !== J.classOf[i]) { console.log('  first mismatch at', i, shippedSeq[i], 'vs', J.classOf[i]); break; } }

// ---- DP: minimal-weight length-<=65-position signed {-1,0,+1} encoding, carry must vanish ----
// digits d_0..d_top with sum d_i 2^i = SIX; minimize sum|d_i|; top position is where carry clears.
// Carry-based DP over positions (LSB->MSB): state = carry c, c_0 = SIX; at pos i pick d in {-1,0,1}
// with d ≡ c (mod 2), c' = (c-d)/2; done when c==0. Records the digit path. Yields the OVERALL
// min-weight signed rep; its top set position = the loop length (implicit leading = top digit).
function minWeightSignedRep(N) {
  // Map carry(bigint) -> {w, path:[digits LSB..]}; iterate a FIXED horizon (>bitlen). Once a state's
  // carry clears (0n) its path is a COMPLETE rep (higher digits all 0). Lingering nonzero carries (e.g.
  // the ...111 = -1 self-loop c=1 -> c=1) only accrue weight, so states.get(0n) is the global min-weight.
  const HORIZON = 70; // 6x+2 < 2^65
  let states = new Map(); states.set(N, { w: 0, path: [] });
  for (let pos = 0; pos < HORIZON; pos++) {
    const next = new Map();
    const relax = (key, w, path) => { const cur = next.get(key); if (!cur || w < cur.w) next.set(key, { w, path }); };
    for (const [c, st] of states) {
      if (c === 0n) { relax(0n, st.w, st.path); continue; } // carry cleared: freeze (no digit appended)
      const parity = ((c % 2n) + 2n) % 2n;
      const choices = parity === 0n ? [0] : [1, -1];
      for (const d of choices) relax((c - BigInt(d)) / 2n, st.w + Math.abs(d), [...st.path, d]);
    }
    states = next;
  }
  const best = states.get(0n);
  if (!best) throw new Error('DP: no carry-cleared state within horizon');
  // trim trailing zeros of the path (positions above the top nonzero)
  const path = [...best.path];
  while (path.length && path[path.length - 1] === 0) path.pop();
  return path; // LSB-first, path[len-1] = top digit
}

const repLSB = minWeightSignedRep(SIX);
// reconstruct value
const valOf = (lsb) => lsb.reduce((s, d, i) => s + BigInt(d) * (1n << BigInt(i)), 0n);
const repVal = valOf(repLSB);
console.log('\n=== minimal-weight signed rep of 6x+2 ===');
console.log('6x+2 =', SIX.toString());
console.log('min-weight rep top position (2^p):', repLSB.length - 1, '| total weight:', repLSB.map(Math.abs).reduce((a, b) => a + b, 0));
console.log('rep reconstructs 6x+2 ?', repVal === SIX);

// The miller loop's "encoding" is MSB-first with the TOP (leading) digit implicit (R=Q / cpow seed).
// Shipped: ATE_NAF is the array BELOW the implicit leading +1 @2^65 (loop length 65).
// Shortened: take the min-weight rep; its top digit is the implicit leading; the array below it
// (MSB-first) is the loop encoding. Loop length = (top position) since leading is implicit.
const topPos = repLSB.length - 1;                 // implicit leading position
const encShortMSB = [];                           // digits at positions topPos-1 .. 0 (MSB-first)
for (let p = topPos - 1; p >= 0; p--) encShortMSB.push(repLSB[p]);
console.log('shortened loop length (implicit leading @2^' + topPos + '):', encShortMSB.length, '| array nonzeros:', encShortMSB.filter(x => x).length);
// sanity: implicit leading + array sums to 6x+2
const reSum = (1n << BigInt(topPos)) + encShortMSB.reduce((s, d, i) => s + BigInt(d) * (1n << BigInt(topPos - 1 - i)), 0n);
console.log('implicit-leading(2^' + topPos + ') + array == 6x+2 ?', reSum === SIX);
console.log('shortened is 1 loop-step shorter than shipped ?', encShortMSB.length === ATE_NAF.length - 1);

// ---- op-list of the shortened encoding + histogram delta ----
const shortSeq = classSeq(encShortMSB);
const hist = (s) => s.reduce((h, c) => (h[c] = (h[c] || 0) + 1, h), {});
const hS = hist(shippedSeq), hL = hist(shortSeq);
console.log('\n=== op histogram delta (shortened - shipped) ===');
const allCls = [...new Set([...Object.keys(hS), ...Object.keys(hL)])].sort();
for (const c of allCls) console.log('  ', c, ':', (hL[c] || 0) - (hS[c] || 0), `(shipped ${hS[c] || 0} -> short ${hL[c] || 0})`);
console.log('shortSeq length:', shortSeq.length, '(shipped', shippedSeq.length, ')');

// removed op-cost via DEPLOYED marginMean (real-VM-measured):
const removed = { sqr: (hS.sqr || 0) - (hL.sqr || 0), dl0: (hS.dl0 || 0) - (hL.dl0 || 0), dlB: (hS.dlB || 0) - (hL.dlB || 0), al0: (hS.al0 || 0) - (hL.al0 || 0), alB: (hS.alB || 0) - (hL.alB || 0), cf: (hS.cf || 0) - (hL.cf || 0) };
let removedOp = 0, removedRed = 0;
for (const [c, n] of Object.entries(removed)) { removedOp += n * J.marginMean[c]; removedRed += n * J.redMargin[c]; }
console.log('\nremoved op-cost (marginMean, real-VM):', removedOp, '=> raw op-pad bytes (op/800):', (removedOp / 800).toFixed(1));
console.log('removed redeem bytes:', removedRed);

// ============ reconstruct DEPLOYED chunkplan DP for BOTH, read repacked byte delta ============
function buildParams(redeemBytesOf, finalStateBytes) {
  return normalizeParams({
    opCostPerByte: 800, densityBase: 41, padSafety: 96, minPad: 3, lockingBytes: 35,
    targetUnlock: TARGET_UNLOCK, hashIterCost: 64,
    opBudget: OP_BUDGET - J.SAFETY_MARGIN,
    finalStateBytes,
    overheadOp: () => J.interceptTyp - J.redBase - HDR,
    redeemBytes: redeemBytesOf, pushHeader: () => HDR,
  });
}
// exact replica of faithful_plan's cost-vector assembly (incl. final-region overwrite)
function assemble(seq, boundaryStateBytes, finalForcedCut) {
  const N = seq.length;
  const blockDelta = { 0: { opTyp: J.deltaGen, opWC: J.deltaGen } };
  const { costVec } = buildClassCostVec(seq, {
    marginMean: J.marginMean, marginMax: J.marginMax, redMargin: J.redMargin,
    boundaryStateBytes, blockDelta, forcedCuts: [finalForcedCut], stage: 'miller',
  });
  const EPS = 1000, tb = N - finalForcedCut;
  for (let k = finalForcedCut; k < N - 1; k++) { costVec[k].opCost = EPS; costVec[k].opCostWorstCase = EPS; }
  const last = Math.max(EPS, J.finalRealOp - J.interceptTyp - EPS * (tb - 1));
  costVec[N - 1].opCost = last; costVec[N - 1].opCostWorstCase = last;
  const redeemBytesOf = (lo, hi) => { let r = J.redBase; for (let k = lo; k < hi; k++) r += J.redMargin[seq[k]]; return r; };
  const params = buildParams(redeemBytesOf, boundaryStateBytes[N]);
  return { costVec, params };
}

// SHIPPED: use the deployed json arrays verbatim (must reproduce modelOnlyDpBytes = 195741)
{
  const { costVec, params } = assemble(J.classOf, J.boundaryStateBytes, J.finalForcedCut);
  const r = planOptimal(costVec, params);
  console.log('\n=== SHIPPED cost vector -> planOptimal ===');
  console.log('reconstructed model DP bytes:', r.totalBytes, '| chunks:', r.partition.length, '| deployed modelOnlyDpBytes: 195741');
  console.log('reconstruction faithful (==195741) ?', r.totalBytes === 195741);
  globalThis._shipModel = r.totalBytes; globalThis._shipChunks = r.partition.length; globalThis._shipParts = r.partition;
}

// SHORTENED: splice out 4 interior blocks (the removed NAF step's sqr+dl0+dlB+dlB) from the
// deployed sequence + boundaryStateBytes, shift the forced-final cut by -4. The removed step is a
// ZERO-digit step (its op-list is exactly [sqr,dl0,dlB,dlB]). Interior boundaryStateBytes ~const 1716.
{
  // Find an interior zero-step block-run [sqr,dl0,dlB,dlB] to splice. The shipped step 0 is zero-digit
  // BUT block 0 carries the genesis reloc delta; splice a DIFFERENT interior zero-step to keep genesis intact.
  // ATE_NAF interior zero steps exist (e.g. index 2). Find its block offset in the sequence.
  let blk = 0, spliceAt = -1;
  for (let k = 0; k < ATE_NAF.length; k++) {
    const isZero = ATE_NAF[k] === 0;
    const stepLen = isZero ? 4 : 8; // [sqr,dl0,dlB,dlB] or [sqr,cf,dl0,al0,dlB,alB,dlB,alB]
    if (isZero && k > 0 && spliceAt < 0) { spliceAt = blk; } // first interior zero step (k>0)
    blk += stepLen;
  }
  // build shortened seq + boundaryStateBytes by removing 4 blocks at spliceAt
  const seqShort = [...J.classOf]; const bsbShort = [...J.boundaryStateBytes];
  // verify the 4 spliced blocks are exactly [sqr,dl0,dlB,dlB]
  const spliced = seqShort.slice(spliceAt, spliceAt + 4);
  console.log('\n=== SHORTENED cost vector ===');
  console.log('splice at block', spliceAt, '-> removing', JSON.stringify(spliced), '(expect ["sqr","dl0","dlB","dlB"])');
  seqShort.splice(spliceAt, 4);
  bsbShort.splice(spliceAt, 4);            // remove the 4 corresponding interior boundary entries (~1716 each)
  const finalForcedCutShort = J.finalForcedCut - 4;
  const { costVec, params } = assemble(seqShort, bsbShort, finalForcedCutShort);
  const r = planOptimal(costVec, params);
  console.log('shortened seq length:', seqShort.length, '(was', J.classOf.length, ')');
  console.log('shortened model DP bytes:', r.totalBytes, '| chunks:', r.partition.length);
  const delta = r.totalBytes - globalThis._shipModel;
  console.log('\n>>> REPACKED MODEL BYTE DELTA (short - shipped):', delta, 'B  <<<');
  console.log('>>> shipped miller-stage real bytes: 193202  ->  projected short real bytes ~=', 193202 + delta);
  console.log('>>> crown 212913  ->  projected P4 crown ~=', 212913 + delta);
}

// ---- A1: fused cInv^(6x+2) exponent totals correctly for the shortened encoding ----
// millerFusedOps builds cpow: seed cInv (=cInv^1), 64 squarings (implicit leading @2^64), and at each
// nonzero digit multiplies by cInv^(+1) [digit+1] or c^(1)=cInv^(-1) [digit-1]. Final cInv-exponent =
// (1 << topPos) + sum(digit_i * 2^i) = value of the representation. Verify == 6x+2 (chain-independent).
let expo = 1n << BigInt(topPos);
for (let i = 0; i < encShortMSB.length; i++) expo += BigInt(encShortMSB[i]) * (1n << BigInt(topPos - 1 - i));
console.log('\n=== A1 soundness (fused exponent) ===');
console.log('cInv-exponent accumulated by shortened fused loop:', expo.toString());
console.log('== 6x+2 (residue tail invariant) ?', expo === SIX);

// ============ ROBUSTNESS CROSS-CHECKS ============
console.log('\n=== cross-check A: per-chunk bound type of the SHIPPED plan ===');
{
  const { chunkBytes } = await import('/home/toorik/Projects/LeanBCH/optimizer/chunkplan.mjs');
  const { costVec, params } = assemble(J.classOf, J.boundaryStateBytes, J.finalForcedCut);
  const parts = globalThis._shipParts;
  let opPad = 0, floor = 0;
  for (const c of parts) { const cb = chunkBytes(costVec, c.lo, c.hi, params); if (cb.bound === 'op-pad') opPad++; else floor++; }
  console.log('op-pad-bound chunks:', opPad, '| floor-bound chunks:', floor, '(of', parts.length, ')');
}

console.log('\n=== cross-check B: DP on the ACTUAL reordered shortened sequence (not a splice) ===');
{
  // reconstruct boundaryStateBytes for shortSeq: genesis(1652), b1(1651), interior 1716, final region, final(1188)
  const N = shortSeq.length; // 344
  const bsb = new Array(N + 1);
  bsb[0] = J.boundaryStateBytes[0];            // 1652 genesis (reloc binds 10 pts) — same structure
  bsb[1] = J.boundaryStateBytes[1];            // 1651
  for (let k = 2; k < N; k++) bsb[k] = 1716;   // interior committed state (f12+R0(6)+cInv12+pts) ~ const
  bsb[N] = J.boundaryStateBytes[J.classOf.length]; // final tail 1188
  const finalForcedCutShort = J.finalForcedCut - 4;
  // guard: the last 4 blocks must still be [pp,pp,pp,cmul1]
  console.log('shortSeq tail:', JSON.stringify(shortSeq.slice(-4)), '| finalForcedCutShort class:', shortSeq[finalForcedCutShort]);
  const { costVec, params } = assemble(shortSeq, bsb, finalForcedCutShort);
  const r = planOptimal(costVec, params);
  console.log('reordered-shortened model DP bytes:', r.totalBytes, '| chunks:', r.partition.length);
  console.log('delta vs shipped:', r.totalBytes - globalThis._shipModel, 'B  (splice gave -2039)');
}

console.log('\n=== cross-check C: fit-residual band on the removed op-cost ===');
{
  // removed op = 1 sqr + 1 dl0 + 2 dlB (marginMean). Bytes = ceil(removedOp/800). Fit maxAbsResid bounds it.
  const removedOp = J.marginMean.sqr + J.marginMean.dl0 + 2 * J.marginMean.dlB;
  const lo = Math.floor((removedOp - J.maxAbsResid) / 800), hi = Math.ceil((removedOp + J.maxAbsResid) / 800);
  console.log('removed op-cost:', removedOp, '| /800 =', (removedOp / 800).toFixed(1), '| band w/ maxAbsResid('+J.maxAbsResid+'):', -hi, '..', -lo, 'B');
}
