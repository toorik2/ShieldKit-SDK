// B3 residue-chunk A/B: the c^-(6x+2)-fused BN254 Miller residue chunks (the fp12Mul-USING build).
// Each chunk exercises fp12Mul (cf/cmul1) + line->mul034 + fp12Sqr. Measures deployed eager (E)
// vs full-lazy V3res (lazy fp12Sqr + lazy mul034 + lazy fp12Mul; all output-reducing so every
// fp12Mul/mul034 operand stays in [0,p)). Real covenant VM (RESCHED). Floor = 41+ceil(op/800).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Fp2, f12limbs, r6limbs, pairsFor, vec, millerBatchOps, singlePairMiller, PT_CFG, ptLimbs, measureCovenantFileResched } from './_millermath.mjs';
import { millerFusedOps, residueWitness } from './_residuemath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const EAGER = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const floorBytes = (op) => 41 + Math.ceil(op / 800);

const PAIRS = pairsFor(vec.publicInputs);
const ptL = PAIRS.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
const { boundary: fRawPlan } = millerBatchOps(PAIRS);
const { c: C_PLAN, cInv: CINV_PLAN } = residueWitness(fRawPlan);
const { ops, states } = millerFusedOps(PAIRS, C_PLAN, CINV_PLAN);
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0]), ...f12limbs(s.c), ...f12limbs(s.cInv)];
const withPts = (limbs) => { const fr = limbs.slice(0, 18); const rest = limbs.slice(18); return [...fr, ...ptL, ...rest]; };
const inState = (i) => withPts(stateLimbs(states[i]));
const outState = (i) => i === states.length - 1
  ? [...f12limbs(states[i].f), ...f12limbs(states[i].c), ...f12limbs(states[i].cInv)]
  : withPts(stateLimbs(states[i]));

const man = JSON.parse(readFileSync(join(GEN, 'manifest_millerres.json'), 'utf8'));
console.log(`residue chunks: ${man.numChunks}, ops=${man.numOps}`);
console.log('idx fp12Mul line sqr |   E_op      V2_op      V3_op   | dOp(V3-E) dOp(V3-V2) | E_B  V2_B V3_B | dB(V3-E) dB(V3-V2) | E V2 V3');
let tE = 0, tV2 = 0, tV3 = 0, tBE = 0, tBV2 = 0, tBV3 = 0, allAcc = true, totMul = 0, totLine = 0;
for (const ch of man.chunks) {
  const file = join(GEN, `millerres_${String(ch.idx).padStart(2, '0')}.cash`);
  const src = readFileSync(file, 'utf8');
  const nMul = (src.match(/fp12Mul/g) || []).length;
  const nLine = (src.match(/line\(/g) || []).length;
  const nSqr = (src.match(/fp12Sqr/g) || []).length;
  totMul += nMul; totLine += nLine;
  const v2file = file.replace(/\.cash$/, '_v2res.cash');
  const v3file = file.replace(/\.cash$/, '_v3res.cash');
  writeFileSync(v2file, src.replace(EAGER, '../variants/V2_miller_lib.cash'));
  writeFileSync(v3file, src.replace(EAGER, '../variants/V3_millerres_lib.cash'));
  const inLimbs = inState(ch.opLo), outLimbs = outState(ch.opHi);
  const rE = measureCovenantFileResched(file, inLimbs, outLimbs);
  const rV2 = measureCovenantFileResched(v2file, inLimbs, outLimbs);
  const rV3 = measureCovenantFileResched(v3file, inLimbs, outLimbs);
  if ([rE, rV2, rV3].some((r) => r.operationCost === Infinity)) { console.log(`  ${ch.idx} ERR ${rE.error || rV2.error || rV3.error}`); allAcc = false; continue; }
  const acc = rE.accepted && rV2.accepted && rV3.accepted; allAcc = allAcc && acc;
  const bE = floorBytes(rE.operationCost), bV2 = floorBytes(rV2.operationCost), bV3 = floorBytes(rV3.operationCost);
  tE += rE.operationCost; tV2 += rV2.operationCost; tV3 += rV3.operationCost; tBE += bE; tBV2 += bV2; tBV3 += bV3;
  const p = (x, n) => String(x).padStart(n);
  console.log(`  ${p(ch.idx, 2)}   ${nMul}     ${p(nLine, 2)}  ${nSqr}  | ${p(rE.operationCost, 9)} ${p(rV2.operationCost, 9)} ${p(rV3.operationCost, 9)} | ${p(rV3.operationCost - rE.operationCost, 8)} ${p(rV3.operationCost - rV2.operationCost, 9)} | ${p(bE, 4)} ${p(bV2, 4)} ${p(bV3, 4)} | ${p(bV3 - bE, 7)} ${p(bV3 - bV2, 8)} | ${rE.accepted ? 'Y' : 'N'} ${rV2.accepted ? 'Y' : 'N'} ${rV3.accepted ? 'Y' : 'N'}${acc ? '' : ' FAIL'}`);
}
const pct = (a, b) => (100 * (a - b) / b).toFixed(2);
console.log('');
console.log(`residue totals: fp12Mul=${totMul} line=${totLine}`);
console.log(`TOTAL op: E=${tE}  V2=${tV2}  V3=${tV3}`);
console.log(`  dOp(V3-E)  = ${tV3 - tE} (${pct(tV3, tE)}%)   [combined lazy sqr+mul034+fp12Mul vs deployed eager]`);
console.log(`  dOp(V3-V2) = ${tV3 - tV2} (${pct(tV3, tV2)}%)   [ISOLATED mul034+fp12Mul lever on top of lazy-sqr]`);
console.log(`  dOp(V2-E)  = ${tV2 - tE} (${pct(tV2, tE)}%)   [fp12Sqr lever alone]`);
console.log(`TOTAL floorBytes: E=${tBE}  V2=${tBV2}  V3=${tBV3}`);
console.log(`  dB(V3-E)=${tBV3 - tBE}  dB(V3-V2)=${tBV3 - tBV2}  dB(V2-E)=${tBV2 - tBE}`);
console.log(`ALL CHUNKS ACCEPT (E&V2&V3, identical boundary commitments): ${allAcc}`);
console.log(JSON.stringify({ opE: tE, opV2: tV2, opV3: tV3, dOp_V3_E: tV3 - tE, dOp_V3_V2: tV3 - tV2, dOp_V2_E: tV2 - tE, floorE: tBE, floorV2: tBV2, floorV3: tBV3, dB_V3_E: tBV3 - tBE, dB_V3_V2: tBV3 - tBV2, dB_V2_E: tBV2 - tBE, allAccept: allAcc, fp12MulCount: totMul, lineCount: totLine }));
