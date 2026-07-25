// B3 chunk-level A/B: real Miller chunk op-cost + op-pad byte floor across THREE libs on the
// SAME real chunks + identical boundary commitments:
//   E  = deployed eager baseline (singleton/bn254/lib/lazy/Bn254Lazy.cash)
//   V2 = lazy fp12Sqr only            (variants/V2_miller_lib.cash)  -- prior lever
//   V3 = lazy fp12Sqr + lazy mul034   (variants/V3_miller_lib.cash)  -- THIS lever (mul034 via line)
// Measured via the real covenant VM (measureCovenantFileResched, RESCHED fork). Floor = 41+ceil(op/800).
// Deltas: (V3-E) combined vs deployed; (V3-V2) isolated mul034 lever (both F<=p, +917 p^2 margin).
import { readFileSync, writeFileSync } from 'node:fs';
import { pairsFor, millerBatchOps, vec, ptLimbs, f12limbs, r6limbs, measureCovenantFileResched } from './_millermath.mjs';
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const man = JSON.parse(readFileSync('generated/manifest_miller.json', 'utf8'));
const pairs = pairsFor(vec.publicInputs.map(BigInt), undefined);
const { states } = millerBatchOps(pairs);
const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
const floorBytes = (op) => 41 + Math.ceil(op / 800);
const EAGER = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';

// every real chunk uses line()->mul034 (0 of them use fp12Mul; fp12Mul is residue-only, measured separately)
const chunks = [];
for (const ch of man.chunks) {
  const file = `generated/miller_${String(ch.idx).padStart(2, '0')}.cash`;
  const s = readFileSync(file, 'utf8');
  const nLine = (s.match(/line\(/g) || []).length;
  const nSqr = (s.match(/fp12Sqr/g) || []).length;
  chunks.push({ ch, file, nLine, nSqr });
}
console.log(`24 real Miller chunks; each uses line()->mul034. line-counts: ${chunks.map((c) => c.nLine).join(',')}`);
console.log('idx nLine nSqr |   E_op       V2_op      V3_op   | dOp(V3-E)  dOp(V3-V2) | E_B  V2_B  V3_B | dB(V3-E) dB(V3-V2) | E V2 V3 acc');
let tE = 0, tV2 = 0, tV3 = 0, tBE = 0, tBV2 = 0, tBV3 = 0, allAcc = true;
for (const { ch, file, nLine, nSqr } of chunks) {
  const inLimbs = [...stateLimbs(states[ch.opLo]), ...ptL];
  const outLimbs = [...stateLimbs(states[ch.opHi]), ...ptL];
  const src = readFileSync(file, 'utf8');
  const v2file = file.replace(/\.cash$/, '_v2ab.cash');
  const v3file = file.replace(/\.cash$/, '_v3ab.cash');
  writeFileSync(v2file, src.replace(EAGER, '../variants/V2_miller_lib.cash'));
  writeFileSync(v3file, src.replace(EAGER, '../variants/V3_miller_lib.cash'));
  const rE = measureCovenantFileResched(file, inLimbs, outLimbs);
  const rV2 = measureCovenantFileResched(v2file, inLimbs, outLimbs);
  const rV3 = measureCovenantFileResched(v3file, inLimbs, outLimbs);
  if ([rE, rV2, rV3].some((r) => r.operationCost === Infinity)) {
    console.log(`  ${ch.idx} ERR ${rE.error || rV2.error || rV3.error}`); allAcc = false; continue;
  }
  const acc = rE.accepted && rV2.accepted && rV3.accepted;
  allAcc = allAcc && acc;
  const bE = floorBytes(rE.operationCost), bV2 = floorBytes(rV2.operationCost), bV3 = floorBytes(rV3.operationCost);
  tE += rE.operationCost; tV2 += rV2.operationCost; tV3 += rV3.operationCost;
  tBE += bE; tBV2 += bV2; tBV3 += bV3;
  const pad = (x, n) => String(x).padStart(n);
  console.log(`  ${pad(ch.idx, 2)}  ${nLine}   ${nSqr}  | ${pad(rE.operationCost, 9)} ${pad(rV2.operationCost, 9)} ${pad(rV3.operationCost, 9)} | ${pad(rV3.operationCost - rE.operationCost, 8)} ${pad(rV3.operationCost - rV2.operationCost, 9)} | ${pad(bE, 4)} ${pad(bV2, 4)} ${pad(bV3, 4)} | ${pad(bV3 - bE, 6)} ${pad(bV3 - bV2, 8)} | ${rE.accepted ? 'Y' : 'N'} ${rV2.accepted ? 'Y' : 'N'} ${rV3.accepted ? 'Y' : 'N'} ${acc ? 'OK' : 'FAIL'}`);
}
const pct = (a, b) => (100 * (a - b) / b).toFixed(2);
console.log('');
console.log(`TOTAL op:   E=${tE}  V2=${tV2}  V3=${tV3}`);
console.log(`  dOp(V3-E)  = ${tV3 - tE} (${pct(tV3, tE)}%)   [combined lazy-sqr + lazy-mul034 vs deployed eager]`);
console.log(`  dOp(V3-V2) = ${tV3 - tV2} (${pct(tV3, tV2)}%)   [ISOLATED mul034 lever on top of lazy-sqr]`);
console.log(`  dOp(V2-E)  = ${tV2 - tE} (${pct(tV2, tE)}%)   [fp12Sqr lever alone, for reference]`);
console.log(`TOTAL floorBytes: E=${tBE}  V2=${tBV2}  V3=${tBV3}`);
console.log(`  dB(V3-E)  = ${tBV3 - tBE}   [combined vs deployed eager]`);
console.log(`  dB(V3-V2) = ${tBV3 - tBV2}   [isolated mul034 lever]`);
console.log(`  dB(V2-E)  = ${tBV2 - tBE}   [fp12Sqr lever alone]`);
console.log(`ALL CHUNKS ACCEPT (E&V2&V3, identical boundary commitments): ${allAcc}`);
console.log(JSON.stringify({
  opE: tE, opV2: tV2, opV3: tV3,
  dOp_V3_E: tV3 - tE, dOp_V3_V2: tV3 - tV2, dOp_V2_E: tV2 - tE,
  floorE: tBE, floorV2: tBV2, floorV3: tBV3,
  dB_V3_E: tBV3 - tBE, dB_V3_V2: tBV3 - tBV2, dB_V2_E: tBV2 - tBE,
  allAccept: allAcc,
}));
