// FIXED-BOUNDARY residue A/B (the proper analog of chunk_ab3.mjs for the fp12Mul-USING
// residue-fused Miller chunks). Unlike chunk_ab3_residue.mjs (which sliced states at a STALE
// manifest whose opLo/opHi no longer match the on-disk chunk windows -> spurious rejects), this
// drives gen_miller_residue.mjs's OWN genChunk/inState/outState so the boundary commitments are
// self-consistent by construction. For each FIXED window it measures the SAME chunk twice:
//   E  = deployed eager baseline (singleton/bn254/lib/lazy/Bn254Lazy.cash)
//   V3 = full-lazy (variants/V3_millerres_lib.cash: lazy fp12Sqr + lazy mul034 + lazy fp12Mul)
// via the real covenant VM (measureCovenantFileResched, RESCHED fork -> compileFileBytecode).
// Identical inState(lo)/outState(hi) for both libs => "EVERY affected chunk still accepts on
// identical boundary commitments". Floor = 41 + ceil(op/800). Windows = the eager re-chunk
// windows produced by v3_fullverifier.mjs (LIB_IMPORT=eager), read from /tmp/v3full_eager.log.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { genChunk, inState, outState, ops } from './gen_miller_residue.mjs';
import { measureCovenantFileResched } from './_millermath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const EAGER = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const V3 = '../variants/V3_millerres_lib.cash';
const floorBytes = (op) => 41 + Math.ceil(op / 800);

// fixed windows = the eager re-chunk boundaries just measured (deployed byte counter, RESCHED)
const eagerJson = JSON.parse(readFileSync('/tmp/v3full_eager.log', 'utf8').split('\n').find((l) => l.startsWith('JSON ')).slice(5));
const windows = eagerJson.chunks.map((c) => [c.opLo, c.opHi]);
console.log(`fixed-boundary residue A/B: ${windows.length} windows (eager re-chunk), ops=${ops.length}`);
console.log('idx  win        fp12Mul line sqr |   E_op       V3_op    | dOp(V3-E) | E_B   V3_B | dB | E V3 acc');

let tE = 0, tV3 = 0, tBE = 0, tBV3 = 0, allAcc = true, totMul = 0, totLine = 0, totSqr = 0;
for (let idx = 0; idx < windows.length; idx++) {
  const [lo, hi] = windows[idx];
  const isFinal = hi === ops.length;
  const srcE = genChunk(lo, hi, isFinal);            // default LIB_IMPORT = eager
  if (!srcE.includes(EAGER)) throw new Error(`chunk ${idx}: eager import string not found (LIB_IMPORT env leaked?)`);
  const srcV3 = srcE.replace(EAGER, V3);
  const nMul = (srcE.match(/fp12Mul\(/g) || []).length;
  const nLine = (srcE.match(/line\(/g) || []).length;
  const nSqr = (srcE.match(/fp12Sqr\(/g) || []).length;
  totMul += nMul; totLine += nLine; totSqr += nSqr;
  const pE = join(GEN, '_probe_resAB_E.cash');
  const pV3 = join(GEN, '_probe_resAB_V3.cash');
  writeFileSync(pE, srcE); writeFileSync(pV3, srcV3);
  const inL = inState(lo).map(BigInt), outL = outState(hi).map(BigInt);
  const rE = measureCovenantFileResched(pE, inL, outL);
  const rV3 = measureCovenantFileResched(pV3, inL, outL);
  if ([rE, rV3].some((r) => r.operationCost === Infinity)) { console.log(`  ${idx} ERR ${rE.error || rV3.error}`); allAcc = false; continue; }
  const acc = rE.accepted && rV3.accepted; allAcc = allAcc && acc;
  const bE = floorBytes(rE.operationCost), bV3 = floorBytes(rV3.operationCost);
  tE += rE.operationCost; tV3 += rV3.operationCost; tBE += bE; tBV3 += bV3;
  const p = (x, n) => String(x).padStart(n);
  console.log(`  ${p(idx, 2)}  [${p(lo, 3)},${p(hi, 3)})   ${nMul}     ${p(nLine, 2)}  ${nSqr}  | ${p(rE.operationCost, 9)} ${p(rV3.operationCost, 9)} | ${p(rV3.operationCost - rE.operationCost, 8)} | ${p(bE, 4)} ${p(bV3, 4)} | ${p(bV3 - bE, 5)} | ${rE.accepted ? 'Y' : 'N'} ${rV3.accepted ? 'Y' : 'N'} ${acc ? 'OK' : 'FAIL'}`);
}
const pct = (a, b) => (100 * (a - b) / b).toFixed(2);
console.log('');
console.log(`residue fixed-boundary totals: fp12Mul=${totMul} line=${totLine} fp12Sqr=${totSqr} over ${windows.length} chunks`);
console.log(`TOTAL op: E=${tE}  V3=${tV3}   dOp(V3-E)=${tV3 - tE} (${pct(tV3, tE)}%)`);
console.log(`TOTAL floorBytes: E=${tBE}  V3=${tBV3}   dB(V3-E)=${tBV3 - tBE}`);
console.log(`opDelta/800 (pure op-pad-floor proxy) = ${((tV3 - tE) / 800).toFixed(0)} B`);
console.log(`ALL CHUNKS ACCEPT (E&V3, identical boundary commitments per window): ${allAcc}`);
console.log('JSON ' + JSON.stringify({
  windows: windows.length, fp12Mul: totMul, line: totLine, fp12Sqr: totSqr,
  opE: tE, opV3: tV3, dOp: tV3 - tE, floorE: tBE, floorV3: tBV3, dBfloor: tBV3 - tBE,
  opDeltaOver800: Math.round((tV3 - tE) / 800), allAccept: allAcc,
}));
