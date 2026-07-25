// Chunk-level A/B: real Miller chunk op-cost + bytes with baseline lib vs V2 delayed-reduction lib.
// Swaps only the imported lib (baseline Bn254Lazy.cash -> V2_miller_lib.cash, which differs ONLY in
// fp12Sqr). Measures via the real covenant VM (measureCovenantFileResched): op-cost, accept, and the
// op-pad-bound byte floor = 41 + ceil(opCost/800).
import { readFileSync, writeFileSync } from 'node:fs';
import { pairsFor, millerBatchOps, vec, ptLimbs, f12limbs, r6limbs, measureCovenantFileResched } from './_millermath.mjs';
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const man = JSON.parse(readFileSync('generated/manifest_miller.json', 'utf8'));
const pairs = pairsFor(vec.publicInputs.map(BigInt), undefined);
const { states } = millerBatchOps(pairs);
const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
const floorBytes = (op) => 41 + Math.ceil(op / 800);

// find chunks containing fp12Sqr
const fp12Chunks = [];
for (const ch of man.chunks) {
  const file = `generated/miller_${String(ch.idx).padStart(2, '0')}.cash`;
  const nSqr = (readFileSync(file, 'utf8').match(/fp12Sqr/g) || []).length;
  if (nSqr > 0) fp12Chunks.push({ ch, file, nSqr });
}
console.log(`chunks with fp12Sqr: ${fp12Chunks.map((c) => `${c.ch.idx}(x${c.nSqr})`).join(' ')}`);
console.log('idx  nSqr   base_opCost  V2_opCost   dOp     base_floorB V2_floorB  dB   base_acc V2_acc');
let totBase = 0, totV2 = 0, totBaseB = 0, totV2B = 0;
for (const { ch, file, nSqr } of fp12Chunks) {
  const inLimbs = [...stateLimbs(states[ch.opLo]), ...ptL];
  const outLimbs = [...stateLimbs(states[ch.opHi]), ...ptL];
  const v2file = file.replace(/miller_(\d+)\.cash/, 'miller_$1_v2.cash');
  let s = readFileSync(file, 'utf8').replace('../../../singleton/bn254/lib/lazy/Bn254Lazy.cash', '../variants/V2_miller_lib.cash');
  writeFileSync(v2file, s);
  const rb = measureCovenantFileResched(file, inLimbs, outLimbs);
  const rv = measureCovenantFileResched(v2file, inLimbs, outLimbs);
  if (rb.operationCost === Infinity || rv.operationCost === Infinity) { console.log(`  ${ch.idx}  ERR ${rb.error || rv.error}`); continue; }
  const bF = floorBytes(rb.operationCost), vF = floorBytes(rv.operationCost);
  totBase += rb.operationCost; totV2 += rv.operationCost; totBaseB += bF; totV2B += vF;
  console.log(`  ${String(ch.idx).padStart(2)}   ${nSqr}    ${String(rb.operationCost).padStart(9)}  ${String(rv.operationCost).padStart(9)}  ${String(rv.operationCost - rb.operationCost).padStart(7)}   ${String(bF).padStart(7)}   ${String(vF).padStart(7)}  ${String(vF - bF).padStart(5)}   ${rb.accepted}    ${rv.accepted}`);
}
console.log(`TOTAL(fp12Sqr chunks)  base_op=${totBase}  V2_op=${totV2}  dOp=${totV2 - totBase} (${(100 * (totV2 - totBase) / totBase).toFixed(1)}%)`);
console.log(`                       base_floorB=${totBaseB}  V2_floorB=${totV2B}  dB=${totV2B - totBaseB}`);
