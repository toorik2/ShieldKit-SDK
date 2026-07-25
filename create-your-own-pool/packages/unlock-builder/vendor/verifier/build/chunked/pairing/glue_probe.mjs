import { readFileSync } from 'node:fs';
import { pairsFor, millerBatchOps, vec, ptLimbs, f12limbs, r6limbs, measureCovenantFileResched, measureCovenantFileRaw2 } from './_millermath.mjs';
const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.Rs[0])];
const man = JSON.parse(readFileSync('generated/manifest_miller.json','utf8'));
const pairs = pairsFor(vec.publicInputs.map(BigInt), undefined);
const { states } = millerBatchOps(pairs);
const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
console.log('chunk compile   opCost      arith%  base%(glue)  push%  lockB  accept');
for (const ci of [0, 6, 11]) {
  const ch = man.chunks[ci];
  const inLimbs = [...stateLimbs(states[ch.opLo]), ...ptL];
  const outLimbs = [...stateLimbs(states[ch.opHi]), ...ptL];
  const file = `generated/miller_${String(ch.idx).padStart(2,'0')}.cash`;
  for (const [tag, fn] of [['resched', measureCovenantFileResched], ['raw', measureCovenantFileRaw2]]) {
    const r = fn(file, inLimbs, outLimbs);
    if (r.operationCost === Infinity || r.arith===undefined) { console.log(`  ${ci}   ${tag}  ERR ${(r.error||'').slice(0,50)}`); continue; }
    const base = r.instr*100, t = r.operationCost||1;
    console.log(`  ${ci}   ${tag.padEnd(7)} ${String(r.operationCost).padStart(9)}  ${(100*r.arith/t).toFixed(1)}%   ${(100*base/t).toFixed(1)}%      ${(100*r.push/t).toFixed(1)}%  ${r.lockingBytes}  ${r.accepted}`);
  }
}
