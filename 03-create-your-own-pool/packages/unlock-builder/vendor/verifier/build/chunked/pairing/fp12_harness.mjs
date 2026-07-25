// Correctness + op-cost harness for a candidate lazy lib's fp12Sqr.
// Usage: node fp12_harness.mjs <import-path-relative-to-generated> [tag]
// - Correctness: fp12Sqr(input) === noble Fp12.sqr(input) mod p (5 seeds), via a per-limb-check contract.
// - Op-cost: measured with the SAME sum-tail as fp12_bench.mjs so the number is directly comparable
//   to the stated baseline 371,354 (the tail is identical across all variants, so deltas are pure body).
import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { writeFileSync } from 'node:fs';
import { measureRun, decompose } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
import { Fp12, Fp } from './_millermath.mjs';

const P = Fp.ORDER;
const importPath = process.argv[2] || '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const tag = process.argv[3] || importPath;

const mk2 = (a, b) => ({ c0: a, c1: b });
const toF12 = (L) => ({
  c0: { c0: mk2(L[0], L[1]), c1: mk2(L[2], L[3]), c2: mk2(L[4], L[5]) },
  c1: { c0: mk2(L[6], L[7]), c1: mk2(L[8], L[9]), c2: mk2(L[10], L[11]) },
});
const limbs = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1,
  f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
const expected = (L) => limbs(Fp12.sqr(toF12(L.map((x) => ((x % P) + P) % P))));

const push = (n) => { const d = bigIntToVmNumber(n); return Uint8Array.from([d.length, ...d]); };
const unlockFor = (a) => Uint8Array.from([...a].reverse().flatMap((x) => [...push(x)]));
const RESCHED = { rescheduleStacks: true };

function correctnessSrc(L) {
  const exp = expected(L);
  const checks = exp.map((e, i) => `(b${i} % ${P}) == ${e}`).join(' &&\n      ');
  return `pragma cashscript ^0.14.0;
import "${importPath}";
contract Bench() {
  function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) {
    int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11 = fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);
    require(
      ${checks});
  }
}`;
}
function rndL(seed) {
  let s = BigInt(seed) * 0x9E3779B97F4A7C15n + 1n;
  const next = () => { s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 256n) - 1n); return s % P; };
  return Array.from({ length: 12 }, () => next());
}

let allOk = true;
for (const seed of [1, 2, 3, 7, 42]) {
  const L = rndL(seed);
  writeFileSync('generated/fp12harness.cash', correctnessSrc(L));
  const bc = utils.asmToBytecode(compileFile('generated/fp12harness.cash', RESCHED).bytecode);
  const r = measureRun(bc, unlockFor(L));
  if (!r.ok) { allOk = false; console.log(`  seed ${seed}: REJECTED ${r.error || ''}`); }
}
console.log(`correctness (${tag}): ${allOk ? 'PASS (5/5 seeds accepted)' : 'FAIL'}`);

// op-cost: identical sum-tail as fp12_bench.mjs (comparable to baseline 371,354)
const stdA = Array.from({ length: 12 }, (_, i) => P - BigInt(1 + i * 7));
const srcStd = `pragma cashscript ^0.14.0;
import "${importPath}";
contract Bench() {
  function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) {
    int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11 = fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);
    int s = (b0+b1+b2+b3+b4+b5+b6+b7+b8+b9+b10+b11) % ${P};
    require(s == 12345678901234567890123456789012345678901234567890123456789012345678901234567);
  }
}`;
writeFileSync('generated/fp12harness.cash', srcStd);
const bc = utils.asmToBytecode(compileFile('generated/fp12harness.cash', RESCHED).bytecode);
const r = measureRun(bc, unlockFor(stdA));
const d = decompose(r);
console.log(`opcost (${tag}) RESCHED: redeem ${bc.length}B  opCost=${r.opCost}  instr=${r.instr}  arith ${d.arithPct}% base ${d.basePct}% push ${d.pushPct}%  (${r.error ? 'ran, require-failed(expected)' : 'accepted'})`);
