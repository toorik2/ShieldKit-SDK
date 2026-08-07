// Correctness (real compiled .cash in the VM) + op-cost (eager baseline vs V3 lazy) for
// fp12Mul and mul034.  Op-cost measured via LeanBCH cost.mjs, identical sum-tail across variants
// so the delta is pure body.
import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { writeFileSync } from 'node:fs';
import { measureRun, decompose } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
import { Fp2, Fp6, Fp12, Fp } from './_millermath.mjs';
const P = Fp.ORDER;
const EAGER = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LAZY = '../variants/V3_mul_delayed.cash';
const RESCHED = { rescheduleStacks: true };

const mk2 = (a, b) => ({ c0: ((a % P) + P) % P, c1: ((b % P) + P) % P });
const toF12 = (L) => ({ c0: { c0: mk2(L[0], L[1]), c1: mk2(L[2], L[3]), c2: mk2(L[4], L[5]) }, c1: { c0: mk2(L[6], L[7]), c1: mk2(L[8], L[9]), c2: mk2(L[10], L[11]) } });
const flat = (f) => [f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1];
const nobleMul = (A, B) => flat(Fp12.mul(toF12(A), toF12(B)));
function nobleMul034(F, o) {
  const f = toF12(F), o0 = mk2(o[0], o[1]), o3 = mk2(o[2], o[3]), o4 = mk2(o[4], o[5]);
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return flat(Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) }));
}

const push = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  return Uint8Array.from([d.length, ...d]);
};
const unlockFor = (a) => Uint8Array.from([...a].reverse().flatMap((x) => [...push(x)]));
const params = (names) => names.join(',');
const compileBc = (path) => utils.asmToBytecode(compileFile(path, RESCHED).bytecode);

// ---- correctness (VM) ----
let s = 20260708123456789n;
const rnd = () => { s ^= s << 13n; s &= (1n << 64n) - 1n; s ^= s >> 7n; s ^= s << 17n; s &= (1n << 64n) - 1n; return s; };
const rndFull = () => { let x = 0n; for (let k = 0; k < 4; k++) x = (x << 64n) | rnd(); return x % P; };
const corners = [0n, 1n, 2n, P - 1n, P - 2n];
const rndCorner = () => corners[Number(rnd() % 5n)];

function mulSrc(import_, A, B) {
  const exp = nobleMul(A, B);
  const decl = params(Array.from({ length: 12 }, (_, i) => `int a${i}`).concat(Array.from({ length: 12 }, (_, i) => `int b${i}`)));
  const args = params(Array.from({ length: 12 }, (_, i) => `a${i}`).concat(Array.from({ length: 12 }, (_, i) => `b${i}`)));
  const outs = params(Array.from({ length: 12 }, (_, i) => `int c${i}`));
  const checks = exp.map((e, i) => `(c${i} % ${P}) == ${e}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${import_}";\ncontract Bench(){function run(${decl}){${outs} = fp12Mul(${args});require(${checks});}}`;
}
function m034Src(import_, F, o) {
  const exp = nobleMul034(F, o);
  const decl = params(Array.from({ length: 12 }, (_, i) => `int f${i}`).concat(['int o0a', 'int o0b', 'int o3a', 'int o3b', 'int o4a', 'int o4b']));
  const args = params(Array.from({ length: 12 }, (_, i) => `f${i}`).concat(['o0a', 'o0b', 'o3a', 'o3b', 'o4a', 'o4b']));
  const outs = params(Array.from({ length: 12 }, (_, i) => `int c${i}`));
  const checks = exp.map((e, i) => `(c${i} % ${P}) == ${e}`).join(' && ');
  return `pragma cashscript ^0.14.0;\nimport "${import_}";\ncontract Bench(){function run(${decl}){${outs} = mul034(${args});require(${checks});}}`;
}

function runCorrectness(label, mkSrc, mkInputs, nRnd, nCorner) {
  const cases = [];
  for (let t = 0; t < nRnd; t++) cases.push(mkInputs(rndFull));
  for (let t = 0; t < nCorner; t++) cases.push(mkInputs(rndCorner));
  let ok = 0, bad = 0;
  for (const inp of cases) {
    writeFileSync('generated/_mulck.cash', mkSrc(LAZY, ...inp.parts));
    const bc = compileBc('generated/_mulck.cash');
    const r = measureRun(bc, unlockFor(inp.stack));
    if (r.ok) ok++; else { bad++; if (bad <= 3) console.log(`   REJECT ${inp.stack.slice(0, 3).map(String).join(',')}... ${r.error || ''}`); }
  }
  console.log(`correctness ${label} (V3 lazy, VM): ${ok}/${cases.length} accepted, ${bad} rejected -> ${bad === 0 ? 'PASS (== noble mod p)' : 'FAIL'}`);
  return bad === 0;
}

const mulInputs = (g) => { const A = Array.from({ length: 12 }, g), B = Array.from({ length: 12 }, g); return { parts: [A, B], stack: [...A, ...B] }; };
const m034Inputs = (g) => { const F = Array.from({ length: 12 }, g), o = Array.from({ length: 6 }, g); return { parts: [F, o], stack: [...F, ...o] }; };

const okMul = runCorrectness('fp12Mul', mulSrc, mulInputs, 12, 8);
const okM034 = runCorrectness('mul034 ', m034Src, m034Inputs, 12, 8);

// ---- op-cost: eager baseline vs V3 lazy (identical sum-tail) ----
const REQTAIL = '12345678901234567890123456789012345678901234567890123456789012345678901234567';
function mulCostSrc(import_) {
  const decl = params(Array.from({ length: 12 }, (_, i) => `int a${i}`).concat(Array.from({ length: 12 }, (_, i) => `int b${i}`)));
  const args = params(Array.from({ length: 12 }, (_, i) => `a${i}`).concat(Array.from({ length: 12 }, (_, i) => `b${i}`)));
  const outs = params(Array.from({ length: 12 }, (_, i) => `int c${i}`));
  const sum = Array.from({ length: 12 }, (_, i) => `c${i}`).join('+');
  return `pragma cashscript ^0.14.0;\nimport "${import_}";\ncontract Bench(){function run(${decl}){${outs} = fp12Mul(${args});int t=(${sum}) % ${P};require(t == ${REQTAIL});}}`;
}
function m034CostSrc(import_) {
  const decl = params(Array.from({ length: 12 }, (_, i) => `int f${i}`).concat(['int o0a', 'int o0b', 'int o3a', 'int o3b', 'int o4a', 'int o4b']));
  const args = params(Array.from({ length: 12 }, (_, i) => `f${i}`).concat(['o0a', 'o0b', 'o3a', 'o3b', 'o4a', 'o4b']));
  const outs = params(Array.from({ length: 12 }, (_, i) => `int c${i}`));
  const sum = Array.from({ length: 12 }, (_, i) => `c${i}`).join('+');
  return `pragma cashscript ^0.14.0;\nimport "${import_}";\ncontract Bench(){function run(${decl}){${outs} = mul034(${args});int t=(${sum}) % ${P};require(t == ${REQTAIL});}}`;
}

function measureCost(label, mkSrc, nParams) {
  const inp = Array.from({ length: nParams }, (_, i) => P - BigInt(1 + i * 7));
  const rows = {};
  for (const [tag, import_] of [['eager', EAGER], ['lazy ', LAZY]]) {
    writeFileSync('generated/_mulcost.cash', mkSrc(import_));
    const bc = compileBc('generated/_mulcost.cash');
    const r = measureRun(bc, unlockFor(inp));
    const d = decompose(r);
    rows[tag] = { bytes: bc.length, opCost: r.opCost, instr: r.instr, d, err: r.error };
    console.log(`opcost ${label} [${tag}] RESCHED: redeem ${bc.length}B  opCost=${r.opCost}  instr=${r.instr}  arith ${d.arithPct}% base ${d.basePct}% push ${d.pushPct}%  (${r.error ? 'ran, require-failed(expected)' : 'accepted'})`);
  }
  const dOp = rows['lazy '].opCost - rows['eager'].opCost;
  const pct = (100 * dOp / rows['eager'].opCost);
  console.log(`  => ${label} op-cost delta: ${dOp} (${pct.toFixed(2)}%)  [eager ${rows['eager'].opCost} -> lazy ${rows['lazy '].opCost}]`);
  return { ...rows, dOp, pct };
}

console.log('');
const costMul = measureCost('fp12Mul', mulCostSrc, 24);
console.log('');
const costM034 = measureCost('mul034 ', m034CostSrc, 18);
console.log('');
console.log(JSON.stringify({
  correct: { fp12Mul: okMul, mul034: okM034 },
  fp12Mul: { eagerOp: costMul['eager'].opCost, lazyOp: costMul['lazy '].opCost, deltaPct: +costMul.pct.toFixed(2) },
  mul034: { eagerOp: costM034['eager'].opCost, lazyOp: costM034['lazy '].opCost, deltaPct: +costM034.pct.toFixed(2) },
}));
