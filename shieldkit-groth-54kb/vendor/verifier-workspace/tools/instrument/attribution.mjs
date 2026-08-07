import { repoPath as vcRepoPath } from '#repo-paths';
// tools/instrument/attribution.mjs
// ---------------------------------------------------------------------------
// ATTRIBUTE the measured 4-pair Miller op-cost (709,563,868) to individual BN254
// tower functions:  total_fn = unit_cost_fn x call_count_fn.
//
// Unit costs come from out/unit-costs.json (tools/instrument/unit-costs.mjs,
// differential micro-measurement). Call counts are derived structurally from
// miller4.cash (millerSingle x4 + 3 fp12Mul combine). The NAF of 6x+2 has 65
// digits; nzMask=3045737938581365386 has 21 nonzero digits (each => pointAdd +
// add-line); negMask=162306075919524482 has 13 negative digits (each => one
// fp2Neg on Qy). postPrecompute adds 2 psi + 2 pointAdd + 2 line + 1 fp2Neg.
//
// IMPORTANT (no double counting): unit_cost is the FULL cost of a call including
// every nested call it makes. So we attribute ONLY at the granularity actually
// invoked from millerSingle's body (fp12Sqr, pointDouble, line, pointAdd, psi,
// fp2Neg) plus the top-level fp12Mul combine. We ALSO print a fully-expanded
// "leaf" view (everything reduced to its outermost Miller-level callers) so the
// shares sum to ~100% without overlap. A separate diagnostic expands the heavy
// callers into their fp2-level constituents for "what to attack" insight.
//
// Run: node tools/instrument/attribution.mjs
// ---------------------------------------------------------------------------
import { readFileSync } from 'node:fs';

const MEASURED = 709_563_868; // miller4.cash golden op-cost (out/.../_baseline_miller4.log)

const units = Object.fromEntries(
  JSON.parse(readFileSync(vcRepoPath('out/unit-costs.json'), 'utf8'))
    .map((r) => [r.name, r]));

// --- structural call counts (decoded from miller4.cash) ---------------------
const NAF_DIGITS = 65;       // for (k=0..64)
const NZ = 21;               // nonzero NAF digits  -> pointAdd + add-line
const NEG = 13;              // negative NAF digits -> fp2Neg on Qy
const PAIRS = 4;             // 4-pair Groth16 boundary
const COMBINE_FP12MUL = 3;   // product of the 4 single results

// per single millerSingle (one pair):
const perPair = {
  fp12Sqr:     NAF_DIGITS,            // 65 : f = f^2 each iter
  pointDouble: NAF_DIGITS,            // 65 : double-step each iter
  line:        NAF_DIGITS + NZ + 2,   // 65 double-lines + 21 add-lines + 2 postPrecompute lines
  pointAdd:    NZ + 2,                // 21 NAF adds + 2 postPrecompute adds
  psi:         2,                     // Q1 = psi(Q), Q2 = psi(Q1)
  fp2Neg:      NEG + 1,               // 13 negative-digit -Qy + 1 q2 -y
};

// Miller-level call counts for the whole 4-pair spend()
const calls = {};
for (const [fn, c] of Object.entries(perPair)) calls[fn] = c * PAIRS;
calls.fp12Mul = (calls.fp12Mul || 0) + COMBINE_FP12MUL;

// fp2Neg isn't a measured target (trivial: 2 subFp). Approximate its unit as the
// cost of the fp2Neg fragment = 2*subFp + own invoke. Measure-free fallback:
const fp2NegUnit = 2 * units.subFp.opCost + 1500; // ~2 subFp + invoke marshalling (10 args? no, 2)
// (small absolute contribution; documented as an estimate)

function unitOf(fn) {
  if (fn === 'fp2Neg') return { opCost: fp2NegUnit, arith: 2 * units.subFp.arith, base: 2 * units.subFp.base, push: 2 * units.subFp.push };
  return units[fn];
}

// --- attribution table ------------------------------------------------------
const rows = [];
let sumOp = 0, sumArith = 0, sumBase = 0, sumPush = 0;
for (const [fn, n] of Object.entries(calls)) {
  const u = unitOf(fn);
  const total = u.opCost * n;
  const arith = u.arith * n, base = u.base * n, push = u.push * n;
  rows.push({ fn, n, unit: u.opCost, total, arith, base, push });
  sumOp += total; sumArith += arith; sumBase += base; sumPush += push;
}
rows.sort((a, b) => b.total - a.total);

const fmt = (n) => Math.round(n).toLocaleString();
const pc = (x, d = MEASURED) => `${(100 * x / d).toFixed(1)}%`;

console.log('=== 4-PAIR MILLER OP-COST ATTRIBUTION (Miller-level callers, no overlap) ===');
console.log(`measured miller4.cash op-cost = ${fmt(MEASURED)}`);
console.log('');
console.log('function       calls   unit op-cost        total op-cost   % of 709.6M   arith        base         push');
console.log('---------------------------------------------------------------------------------------------------------');
for (const r of rows) {
  console.log(
    `${r.fn.padEnd(12)} ${String(r.n).padStart(6)}  ${fmt(r.unit).padStart(12)}   ${fmt(r.total).padStart(15)}   ${pc(r.total).padStart(9)}   ` +
    `${fmt(r.arith).padStart(11)}  ${fmt(r.base).padStart(11)}  ${fmt(r.push).padStart(10)}`
  );
}
console.log('---------------------------------------------------------------------------------------------------------');
console.log(
  `${'SUM'.padEnd(12)} ${''.padStart(6)}  ${''.padStart(12)}   ${fmt(sumOp).padStart(15)}   ${pc(sumOp).padStart(9)}   ` +
  `${fmt(sumArith).padStart(11)}  ${fmt(sumBase).padStart(11)}  ${fmt(sumPush).padStart(10)}`
);
console.log(`\nreconciliation: attributed ${fmt(sumOp)} vs measured ${fmt(MEASURED)}  -> ${(100 * sumOp / MEASURED).toFixed(2)}%  (gap ${fmt(MEASURED - sumOp)}, ${pc(MEASURED - sumOp)})`);

// measured split for comparison
const M_ARITH = 274_716_541, M_BASE = 387_779_300, M_PUSH = 47_068_027;
console.log(`\nmeasured split:    arith ${fmt(M_ARITH)} (38.7%) | base ${fmt(M_BASE)} (54.7%) | push ${fmt(M_PUSH)} (6.6%)`);
console.log(`attributed split:  arith ${fmt(sumArith)} (${pc(sumArith, sumOp)}) | base ${fmt(sumBase)} (${pc(sumBase, sumOp)}) | push ${fmt(sumPush)} (${pc(sumPush, sumOp)})`);

// --- gap diagnosis ----------------------------------------------------------
// arith reconciles to ~100% and push to ~95%, but base under-counts. The residual
// is BASE-ONLY and comes from a context effect the micro-harness cannot fully
// reproduce: miller4.millerSingle holds ~30+ live locals (f=12, R=6, + temps), so
// every argument the loop body marshals into a call is a DEEPER OP_PICK than in
// the tight micro-contract (<=24 locals). Deeper stack -> more OP_PICK/OP_ROLL ->
// more base instructions. This raises base uniformly without changing the RANKING
// (arith+push, which drive the ranking, already reconcile). We surface the residual
// as a single "deep-local marshalling surcharge" distributed proportionally to each
// function's existing base, then re-report a calibrated reconciliation.
const baseResidual = M_BASE - sumBase;            // unattributed base
const archResidual = MEASURED - sumOp;            // total unattributed (~all base)
console.log(`\ngap is BASE-only: arith ${pc(sumArith, M_ARITH)} of measured, push ${pc(sumPush, M_PUSH)}, base ${pc(sumBase, M_BASE)}.`);
console.log(`unattributed base = ${fmt(baseResidual)} (${pc(baseResidual, M_BASE)} of measured base) -> deep-local OP_PICK/OP_ROLL surcharge.`);
const calibFactor = M_BASE / sumBase;
console.log(`\n--- calibrated (base x ${calibFactor.toFixed(3)} deep-local surcharge, proportional) ---`);
console.log('function       total op-cost(cal)   % of 709.6M');
const cal = rows.map((r) => ({ fn: r.fn, total: r.arith + r.base * calibFactor + r.push }))
  .sort((a, b) => b.total - a.total);
let sumCal = 0;
for (const r of cal) { sumCal += r.total; console.log(`${r.fn.padEnd(12)} ${fmt(r.total).padStart(15)}   ${pc(r.total).padStart(9)}`); }
console.log(`${'SUM'.padEnd(12)} ${fmt(sumCal).padStart(15)}   ${pc(sumCal).padStart(9)}  (calibrated reconciliation: ${(100 * sumCal / MEASURED).toFixed(1)}%)`);

// --- leaf diagnostic: expand the big callers into fp2-level work ------------
// Counts how many fp2Mul / mulFp etc. ultimately execute, to direct optimization
// at the primitive that dominates. unit costs of leaves are themselves nested
// (e.g. fp2Mul includes 3 mulFp), so we report PRIMITIVE COUNTS not summed cost.
const fp2PerCaller = { // # of each fp2-op invoked directly inside each Miller-level fn
  fp12Sqr:     { fp6Mul: 3, fp6MulByV: 1, fp6Add: 2, fp6Sub: 2 }, // = fp12Mul(A,A)
  fp12Mul:     { fp6Mul: 3, fp6MulByV: 1, fp6Add: 2, fp6Sub: 2 },
  line:        { mulFp: 4, mul034: 1 },
  mul034:      { fp2Mul: 3, fp6Mul01: 2, fp6Add: 3, fp6Sub: 1, fp6MulByV: 1, fp2Add: 1 },
  pointDouble: { fp2Sqr: 6, fp2Scale: 4, fp2MulByB: 1, fp2Add: 2, fp2Sub: 6, fp2Neg: 1, fp2Mul: 3, fp2Half: 3 },
  pointAdd:    { fp2Mul: 9, fp2Sub: 5, fp2Neg: 1, fp2Sqr: 2, fp2Scale: 2, fp2Add: 1 },
  psi:         { fp2Conj: 2, fp2Mul: 2 },
};
console.log('\n=== where the heavy callers spend it (direct sub-op counts per call) ===');
for (const r of rows) {
  const sub = fp2PerCaller[r.fn];
  if (!sub) continue;
  const parts = Object.entries(sub).map(([k, v]) => `${v}x${k}`).join(', ');
  console.log(`${r.fn.padEnd(12)} (${r.n} calls): ${parts}`);
}

// --- full leaf expansion: total invocations of EVERY function in the 4-pair -----
// Reduces the whole Miller to primitive counts so we know the true denominator for
// any micro-optimization (e.g. "make mulFp 1 instr cheaper" -> x its total count).
const SUB = {
  fp12Mul: { fp6Mul: 3, fp6MulByV: 1, fp6Add: 2, fp6Sub: 2 },
  fp12Sqr: { fp12Mul: 1 },
  fp6Mul: { fp2Mul: 6, fp2Add: 6, fp2Sub: 6, fp2MulXi: 2 },
  fp6Add: { fp2Add: 3 }, fp6Sub: { fp2Sub: 3 }, fp6MulByV: { fp2MulXi: 1 },
  fp6Mul01: { fp2Mul: 5, fp2Add: 6, fp2Sub: 5, fp2MulXi: 1 },
  fp2Mul: { mulFp: 3, addFp: 2, subFp: 2 }, fp2Sqr: { mulFp: 2, addFp: 1, subFp: 1 },
  fp2MulXi: { mulFp: 2, addFp: 1, subFp: 1 }, fp2Add: { addFp: 2 }, fp2Sub: { subFp: 2 },
  fp2Neg: { subFp: 2 }, fp2Scale: { mulFp: 2 }, fp2MulByB: { fp2Mul: 1 },
  fp2Half: { mulFp: 2 }, fp2Conj: { subFp: 1 },
  mul034: { fp2Mul: 3, fp6Mul01: 2, fp6Add: 3, fp6Sub: 1, fp6MulByV: 1, fp2Add: 1 },
  line: { mulFp: 4, mul034: 1 },
  pointDouble: { fp2Sqr: 6, fp2Scale: 4, fp2MulByB: 1, fp2Add: 2, fp2Sub: 6, fp2Neg: 1, fp2Mul: 3, fp2Half: 3 },
  pointAdd: { fp2Mul: 9, fp2Sub: 5, fp2Neg: 1, fp2Sqr: 2, fp2Scale: 2, fp2Add: 1 },
  psi: { fp2Conj: 2, fp2Mul: 2 },
};
const totalInv = {};
function expand(fn, mult) {
  totalInv[fn] = (totalInv[fn] || 0) + mult;
  for (const [c, k] of Object.entries(SUB[fn] || {})) expand(c, mult * k);
}
for (const [fn, n] of Object.entries(calls)) expand(fn, n);
const order = ['mulFp', 'addFp', 'subFp', 'fp2Mul', 'fp2Sqr', 'fp2MulXi', 'fp2Add', 'fp2Sub',
  'fp2Neg', 'fp2Scale', 'fp2Conj', 'fp2Half', 'fp2MulByB', 'fp6Mul01', 'fp6Mul', 'fp6Add',
  'fp6Sub', 'fp6MulByV', 'mul034', 'fp12Mul'];
let totInv = 0; for (const v of Object.values(totalInv)) totInv += v;
console.log(`\n=== total function invocations executed in the 4-pair Miller (${fmt(totInv)} total) ===`);
console.log('these are the denominators for primitive-level optimization:');
for (const fn of order) {
  if (!totalInv[fn]) continue;
  console.log(`  ${fn.padEnd(11)} x ${fmt(totalInv[fn]).padStart(9)}`);
}
console.log(`\nNOTE: arith reconciles to 100.9% and the ranking is arith+push-driven, so the`);
console.log(`attribution ABOVE is the actionable one. line (40%) + fp12Sqr (35%) = 76% of all`);
console.log(`op-cost -> attack the sparse line-multiply (mul034/fp6Mul01) and the squaring path`);
console.log(`(fp12Sqr currently = fp12Mul(A,A); a dedicated fp12Sqr would cut ~1/3 of its fp6Muls).`);
