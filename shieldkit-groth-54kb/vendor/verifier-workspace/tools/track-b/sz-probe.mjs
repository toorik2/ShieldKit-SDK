import { repoPath as vcRepoPath } from '#repo-paths';
// SZ-witness prototype: is the Schwartz-Zippel check of an Fp12 multiply cheaper than
// computing it? Fp12 = Fp[v]/M(v), M(v)=v^12-18v^6+82 (direct ext). c=a*b is WITNESSED;
// prover also gives quotient Q (deg<=10): a*b = Q*M + c (as deg-22 polys). On-chain check
// at FS challenge r:  a(r)*b(r) == Q(r)*M(r) + c(r) (mod p).  ~50 Fp muls vs the full mul.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { push, measure, P } from './asm-measure.mjs';
import { hexToBin } from '../../node_modules/@bitauth/libauth/build/index.js';

const mod = (x) => ((x % P) + P) % P;
// M(v) = v^12 - 18 v^6 + 82  (coeff array index 0..12)
const M = Array(13).fill(0n); M[0] = 82n; M[6] = mod(-18n); M[12] = 1n;
const polyMul = (a, b) => { const r = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) for (let j = 0; j < b.length; j++) r[i + j] = mod(r[i + j] + a[i] * b[j]); return r; };
const polyDivByM = (prod) => { // prod deg<=22, M monic deg 12 -> Q (deg<=10), R (deg<=11)
  const R = prod.slice(); while (R.length < 23) R.push(0n);
  const Q = Array(R.length - 12).fill(0n);
  for (let i = R.length - 1; i >= 12; i--) { const c = R[i]; if (c === 0n) continue; Q[i - 12] = c; for (let j = 0; j <= 12; j++) R[i - 12 + j] = mod(R[i - 12 + j] - c * M[j]); }
  return { Q: Q.slice(0, 11), c: R.slice(0, 12) };
};
const rng = (() => { let s = 0x5a17n; return () => { s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return mod(s * 0x2545F4914F6CDD1Dn); }; })();
const a = Array.from({ length: 12 }, rng), b = Array.from({ length: 12 }, rng);
const { Q, c } = polyDivByM(polyMul(a, b));
const r = rng();
const ev = (poly) => { let acc = 0n; for (let i = poly.length - 1; i >= 0; i--) acc = mod(acc * r + poly[i]); return acc; };
const Mr = mod(ev(M)); // = r^12-18r^6+82
const ok = mod(ev(a) * ev(b)) === mod(ev(Q) * Mr + ev(c));
console.log('JS SZ identity holds:', ok);

// ---- emit the on-chain SZ-check as CashScript, compile, measure ----
const horner = (name, n) => { // a(r) via Horner, n coeffs (deg n-1)
  let s = `        int ${name}r = ${name}${n - 1};\n`;
  for (let i = n - 2; i >= 0; i--) s += `        ${name}r = (${name}r * r + ${name}${i}) % P;\n`;
  return s;
};
const params = (p, n) => Array.from({ length: n }, (_, i) => `int ${p}${i}`).join(',');
const src = `pragma cashscript ^0.13.0;
contract SZ() {
    function spend(${params('a', 12)}, ${params('b', 12)}, ${params('c', 12)}, ${params('q', 11)}, int r) {
        int P = ${P};
${horner('a', 12)}${horner('b', 12)}${horner('c', 12)}${horner('q', 11)}
        int r2 = (r * r) % P; int r3 = (r2 * r) % P; int r6 = (r3 * r3) % P; int r12 = (r6 * r6) % P;
        int Mr = (r12 + 82 + 18 * P - (18 * r6) % P) % P;
        require((ar * br) % P == (qr * Mr + cr) % P);
    }
}
`;
const F = vcRepoPath('tools/track-b/sz_check.cash');
writeFileSync(F, src);
const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const tpl = hexToBin(execFileSync('node', [CLI, F, '-h'], { encoding: 'utf8' }).trim());
// unlocking: decl order [a..,b..,c..,q..,r] reversed (first param on top)
const declOrder = [...a, ...b, ...c, ...Q, r];
const unlocking = Uint8Array.from(declOrder.slice().reverse().flatMap((x) => push(x)));
const res = measure(tpl, unlocking);
console.log('SZ-check on-chain:', JSON.stringify({ accepted: res.accepted, opCost: res.opCost, arith: res.arith, base: res.instr * 100, instr: res.instr, error: res.error }));
// tamper: wrong c -> must reject
const bad = Uint8Array.from([...a, ...b, c[0] + 1n, ...c.slice(1), ...Q, r].slice().reverse().flatMap((x) => push(x)));
console.log('  tamper (wrong c0) accepted =', measure(tpl, bad).accepted, '(must be false)');
console.log('  vs fp12Mul (tower, chunked) ~1,290,406 op-cost | mul034 (sparse line) ~653,212');
console.log('  ratio vs fp12Mul:', (res.opCost / 1290406).toFixed(2) + '× | vs mul034:', (res.opCost / 653212).toFixed(2) + '×');
