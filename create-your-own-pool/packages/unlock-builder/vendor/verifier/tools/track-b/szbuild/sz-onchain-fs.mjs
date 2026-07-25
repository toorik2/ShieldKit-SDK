import { repoPath as vcRepoPath } from '#repo-paths';
// STEP 1 of the SZ-Miller build: VM-validate a SOUND on-chain Fiat-Shamir quotient-SZ
// check for ONE Fp12 mul, with z DERIVED IN THE LOCKING SCRIPT (never witnessed).
// Gate: honest (R,Q) ACCEPT; wrong R OR wrong Q REJECT; z-grind structurally impossible.
//
// Fp12 = Fp[v]/M(v), M(v)=v^12-18v^6+82 (DIRECT extension, noble's bn254 tower maps to it).
// c = a*b is WITNESSED; prover also gives quotient Q (deg<=10): a*b = Q*M + c (deg-22 ids).
// On-chain: z = HASH256(transcript) % P  (transcript COMMITS a,b,c,Q FIRST => commit-then-challenge),
//           require a(z)*b(z) == Q(z)*M(z) + c(z)  (mod p).
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { push, measure, P, O, asm } from '../asm-measure.mjs';
import { hexToBin, binToHex } from '../../../node_modules/@bitauth/libauth/build/index.js';
import { createHash } from 'node:crypto';

const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const mod = (x) => ((x % P) + P) % P;
const M = Array(13).fill(0n); M[0] = 82n; M[6] = mod(-18n); M[12] = 1n;
const polyMul = (a, b) => { const r = Array(a.length + b.length - 1).fill(0n); for (let i = 0; i < a.length; i++) for (let j = 0; j < b.length; j++) r[i + j] = mod(r[i + j] + a[i] * b[j]); return r; };
const polyDivByM = (prod) => {
  const R = prod.slice(); while (R.length < 23) R.push(0n);
  const Q = Array(R.length - 12).fill(0n);
  for (let i = R.length - 1; i >= 12; i--) { const c = R[i]; if (c === 0n) continue; Q[i - 12] = c; for (let j = 0; j <= 12; j++) R[i - 12 + j] = mod(R[i - 12 + j] - c * M[j]); }
  return { Q: Q.slice(0, 11), c: R.slice(0, 12) };
};
const rng = (() => { let s = 0x5a17n; return () => { s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return mod(s * 0x2545F4914F6CDD1Dn); }; })();
const sha256 = (b) => createHash('sha256').update(b).digest();
const sha256d = (b) => sha256(sha256(b));
const le40 = (n) => { const b = Buffer.alloc(40); let x = mod(BigInt(n)); for (let i = 0; i < 40; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };

const a = Array.from({ length: 12 }, rng), b = Array.from({ length: 12 }, rng);
const { Q, c } = polyDivByM(polyMul(a, b));

// ---- COMMIT-THEN-CHALLENGE: z = HASH256(le40(a..)||le40(b..)||le40(c..)||le40(Q..)) % P ----
// (matches the contract's hash256(toPaddedBytes(.,40)) preimage built from the WITNESSED limbs)
const transcript = Buffer.concat([...a, ...b, ...c, ...Q].map(le40));
const Tdigest = sha256d(transcript);                 // 32 bytes, little-endian VM number when read as int
const zBig = mod(Buffer.from(Tdigest).reduce((acc, byte, i) => acc + (BigInt(byte) << (8n * BigInt(i))), 0n)); // LE int % P
const ev = (poly, r) => { let acc = 0n; for (let i = poly.length - 1; i >= 0; i--) acc = mod(acc * r + poly[i]); return acc; };
const okJS = mod(ev(a, zBig) * ev(b, zBig)) === mod(ev(Q, zBig) * mod(ev(M, zBig)) + ev(c, zBig));
console.log('JS on-chain-z SZ identity holds:', okJS, ' z=', zBig.toString(16).slice(0, 16) + '...');

// ---- the CashScript: derive z from the witnessed limbs IN THE LOCKING, then SZ-check ----
const horner = (name, n) => {
  let s = `        int ${name}z = ${name}${n - 1};\n`;
  for (let i = n - 2; i >= 0; i--) s += `        ${name}z = (${name}z * z + ${name}${i}) % P;\n`;
  return s;
};
const params = (p, n) => Array.from({ length: n }, (_, i) => `int ${p}${i}`).join(',');
// preimage = toPaddedBytes(a0,40)+...+toPaddedBytes(q10,40); z = int(hash256(preimage)) % P.
const allLimbs = [...Array(12).keys()].map((i) => `a${i}`).concat([...Array(12).keys()].map((i) => `b${i}`), [...Array(12).keys()].map((i) => `c${i}`), [...Array(11).keys()].map((i) => `q${i}`));
const preimage = allLimbs.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ');
const src = `pragma cashscript ^0.13.0;
contract SZfs() {
    function spend(${params('a', 12)}, ${params('b', 12)}, ${params('c', 12)}, ${params('q', 11)}) {
        int P = ${P};
        // COMMIT-THEN-CHALLENGE: z derived from ALL witnessed limbs (in the locking, never witnessed).
        bytes32 td = hash256(${preimage});
        int z = int(td) % P;
        int z2 = (z * z) % P; int z3 = (z2 * z) % P; int z6 = (z3 * z3) % P; int z12 = (z6 * z6) % P;
        int Mz = (z12 + 82 + 18 * P - (18 * z6) % P) % P;
${horner('a', 12)}${horner('b', 12)}${horner('c', 12)}${horner('q', 11)}
        require((az * bz) % P == (qz * Mz + cz) % P);
    }
}
`;
const F = vcRepoPath('tools/track-b/szbuild/sz_fs.cash');
writeFileSync(F, src);
const tpl = hexToBin(execFileSync('node', [CLI, F, '-h'], { encoding: 'utf8' }).trim());
// CRITICAL: confirm the VM's int(hash256) decoding == our zBig (LE, mod P). cashscript int() of a
// bytes32 reads it as a little-endian VM number (sign bit!). We must match. Check via a tiny probe.
const declOrder = [...a, ...b, ...c, ...Q];
const unlocking = Uint8Array.from(declOrder.slice().reverse().flatMap((x) => push(x)));
const res = measure(tpl, unlocking);
console.log('SZ-FS on-chain (z derived in locking):', JSON.stringify({ accepted: res.accepted, opCost: res.opCost, arith: res.arith, base: res.instr * 100, instr: res.instr, error: res.error }));

// ---- FORGERY GATE ----
// wrong c (R): flip c0. The transcript CHANGES => z changes too, but the SZ identity must still fail
// w.h.p. (the forged c does NOT satisfy a*b=Q*M+c at the NEW z). REJECT expected.
const badC = [...a, ...b, mod(c[0] + 1n), ...c.slice(1), ...Q];
const rBadC = measure(tpl, Uint8Array.from(badC.slice().reverse().flatMap((x) => push(x))));
console.log('  FORGE wrong R(c0+1): accepted =', rBadC.accepted, '(must be false)');
// wrong Q: flip Q0.
const badQ = [...a, ...b, ...c, mod(Q[0] + 1n), ...Q.slice(1)];
const rBadQ = measure(tpl, Uint8Array.from(badQ.slice().reverse().flatMap((x) => push(x))));
console.log('  FORGE wrong Q(q0+1): accepted =', rBadQ.accepted, '(must be false)');
// fully forged product: pick a random c (not = a*b mod M), honest Q for THAT bogus c won't exist;
// attacker's best is to pick c AND Q freely. They can satisfy the identity at a CHOSEN r, but r is
// derived AFTER commit => they'd need a*b - Q*M - c == 0 as a polynomial (=> c = a*b mod M, Q = quotient).
// Model a grind: attacker tries G random (c,Q) pairs hoping one hits z. Expect ALL reject.
let grindHit = 0; const G = 200;
for (let g = 0; g < G; g++) {
  const fc = Array.from({ length: 12 }, rng), fq = Array.from({ length: 11 }, rng);
  const r = measure(tpl, Uint8Array.from([...a, ...b, ...fc, ...fq].slice().reverse().flatMap((x) => push(x))));
  if (r.accepted) grindHit++;
}
console.log(`  GRIND ${G} random (c,Q) forgeries: ${grindHit} accepted (must be 0; ε≈deg/p≈2^-241)`);

// ---- confirm the int(hash256) VM-decode matches zBig (soundness of the z we reason about) ----
// re-emit a probe contract that just outputs whether int(hash256(preimage)) % P == zBig.
const srcZ = `pragma cashscript ^0.13.0;
contract Zc() {
    function spend(${params('a', 12)}, ${params('b', 12)}, ${params('c', 12)}, ${params('q', 11)}) {
        int P = ${P};
        bytes32 td = hash256(${preimage});
        int z = int(td) % P;
        require(z == ${zBig});
    }
}
`;
writeFileSync(vcRepoPath('tools/track-b/szbuild/zc.cash'), srcZ);
const tplZ = hexToBin(execFileSync('node', [CLI, vcRepoPath('tools/track-b/szbuild/zc.cash'), '-h'], { encoding: 'utf8' }).trim());
const rZ = measure(tplZ, unlocking);
console.log('  z-DECODE check: VM int(hash256(...)) % P == JS zBig ->', rZ.accepted, '(must be true; proves we reason about the SAME z)');

console.log('\n  vs mul034 (sparse line) 653,212 op: ratio', (res.opCost / 653212).toFixed(3) + '×  | vs fp12Sqr 966K:', (res.opCost / 966000).toFixed(3) + '×');
