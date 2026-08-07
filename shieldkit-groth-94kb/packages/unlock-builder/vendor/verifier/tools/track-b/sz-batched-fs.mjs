import { repoPath as vcRepoPath } from '#repo-paths';
// SOUND batched Fiat-Shamir SZ-witness cost model — measured on real VM.
// Three cost components for the chunked Miller:
//  (A) per-mul on-chain Horner work in the BATCHED design (eval A(z),B(z),R(z) + RLC accumulate)
//  (B) FS transcript hash cost (incremental OP_CAT + OP_HASH256 over all committed limbs)
//  (C) witness-mass push cost (R limbs in unlocking)
// Compare to the per-op tower cost (line / fp12Sqr) it replaces.
import { push, measure, P, O, asm } from './asm-measure.mjs';
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { hexToBin } from '../../node_modules/@bitauth/libauth/build/index.js';

const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const mod = (x) => ((x % P) + P) % P;
const rng = (() => { let s = 0x5a17n; return () => { s = (s * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return mod(s * 0x2545F4914F6CDD1Dn); }; })();
const compile = (src) => { const F = '/tmp/szb.cash'; writeFileSync(F, src); return hexToBin(execFileSync('node', [CLI, F, '-h'], { encoding: 'utf8' }).trim()); };

// ============ COMPONENT A: per-mul on-chain Horner work (BATCHED) ============
// In the batched design, on-chain per-mul work is: given z (challenge, shared),
// eval A_i(z) (12-coeff Horner), B_i(z) (12), R_i(z) (12), accumulate into the
// RLC sums with power c0^i. We measure ONE such per-mul block.
// LHS accum: acc_lhs += w * A_i(z)*B_i(z); RHS accum: acc_rhs += w * R_i(z); w*=c0.
// (A_i, B_i are the two Fp12 operands — but in a chained Miller f_{i+1}=f_i*op,
//  A_i is the PREVIOUS R (=f_i, already evaluated) and B_i is the op. So A_i(z)
//  can be REUSED from the prior step's R eval. We measure the general case = 3 Horners,
//  then note the chained optimization separately.)
const horner = (name, n) => {
  let s = `        int ${name}z = ${name}${n - 1};\n`;
  for (let i = n - 2; i >= 0; i--) s += `        ${name}z = (${name}z * r + ${name}${i}) % P;\n`;
  return s;
};
const params = (p, n) => Array.from({ length: n }, (_, i) => `int ${p}${i}`).join(',');

// One per-mul block: 3 Horners (A,B,R) + product + 2 RLC accumulates + power update.
const perMulSrc = `pragma cashscript ^0.13.0;
contract PerMul(int P) {
    function spend(${params('a', 12)}, ${params('b', 12)}, ${params('rr', 12)}, int r, int w, int c0, int accL, int accR) {
${horner('a', 12)}${horner('b', 12)}${horner('rr', 12)}
        int lhs = (az * bz) % P;
        int newAccL = (accL + (w * lhs) % P) % P;
        int newAccR = (accR + (w * rrz) % P) % P;
        int newW = (w * c0) % P;
        require(newAccL >= 0); require(newAccR >= 0); require(newW >= 0);
    }
}`;
{
  const tpl = compile(perMulSrc);
  const a = Array.from({ length: 12 }, rng), b = Array.from({ length: 12 }, rng), rr = Array.from({ length: 12 }, rng);
  const r = rng(), w = rng(), c0 = rng(), accL = rng(), accR = rng();
  // decl order: P is constructor (pushed in locking via -h? No: constructor arg is part of locking template). Use function params only.
  const declOrder = [...a, ...b, ...rr, r, w, c0, accL, accR];
  const unlocking = Uint8Array.from(declOrder.slice().reverse().flatMap((x) => push(x)));
  // constructor P must be supplied. cashc -h bakes constructor? Actually constructor args go in the locking. Re-emit with P literal instead.
  void tpl; void unlocking;
}
// Simpler: inline P as literal to avoid constructor handling.
const perMulSrc2 = `pragma cashscript ^0.13.0;
contract PerMul() {
    function spend(${params('a', 12)}, ${params('b', 12)}, ${params('rr', 12)}, int r, int w, int c0, int accL, int accR) {
        int P = ${P};
${horner('a', 12)}${horner('b', 12)}${horner('rr', 12)}
        int lhs = (az * bz) % P;
        int newAccL = (accL + (w * lhs) % P) % P;
        int newAccR = (accR + (w * rrz) % P) % P;
        int newW = (w * c0) % P;
        require(newW + newAccL + newAccR >= 0);
    }
}`;
{
  const tpl = compile(perMulSrc2);
  const a = Array.from({ length: 12 }, rng), b = Array.from({ length: 12 }, rng), rr = Array.from({ length: 12 }, rng);
  const r = rng(), w = rng(), c0 = rng(), accL = rng(), accR = rng();
  const declOrder = [...a, ...b, ...rr, r, w, c0, accL, accR];
  const unlocking = Uint8Array.from(declOrder.slice().reverse().flatMap((x) => push(x)));
  const res = measure(tpl, unlocking);
  console.log('A) per-mul block (3 Horners + product + 2 RLC):', JSON.stringify({ accepted: res.accepted, opCost: res.opCost, arith: res.arith, base: res.instr * 100, push: res.push, instr: res.instr }));

  // chained variant: A is reused (the previous step's f eval) -> only 2 Horners (B,R)
  const perMulChained = `pragma cashscript ^0.13.0;
contract PerMulCh() {
    function spend(${params('b', 12)}, ${params('rr', 12)}, int az, int r, int w, int c0, int accL, int accR) {
        int P = ${P};
${horner('b', 12)}${horner('rr', 12)}
        int lhs = (az * bz) % P;
        int newAccL = (accL + (w * lhs) % P) % P;
        int newAccR = (accR + (w * rrz) % P) % P;
        int newW = (w * c0) % P;
        require(newW + newAccL + newAccR >= 0);
    }
}`;
  const tpl2 = compile(perMulChained);
  const declOrder2 = [...b, ...rr, rng(), r, w, c0, accL, accR];
  const unlocking2 = Uint8Array.from(declOrder2.slice().reverse().flatMap((x) => push(x)));
  const res2 = measure(tpl2, unlocking2);
  console.log('A2) per-mul CHAINED (reuse A eval, 2 Horners):', JSON.stringify({ accepted: res2.accepted, opCost: res2.opCost, arith: res2.arith, base: res2.instr * 100, instr: res2.instr }));
}

// ============ COMPONENT B: FS transcript hash cost ============
// Bind N committed Fp12 intermediates (12 limbs * 40B = 480B each) into ONE challenge.
// Incremental: state = HASH256(state || limb_chunk). Measure cost of hashing M bytes.
// Cost model (R-bch-vm): OP_HASH256 = 100 + (2 + ceil((L+8)/64)) * iterCost ; iterCost=64 consensus / 192 std.
// We measure the REAL op-cost of hashing a transcript of K 40-byte limbs incrementally.
function fsHashCost(numLimbs) {
  // Build: push limb0..limbK as 40-byte items, OP_CAT them all, OP_HASH256, compare to a precomputed digest.
  // Simulate the per-chunk transcript: all R limbs (12/mul) for the muls in this chunk + Q/big_Q + proof part.
  const limbs = Array.from({ length: numLimbs }, () => {
    const v = rng();
    // 40-byte little-endian pad
    const buf = Buffer.alloc(40);
    let x = v; for (let i = 0; i < 40 && x > 0n; i++) { buf[i] = Number(x & 0xffn); x >>= 8n; }
    return Uint8Array.from(buf);
  });
  // locking: cat all then hash256, then OP_SIZE check (just to consume). We measure op-cost.
  const parts = [];
  for (let i = 0; i < limbs.length; i++) { parts.push([0x28, ...limbs[i]]); if (i > 0) parts.push(O.OP_CAT); }
  parts.push(O.OP_HASH256);
  parts.push(O.OP_SIZE); parts.push([0x01, 0x20]); parts.push(O.OP_NUMEQUALVERIFY); parts.push(O.OP_DROP); parts.push(O.OP_1);
  const lk = asm(...parts);
  const res = measure(lk);
  return { numLimbs, bytes: numLimbs * 40, opCost: res.opCost, push: res.push, instr: res.instr, accepted: res.accepted, error: res.error };
}
// Realistic per-chunk: ~13 muls/chunk (baked Miller ~16 line+sqr ops/chunk). Each commits R (12 limbs).
// Plus Q is BATCHED (one big_Q for whole Miller = 11 limbs, committed once globally, not per chunk).
console.log('B) FS hash cost (incremental OP_CAT+HASH256 over transcript):');
for (const nm of [12, 12 * 13, 12 * 16, 12 * 330, 12 * 330 + 11]) {
  console.log('  ', JSON.stringify(fsHashCost(nm)));
}

// ============ COMPONENT C: witness mass ============
// Each committed R intermediate = 12 limbs * ~32-40 bytes pushed in unlocking.
// Push cost = stackPushedBytes (1x for data push, billed once). 12 limbs ~ 12*33 = 396 bytes/mul.
console.log('C) witness mass: R = 12 limbs/mul. push ~33B/limb (32B val + len) => ~396B/mul stack-pushed.');
console.log('   These bytes go in UNLOCKING (displaces op-cost padding in op-bound chunks, but ADD to tx size).');
